#!/usr/bin/env python3
"""nonstatic — dynamic DNS updater for NSD on OpenBSD.

Receives HTTP GET from router with updated IP addresses, edits
zone file (A/AAAA records + SOA serial), pipes result to a
privileged helper script via doas for DNSSEC signing and reload.

Hardened with pledge(2) and unveil(2).
"""

import ctypes
import ctypes.util
import datetime
import ipaddress
import logging
import os
import re
import signal
import subprocess
import sys
import syslog as _syslog_mod
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# --- configuration -----------------------------------------------------------

LISTEN_ADDR = "127.0.0.1"
LISTEN_PORT = 5001
PIDFILE = "/var/run/nonstatic/nonstatic.pid"
SIGN_SCRIPT = "/usr/local/bin/sign_zone.sh"
ZONEFILE = "/var/nsd/zones/master/jitter.eu.zone"
ZONE = "jitter.eu"
SUBPROCESS_TIMEOUT = 30
CONN_TIMEOUT = 10
RATE_LIMIT_SECONDS = 5
MAX_REQUEST_LINE = 2048

ALLOWED_IPS = frozenset(
    {
        "10.0.32.1",  # gateway wg side (forwarded router requests)
        "127.0.0.1",
    }
)

# hostname label: alphanumeric + hyphens, no leading/trailing hyphen, max 63 chars
_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# zone file patterns
_RR_A_RE = re.compile(r"^(\S+)\s+IN\s+A\s+\S+")
_RR_AAAA_RE = re.compile(r"^(\S+)\s+IN\s+AAAA\s+\S+")

# --- logging -----------------------------------------------------------------

log = logging.getLogger("nonstatic")
log.setLevel(logging.INFO)

_fmt = logging.Formatter("nonstatic: %(message)s")
_syslog_fmt = logging.Formatter("%(message)s")  # openlog already sets ident


class _SyslogHandler(logging.Handler):
    """Syslog handler using the C syslog(3) interface. Works under pledge."""

    _LEVEL_MAP = {
        logging.DEBUG: _syslog_mod.LOG_DEBUG,
        logging.INFO: _syslog_mod.LOG_NOTICE,  # INFO -> notice (visible in default syslog.conf)
        logging.WARNING: _syslog_mod.LOG_WARNING,
        logging.ERROR: _syslog_mod.LOG_ERR,
        logging.CRITICAL: _syslog_mod.LOG_CRIT,
    }

    def emit(self, record):
        priority = self._LEVEL_MAP.get(record.levelno, _syslog_mod.LOG_INFO)
        _syslog_mod.syslog(priority, self.format(record))


_syslog_mod.openlog("nonstatic", _syslog_mod.LOG_PID, _syslog_mod.LOG_DAEMON)
_syslog_h = _SyslogHandler()
_syslog_h.setFormatter(_syslog_fmt)
log.addHandler(_syslog_h)

_stderr = logging.StreamHandler(sys.stderr)
_stderr.setFormatter(_fmt)
log.addHandler(_stderr)

# --- pledge / unveil via ctypes ----------------------------------------------

_libc_cache = None


def _libc():
    """Load libc (cached). Fatal if unavailable."""
    global _libc_cache
    if _libc_cache is not None:
        return _libc_cache
    path = ctypes.util.find_library("c")
    if not path:
        log.critical("cannot locate libc")
        sys.exit(1)
    _libc_cache = ctypes.CDLL(path, use_errno=True)
    return _libc_cache


def pledge(promises, execpromises=None):
    """pledge(2) wrapper. Fatal on failure."""
    libc = _libc()
    libc.pledge.restype = ctypes.c_int
    libc.pledge.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    p = promises.encode() if promises else None
    e = execpromises.encode() if execpromises else None
    if libc.pledge(p, e) != 0:
        errno = ctypes.get_errno()
        log.critical("pledge(%r) failed: errno %d", promises, errno)
        sys.exit(1)


def unveil(path, permissions):
    """unveil(2) wrapper. Pass (None, None) to lock."""
    libc = _libc()
    libc.unveil.restype = ctypes.c_int
    libc.unveil.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    p = path.encode() if path else None
    f = permissions.encode() if permissions else None
    if libc.unveil(p, f) != 0:
        errno = ctypes.get_errno()
        log.critical("unveil(%r, %r) failed: errno %d", path, permissions, errno)
        sys.exit(1)


# --- zone file editing -------------------------------------------------------


def read_zone():
    """Read the zone file. Returns content as string."""
    with open(ZONEFILE, "r") as f:
        return f.read()


def find_dynamic_block(lines):
    """Find the dynamic block ($TTL 60 ... next $TTL). Returns (start, end) line indices."""
    start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if start is None:
            # match $TTL 60 with optional suffix (s/m) and comments
            if re.match(r"^\$TTL\s+60[sm]?\s*(;.*)?$", stripped):
                start = i
        else:
            if re.match(r"^\$TTL\s+", stripped):
                return (start, i)
    if start is not None:
        return (start, len(lines))  # block extends to end of file
    return None


def _host_match(record_name, host):
    """Check if a zone file record name matches the target host.

    Handles bare hostname ('svaha') and FQDN ('svaha.jitter.eu.').
    """
    name = record_name.lower().rstrip(".")
    h = host.lower()
    fqdn = f"{h}.{ZONE.lower()}"
    return name == h or name == fqdn


def update_records(content, host, v4=None, v6=None):
    """Update A/AAAA records for host in the dynamic block. Returns (new_content, changes)."""
    lines = content.splitlines(keepends=True)
    block = find_dynamic_block(lines)
    if block is None:
        return None, "no dynamic block ($TTL 60) found in zone file"

    start, end = block
    changes = []

    for i in range(start, end):
        line = lines[i]

        if v4 is not None:
            m = _RR_A_RE.match(line)
            if m and _host_match(m.group(1), host):
                # preserve original name form (bare or FQDN)
                name = m.group(1)
                lines[i] = f"{name}\tIN\tA\t{v4}\n"
                changes.append(f"A={v4}")

        if v6 is not None:
            m = _RR_AAAA_RE.match(line)
            if m and _host_match(m.group(1), host):
                name = m.group(1)
                lines[i] = f"{name}\tIN\tAAAA\t{v6}\n"
                changes.append(f"AAAA={v6}")

    if not changes:
        return None, f"no matching records for '{host}' in dynamic block"

    # check: if v4 requested but no A found, or v6 requested but no AAAA found
    if v4 is not None and not any(c.startswith("A=") for c in changes):
        return None, f"no A record for '{host}' in dynamic block"
    if v6 is not None and not any(c.startswith("AAAA=") for c in changes):
        return None, f"no AAAA record for '{host}' in dynamic block"

    return "".join(lines), ", ".join(changes)


def bump_serial(content):
    """Increment SOA serial (YYYYMMDDNN format). Returns (new_content, new_serial).

    Per RFC 1035 s3.3.13, SOA RDATA is: MNAME RNAME serial refresh retry expire minimum.
    The serial is the first integer after the opening '(' in the SOA record.
    """
    today = datetime.date.today().strftime("%Y%m%d")

    # find SOA record, then first integer after '(' is the serial (RFC 1035)
    soa_match = re.search(r"\bSOA\b", content)
    if not soa_match:
        return None, "no SOA record found in zone file"

    paren_pos = content.find("(", soa_match.end())
    if paren_pos == -1:
        return None, "no opening '(' in SOA record"

    m = re.search(r"(\d+)", content[paren_pos + 1 :])
    if not m:
        return None, "no serial number found in SOA record"

    serial_start = paren_pos + 1 + m.start(1)
    serial_end = paren_pos + 1 + m.end(1)
    old_serial = m.group(1)

    # bump: YYYYMMDDNN format
    if len(old_serial) == 10 and old_serial[:8] == today:
        new_serial = str(int(old_serial) + 1)
    else:
        new_serial = today + "01"

    new_content = content[:serial_start] + new_serial + content[serial_end:]
    return new_content, new_serial


def apply_update(host, v4=None, v6=None):
    """Read zone, update records, bump serial, pipe to sign script.

    Returns (success: bool, message: str).
    """
    try:
        content = read_zone()
    except OSError as exc:
        return False, f"cannot read zone file: {exc}"

    new_content, result = update_records(content, host, v4=v4, v6=v6)
    if new_content is None:
        return False, result  # result is error message

    new_content, serial = bump_serial(new_content)
    if new_content is None:
        return False, serial  # serial is error message

    # pipe edited zone to privileged sign script
    try:
        proc = subprocess.run(
            ["doas", SIGN_SCRIPT],
            input=new_content.encode("utf-8"),
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "sign_zone.sh timed out"
    except OSError as exc:
        return False, f"exec failed: {exc}"

    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        return False, f"sign_zone.sh exited {proc.returncode}: {stderr[:256]}"

    return True, f"{result} serial={serial}"


# --- request handler ---------------------------------------------------------


class NonstaticHandler(BaseHTTPRequestHandler):
    """Handle GET /nonstatic?domain=<host>&ipaddr=<v4>&ip6addr=<v6>."""

    server_version = "nonstatic/2"
    sys_version = ""  # suppress python version in Server header
    _last_update = 0.0  # class-level rate limiter

    def log_message(self, format, *args):  # noqa: A002 — match parent signature
        """Suppress default access log — we log updates explicitly."""
        pass

    def log_error(self, format, *args):  # noqa: A002
        log.warning("%s %s", self.client_address[0], format % args)

    def _respond(self, code, body):
        encoded = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)

    # reject everything except GET
    def do_POST(self):
        self._respond(405, "method not allowed\n")

    def do_PUT(self):
        self._respond(405, "method not allowed\n")

    def do_DELETE(self):
        self._respond(405, "method not allowed\n")

    def do_PATCH(self):
        self._respond(405, "method not allowed\n")

    def do_GET(self):
        # --- source IP check -------------------------------------------------
        client_ip = self.client_address[0]
        if client_ip not in ALLOWED_IPS:
            log.warning("rejected: %s not in allowlist", client_ip)
            self._respond(403, "forbidden\n")
            return

        # --- path check ------------------------------------------------------
        parsed = urlparse(self.path)
        if parsed.path != "/nonstatic":
            self._respond(404, "not found\n")
            return

        # --- rate limit ------------------------------------------------------
        now = time.monotonic()
        if now - NonstaticHandler._last_update < RATE_LIMIT_SECONDS:
            log.warning("rate limited")
            self._respond(429, "ratelimit\n")
            return

        # --- parse and validate params ---------------------------------------
        params = parse_qs(parsed.query)

        # domain is required — tells us which record to update
        # router sends FQDN (e.g. "svaha.jitter.eu"), strip zone suffix
        domain = _single_param(params, "domain")
        if domain is None:
            self._respond(400, "badrequest: missing domain\n")
            return
        host = _extract_host(domain)
        if host is None:
            log.warning("invalid domain: %r", domain[:64])
            self._respond(400, "badrequest: invalid domain\n")
            return

        v4_str = _single_param(params, "ipaddr")
        v6_str = _single_param(params, "ip6addr")
        # router may also send: username, pass, ip6lanprefix, dualstack
        # — all silently ignored (auth is IP-based, not credential-based)

        if v4_str is None and v6_str is None:
            self._respond(400, "badrequest: missing ipaddr or ip6addr\n")
            return

        v4 = None
        if v4_str is not None:
            v4 = _validate_ipv4(v4_str)
            if v4 is None:
                log.warning("bad ipv4: %r", v4_str[:64])
                self._respond(400, "badrequest: invalid ipv4\n")
                return

        v6 = None
        if v6_str is not None:
            v6 = _validate_ipv6(v6_str)
            if v6 is None:
                log.warning("bad ipv6: %r", v6_str[:64])
                self._respond(400, "badrequest: invalid ipv6\n")
                return

        # --- apply update ----------------------------------------------------
        log.info("update: host=%s v4=%s v6=%s", host, v4 or "none", v6 or "none")

        ok, msg = apply_update(host, v4=v4, v6=v6)
        if not ok:
            log.error("update failed: %s", msg)
            self._respond(500, f"servfail: {msg}\n")
            return

        NonstaticHandler._last_update = now
        log.info("update ok: %s", msg)
        self._respond(200, f"good {msg}\n")

    def parse_request(self):
        """Override to enforce max request line length."""
        # raw_requestline is set by handle_one_request() before this is called
        if len(self.raw_requestline) > MAX_REQUEST_LINE:  # type: ignore[attr-defined]
            self.send_error(414, "request too long")
            return False
        return super().parse_request()


# --- input validation --------------------------------------------------------


def _extract_host(domain):
    """Extract hostname from FQDN domain param. Requires zone suffix. Returns None if invalid."""
    d = domain.lower().rstrip(".")
    zone = ZONE.lower()
    if not d.endswith("." + zone):
        return None  # must be FQDN with zone suffix
    host = d[: -(len(zone) + 1)]
    if not host or not _LABEL_RE.match(host):
        return None
    return host


def _single_param(params, key):
    """Extract a single query parameter. Returns None if missing, empty, or multiple."""
    vals = params.get(key)
    if not vals or len(vals) != 1:
        return None
    val = vals[0].strip()
    if not val:
        return None
    if len(val) > 64:  # no valid IP is longer than 45 chars
        return None
    return val


def _validate_ipv4(s):
    """Parse and validate an IPv4 address. Returns IPv4Address or None."""
    try:
        addr = ipaddress.IPv4Address(s)
    except (ipaddress.AddressValueError, ValueError):
        return None
    if not addr.is_global:
        return None
    return addr


def _validate_ipv6(s):
    """Parse and validate an IPv6 address. Returns IPv6Address or None."""
    try:
        addr = ipaddress.IPv6Address(s)
    except (ipaddress.AddressValueError, ValueError):
        return None
    if not addr.is_global:
        return None
    return addr


# --- PID file ----------------------------------------------------------------


def write_pidfile():
    try:
        with open(PIDFILE, "w") as f:
            f.write(str(os.getpid()) + "\n")
    except OSError as exc:
        log.critical("cannot write pidfile %s: %s", PIDFILE, exc)
        sys.exit(1)


def remove_pidfile():
    try:
        os.unlink(PIDFILE)
    except OSError:
        pass


# --- main --------------------------------------------------------------------


def harden():
    """Apply unveil and pledge. Must be called after bind, before serving."""
    unveil("/usr/bin/doas", "x")
    unveil(ZONEFILE, "r")  # read zone file for editing in python
    unveil("/var/run/nonstatic", "rwc")  # pidfile
    unveil(None, None)  # lock filesystem view
    # syslog(3) uses fd opened by openlog() before pledge — no unveil needed
    pledge("stdio rpath cpath wpath inet proc exec")


def main():
    # PID file first (needs filesystem access)
    write_pidfile()

    # signal handlers for clean shutdown
    def _shutdown(signum, frame):
        log.info("caught signal %d, shutting down", signum)
        remove_pidfile()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # bind
    server = HTTPServer((LISTEN_ADDR, LISTEN_PORT), NonstaticHandler)
    server.timeout = CONN_TIMEOUT
    log.info("listening on %s:%d", LISTEN_ADDR, LISTEN_PORT)

    # harden
    harden()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        remove_pidfile()


if __name__ == "__main__":
    main()
