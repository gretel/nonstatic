#!/usr/bin/env python3
"""Smoke tests for zone editing functions."""

import datetime
from nonstatic import update_records, bump_serial, _extract_host, find_dynamic_block

TODAY = datetime.date.today().strftime("%Y%m%d")

# --- zone with bare hostnames ------------------------------------------------

ZONE_BARE = """\
$TTL 86400
@       IN      SOA     ns1.jitter.eu. admin.jitter.eu. (
                        2026040501      ; serial
                        3600            ; refresh
                        900             ; retry
                        604800          ; expire
                        60 )            ; minimum
        IN      NS      ns1.jitter.eu.
$TTL 60
svaha   IN      A       109.230.104.248
svaha   IN      AAAA    2a04:4540:6800:48fb::1
$TTL 86400
www     IN      A       46.23.91.144
"""

# --- zone with FQDN hostnames -----------------------------------------------

ZONE_FQDN = """\
$TTL 86400
@       IN      SOA     ns1.jitter.eu. admin.jitter.eu. (
                        2026040501      ; serial
                        3600            ; refresh
                        900             ; retry
                        604800          ; expire
                        60 )            ; minimum
        IN      NS      ns1.jitter.eu.
$TTL 60
svaha.jitter.eu.   IN      A       109.230.104.248
svaha.jitter.eu.   IN      AAAA    2a04:4540:6800:48fb::1
$TTL 86400
www.jitter.eu.     IN      A       46.23.91.144
"""

# --- zone with comment on $TTL line -----------------------------------------

ZONE_COMMENT = """\
$TTL 86400
@       IN      SOA     ns1.jitter.eu. admin.jitter.eu. (
                        2026040501      ; serial
                        3600            ; refresh
                        900             ; retry
                        604800          ; expire
                        60 )            ; minimum
        IN      NS      ns1.jitter.eu.
$TTL 60 ; dynamic records - lower TTL
svaha   IN      A       109.230.104.248
svaha   IN      AAAA    2a04:4540:6800:48fb::1
$TTL 86400
"""


# --- find_dynamic_block ------------------------------------------------------


def test_find_dynamic_block():
    for name, zone in [
        ("bare", ZONE_BARE),
        ("fqdn", ZONE_FQDN),
        ("comment", ZONE_COMMENT),
    ]:
        lines = zone.splitlines(keepends=True)
        block = find_dynamic_block(lines)
        assert block is not None, f"dynamic block not found in {name} zone"
        start, end = block
        block_text = "".join(lines[start:end])
        assert "$TTL" in block_text
        assert "IN" in block_text
        print(f"find_dynamic_block ({name}): OK (lines {start}-{end})")


test_find_dynamic_block()

# --- update_records with bare hostnames --------------------------------------

new, msg = update_records(ZONE_BARE, "svaha", v4="1.2.3.4", v6="2a04::99")
assert new is not None, f"expected success, got: {msg}"
assert "A=1.2.3.4" in msg
assert "AAAA=2a04::99" in msg
assert "svaha\tIN\tA\t1.2.3.4\n" in new
assert "svaha\tIN\tAAAA\t2a04::99\n" in new
assert "109.230" not in new  # old IP gone
assert "www     IN      A       46.23.91.144" in new  # static untouched
print(f"update_records (bare): OK ({msg})")

# v4 only
new_v4, msg_v4 = update_records(ZONE_BARE, "svaha", v4="5.6.7.8")
assert new_v4 is not None
assert "A=5.6.7.8" in msg_v4
assert "AAAA" not in msg_v4
assert "2a04:4540:6800:48fb::1" in new_v4  # v6 untouched
print(f"update_records v4-only: OK ({msg_v4})")

# v6 only
new_v6, msg_v6 = update_records(ZONE_BARE, "svaha", v6="2a04::ff")
assert new_v6 is not None
assert "AAAA=2a04::ff" in msg_v6
assert "109.230.104.248" in new_v6  # v4 untouched
print(f"update_records v6-only: OK ({msg_v6})")

# --- update_records with FQDN hostnames -------------------------------------

new_fqdn, msg_fqdn = update_records(ZONE_FQDN, "svaha", v4="1.2.3.4", v6="2a04::99")
assert new_fqdn is not None, f"expected success for FQDN zone, got: {msg_fqdn}"
assert "A=1.2.3.4" in msg_fqdn
assert "AAAA=2a04::99" in msg_fqdn
# original FQDN form preserved in output
assert "svaha.jitter.eu.\tIN\tA\t1.2.3.4\n" in new_fqdn
assert "svaha.jitter.eu.\tIN\tAAAA\t2a04::99\n" in new_fqdn
assert "109.230" not in new_fqdn
print(f"update_records (fqdn): OK ({msg_fqdn})")

# --- update_records with $TTL comment ----------------------------------------

new_cmt, msg_cmt = update_records(ZONE_COMMENT, "svaha", v4="1.2.3.4")
assert new_cmt is not None, f"expected success for comment zone, got: {msg_cmt}"
print(f"update_records (comment): OK ({msg_cmt})")

# --- bump_serial (multi-line SOA) --------------------------------------------

bumped, serial = bump_serial(new)
assert bumped is not None
assert serial is not None
assert "2026040501" not in bumped  # old serial replaced
assert serial.startswith(TODAY) or int(serial) > 2026040501  # bumped forward
print(f"bump_serial (multi-line): OK (serial={serial})")

# --- bump_serial (single-line SOA) -------------------------------------------

ZONE_SINGLE_SOA = """\
$TTL 86400
@       IN      SOA     ns1.jitter.eu. hostmaster.jitter.eu. ( 2026040501 7200 900 1209600 86400 )
        IN      NS      ns1.jitter.eu.
$TTL 60
svaha   IN      A       109.230.104.248
$TTL 86400
"""

bumped_s, serial_s = bump_serial(ZONE_SINGLE_SOA)
assert bumped_s is not None, "bump_serial failed on single-line SOA"
assert "2026040501" not in bumped_s
assert "7200 900 1209600 86400" in bumped_s  # other SOA values intact
print(f"bump_serial (single-line): OK (serial={serial_s})")

# --- bump_serial (real zone SOA format) --------------------------------------

ZONE_REAL_SOA = """\
$ORIGIN jitter.eu.
$TTL 86400

; SOA Record
@       IN      SOA     ns1.jitter.eu. hostmaster.jitter.eu. ( 2026040502 7200 900 1209600 86400 )

; NS Records
@       IN      NS      ns1.jitter.eu.
$TTL 60
svaha   IN      A       109.230.104.248
$TTL 86400
"""

bumped_r, serial_r = bump_serial(ZONE_REAL_SOA)
assert bumped_r is not None, "bump_serial failed on real SOA format"
assert "2026040502" not in bumped_r
assert "7200 900 1209600 86400" in bumped_r  # other SOA values intact
print(f"bump_serial (real SOA): OK (serial={serial_r})")

# --- rejection cases ---------------------------------------------------------

# host outside dynamic block
r, m = update_records(ZONE_BARE, "www", v4="9.9.9.9")
assert r is None, f"www should be rejected, got: {m}"
print(f"static host rejected: {m}")

# nonexistent host
r, m = update_records(ZONE_BARE, "bogus", v4="9.9.9.9")
assert r is None
print(f"bogus host rejected: {m}")

# FQDN zone: static host rejected
r2, m2 = update_records(ZONE_FQDN, "www", v4="9.9.9.9")
assert r2 is None
print(f"static host rejected (fqdn): {m2}")

# --- _extract_host -----------------------------------------------------------

assert _extract_host("svaha.jitter.eu") == "svaha"
assert _extract_host("svaha.jitter.eu.") == "svaha"
assert _extract_host("SVAHA.JITTER.EU") == "svaha"
assert _extract_host("svaha") is None  # bare hostname rejected
assert _extract_host("jitter.eu") is None  # bare zone rejected
assert _extract_host("") is None
assert _extract_host("-bad.jitter.eu") is None
assert _extract_host("svaha.other.com") is None  # wrong zone
print("_extract_host: OK")

print("\nALL TESTS PASSED")
