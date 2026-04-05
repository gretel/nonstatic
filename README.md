# nonstatic

dynamic DNS updater for [NSD](https://nlnetlabs.nl/projects/nsd/) on
[OpenBSD](https://www.openbsd.org/). an HTTP endpoint receives IP
address updates from a router, edits the zone file, DNSSEC-signs it,
and reloads NSD.

only records inside a dynamic block can be updated — delimited by
`$TTL 60` and the next `$TTL`:

    $TTL 60
    home    IN      A       1.2.3.4
    home    IN      AAAA    2001:db8::1
    office  IN      A       5.6.7.8
    $TTL 86400

requests for hosts without a record in this block are rejected.

## hardening

- **pledge(2)**: `stdio rpath cpath wpath inet proc exec`
- **unveil(2)**: only zone file (read), doas (exec), pidfile dir
- **syslog(3)**: uses C `sendsyslog(2)`, works under `stdio` pledge
- **IP allowlist**: only configured source IPs can trigger updates
- **input validation**: `ipaddress` module, global unicast only
- **privilege separation**: python runs unprivileged, signing via doas

## requirements

- OpenBSD (NSD is in base)
- `pkg_add python ldns-utils`
- DNSSEC keys (KSK + ZSK) already set up

## install

    doas make

creates `_nonstatic` service user if missing, installs:

| source | destination |
|--------|------------|
| `nonstatic.py` | `/usr/local/lib/nonstatic/nonstatic.py` |
| `sign_zone.sh` | `/usr/local/bin/sign_zone.sh` |
| `rc.d/nonstatic` | `/etc/rc.d/nonstatic` |

## post-install

add to `/etc/doas.conf`:

    permit nopass _nonstatic cmd /usr/local/bin/sign_zone.sh

add pf rules — adapt `pf.conf.fragment` to your network, then:

    pfctl -n -f /etc/pf.conf && pfctl -f /etc/pf.conf

enable and start:

    rcctl enable nonstatic
    rcctl start nonstatic

## verify

    curl "http://127.0.0.1:5001/nonstatic?domain=home.example.com&ipaddr=1.2.3.4"

expected response:

    good A=1.2.3.4 serial=2026040501

check syslog:

    grep nonstatic /var/log/messages

## update

    git pull && doas make && doas rcctl restart nonstatic

## uninstall

    doas make uninstall

remove doas.conf and pf.conf entries manually.

## client config

update URL ([fritzbox placeholders](https://fritz.com/en/apps/knowledge-base/FRITZ-Box-7590/30_Setting-up-dynamic-DNS-in-the-FRITZ-Box)):

    http://<server>:5001/nonstatic?domain=<domain>&ipaddr=<ipaddr>&ip6addr=<ip6addr>&ip6lanprefix=<ip6lanprefix>

parameters:

| param | required | description |
|-------|----------|-------------|
| `domain` | yes | FQDN to update (e.g. `home.example.com`, must exist in dynamic block) |
| `ipaddr` | no* | IPv4 address (global unicast) |
| `ip6addr` | no* | IPv6 address (global unicast) |
| `username` | no | accepted, ignored |
| `pass` | no | accepted, ignored |
| `ip6lanprefix` | no | accepted, ignored |
| `dualstack` | no | accepted, ignored |

\* at least one of `ipaddr` or `ip6addr` is required.

auth is IP-based (`ALLOWED_IPS`), not credential-based.

## configuration

`nonstatic.py` — edit constants at top:

| constant | default | description |
|----------|---------|-------------|
| `ALLOWED_IPS` | `{"10.0.32.1", "127.0.0.1"}` | source IPs allowed to trigger updates |
| `LISTEN_PORT` | `5001` | HTTP listen port |
| `ZONEFILE` | `/var/nsd/zones/master/jitter.eu.zone` | path to zone file |
| `ZONE` | `jitter.eu` | zone name (strips FQDN to hostname) |

`sign_zone.sh` — edit constants at top:

| constant | description |
|----------|-------------|
| `ZONE` | zone name (must match `nonstatic.py`) |
| `KSK` | path to key-signing key |
| `ZSK` | path to zone-signing key |

## tests

    python3 test_zone.py

## license

ISC
