#!/bin/sh
# sign_zone.sh — write zone file from stdin, validate, sign, reload.
#
# Called via doas by nonstatic.py. Reads new zone content from stdin.
# All input validation and text manipulation happens in Python.
#
# Usage: sign_zone.sh < new-zone-content
#
# Install: /usr/local/bin/sign_zone.sh  root:wheel 0755

set -eu

ZONE="jitter.eu"
ZONEDIR="/var/nsd/zones/master"
KEYDIR="/var/nsd"
KSK="${KEYDIR}/Kjitter.eu.+013+21181"
ZSK="${KEYDIR}/Kjitter.eu.+013+61557"

ZONEFILE="${ZONEDIR}/${ZONE}.zone"

die() { echo "sign_zone: $*" >&2; exit 1; }

[ $# -eq 0 ] || die "usage: $0 < new-zone-content"

# read stdin into zone file
cat > "$ZONEFILE" || die "failed to write $ZONEFILE"

# validate
nsd-checkzone "$ZONE" "$ZONEFILE" || die "zone check failed"

# sign
cd "$ZONEDIR"
ldns-signzone -n -o "$ZONE" "$ZONEFILE" "$KSK" "$ZSK" || die "signing failed"

# reload
nsd-control reload "$ZONE" || die "reload failed"

echo "sign_zone: signed and reloaded $ZONE"
