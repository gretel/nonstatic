PREFIX = /usr/local
LIBDIR = ${PREFIX}/lib/nonstatic
BINDIR = ${PREFIX}/bin
RCDIR  = /etc/rc.d
RUNDIR = /var/run/nonstatic
USER   = _nonstatic

all: install

install:
	id -u ${USER} >/dev/null 2>&1 || useradd -s /sbin/nologin -d /nonexistent -L daemon -c nonstatic ${USER}
	install -d -o root -g wheel -m 0755 ${LIBDIR}
	install -o root -g wheel -m 0644 nonstatic.py ${LIBDIR}/
	install -o root -g wheel -m 0755 sign_zone.sh ${BINDIR}/
	install -o root -g wheel -m 0755 rc.d/nonstatic ${RCDIR}/
	install -d -o ${USER} -g wheel -m 0755 ${RUNDIR}
	-rm -f ${BINDIR}/update_and_sign.sh

uninstall:
	rcctl stop nonstatic || true
	rcctl disable nonstatic || true
	rm -f ${RCDIR}/nonstatic
	rm -f ${BINDIR}/sign_zone.sh
	rm -f ${BINDIR}/update_and_sign.sh
	rm -rf ${LIBDIR}
	rm -rf ${RUNDIR}
