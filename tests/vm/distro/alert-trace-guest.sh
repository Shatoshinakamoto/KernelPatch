#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# alert-trace-guest.sh - TODO P2-3 "Done when" in a real guest: one event
# traced from the secure_sudo kernel, through secure-sudod's local log, to a
# collector and to an external alert, with the failures observable.
#
#   1. a local UDP collector and an alert command that records its arguments
#   2. the non-sudo user "plain", holding CAP_SETUID, tries setuid(0): the
#      kernel denies it and raises a credential_change record
#   3. the record is in /var/log/secure_sudo, reached the collector with the
#      critical syslog priority (<82>), and ran alert_cmd as "critical"
#   4. `secure-sudo health` counts the alert
#   5. an alert command that fails is an alert_failed record and makes
#      health degraded
#
# Runs as root in the guest made by run-install-test.sh, on the secure_sudo
# kernel. Restores secure-sudo.conf and the daemon when done. TAP on stdout.
set -uo pipefail
SS=/root/ss/KernelPatch-merged
# shellcheck source=/dev/null
. "$SS/tests/lib/tap.sh"
CONF=/etc/secure_sudo/secure-sudo.conf
# Not under /root: secure-sudod runs with ProtectHome=yes, and alert_cmd
# inherits its sandbox, so an alert command cannot write there.
W=/run/ss-p23
LOGDIR=/var/log/secure_sudo
rm -rf "$W"; mkdir -p "$W"
cp "$CONF" "$W/conf.orig"
COL=""
cleanup() {
	[ -n "$COL" ] && kill "$COL" 2>/dev/null
	cp "$W/conf.orig" "$CONF"
	systemctl restart secure-sudod
	rm -f /usr/local/sbin/ss-alert-trace /usr/local/sbin/ss-alert-fail
}
trap cleanup EXIT

# 1. the collector and the alert commands
python3 -u - "$W/collected" > /dev/null 2>&1 <<'PY' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 5514))
with open(sys.argv[1], "ab", 0) as f:
    while True:
        f.write(s.recv(65535) + b"\n")
PY
COL=$!
printf '#!/bin/sh\nprintf "%%s|" "$@" >> %s/alerts\necho >> %s/alerts\n' "$W" "$W" > /usr/local/sbin/ss-alert-trace
printf '#!/bin/sh\nexit 3\n' > /usr/local/sbin/ss-alert-fail
chmod 0755 /usr/local/sbin/ss-alert-trace /usr/local/sbin/ss-alert-fail
{
	echo 'remote_syslog = 127.0.0.1:5514'
	echo 'remote_syslog_transport = udp'
	echo 'alert_cmd = ss-alert-trace %s %t %d %u "%m"'
	echo 'alert_min_severity = critical'
} >> "$CONF"
check "the alert settings pass secure-sudo lint" secure-sudo lint --no-pam -q
systemctl restart secure-sudod
sleep 2
check "secure-sudod runs with alerting on" systemctl is-active -q secure-sudod

# 2. the kernel event
PU=$(id -u plain)
# setpriv changes the UID before the GID, and secure_sudo refuses the GID
# change of a non-sudo UID (a setgid denial, not the setuid one this test is
# about). So drop the GID and groups as root first, then the UID.
deny() {
	setpriv --regid=plain --clear-groups -- setpriv --reuid=plain --inh-caps=+setuid \
		--ambient-caps=+setuid python3 -c '
import os, sys
try:
    os.setuid(0)
except PermissionError:
    sys.exit(1)
sys.exit(0)'
}
refute "plain (no sudo, with CAP_SETUID) cannot setuid(0)" deny

# 3. local log, collector, alert
waitfor() { # file regex

	for _ in $(seq 30); do
		grep -qE -- "$2" "$1" 2>/dev/null && return 0
		sleep 0.5
	done
	return 1
}
REC='"event_type":"credential_change".*"operation":"setuid".*"decision":"deny".*"target_uid":'"$PU"','
check "the kernel record is in the local log" sh -c "cat $LOGDIR/*.log | grep -qE '$REC'"
check "it reached the collector with the critical priority (<82>)" waitfor "$W/collected" "^<82>secure_sudo: .*$REC"
check "it ran alert_cmd as a critical credential_change, denied, for plain" \
	waitfor "$W/alerts" "^critical\|credential_change\|deny\|$PU\|creds: non-sudo UID $PU denied setuid"
sed 's/^/# alert: /' "$W/alerts" 2>/dev/null | head -3

# 4. health
sleep 6		# the heartbeat is written every 5 s
H="$(secure-sudo health --json 2>/dev/null)"
printf '# %s\n' "$H" | cut -c1-400
check "secure-sudo health counts the alert" sh -c "printf '%s' '$H' | grep -q '\"alert_state\":\"ok\",\"alerts_sent\":[1-9]'"

# 5. a failing alert command is visible
sed -i 's|^alert_cmd = .*|alert_cmd = ss-alert-fail %t|' "$CONF"
systemctl restart secure-sudod
sleep 2
deny
check "a failing alert_cmd is an alert_failed record in the local log" \
	waitfor "$(ls -t $LOGDIR/*.log | head -1)" '"event_type":"alert_failed","alert_for":"credential_change","failure":"exited_nonzero","status":3'
check "... which reaches the collector too" waitfor "$W/collected" '"event_type":"alert_failed"'
sleep 6
H="$(secure-sudo health --json 2>/dev/null)"
check "... and makes secure-sudo health degraded (alert_state failing)" sh -c "
	printf '%s' '$H' | grep -q '\"overall\":\"degraded\"' && printf '%s' '$H' | grep -q '\"alert_state\":\"failing\"'"

tap_done
