#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# recovery-exercises.sh - TODO P0-6 in a real guest: lint and load against
# the running secure_sudo kernel, then four operator mistakes, each detected
# by the preflight and each recovered from the root session that stays open
# (the way docs/RECOVERY.md tells an operator to work):
#   E1 wrong admin_gid with the setid-exec gate on (sudo users lose sudo)
#   E2 incomplete setid_exec_allow (a non-sudo user loses passwd)
#   E3 a PAM change that breaks sudo (OTP wired before it is set up)
#   E4 an accidental one-way lock with a policy change pending
# E4 needs a reboot: the first run leaves /root/needs-reboot, and the runner
# reboots and calls this again with --after-reboot.
#
# Runs as root in the guest made by run-install-test.sh (users "tester", in
# the sudo group, and "plain"). TAP on stdout.
set -uo pipefail
SS=/root/ss/KernelPatch-merged
# shellcheck source=/dev/null
. "$SS/tests/lib/tap.sh"
CONF=/etc/secure_sudo/secure-sudo.conf
ALLOW=/etc/secure_sudo/setid_exec_allow.conf
SYS=/sys/kernel/secure_sudo

setconf() { # key value
	if grep -qE "^[[:space:]]*$1[[:space:]]*=" "$CONF"; then
		sed -i -E "s|^[[:space:]]*$1[[:space:]]*=.*|$1 = $2|" "$CONF"
	else
		echo "$1 = $2" >> "$CONF"
	fi
}
tester_sudo() { su tester -c "printf '%s\n' tester-pw-1 | sudo -S -k -p '' true" >/dev/null 2>&1; }
tester_sudo_wrong() { su tester -c "printf '%s\n' wrong | sudo -S -k -p '' true" >/dev/null 2>&1; }
plain_passwd() { su plain -c '/usr/bin/passwd -S plain' >/dev/null 2>&1; }
# run CMD..., keeping its output in $OUT and exit status in $RC
run() { OUT="$("$@" 2>&1)"; RC=$?; printf '%s\n' "$OUT" | sed 's/^/#   /'; }
out_has() { printf '%s\n' "$OUT" | grep -qE -- "$1"; }

if [ "${1:-}" != --after-reboot ]; then
	[ -f /root/pam-sudo.orig ] || cp -a /etc/pam.d/sudo /root/pam-sudo.orig
	[ -f /root/conf.orig ] || cp -a "$CONF" /root/conf.orig
	[ -f /root/allow.orig ] || cp -a "$ALLOW" /root/allow.orig
	GID="$(getent group sudo | cut -d: -f3)"

	echo "# baseline: the installed policy on the real kernel"
	run secure-sudo lint
	check "lint: the installed configuration has no errors" test "$RC" -eq 0
	run secure-sudo load
	check "load: succeeds" test "$RC" -eq 0
	check "load: every setting accepted by the kernel, none rejected" out_has ', 0 rejected'
	check "the kernel holds the detected admin group ($GID)" grep -qw "$GID" "$SYS/admin_gid"
	check "tester (sudo group) can sudo" tester_sudo
	check "plain (no sudo) can run passwd" plain_passwd

	echo "# E1: admin_gid points at a group that does not exist, setid-exec gate on"
	setconf admin_gid 4242; setconf block_setid_exec 1
	run secure-sudo lint
	check "E1 lint fails" test "$RC" -ne 0
	check "E1 lint names the missing GID 4242" out_has 'GID 4242 does not exist'
	run secure-sudo load
	check "E1 load fails" test "$RC" -ne 0
	check "E1 load says it refused and changed nothing" out_has 'load refused.*nothing was changed'
	check "E1 the kernel still has the good admin group" grep -qw "$GID" "$SYS/admin_gid"
	check "E1 tester can still sudo (nothing was applied)" tester_sudo
	run secure-sudo load --force
	refute "E1 forced through anyway: tester's sudo is denied by the setid-exec gate" tester_sudo
	echo "# E1 recovery: from the open root session, restore the config and load"
	cp -a /root/conf.orig "$CONF"
	run secure-sudo load
	check "E1 recovery: load accepted" test "$RC" -eq 0
	check "E1 recovery: tester can sudo again" tester_sudo

	echo "# E2: setid-exec gate on, allowlist missing passwd"
	setconf block_setid_exec 1
	run secure-sudo load
	check "E2 load accepted" test "$RC" -eq 0
	check "E2 tester (admin) is unaffected" tester_sudo
	refute "E2 plain cannot run passwd: the allowlist is incomplete" plain_passwd
	echo "# E2 recovery: allowlist the binary, load"
	echo /usr/bin/passwd >> "$ALLOW"
	run secure-sudo load
	check "E2 recovery: load accepted" test "$RC" -eq 0
	check "E2 recovery: plain can run passwd again" plain_passwd
	cp -a /root/conf.orig "$CONF"; cp -a /root/allow.orig "$ALLOW"
	run secure-sudo load

	echo "# E3: OTP wired into sudo before any OTP is set up"
	sed -i '/^@include common-auth/a auth\trequired\tpam_secure_otp.so' /etc/pam.d/sudo
	run secure-sudo lint
	check "E3 lint fails" test "$RC" -ne 0
	check "E3 lint: OTP is wired but not set up" out_has 'no OTP is set up'
	refute "E3 sudo now fails for tester" tester_sudo
	echo "# E3 recovery: from the open root session, take the line out"
	sed -i '/pam_secure_otp\.so/d' /etc/pam.d/sudo
	check "E3 recovery: tester can sudo again" tester_sudo
	echo "# the documented cooldown feed line, kept for the uninstall test"
	sed -i '/^@include common-auth/i auth\toptional\tpam_secure_sudo.so' /etc/pam.d/sudo
	run secure-sudo lint
	check "lint accepts the documented PAM wiring" test "$RC" -eq 0
	check "sudo works with the cooldown feed wired" tester_sudo
	refute "a wrong password is still refused" tester_sudo_wrong

	echo "# E4: the one-way lock engaged by accident, a policy change still pending"
	run secure-sudo lock -y
	check "E4 the lock engages" grep -qx 1 "$SYS/lock"
	setconf sudo_max_fails 7
	run secure-sudo lint
	check "E4 lint fails" test "$RC" -ne 0
	check "E4 lint: the kernel is locked until reboot" out_has 'locked until reboot'
	run secure-sudo load --force
	check "E4 load while locked fails" test "$RC" -ne 0
	check "E4 load says INCOMPLETE, not success" out_has 'INCOMPLETE'
	refute "E4 the lock cannot be undone in place" sh -c "echo 0 > $SYS/lock"
	check "E4 the change has not reached the kernel" sh -c "! grep -qx 7 $SYS/sudo_max_fails"
	check "E4 root can still fix the config file while locked" grep -q '^sudo_max_fails = 7' "$CONF"
	echo "# E4 recovery: reboot (the lock lasts until reboot; load runs at boot)"
	touch /root/needs-reboot
else
	echo "# E4 after the reboot"
	check "E4 the reboot cleared the lock" grep -qx 0 "$SYS/lock"
	check "E4 the fixed config was applied at boot" grep -qx 7 "$SYS/sudo_max_fails"
	check "E4 tester can sudo" tester_sudo
	cp -a /root/conf.orig "$CONF"
	run secure-sudo load
	check "back to the installed policy" test "$RC" -eq 0
	rm -f /root/needs-reboot
fi
tap_done
