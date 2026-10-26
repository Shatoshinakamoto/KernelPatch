#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# run-stig-test.sh - the DISA STIG release run in a real VM (TODO P0-3).
#
# A container cannot evaluate the machine-level STIG rules (no init, no
# AppArmor, no bootloader), so the release gate refuses to run in one. This
# runs the gate where it means something: a fresh Ubuntu 24.04 cloud-image
# guest with the secure_sudo kernel installed and committed through
# install.sh, AppArmor stacked, systemd as PID 1 and GRUB on a virtual disk.
#
#   1. install + commit the secure_sudo kernel and userspace (install.sh)
#   2. site steps a STIG profile cannot do for you (VM-only values):
#      rate-limited SSH in ufw, then ufw enabled; a GRUB superuser password
#      with --unrestricted menu entries (booting stays unattended, editing
#      the command line needs the password); an NTP server, named as the
#      approved one in a tailoring file (stig-vm-tailoring.xml); a weekly
#      audit-log offload job (to a local stand-in: the VM has no log host)
#   3. remediation (scripts/stig-harden.sh --remediate: baseline scan, two
#      fix passes, rescan), reboot, final scan
#   4. tests/oscap/stig-gate.sh (release mode) on the final result
#
# STIG remediation disables root SSH logins, so after step 3 starts the guest
# is driven as "tester" (sudo group) with sudo -S, the way an admin would.
#
# Usage: run-stig-test.sh IMAGE KERNEL-OUT-DIR SSG-DATASTREAM RESULTS-DIR
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
IMG="$(readlink -f "${1:?usage: $0 IMAGE KERNEL-OUT-DIR SSG-DATASTREAM RESULTS-DIR}")"
KOUT="$(cd "${2:?KERNEL-OUT-DIR}" && pwd)"
DS="$(readlink -f "${3:?SSG-DATASTREAM}")"
RES="${4:?RESULTS-DIR}"; mkdir -p "$RES"; RES="$(cd "$RES" && pwd)"
W="${VM_WORK:-$RES/vm}"
VM="$HERE/vm.sh"
REL="$(basename "$KOUT")"
PW=tester-pw-1
STEP=0

G() { bash "$VM" ssh "$W" "$@"; }
# As tester, through sudo (what works once root SSH logins are off).
GT() {
	# One shared connection: ufw's rate limit on SSH (ufw_rate_limit) blocks a
	# 6th new connection within 30 s, and the polls below make many calls.
	ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
		-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 \
		-o ControlMaster=auto -o ControlPath="$work/cm-%C" -o ControlPersist=120 \
		-i "$W/id_vm" -p "${VM_PORT:-2222}" tester@127.0.0.1 \
		"printf '%s\n' '$PW' | sudo -S -p '' bash -c $(printf %q "$*")"
}
# GTJOB CMD: run CMD as root in the guest, detached from the SSH session
# (nohup + setsid), and wait for it. The remediation and the scans run for
# an hour or more without KVM; a dropped connection must not kill them.
GTJOB() {
	local id rc t0=$SECONDS
	id="job$$-$STEP"
	GT "rm -f /root/$id.rc; nohup setsid bash -c $(printf %q "{ $*; } > /root/$id.log 2>&1; echo \$? > /root/$id.rc") </dev/null >/dev/null 2>&1 &" || return 2
	until rc="$(GT "cat /root/$id.rc" 2>/dev/null)" && [ -n "$rc" ]; do
		[ $((SECONDS - t0)) -lt "${JOB_TIMEOUT:-21600}" ] || { echo "guest job $id: no result after ${JOB_TIMEOUT:-21600}s"; return 124; }
		sleep 30
	done
	GT "cat /root/$id.log"
	return "$rc"
}
step() { # name runner cmd
	local name="$1" r="$2"; shift 2
	STEP=$((STEP + 1)); LAST="$RES/$(printf %02d "$STEP")-$name.log"
	"$r" "$@" > "$LAST" 2>&1; GRC=$?
	return "$GRC"
}
running() { GT uname -r 2>/dev/null || G uname -r 2>/dev/null; }
reboot_vm() { # the vm.sh reboot uses root ssh; do it as tester instead
	local bid nb t0
	bid="$(GT cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
	GT 'systemctl reboot' >/dev/null 2>&1
	sleep 20; t0=$SECONDS
	while [ $((SECONDS - t0)) -lt 1500 ]; do
		nb="$(GT cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
		[ -n "$nb" ] && [ "$nb" != "$bid" ] && return 0
		sleep 10
	done
	return 1
}
I='cd /root/ss/KernelPatch-merged && bash install/install.sh'

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
bash "$ROOT/ci/make-release.sh" --out "$work/rel" > "$RES/make-release.log" 2>&1 || { echo "Bail out! make-release"; exit 2; }
bash "$ROOT/install/install.sh" stage-userspace "$work/stage" > "$RES/stage.log" 2>&1 || { echo "Bail out! stage"; exit 2; }
tar -C "$work" -czf "$work/stage.tgz" stage

# --------------------------------------------- 1. secure_sudo installed
rm -rf "$W"
if bash "$VM" up "$W" "$IMG" >> "$RES/vm.log" 2>&1; then ok "fresh guest boots"; else not_ok "fresh guest boots"; tap_done; exit 1; fi
G 'cloud-init status --wait' >/dev/null 2>&1
rel_tgz=("$work"/rel/*.tar.gz)
bash "$VM" put "$W" "${rel_tgz[0]}" /root/release.tar.gz
bash "$VM" put "$W" "$work/stage.tgz" /root/stage.tgz
bash "$VM" put "$W" "$KOUT" /root/kout
bash "$VM" put "$W" "$DS" /root/ssg-ubuntu2404-ds.xml
bash "$VM" put "$W" "$HERE/stig-vm-tailoring.xml" /root/stig-vm-tailoring.xml
step install G "mkdir -p /root/ss && tar -C /root/ss -xzf /root/release.tar.gz && tar -C /root -xzf /root/stage.tgz &&
	$I install-kernel /root/kout && $I userspace --prebuilt /root/stage"
check "install-kernel + userspace succeed" test "$GRC" -eq 0
bash "$VM" reboot "$W" >> "$RES/vm.log" 2>&1
step commit G "$I verify --commit"
check "trial boot of $REL verified and committed" test "$GRC" -eq 0
eq "running the secure_sudo kernel" "$(G uname -r)" "$REL"

# ------------------------------------------------------ 2. site steps
step site G "set -e
	apt-get update -q
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q openscap-scanner ufw chrony
	install -D -m0644 /root/ssg-ubuntu2404-ds.xml /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml
	ufw limit 22/tcp
	# GRUB superuser (VM test password) with unrestricted boot entries.
	hash=\$(printf 'grub-vm-pw\ngrub-vm-pw\n' | grub-mkpasswd-pbkdf2 | sed -n 's/.*is \\(grub\\.pbkdf2.*\\)/\\1/p')
	printf '#!/bin/sh\nexec tail -n +3 \$0\nset superusers=\"root\"\npassword_pbkdf2 root %s\n' \"\$hash\" > /etc/grub.d/01_password
	chmod 0755 /etc/grub.d/01_password
	sed -i 's/^CLASS=\"--class gnu-linux --class gnu --class os\"/CLASS=\"--class gnu-linux --class gnu --class os --unrestricted\"/' /etc/grub.d/10_linux
	grep -q -- '--unrestricted' /etc/grub.d/10_linux
	update-grub
	grep -q '^set superusers' /boot/grub/grub.cfg
	echo 'server 10.0.2.2 iburst maxpoll 16' > /etc/chrony/conf.d/site.conf
	# Weekly audit-log offload. A real site copies to another system (its log
	# host); this VM has none, so the stand-in destination is local.
	printf '%s\n' '#!/bin/sh' 'set -eu' 'd=/var/backups/audit-offload/\$(date +%Y%m%d)' \
		'mkdir -p -m 0700 \"\$d\"' 'find /var/log/audit -name \"audit.log.*\" -exec cp -p {} \"\$d\"/ \\;' \
		> /etc/cron.weekly/audit-offload
	chmod 0700 /etc/cron.weekly/audit-offload
	sh -n /etc/cron.weekly/audit-offload
	ufw --force enable
	ufw status | grep -q 'Status: active'
	echo done"
check "site steps applied (ufw limits ssh and is on, GRUB password with unrestricted entries, chrony server, audit offload job)" test "$GRC" -eq 0
# tester will drive the guest after remediation: prove it works now.
GT id -u > "$RES/tester-sudo.log" 2>&1; eq "tester can reach root through sudo" "$(tail -1 "$RES/tester-sudo.log")" 0

# ------------------------------------------- 3. scan, remediate, rescan
# --remediate scans first (the baseline), then runs its passes and rescans.
SH='bash /root/ss/KernelPatch-merged/scripts/stig-harden.sh --tailoring /root/stig-vm-tailoring.xml'
step remediate GTJOB "$SH --remediate --yes --outdir /var/log/secure_sudo/stig/remediate"
check "baseline scan, remediation and rescan ran to the end" sh -c "[ $GRC -eq 0 ] && grep -q 'remediation complete' '$LAST'"
if reboot_vm; then ok "the hardened guest reboots"; else not_ok "the hardened guest reboots"; fi
eq "after hardening it still runs the secure_sudo kernel" "$(running)" "$REL"
step lsm GT 'cat /sys/kernel/security/lsm; echo; aa-status --enabled && echo apparmor-enabled; systemctl is-system-running; systemctl --failed --no-legend'
check "secure_sudo and AppArmor both active after hardening" sh -c "grep -q secure_sudo '$LAST' && grep -q apparmor-enabled '$LAST'"
step scan-final GTJOB "$SH --scan --outdir /var/log/secure_sudo/stig/final; ls -t /var/log/secure_sudo/stig/final/*results*.xml | head -1 > /tmp/final-xml; chmod 644 /tmp/final-xml"
check "final scan ran" test -s "$LAST"
FX="$(GT cat /tmp/final-xml 2>/dev/null | tail -1)"
GT "cat $FX" > "$RES/final-results.xml" 2>/dev/null
GT "cat ${FX%.xml}.crosscheck" > "$RES/final-results.crosscheck" 2>/dev/null
check "the independent checks (OSB-19) were recorded with the final scan" grep -q encrypt_partitions "$RES/final-results.crosscheck"
GT "tar -C /var/log/secure_sudo -czf - stig" > "$RES/stig-reports.tgz" 2>/dev/null

# ------------------------------------------------------------ 4. gate
bash "$ROOT/tests/oscap/stig-gate.sh" "$RES/final-results.xml" > "$RES/gate-release.txt" 2>&1; rc=$?
sed 's/^/# /' "$RES/gate-release.txt"
check "STIG release gate passes on the VM result" test "$rc" -eq 0
python3 -I "$ROOT/scripts/oscap-results.py" tally "$RES/final-results.xml" > "$RES/tally.txt" 2>&1
python3 -I "$ROOT/scripts/oscap-results.py" rules "$RES/final-results.xml" --not-pass > "$RES/not-pass.txt" 2>&1
echo "# tally: $(cat "$RES/tally.txt")"
check "no evaluation errors" sh -c "grep -q 'error=0' '$RES/tally.txt'"
check "apparmor_configured evaluates (no error) and passes" sh -c "! grep -q 'apparmor_configured' '$RES/not-pass.txt'"

GT 'systemctl poweroff' >/dev/null 2>&1; sleep 30
bash "$VM" stop "$W" >> "$RES/vm.log" 2>&1
cp "$W"/console*.log "$RES/" 2>/dev/null
tap_done
