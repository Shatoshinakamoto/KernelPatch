#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# run-install-test.sh - the full install / trial boot / rollback / removal
# exercise in a real distro VM (TODO P0-3, P0-5, P0-6).
#
# On a fresh cloud-image guest it runs the release exactly as an operator
# would, then checks the result from outside:
#   1. preflight, install-kernel (trial boot armed), userspace, verify
#   2. reboot: the secure_sudo kernel comes up once; LSM list, AppArmor,
#      services, verify
#   3. reboot without committing: the previous kernel comes back by itself
#   4. re-arm, reboot, verify --commit, reboot: the new kernel is now default
#   5. policy and recovery exercises on the real kernel (recovery-exercises.sh)
#   6. boot the previous kernel on request, uninstall (refused while PAM uses
#      the modules), check that nothing of ours is left, reboot
# Output is TAP on stdout; every guest command's output is kept in RESULTS.
#
# Usage: run-install-test.sh IMAGE KERNEL-OUT-DIR RESULTS-DIR
#   IMAGE           verified cloud image (tests/vm/distro/README.md)
#   KERNEL-OUT-DIR  what `install.sh build-kernel` wrote: $BUILD_ROOT/out/<release>
# The host must be the guest's distro release (userspace is built here).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
IMG="$(readlink -f "${1:?usage: $0 IMAGE KERNEL-OUT-DIR RESULTS-DIR}")"
KOUT="$(cd "${2:?KERNEL-OUT-DIR}" 2>/dev/null && pwd)"
# Without set -e a failed cd above only empties KOUT, and every check would
# then run against the distro kernel with an empty expected release.
compgen -G "$KOUT/linux-image-*.deb" > /dev/null ||
	{ echo "Bail out! no linux-image package in KERNEL-OUT-DIR '${2}'"; exit 2; }
RES="${3:?RESULTS-DIR}"; mkdir -p "$RES"; RES="$(cd "$RES" && pwd)"
# The VM work dir holds the guest's disk and its SSH key; keep it out of
# RESULTS (which is uploaded as evidence) unless VM_WORK says otherwise.
W_OWNED=""
if [ -n "${VM_WORK:-}" ]; then W="$VM_WORK"
else W="$(mktemp -d "${TMPDIR:-/tmp}/ss-vm.XXXXXX")"; W_OWNED=1; fi
VM="$HERE/vm.sh"
REL="$(basename "$KOUT")"
STEP=0

G() { bash "$VM" ssh "$W" "$@"; }
# gstep NAME CMD: run CMD in the guest, keep its output as RESULTS/NN-NAME.log
gstep() {
	local name="$1"; shift
	STEP=$((STEP + 1))
	G "$@" > "$RES/$(printf %02d "$STEP")-$name.log" 2>&1
	GRC=$?
	LAST="$RES/$(printf %02d "$STEP")-$name.log"
	return "$GRC"
}
inlast() { grep -qE -- "$1" "$LAST"; }
running() { G uname -r 2>/dev/null; }
reboot_vm() { bash "$VM" reboot "$W" >> "$RES/vm.log" 2>&1; }
I='cd /root/ss/KernelPatch-merged && bash install/install.sh'
# What install.sh is allowed to touch, listed with hashes, for before/after.
SNAP='bash /root/guest-snapshot.sh snap'

# ------------------------------------------------------------------ setup
. /etc/os-release
[ "$ID $VERSION_ID" = "ubuntu 24.04" ] || { echo "Bail out! host is $ID $VERSION_ID; build userspace on the guest's release" ; exit 2; }
work="$(mktemp -d)"
trap 'rm -rf "$work"; [ -z "$W_OWNED" ] || { bash "$VM" stop "$W" > /dev/null 2>&1; rm -rf "$W"; }' EXIT
bash "$ROOT/ci/make-release.sh" --out "$work/rel" > "$RES/make-release.log" 2>&1 ||
	{ echo "Bail out! make-release failed"; exit 2; }
bash "$ROOT/install/install.sh" stage-userspace "$work/stage" > "$RES/stage.log" 2>&1 ||
	{ echo "Bail out! stage-userspace failed"; exit 2; }
tar -C "$work" -czf "$work/stage.tgz" stage

rm -rf "$W"
if bash "$VM" up "$W" "$IMG" >> "$RES/vm.log" 2>&1; then ok "fresh guest boots from the verified image"
else not_ok "fresh guest boots"; tap_done; exit 1; fi
G 'cloud-init status --wait' > /dev/null 2>&1
PREV="$(running)"
ok "guest runs the distro kernel $PREV"
rel_tgz=("$work"/rel/*.tar.gz)
bash "$VM" put "$W" "${rel_tgz[0]}" /root/release.tar.gz
bash "$VM" put "$W" "$work/stage.tgz" /root/stage.tgz
bash "$VM" put "$W" "$KOUT" /root/kout
bash "$VM" put "$W" "$HERE/guest-snapshot.sh" /root/guest-snapshot.sh
gstep unpack 'mkdir -p /root/ss && tar -C /root/ss -xzf /root/release.tar.gz && tar -C /root -xzf /root/stage.tgz && ls /root/ss/KernelPatch-merged/install/install.sh'
check "release tarball, staged userspace and kernel packages are in the guest" test "$GRC" -eq 0
# grub.cfg is checked separately: after removal it must equal what GRUB
# generates for this system before anything is installed (written aside,
# the real menu is not touched).
gstep snapshot-before "$SNAP > /root/before.sha; dpkg-query -W -f '\${Package}\n' | sort > /root/pkgs-before
	cp /boot/grub/grub.cfg /root/grub.cfg.image; grub-mkconfig -o /root/grub.cfg.regen 2>/dev/null; wc -l /root/before.sha"

# ------------------------------------------------------- 1. install
# The packages were built on the host, so check what this guest will run.
# (A plain "preflight" also checks the ~20 GB a kernel build needs, which a
# cloud image's disk does not have, and blocks on it.)
gstep preflight "$I preflight install-kernel && $I preflight userspace --prebuilt /root/stage"
check "preflight (install-kernel, userspace) passes on the guest" test "$GRC" -eq 0
check "preflight: trial boot will be used" inlast 'trial boot +yes'
check "preflight: changed nothing" G "$SNAP | cmp -s - /root/before.sha"
gstep install-kernel "$I install-kernel /root/kout"
check "install-kernel succeeds" test "$GRC" -eq 0
check "install-kernel: trial boot armed" inlast 'trial boot armed'
check "the kernel package is installed" G "dpkg-query -W -f '\${Status}' linux-image-$REL | grep -q 'install ok installed'"
check "the boot menu has the new kernel" G "grep -q 'vmlinuz-$REL ' /boot/grub/grub.cfg"
check "the boot menu still has $PREV" G "grep -q 'vmlinuz-$PREV ' /boot/grub/grub.cfg"
check "GRUB default stays on $PREV" G "grub-editenv list | grep -q '^saved_entry=.*gnulinux-$PREV-advanced'"
check "the next boot (only) is the new kernel" G "grub-editenv list | grep -q '^next_entry=.*gnulinux-$REL-advanced'"
gstep userspace "$I userspace --prebuilt /root/stage"
check "userspace install succeeds" test "$GRC" -eq 0
gstep verify-before-reboot "$I verify"
check "verify passes before the reboot" test "$GRC" -eq 0
check "verify: the trial boot is armed" inlast 'armed: the next boot tries it once'

# ------------------------------------------------------ 2. trial boot
reboot_vm
eq "trial boot: the secure_sudo kernel came up" "$(running)" "$REL"
gstep lsm-list 'cat /sys/kernel/security/lsm; echo; cat /proc/cmdline'
check "secure_sudo is an active LSM" inlast 'secure_sudo'
check "AppArmor is still active next to it" inlast 'apparmor'
gstep apparmor 'aa-status --enabled && echo enabled; aa-status 2>&1 | head -5'
check "AppArmor is enabled and loads profiles" inlast '^enabled'
gstep services 'systemctl is-system-running; systemctl --failed --no-legend; systemctl is-active secure-sudod ssh'
check "secure-sudod and sshd are active" sh -c "grep -c '^active' '$LAST' | grep -qx 2"
gstep verify-trial "$I verify"
check "verify passes on the trial boot" test "$GRC" -eq 0
check "verify: running kernel checks" inlast 'ok +active LSMs: .*secure_sudo'
check "verify: module signatures enforced" inlast 'ok +module.sig_enforce=Y'
check "verify: the trial is up, waiting for --commit" inlast 'trial boot is up'
gstep status 'secure-sudo status && secure-sudo lint'
check "secure-sudo status and lint pass against the real kernel" test "$GRC" -eq 0

# --------------------------------------------- 3. uncommitted fallback
reboot_vm
eq "an uncommitted trial falls back to $PREV on the next boot" "$(running)" "$PREV"
gstep verify-fallback "$I verify"
check "verify reports the trial did not stay" inlast 'did not stay up'

# ------------------------------------------------------- 4. commit
gstep rearm "$I install-kernel /root/kout"
check "re-arming the trial (reinstall) succeeds" test "$GRC" -eq 0
reboot_vm
eq "second trial boot runs the secure_sudo kernel" "$(running)" "$REL"
gstep commit "$I verify --commit"
check "verify --commit succeeds" test "$GRC" -eq 0
check "commit makes it the default" inlast 'is now the default boot entry'
reboot_vm
eq "after commit the secure_sudo kernel boots by default" "$(running)" "$REL"

# ----------------------------------------- 5. policy + recovery exercises
bash "$VM" put "$W" "$HERE/recovery-exercises.sh" /root/recovery-exercises.sh
gstep recovery 'bash /root/recovery-exercises.sh'
sed 's/^/# guest: /' "$LAST" | grep -E '^# guest: (ok|not ok)' | sed 's/^# guest: //' | while read -r line; do echo "# $line"; done
check "recovery exercises all pass in the guest" sh -c "! grep -q '^not ok' '$LAST' && grep -q '^1\\.\\.' '$LAST' && [ $GRC -eq 0 ]"
if G 'test -f /root/needs-reboot'; then
	reboot_vm
	eq "after the lock exercise the box reboots into the secure_sudo kernel" "$(running)" "$REL"
	gstep recovery-after-reboot 'bash /root/recovery-exercises.sh --after-reboot'
	check "after the reboot the lock is gone and the fixed policy applies" sh -c "! grep -q '^not ok' '$LAST' && [ $GRC -eq 0 ]"
fi

# ------------------------------------------------ 6. rollback + removal
gstep rollback "$I rollback"
check "install.sh rollback arms the previous kernel for the next boot" sh -c "[ $GRC -eq 0 ] && grep -q 'next boot runs $PREV' '$LAST'"
reboot_vm
eq "rollback: $PREV boots on request" "$(running)" "$PREV"
gstep uninstall-refused "$I uninstall"
check "uninstall refuses while PAM uses the modules" sh -c "[ $GRC -ne 0 ] && grep -q 'PAM still uses' '$LAST'"
gstep uninstall "$I uninstall --remove-pam-lines"
check "uninstall --remove-pam-lines succeeds" test "$GRC" -eq 0
check "uninstall reports a complete removal" inlast 'uninstall complete'
check "no secure_sudo kernel package is left" G "! dpkg-query -W 'linux-*secure-sudo*' 2>/dev/null | grep -q ."
check "the boot menu no longer lists the secure_sudo kernel" G "! grep -q 'secure-sudo' /boot/grub/grub.cfg"
check "grubenv has no saved or one-shot entry left" G "! grub-editenv list | grep -qE '^(saved_entry|next_entry)=.'"
check "the install record is gone" G "! test -e /var/lib/secure_sudo/install"
check "PAM files are back to their original content" G "cmp -s /etc/pam.d/sudo /root/pam-sudo.orig"
gstep compare-after "$SNAP > /root/after.sha; bash /root/guest-snapshot.sh compare /root/before.sha /root/after.sha /root/pkgs-before"
check "clean removal: every file install.sh placed is gone and every file it changed is back" test "$GRC" -eq 0
check "the only packages left behind are runtime libraries/tools, no kernel" sh -c "! grep -q 'packages installed since:.* linux-' '$LAST'"
gstep grub-cfg-after 'diff /root/grub.cfg.regen /boot/grub/grub.cfg; echo "diff-vs-regen=$?"; diff /root/grub.cfg.image /boot/grub/grub.cfg | head -40'
check "the boot menu is byte-identical to the one GRUB generated before the install" inlast '^diff-vs-regen=0$'

reboot_vm
eq "after removal the box boots $PREV" "$(running)" "$PREV"
gstep final-state 'systemctl is-system-running; cat /sys/kernel/security/lsm; echo'
check "after removal systemd is healthy" inlast '^(running|degraded)'

bash "$VM" stop "$W" >> "$RES/vm.log" 2>&1
cp "$W"/console*.log "$RES/" 2>/dev/null
tap_done
