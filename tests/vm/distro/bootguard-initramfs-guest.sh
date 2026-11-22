#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# bootguard-initramfs-guest.sh - runs INSIDE the throwaway guest (driven by
# run-bootguard-initramfs-test.sh, TODO P2-4). Phases, selected by $1:
#   prep   baseline /boot (+ the separate ESP), check the initramfs contents,
#          tamper a /boot file and an ESP file, scan -> a restore is staged
#   verify (after a reboot) the initramfs stage applied it before systemd
# Prints "R ok NAME" / "R fail NAME" lines. Changes the guest freely.
set -u
L=/var/log/secure_sudo/addons
ST=/var/lib/secure_sudo/addons/bootguard
pass=0; fail=0
r() { if eval "$2"; then echo "R ok $1"; pass=$((pass+1)); else echo "R fail $1"; fail=$((fail+1)); fi; }

# evidence_has TEXT: an evidence blob (8-byte LE length header, then zlib) under
# the BootGuard evidence dir contains TEXT. Kept out of the r "..." strings,
# which are eval'd, so no quoting can change the Python.
evidence_has() {
	python3 - "$1" <<'PY'
import glob, sys, zlib
want = sys.argv[1].encode()
found = False
for f in glob.glob('/var/lib/secure_sudo/addons/evidence/bootguard/*/evidence.*.z'):
    try:
        if want in zlib.decompress(open(f, 'rb').read()[8:]):
            found = True
    except (zlib.error, OSError):
        pass
sys.exit(0 if found else 1)
PY
}

case "${1:-}" in
prep)
	IMG="/boot/initrd.img-$(uname -r)"
	r "the initramfs carries the BootGuard local-bottom script" \
		"lsinitramfs $IMG | grep -q 'scripts/local-bottom/secure-sudo-bootguard'"
	r "... a chroot" "lsinitramfs $IMG | grep -qE '(^|/)chroot\$'"
	r "... and vfat for the ESP (a module in it, or built into the kernel)" \
		"lsinitramfs $IMG | grep -q 'vfat' || grep -q '^CONFIG_VFAT_FS=y' /boot/config-$(uname -r)"
	r "the guest has a separate ESP mounted at /boot/efi (the case under test)" \
		"findmnt -n /boot/efi >/dev/null && [ \"\$(findmnt -n -o SOURCE /boot/efi)\" != \"\$(findmnt -n -o SOURCE /)\" ]"
	echo good-boot > /boot/ss-p24.txt
	echo good-esp > /boot/efi/ss-p24.txt
	sync
	secure-sudo-bootguard baseline > /dev/null
	r "baseline covers the file on the separate ESP" "grep -q 'efi/ss-p24.txt' $ST/manifest* 2>/dev/null || grep -rq 'efi/ss-p24.txt' $ST 2>/dev/null"
	systemctl enable secure-sudo-bootguard-restore.service >/dev/null 2>&1
	echo evil-boot > /boot/ss-p24.txt
	echo evil-esp > /boot/efi/ss-p24.txt
	sync
	secure-sudo-bootguard scan > "$L/p24-scan.out" 2>&1
	r "scan stages a restore for next boot (nothing written live)" \
		"[ -e $ST/PENDING ] && [ \"\$(cat /boot/ss-p24.txt)\" = evil-boot ] && [ \"\$(cat /boot/efi/ss-p24.txt)\" = evil-esp ]"
	;;
verify)
	r "after the reboot /boot is restored" "[ \"\$(cat /boot/ss-p24.txt)\" = good-boot ]"
	r "... and the separate ESP is restored" "[ \"\$(cat /boot/efi/ss-p24.txt)\" = good-esp ]"
	r "the PENDING flag is cleared" "[ ! -e $ST/PENDING ]"
	r "the log says the initramfs stage applied it" "grep -q 'applying before system start (stage: initramfs)' $L/bootguard.log"
	r "the systemd unit found nothing left to do (it did not restore again)" \
		"! grep -q 'stage: systemd' $L/bootguard.log && [ \"\$(systemctl show -p Result --value secure-sudo-bootguard-restore.service)\" = success ]"
	r "the replaced bytes are kept as evidence (compressed copies hold the tampered content)" \
		"evidence_has evil-boot"
	r "the status line reports the initramfs stage installed" "secure-sudo-bootguard status | grep -qi 'initramfs stage:.*installed'"
	secure-sudo-bootguard scan | tail -1
	r "a fresh scan after the restore is clean" "secure-sudo-bootguard scan 2>&1 | grep -qi 'intact\|0 tampered'"
	;;
esac
echo "# $pass passed, $fail failed"
