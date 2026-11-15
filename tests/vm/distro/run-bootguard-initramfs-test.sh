#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# run-bootguard-initramfs-test.sh - BootGuard's initramfs-stage restore on a
# real distro guest with a SEPARATE ESP (TODO P2-4).
#
# Installs the add-ons with --initramfs, baselines /boot and the ESP, tampers a
# file on each, stages a restore, REBOOTS and checks that the initramfs stage
# (not systemd) restored both, the PENDING flag is cleared and the evidence kept.
# VM_UEFI=1 boots the guest through OVMF (the ESP is then the boot filesystem);
# without it the guest boots by BIOS/GRUB. Not covered (recorded in
# docs/BOOT_ASSURANCE.md): encrypted roots, systemd-boot, dracut distros.
#
# Usage: [VM_UEFI=1] run-bootguard-initramfs-test.sh IMAGE RESULTS-DIR
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
IMG="$(readlink -f "${1:?usage: $0 IMAGE RESULTS-DIR}")"
RES="${2:?RESULTS-DIR}"; mkdir -p "$RES"; RES="$(cd "$RES" && pwd)"
W="$(mktemp -d "${TMPDIR:-/tmp}/ss-bgi-vm.XXXXXX")"
VM="$HERE/vm.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"; bash "$VM" stop "$W" > /dev/null 2>&1; rm -rf "$W"' EXIT
G() { bash "$VM" ssh "$W" "$@"; }
tapify() { # LOGFILE: turn the guest's R lines into TAP
	while IFS= read -r line; do
		case "$line" in
		"R ok "*) ok "${line#R ok }" ;;
		"R fail "*) not_ok "${line#R fail }" ;;
		esac
	done < "$1"
}

if bash "$VM" up "$W" "$IMG" >> "$RES/vm.log" 2>&1; then ok "fresh guest boots (UEFI=${VM_UEFI:-0})"
else not_ok "fresh guest boots"; tap_done; exit 1; fi
G 'cloud-init status --wait' > /dev/null 2>&1
(cd "$ROOT" && tar -czf "$work/a.tgz" temporary tests/vm/distro/bootguard-initramfs-guest.sh)
bash "$VM" put "$W" "$work/a.tgz" /root/a.tgz >> "$RES/vm.log" 2>&1
G 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq gcc make libssl-dev zlib1g-dev' \
	> "$RES/01-apt.log" 2>&1; rc=$?
check "the guest has a compiler and the add-ons' libraries" test "$rc" -eq 0
G 'rm -rf /root/a && mkdir /root/a && tar -xzf /root/a.tgz -C /root/a && bash /root/a/temporary/install-temporary.sh --initramfs' \
	> "$RES/02-install.log" 2>&1; rc=$?
check "install-temporary.sh --initramfs installs the hook and rebuilds the initramfs" sh -c "
	[ $rc -eq 0 ] && grep -qF 'Done.' '$RES/02-install.log'"
G 'bash /root/a/tests/vm/distro/bootguard-initramfs-guest.sh prep' > "$RES/03-prep.log" 2>&1
tapify "$RES/03-prep.log"
if bash "$VM" reboot "$W" >> "$RES/vm.log" 2>&1; then ok "guest reboots with the restore staged"
else not_ok "guest reboots"; tap_done; exit 1; fi
G 'bash /root/a/tests/vm/distro/bootguard-initramfs-guest.sh verify' > "$RES/04-verify.log" 2>&1
tapify "$RES/04-verify.log"
G 'journalctl -b --no-pager | grep -i "secure_sudo bootguard"; cat /var/log/secure_sudo/addons/bootguard.log' > "$RES/05-journal.log" 2>&1
tap_done
