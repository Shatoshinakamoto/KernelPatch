#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# vm.sh - drive a throwaway full-distro QEMU guest (TODO P0-3/P0-5/P0-6).
#
# Unlike tests/vm/boot-test.sh (a RAM-only initramfs), this boots a real
# distro cloud image with its own bootloader, systemd, AppArmor and package
# manager, on a copy-on-write overlay: the downloaded image is never written,
# and "down" throws the guest away. The guest is reached over SSH on a
# forwarded localhost port with a per-run key; its serial console is logged.
#
# Uses KVM when /dev/kvm is writable, else TCG emulation (a boot then takes
# a few minutes).
# Needs: qemu-system-x86_64, qemu-img, cloud-localds, ssh, scp.
#
# Usage:
#   vm.sh up     WORKDIR IMAGE   create the overlay + seed, boot, wait for SSH
#   vm.sh boot   WORKDIR         boot the existing overlay again (after "stop")
#   vm.sh ssh    WORKDIR CMD...  run CMD as root in the guest
#   vm.sh put    WORKDIR SRC DST copy a host file/dir into the guest
#   vm.sh get    WORKDIR SRC DST copy a guest file/dir out
#   vm.sh reboot WORKDIR         reboot the guest and wait for SSH
#   vm.sh wait   WORKDIR         wait for SSH
#   vm.sh stop   WORKDIR         power the guest off (overlay kept)
#   vm.sh down   WORKDIR         power off and delete the overlay
# Env: VM_MEM (MiB, 4096) VM_CPUS (nproc) VM_PORT (2222) VM_DISK (20G)
#      VM_BOOT_TIMEOUT (seconds, 1200)
#      VM_TPM=1: give the guest a TPM 2.0 (swtpm; its state lives in
#      WORKDIR/tpm, so it is the same TPM across reboots) - gap G3.
#      VM_UEFI=1: boot through OVMF (UEFI firmware, its variables in
#      WORKDIR/OVMF_VARS.fd). With VM_TPM=1 the firmware and GRUB then
#      measure the boot and leave a TPM event log (P2-1).
set -uo pipefail

cmd="${1:?usage: vm.sh up|boot|ssh|put|get|reboot|wait|stop|down WORKDIR ...}"
W="${2:?WORKDIR}"; shift 2
MEM="${VM_MEM:-4096}"; CPUS="${VM_CPUS:-$(nproc)}"; PORT="${VM_PORT:-2222}"
BOOT_TIMEOUT="${VM_BOOT_TIMEOUT:-1200}"
SSHO=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=8
	-o BatchMode=yes -i "$W/id_vm")

log() { printf '[vm] %s\n' "$*" >&2; }

vssh() { ssh "${SSHO[@]}" -p "$PORT" root@127.0.0.1 "$@"; }

wait_ssh() {
	local t0=$SECONDS
	while [ $((SECONDS - t0)) -lt "$BOOT_TIMEOUT" ]; do
		if ! kill -0 "$(cat "$W/qemu.pid" 2>/dev/null)" 2>/dev/null; then
			log "guest is not running (see $W/console.log)"; return 2
		fi
		vssh true 2>/dev/null && { log "ssh up after $((SECONDS - t0))s"; return 0; }
		sleep 5
	done
	log "no ssh after ${BOOT_TIMEOUT}s (see $W/console.log)"; return 2
}

start_qemu() {
	local n; n=$(find "$W" -maxdepth 1 -name 'console*.log' | wc -l)
	[ -f "$W/console.log" ] && mv "$W/console.log" "$W/console.$n.log"
	local accel="tcg,thread=multi" cpu=max tpm=() fw=()
	if [ -w /dev/kvm ]; then accel=kvm; cpu=host; fi
	if [ "${VM_TPM:-0}" = 1 ]; then
		mkdir -p "$W/tpm"
		# One swtpm per QEMU run; it exits when QEMU does.
		swtpm socket --tpm2 --tpmstate dir="$W/tpm" \
			--ctrl type=unixio,path="$W/tpm/sock" --terminate \
			--daemon --pid file="$W/tpm/pid" --log file="$W/tpm/log" ||
			{ log "swtpm failed to start"; return 2; }
		tpm=(-chardev "socket,id=chrtpm,path=$W/tpm/sock"
			-tpmdev "emulator,id=tpm0,chardev=chrtpm" -device "tpm-tis,tpmdev=tpm0")
	fi
	if [ "${VM_UEFI:-0}" = 1 ]; then
		local code=/usr/share/OVMF/OVMF_CODE_4M.fd vars=/usr/share/OVMF/OVMF_VARS_4M.fd
		[ -r "$code" ] || { log "VM_UEFI=1 needs OVMF ($code)"; return 2; }
		[ -f "$W/OVMF_VARS.fd" ] || cp "$vars" "$W/OVMF_VARS.fd"
		fw=(-drive "if=pflash,format=raw,readonly=on,file=$code"
			-drive "if=pflash,format=raw,file=$W/OVMF_VARS.fd")
	fi
	qemu-system-x86_64 -name ss-distro-vm -machine q35 -accel "$accel" \
		-cpu "$cpu" -smp "$CPUS" -m "$MEM" "${fw[@]}" "${tpm[@]}" \
		-drive file="$W/disk.qcow2",if=virtio,format=qcow2 \
		-drive file="$W/seed.img",if=virtio,format=raw,readonly=on \
		-netdev user,id=n0,hostfwd=tcp:127.0.0.1:"$PORT"-:22 \
		-device virtio-net-pci,netdev=n0 \
		-serial file:"$W/console.log" -monitor none -display none \
		-daemonize -pidfile "$W/qemu.pid" || { log "qemu failed to start"; return 2; }
}

stop_qemu() {
	local pid; pid="$(cat "$W/qemu.pid" 2>/dev/null)" || return 0
	kill -0 "$pid" 2>/dev/null || return 0
	vssh 'systemctl poweroff' 2>/dev/null
	for _ in $(seq 60); do kill -0 "$pid" 2>/dev/null || return 0; sleep 2; done
	kill "$pid" 2>/dev/null; sleep 2; kill -9 "$pid" 2>/dev/null; return 0
}

case "$cmd" in
up)
	img="$(readlink -f "${1:?IMAGE}")"
	mkdir -p "$W"
	[ -f "$W/id_vm" ] || ssh-keygen -q -t ed25519 -N '' -C ss-vm -f "$W/id_vm"
	qemu-img create -q -f qcow2 -F qcow2 -b "$img" "$W/disk.qcow2" "${VM_DISK:-20G}" || exit 2
	cat > "$W/user-data" <<EOF
#cloud-config
hostname: ss-distro-vm
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys: ["$(cat "$W/id_vm.pub")"]
  - name: tester
    groups: [sudo]
    shell: /bin/bash
    lock_passwd: false
    ssh_authorized_keys: ["$(cat "$W/id_vm.pub")"]
  - name: plain
    shell: /bin/bash
    lock_passwd: false
    ssh_authorized_keys: ["$(cat "$W/id_vm.pub")"]
chpasswd:
  expire: false
  users:
    - {name: tester, password: tester-pw-1, type: text}
    - {name: plain, password: plain-pw-1, type: text}
package_update: false
package_upgrade: false
EOF
	printf 'instance-id: ss-%s\nlocal-hostname: ss-distro-vm\n' "$(date +%s)" > "$W/meta-data"
	cloud-localds "$W/seed.img" "$W/user-data" "$W/meta-data" || exit 2
	start_qemu || exit 2
	wait_ssh ;;
boot)   start_qemu || exit 2; wait_ssh ;;
wait)   wait_ssh ;;
ssh)    vssh "$@" ;;
put)    scp "${SSHO[@]}" -P "$PORT" -r -q "$1" root@127.0.0.1:"$2" ;;
get)    scp "${SSHO[@]}" -P "$PORT" -r -q root@127.0.0.1:"$1" "$2" ;;
reboot)
	bid="$(vssh cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
	vssh 'systemctl reboot' 2>/dev/null
	sleep 20
	t0=$SECONDS
	while [ $((SECONDS - t0)) -lt "$BOOT_TIMEOUT" ]; do
		kill -0 "$(cat "$W/qemu.pid")" 2>/dev/null || { log "guest died during reboot"; exit 2; }
		nb="$(vssh cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
		if [ -n "$nb" ] && [ "$nb" != "$bid" ]; then log "rebooted after $((SECONDS - t0 + 20))s"; exit 0; fi
		sleep 5
	done
	log "guest did not come back after reboot (see $W/console.log)"; exit 2 ;;
stop)   stop_qemu ;;
down)   stop_qemu; rm -f "$W/disk.qcow2" "$W/qemu.pid" ;;
*)      echo "vm.sh: unknown command $cmd" >&2; exit 2 ;;
esac
