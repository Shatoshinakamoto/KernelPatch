#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# boot-test.sh - boot a secure_sudo kernel in a throwaway QEMU guest and run
# the in-kernel functional tests (tests/vm/ss-functest.c) against it.
# Nothing touches the host: the guest is a RAM-only initramfs with busybox,
# the test program and the kernel's modules, and it powers off at the end.
#
# Works without KVM (TCG emulation, slower). Needs: qemu-system-x86_64, a
# static busybox, gcc with static libc, cpio, gzip.
#
# Usage: tests/vm/boot-test.sh <kernel-out-dir> [result-dir]
#   <kernel-out-dir> is what build-test-kernel.sh produced (bzImage, modules/).
# Exit: 0 all tests passed; 1 a test failed; 2 the guest did not boot/finish.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
kdir="$(cd "${1:?usage: $0 <kernel-out-dir> [result-dir]}" && pwd)"
res="${2:-$kdir/results}"
TIMEOUT="${TIMEOUT:-900}"
BUSYBOX="${BUSYBOX:-$(command -v busybox)}"
mkdir -p "$res"; res="$(cd "$res" && pwd)"

[ -f "$kdir/bzImage" ] || { echo "no bzImage in $kdir" >&2; exit 2; }
file -L "$BUSYBOX" | grep -q 'statically linked' ||
	{ echo "need a static busybox (apt install busybox-static)" >&2; exit 2; }

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
root="$work/root"
mkdir -p "$root"/{bin,sbin,proc,sys,dev,tmp,etc,lib}
cp "$BUSYBOX" "$root/bin/busybox"
gcc -static -O2 -Wall -Wextra -Werror -o "$root/ss-functest" "$HERE/ss-functest.c" \
	2> >(grep -v 'Using .popen' >&2) || { echo "ss-functest build failed" >&2; exit 2; }
[ -d "$kdir/modules/lib/modules" ] && cp -a "$kdir/modules/lib/modules" "$root/lib/"

cat > "$root/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mount -t securityfs none /sys/kernel/security
mount -t tmpfs tmp /tmp
echo "SS_BOOT_OK $(uname -r)"
echo "SS_LSM $(cat /sys/kernel/security/lsm)"
echo "SS_LOCKDOWN $(cat /sys/kernel/security/lockdown 2>/dev/null)"
dmesg | grep -i secure_sudo | sed 's/^/SS_DMESG /'
/ss-functest
echo "SS_EXIT=$?"
# A WARN() splat reads "WARNING: CPU: n PID: n at file:line". A bare
# "WARNING:" also appears in CPU vulnerability notices (SRSO on AMD hosts
# under KVM), which say nothing about this kernel's code.
dmesg | grep -E 'BUG:|Oops|WARNING: CPU:|cut here|Kernel panic|general protection|refcount_t:|UBSAN|KASAN' | sed 's/^/SS_KERNEL_PROBLEM /'
poweroff -f
EOF
chmod 0755 "$root/init" "$root/ss-functest"
(cd "$root" && find . | cpio -o -H newc --quiet | gzip -9n) > "$work/initramfs.gz"

accel=(-accel tcg -cpu max)
[ -w /dev/kvm ] && accel=(-accel kvm -cpu host)
log="$res/console.log"
echo "booting $(sed -n 's/^kernel_release=//p' "$kdir/build-info.txt" 2>/dev/null) under ${accel[1]} (timeout ${TIMEOUT}s)"
# A software TPM for the P2-1 measurement checks, when swtpm is installed
# (SS_VM_TPM=0 boots without one; the PCR replay is then skipped, not failed).
tpm=()
if [ "${SS_VM_TPM:-1}" != 0 ] && command -v swtpm >/dev/null 2>&1; then
	mkdir -p "$work/tpm"
	swtpm socket --tpm2 --tpmstate dir="$work/tpm" --ctrl type=unixio,path="$work/tpm/sock" \
		--daemon --pid file="$work/tpm/pid"
	tpm=(-chardev "socket,id=chrtpm,path=$work/tpm/sock"
		-tpmdev "emulator,id=tpm0,chardev=chrtpm" -device "tpm-tis,tpmdev=tpm0")
	echo "guest TPM: swtpm"
fi
timeout "$TIMEOUT" qemu-system-x86_64 "${accel[@]}" -m 1024 -smp 2 -nographic -no-reboot \
	"${tpm[@]}" -kernel "$kdir/bzImage" -initrd "$work/initramfs.gz" \
	-append "console=ttyS0 panic=-1 loglevel=4" > "$log" 2>&1
qrc=$?
[ -s "$work/tpm/pid" ] && kill "$(cat "$work/tpm/pid")" 2>/dev/null
tr -d '\r' < "$log" > "$log.tmp" && mv "$log.tmp" "$log"

grep -E '^(ok|not ok|1\.\.|#)' "$log" > "$res/functest.tap"
cp "$kdir/build-info.txt" "$res/" 2>/dev/null
grep -q 'SS_BOOT_OK' "$log" || { echo "guest did not boot (qemu rc $qrc); see $log" >&2; exit 2; }
grep -q '^SS_FUNCTEST_DONE' "$log" || { echo "tests did not finish (qemu rc $qrc); see $log" >&2; exit 2; }
grep -E '^SS_(LSM|LOCKDOWN|FUNCTEST_DONE|KERNEL_PROBLEM)' "$log"
grep '^not ok' "$res/functest.tap"
# Skips and diagnostics (measured rates, sample records) go to the job log
# too: CI artifacts are not always reachable, and a check that skipped must
# not look the same as one that passed.
grep -E '^#|^ok .*# SKIP' "$res/functest.tap"
if grep -q '^SS_KERNEL_PROBLEM' "$log"; then
	echo "kernel reported a BUG/WARNING during the run" >&2; exit 1
fi
grep -q '^SS_FUNCTEST_DONE pass=[0-9]* fail=0$' "$log"
