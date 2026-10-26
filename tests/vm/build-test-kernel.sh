#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# build-test-kernel.sh - build a small kernel with secure_sudo built in for
# the disposable QEMU tests (tests/vm/boot-test.sh). The source tree must be
# one you have already verified (scripts/verify-kernel-source.sh for a
# kernel.org release, or apt-get source for a distro tree).
#
# Usage: [EXTRA_CONFIG=overlay.config] tests/vm/build-test-kernel.sh <kernel-source-tree> <out-dir>
# Leaves <out-dir>/bzImage, <out-dir>/modules/ and <out-dir>/build-info.txt.
# EXTRA_CONFIG layers another fragment on top (e.g. kernel-stack-apparmor.config).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
src="$(cd "${1:?usage: $0 <kernel-tree> <out-dir>}" && pwd)"
out="${2:?usage: $0 <kernel-tree> <out-dir>}"
JOBS="${JOBS:-$(nproc)}"
mkdir -p "$out"; out="$(cd "$out" && pwd)"
obj="$out/obj"

bash "$ROOT/ci/graft-lsm.sh" "$src"
make -C "$src" O="$obj" -s x86_64_defconfig
make -C "$src" O="$obj" -s kvm_guest.config
frags=("$HERE/kernel.config")
[ -n "${EXTRA_CONFIG:-}" ] && frags+=("$(cd "$(dirname "$EXTRA_CONFIG")" && pwd)/$(basename "$EXTRA_CONFIG")")
"$src/scripts/kconfig/merge_config.sh" -m -O "$obj" "$obj/.config" "${frags[@]}" >/dev/null
make -C "$src" O="$obj" -s olddefconfig

# Every fragment line must have survived olddefconfig, or the VM would test
# a different kernel than the one asked for.
# The last fragment wins for a symbol both set (e.g. CONFIG_LSM).
missing=0
while IFS= read -r line; do
	case "$line" in ''|'#'*) continue ;; esac
	sym="${line%%=*}"
	want="$(grep -h "^$sym=" "${frags[@]}" | tail -1)"
	grep -qxF "$want" "$obj/.config" || { echo "config not applied: $want" >&2; missing=1; }
done < <(cat "${frags[@]}")
[ "$missing" -eq 0 ] || exit 1

make -C "$src" O="$obj" -j"$JOBS" bzImage modules
rm -rf "$out/modules"
make -C "$src" O="$obj" -s INSTALL_MOD_PATH="$out/modules" modules_install
cp "$obj/arch/x86/boot/bzImage" "$out/bzImage"
{
	echo "kernel_release=$(cat "$obj/include/config/kernel.release")"
	echo "source_tree=$src"
	echo "compiler=$(gcc --version | head -1)"
	echo "config_sha256=$(sha256sum "$obj/.config" | cut -d' ' -f1)"
	echo "lsm_list=$(sed -n 's/^CONFIG_LSM=//p' "$obj/.config")"
	echo "fragments=${frags[*]##*/}"
	echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$out/build-info.txt"
cat "$out/build-info.txt"
