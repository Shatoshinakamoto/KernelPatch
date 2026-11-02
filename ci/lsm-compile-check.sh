#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# lsm-compile-check.sh - compile every secure_sudo LSM source file against one
# or more kernel header trees, with warnings as errors. This is a fast
# compile check, NOT a substitute for the in-tree build (ci/build-gate.sh
# --kernel-tree) or a boot test (tests/vm/boot-test.sh).
#
# Modes:
#   kbuild  (default) out-of-tree Kbuild run: make -C <tree> M=<copy>. This
#           executes the tree's own host tools (fixdep, modpost, objtool), so
#           use it only for header trees installed by your package manager.
#   direct  calls the system compiler on each file with the x86_64 kernel
#           flags and the tree's include paths. Nothing from the tree is
#           executed, so it is safe for header trees you downloaded and only
#           verified (e.g. Ubuntu mainline builds of a 6.12.y release).
#
# A built-in LSM is compiled here as a module, so modpost's MODULE_LICENSE /
# undefined-symbol complaints are expected and ignored; success means every
# object compiled.
#
# Usage: ci/lsm-compile-check.sh [--mode kbuild|direct] [--cc gcc]
#                                [--record FILE] TREE...
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SRC="$ROOT/kernel/security/secure_sudo"
MODE=kbuild
CC_BIN="${CC:-gcc}"
RECORD=""
TREES=()

while [ $# -gt 0 ]; do
	case "$1" in
	--mode)   MODE="$2"; shift 2 ;;
	--cc)     CC_BIN="$2"; shift 2 ;;
	--record) RECORD="$2"; shift 2 ;;
	-h|--help) sed -n '3,27p' "$0"; exit 0 ;;
	*) TREES+=("$1"); shift ;;
	esac
done
[ "${#TREES[@]}" -gt 0 ] || { echo "usage: $0 [--mode kbuild|direct] TREE..." >&2; exit 2; }
case "$MODE" in kbuild|direct) ;; *) echo "bad --mode $MODE" >&2; exit 2 ;; esac

mapfile -t FILES < <(find "$SRC" -maxdepth 1 -name '*.c' -printf '%f\n' | sort)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Kernel x86_64 CFLAGS (from a 6.14 Kbuild V=1 run), minus the retpoline,
# sanitizer and objtool steps that only matter for the final image.
# -DMODULE is deliberately absent: this code is built in.
direct_flags() {
	local t="$1"
	local f=(
		-nostdinc
		-I"$t/arch/x86/include" -I"$t/arch/x86/include/generated"
		-I"$t/include" -I"$t/arch/x86/include/uapi"
		-I"$t/arch/x86/include/generated/uapi" -I"$t/include/uapi"
		-I"$t/include/generated/uapi"
		-include "$t/include/linux/compiler-version.h"
		-include "$t/include/linux/kconfig.h"
	)
	[ -d "$t/ubuntu/include" ] && f+=(-I"$t/ubuntu/include")
	# A tree configured by a newer compiler (e.g. Ubuntu mainline 6.12.y is
	# built with gcc-15) enables attributes such as counted_by that an older
	# host compiler ignores; that is a header/compiler mismatch, not a fault
	# in this code, so only that one diagnostic is relaxed.
	local tree_gcc cc_gcc
	tree_gcc="$(sed -n 's/^CONFIG_GCC_VERSION=//p' "$t/include/config/auto.conf" 2>/dev/null)"
	cc_gcc="$("$CC_BIN" -dumpfullversion 2>/dev/null | awk -F. '{printf "%d%02d%02d", $1, $2, $3}')"
	if [ -n "$tree_gcc" ] && [ -n "$cc_gcc" ] && [ "$cc_gcc" -lt "$tree_gcc" ]; then
		f+=(-Wno-attributes)
		echo "   note: tree built with gcc $tree_gcc, using $cc_gcc; -Wno-attributes added" >&2
	fi
	f+=(
		-include "$t/include/linux/compiler_types.h"
		-D__KERNEL__ -std=gnu11 -fshort-wchar -funsigned-char -fno-common
		-fno-PIE -fno-strict-aliasing -mno-sse -mno-mmx -mno-sse2 -mno-3dnow
		-mno-avx -fcf-protection=none -m64 -mno-80387 -mno-fp-ret-in-387
		-mpreferred-stack-boundary=3 -mskip-rax-setup -mtune=generic
		-mno-red-zone -mcmodel=kernel -fno-asynchronous-unwind-tables
		-fno-delete-null-pointer-checks -O2 -fno-allow-store-data-races
		-fstack-protector-strong -fno-omit-frame-pointer
		-fno-optimize-sibling-calls -fno-strict-overflow -fno-stack-check
		-fconserve-stack -pg -mrecord-mcount -mfentry -DCC_USING_FENTRY
		-Wall -Wextra -Wundef -Werror=implicit-function-declaration
		-Werror=implicit-int -Werror=return-type -Werror=strict-prototypes
		-Wno-format-security -Wno-trigraphs -Wno-frame-address
		-Wno-address-of-packed-member -Wmissing-declarations
		-Wmissing-prototypes -Wframe-larger-than=1024 -Wno-main
		-Wno-dangling-pointer -Wvla -Wno-pointer-sign -Wcast-function-type
		-Wno-array-bounds -Wno-stringop-overflow -Wno-alloc-size-larger-than
		-Wimplicit-fallthrough=5 -Werror=date-time
		-Werror=incompatible-pointer-types -Werror=designated-init
		-Wenum-conversion -Wunused -Wno-unused-but-set-variable
		-Wno-unused-const-variable -Wno-packed-not-aligned
		-Wno-format-overflow -Wno-format-truncation -Wno-stringop-truncation
		-Wno-override-init -Wno-missing-field-initializers -Wno-type-limits
		-Wno-shift-negative-value -Wno-maybe-uninitialized -Wno-sign-compare
		-Wno-unused-parameter
		-DCONFIG_SECURITY_SECURE_SUDO=1 -Werror
		-DKBUILD_MODNAME='"secure_sudo"' -D__KBUILD_MODNAME=kmod_secure_sudo
	)
	printf '%s\n' "${f[@]}"
}

tree_version() {
	local t="$1" v=""
	if [ -f "$t/include/config/kernel.release" ]; then
		v="$(cat "$t/include/config/kernel.release")"
	elif [ -f "$t/include/generated/utsrelease.h" ]; then
		v="$(sed -n 's/.*UTS_RELEASE "\(.*\)".*/\1/p' "$t/include/generated/utsrelease.h")"
	fi
	printf '%s' "${v:-unknown}"
}

overall=0
results=()
for t in "${TREES[@]}"; do
	t="$(cd "$t" && pwd)" || { echo "no such tree: $t" >&2; overall=1; continue; }
	ver="$(tree_version "$t")"
	echo "== $ver ($MODE) $t"
	b="$WORK/$(basename "$t")"; rm -rf "$b"; cp -r "$SRC" "$b"
	pass=0; fail=0; failed=()
	if [ "$MODE" = kbuild ]; then
		objs="$(printf '%s\n' "${FILES[@]}" | sed 's/\.c$/.o/' | tr '\n' ' ')"
		printf 'obj-m := secure_sudo.o\nsecure_sudo-y := %s\nccflags-y := -DCONFIG_SECURITY_SECURE_SUDO=1 -Werror\n' \
			"$objs" > "$b/Kbuild"
		rm -f "$b/Makefile"
		make -k -C "$t" M="$b" KBUILD_MODPOST_WARN=1 modules > "$b/build.log" 2>&1
		for f in "${FILES[@]}"; do
			if [ -f "$b/${f%.c}.o" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); failed+=("$f"); fi
		done
		grep -E 'error:|warning:' "$b/build.log" | grep -v 'compiler differs' | sort -u | head -40
	else
		mapfile -t FL < <(direct_flags "$t")
		for f in "${FILES[@]}"; do
			if (cd "$b" && "$CC_BIN" "${FL[@]}" -DKBUILD_BASENAME="\"${f%.c}\"" \
				-c -o "${f%.c}.o" "$f") > "$b/${f%.c}.log" 2>&1; then
				pass=$((pass + 1))
			else
				fail=$((fail + 1)); failed+=("$f")
				grep -E 'error:|warning:' "$b/${f%.c}.log" | head -10
			fi
		done
	fi
	echo "   compiled $pass/${#FILES[@]} files${failed[*]:+; FAILED: ${failed[*]}}"
	[ "$fail" -eq 0 ] || overall=1
	results+=("$(printf '{"tree":"%s","release":"%s","mode":"%s","files":%d,"passed":%d,"failed":"%s"}' \
		"$t" "$ver" "$MODE" "${#FILES[@]}" "$pass" "${failed[*]:-}")")
done

if [ -n "$RECORD" ]; then
	{
		printf '{"tool":"lsm-compile-check","date":"%s","cc":"%s","results":[' \
			"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$("$CC_BIN" --version | head -1)"
		(IFS=,; printf '%s' "${results[*]}")
		printf ']}\n'
	} > "$RECORD"
fi
exit "$overall"
