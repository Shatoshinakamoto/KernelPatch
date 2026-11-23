#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# build-gate.sh - the release build gate (TODO P0-1). CI runs exactly this;
# so can you, from a clean checkout. Each stage works in a scratch copy, so
# the checkout is never modified, and the whole run is recorded in one file.
#
# Stages (default: all that can run here):
#   lint        bash -n + shellcheck on every shell script, py_compile on the
#               GUI, and the duplicate-LSM-hook check
#   userspace   CLI, daemon, PAM modules, OTP helper, PheonixBox: -Werror
#   addons      every temporary/ add-on: -Werror
#   lsm-headers LSM compile check against installed kernel header trees
#               (or --headers DIR, repeatable), plus --headers-direct DIR
#               trees (downloaded headers, compiled without their kbuild)
#   lsm-tree    in-tree build of the LSM for every ci/kconfig/*.config variant
#               (needs --kernel-tree DIR, a verified kernel source tree)
#   tests       tests/run-all.sh (no root, no network, no kernel needed)
#   package     reproducible release tarball, built twice and compared
#
# Usage: ci/build-gate.sh [--stages a,b,...] [--kernel-tree DIR]
#                         [--headers DIR]... [--headers-direct DIR]...
#                         [--record FILE]
# Exit: 0 every requested stage passed; 1 otherwise.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
STAGES="lint,userspace,addons,lsm-headers,tests,package"
KTREE=""
HEADERS=()
DHEADERS=()
RECORD=""
JOBS="${JOBS:-$(nproc)}"

while [ $# -gt 0 ]; do
	case "$1" in
	--stages)      STAGES="$2"; shift 2 ;;
	--kernel-tree) KTREE="$2"; shift 2 ;;
	--headers)     HEADERS+=("$2"); shift 2 ;;
	--headers-direct) DHEADERS+=("$2"); shift 2 ;;
	--record)      RECORD="$2"; shift 2 ;;
	-h|--help)     sed -n '3,25p' "$0"; exit 0 ;;
	*) echo "build-gate: unknown argument $1" >&2; exit 2 ;;
	esac
done
[ -n "$KTREE" ] && case ",$STAGES," in *,lsm-tree,*) ;; *) STAGES="$STAGES,lsm-tree" ;; esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
RECORD="${RECORD:-$ROOT/build-gate-record.txt}"
declare -A RESULT
fail=0

stage_on() { case ",$STAGES," in *,"$1",*) return 0 ;; esac; return 1; }
say() { printf '\n=== %s\n' "$*"; }
result() { # stage status note
	RESULT[$1]="$2${3:+ ($3)}"
	[ "$2" = pass ] || [ "$2" = skip ] || fail=1
	printf -- '--- %s: %s%s\n' "$1" "$2" "${3:+ ($3)}"
}

# A pristine copy: the gate never builds inside the checkout, and the copy
# restores the executable bits a file share may have dropped.
SRC="$WORK/src"
mkdir -p "$SRC"
(cd "$ROOT" && tar --exclude=./build-gate-record.txt --exclude=./.git -cf - .) | (cd "$SRC" && tar -xf -)
# A second copy that no stage ever touches. The stages build inside $SRC, so
# hashing or packaging $SRC would fold build output into the recorded tree hash
# and the package (TODO P0-1, P0-4): the record's source_tree_sha256 and the
# release package come from $PRISTINE, which is exactly the checked-out sources.
PRISTINE="$WORK/pristine"
cp -a "$SRC" "$PRISTINE"

shell_scripts() {
	(cd "$SRC" && { find . -name '*.sh' -type f; \
		grep -rlE '^#!/(usr/)?bin/(env )?(ba)?sh' --exclude-dir=docs --exclude='*.sh' . 2>/dev/null; } |
		grep -v '/docs/stig/results/' | sed 's|^\./||' | LC_ALL=C sort -u)
}

# ------------------------------------------------------------------ lint
if stage_on lint; then
	say "lint"
	bad=0; n=0
	while IFS= read -r f; do
		n=$((n + 1))
		bash -n "$SRC/$f" || { echo "syntax: $f"; bad=$((bad + 1)); }
	done < <(shell_scripts)
	if command -v shellcheck >/dev/null 2>&1; then
		mapfile -t SH < <(shell_scripts)
		(cd "$SRC" && shellcheck -S warning "${SH[@]}") || bad=$((bad + 1))
	else
		echo "shellcheck not installed"; bad=$((bad + 1))
	fi
	python3 -m py_compile "$SRC/temporary/gui/secure-sudo-gui" || bad=$((bad + 1))
	bash "$SRC/ci/check-lsm-hooks.sh" || bad=$((bad + 1))
	python3 -B "$SRC/ci/check-addon-maturity.py" "$SRC" > "$WORK/addon-maturity.log" 2>&1 ||
		{ grep -v '^ok' "$WORK/addon-maturity.log"; bad=$((bad + 1)); }
	tail -1 "$WORK/addon-maturity.log"
	# the release-support matrix must be current for this release (P3-1)
	python3 -B "$SRC/ci/check-support-matrix.py" "$SRC" > "$WORK/support-matrix.log" 2>&1 ||
		{ grep -v '^ok' "$WORK/support-matrix.log"; bad=$((bad + 1)); }
	tail -1 "$WORK/support-matrix.log"
	# the disclosure and maintenance process documents must stay complete (P3-3)
	python3 -B "$SRC/ci/check-process-docs.py" "$SRC" > "$WORK/process-docs.log" 2>&1 ||
		{ grep -v '^ok' "$WORK/process-docs.log"; bad=$((bad + 1)); }
	tail -1 "$WORK/process-docs.log"
	if [ "$bad" -eq 0 ]; then result lint pass "$n shell scripts"; else result lint FAIL "$bad problems"; fi
fi

# ------------------------------------------------------ userspace / addons
WFLAGS="-O2 -Wall -Wextra -Werror -Wformat -Werror=format-security"
build_dirs() { # stage dir...
	local stage="$1" bad=0 d; shift
	for d in "$@"; do
		local fl="$WFLAGS"
		case "$d" in */pam) fl="$fl -fPIC" ;; esac
		if (cd "$SRC/$d" && make clean >/dev/null 2>&1; CFLAGS="$fl" make -j"$JOBS") > "$WORK/build-${d//\//_}.log" 2>&1; then
			echo "built $d"
		else
			echo "FAILED $d"; tail -20 "$WORK/build-${d//\//_}.log"; bad=$((bad + 1))
		fi
	done
	if [ "$bad" -eq 0 ]; then result "$stage" pass "$# components, -Werror"; else result "$stage" FAIL "$bad failed"; fi
}
if stage_on userspace; then
	say "userspace"
	build_dirs userspace userspace/cli userspace/daemon userspace/pam userspace/otp userspace/pheonixbox userspace/attest
fi
if stage_on addons; then
	say "addons"
	mapfile -t AD < <(cd "$SRC" && find temporary -mindepth 2 -maxdepth 2 -name Makefile -printf '%h\n' | grep -v '/gui$' | LC_ALL=C sort)
	build_dirs addons "${AD[@]}"
fi

# ------------------------------------------------------------ lsm-headers
if stage_on lsm-headers; then
	say "lsm-headers"
	unsupported=()
	if [ "${#HEADERS[@]}" -eq 0 ]; then
		# Auto-discovered header trees older than the documented minimum
		# (docs/SUPPORT.md: older than 6.11 is unsupported; 6.8 has no BPF-token
		# LSM hooks) are recorded as unsupported, not compiled. A tree named
		# with --headers is always compiled.
		MIN_KERNEL_MAJMIN=611
		while IFS= read -r h; do
			v="${h##*/linux-headers-}"; mm=$(( ${v%%.*} * 100 + $(echo "$v" | cut -d. -f2 | tr -dc 0-9) ))
			if [ "$mm" -ge "$MIN_KERNEL_MAJMIN" ]; then HEADERS+=("$h"); else unsupported+=("${v%%-*}"); fi
		done < <(find /usr/src -maxdepth 1 -name 'linux-headers-*-generic' -type d 2>/dev/null | sort)
		[ "${#unsupported[@]}" -eq 0 ] || echo "lsm-headers: not compiled, older than 6.11 (unsupported): ${unsupported[*]}"
	fi
	bad=0; : > "$WORK/lsm-headers.json"
	if [ "${#HEADERS[@]}" -gt 0 ]; then
		bash "$SRC/ci/lsm-compile-check.sh" --mode kbuild --record "$WORK/lsm-k.json" "${HEADERS[@]}" || bad=1
		cat "$WORK/lsm-k.json" >> "$WORK/lsm-headers.json" 2>/dev/null
	fi
	if [ "${#DHEADERS[@]}" -gt 0 ]; then
		bash "$SRC/ci/lsm-compile-check.sh" --mode direct --record "$WORK/lsm-d.json" "${DHEADERS[@]}" || bad=1
		cat "$WORK/lsm-d.json" >> "$WORK/lsm-headers.json" 2>/dev/null
	fi
	nh=$(( ${#HEADERS[@]} + ${#DHEADERS[@]} ))
	if [ "$nh" -eq 0 ]; then
		result lsm-headers skip "no supported kernel headers installed${unsupported[*]:+; unsupported, not compiled: ${unsupported[*]}}"
	elif [ "$bad" -eq 0 ]; then
		result lsm-headers pass "$nh trees (${#HEADERS[@]} kbuild, ${#DHEADERS[@]} direct)"
	else
		result lsm-headers FAIL "see output"
	fi
fi

# --------------------------------------------------------------- lsm-tree
if stage_on lsm-tree; then
	say "lsm-tree"
	if [ -z "$KTREE" ]; then
		result lsm-tree skip "no --kernel-tree given"
	else
		KTREE="$(cd "$KTREE" && pwd)"
		kv="$(make -s -C "$KTREE" kernelversion 2>/dev/null)"
		bash "$SRC/ci/graft-lsm.sh" "$KTREE" >/dev/null || { result lsm-tree FAIL "graft"; KTREE=""; }
		bad=0; nv=0
		for v in "$SRC"/ci/kconfig/*.config; do
			[ -n "$KTREE" ] || break
			name="$(basename "$v" .config)"; nv=$((nv + 1))
			o="$WORK/kobj-$name"
			{
				make -C "$KTREE" O="$o" -s x86_64_defconfig &&
				"$KTREE/scripts/kconfig/merge_config.sh" -m -O "$o" "$o/.config" \
					"$SRC/tests/vm/kernel.config" "$v" >/dev/null &&
				make -C "$KTREE" O="$o" -s olddefconfig
			} > "$WORK/kcfg-$name.log" 2>&1 || { echo "config FAILED: $name"; bad=$((bad + 1)); continue; }
			ok=1
			grep -qx 'CONFIG_SECURITY_SECURE_SUDO=y' "$o/.config" || ok=0
			while IFS= read -r line; do
				case "$line" in
				'# CONFIG_'*' is not set') sym="${line#\# }"; sym="${sym%% *}"
					grep -qE "^$sym=[ym]" "$o/.config" && ok=0 ;;
				CONFIG_*) grep -qxF "$line" "$o/.config" || ok=0 ;;
				esac
			done < "$v"
			[ "$ok" -eq 1 ] || { echo "variant $name did not apply"; bad=$((bad + 1)); continue; }
			if make -C "$KTREE" O="$o" -j"$JOBS" KCFLAGS=-Werror prepare security/secure_sudo/ \
				> "$WORK/kbuild-$name.log" 2>&1; then
				echo "variant $name: OK (config $(sha256sum "$o/.config" | cut -c1-12))"
				echo "$name $(sha256sum "$o/.config" | cut -d' ' -f1)" >> "$WORK/variants.txt"
			else
				echo "variant $name: FAILED"; grep -E 'error|warning' "$WORK/kbuild-$name.log" | head -20
				bad=$((bad + 1))
			fi
		done
		[ -n "$KTREE" ] && { if [ "$bad" -eq 0 ]; then result lsm-tree pass "$kv, $nv variants"; else result lsm-tree FAIL "$bad of $nv variants"; fi; }
	fi
fi

# ------------------------------------------------------------------ tests
if stage_on tests; then
	say "tests"
	if bash "$SRC/tests/run-all.sh" > "$WORK/tests.log" 2>&1; then
		result tests pass "$(grep -c '^ok' "$WORK/tests.log") checks"
	else
		grep -E '^not ok|FAIL' "$WORK/tests.log" | head -40
		result tests FAIL "$(grep -c '^not ok' "$WORK/tests.log") failing"
	fi
fi

# ---------------------------------------------------------------- package
if stage_on package; then
	say "package"
	a="$WORK/pkg-a"; b="$WORK/pkg-b"; mkdir -p "$a" "$b"
	if bash "$PRISTINE/ci/make-release.sh" --out "$a" >/dev/null && bash "$PRISTINE/ci/make-release.sh" --out "$b" >/dev/null; then
		ha="$(cd "$a" && sha256sum ./*.tar.gz | cut -d' ' -f1)"; hb="$(cd "$b" && sha256sum ./*.tar.gz | cut -d' ' -f1)"
		if [ "$ha" = "$hb" ]; then
			result package pass "reproducible, sha256 ${ha:0:16}"
		else
			result package FAIL "two builds differ"
		fi
	else
		result package FAIL "make-release failed"
	fi
fi

# ----------------------------------------------------------------- record
{
	echo "secure_sudo build gate record"
	echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "version=$(cat "$ROOT/VERSION" 2>/dev/null)"
	echo "source_tree_sha256=$(bash "$PRISTINE/scripts/gen-sbom.sh" --tree-hash)"
	# shellcheck disable=SC1091
	echo "host=$(. /etc/os-release; echo "$ID $VERSION_ID") $(uname -m)"
	echo "cc=$(gcc --version | head -1)"
	echo "make=$(make --version | head -1)"
	echo "shellcheck=$(shellcheck --version 2>/dev/null | sed -n 's/^version: //p')"
	[ -n "$KTREE" ] && echo "kernel_tree=$KTREE ($kv)"
	[ -f "$WORK/variants.txt" ] && sed 's/^/kernel_variant_config_sha256 /' "$WORK/variants.txt"
	[ -s "$WORK/lsm-headers.json" ] && sed 's/^/lsm_headers=/' "$WORK/lsm-headers.json"
	for s in lint userspace addons lsm-headers lsm-tree tests package; do
		[ -n "${RESULT[$s]:-}" ] && echo "stage_$s=${RESULT[$s]}"
	done
	echo "overall=$([ "$fail" -eq 0 ] && echo pass || echo FAIL)"
} > "$RECORD"
echo; cat "$RECORD"
exit "$fail"
