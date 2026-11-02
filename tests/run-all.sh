#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# run-all.sh - run every host-side test suite (TODO P0-2). The build gate's
# "tests" stage runs exactly this.
#
# Suites print TAP. None needs the secure_sudo kernel, the network, or changes
# to the host: they build what they test into scratch directories. Parts that
# need root (real pam_unix in a private mount namespace, real nft in
# throwaway network namespaces, ownership checks) are marked ROOT-ONLY in the
# suites and skipped when not root. The in-kernel tests run in a VM instead:
# tests/vm/build-test-kernel.sh + tests/vm/boot-test.sh.
#
# Usage: tests/run-all.sh [suite-name-substring]
# Exit: 0 every suite passed; 1 otherwise.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILTER="${1:-}"

mapfile -t SUITES < <(cd "$HERE" && find . -name 'test-*.sh' -not -path './vm/*' | sed 's|^\./||' | LC_ALL=C sort)
fail=0; total=0; failed=()
for s in "${SUITES[@]}"; do
	case "$s" in *"$FILTER"*) ;; *) continue ;; esac
	echo "# ===== $s"
	out="$(bash "$HERE/$s" 2>&1)"; rc=$?
	printf '%s\n' "$out"
	n="$(printf '%s\n' "$out" | grep -c '^ok')"
	bad="$(printf '%s\n' "$out" | grep -c '^not ok')"
	total=$((total + n + bad))
	if [ "$rc" -ne 0 ] || [ "$bad" -ne 0 ] || ! printf '%s\n' "$out" | grep -q '^1\.\.[0-9]'; then
		fail=1; failed+=("$s (exit $rc, $bad failing)")
	fi
done
echo "# ===== $total checks in ${#SUITES[@]} suites"
if [ "$fail" -ne 0 ]; then
	printf '# FAILED: %s\n' "${failed[@]}"
	exit 1
fi
echo "# all suites passed"
