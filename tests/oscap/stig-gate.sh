#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# stig-gate.sh - the STIG regression gate (TODO P0-2/P0-3).
#
#   tests/oscap/stig-gate.sh [--diagnostic] [--expect FILE] [RESULTS]
#
# Compares an OpenSCAP result, rule by rule, with tests/oscap/
# ubuntu2404-stig.expect: only the listed fails (encrypt_partitions, OSB-12,
# and the accepted exceptions), no error, no unknown, and every notchecked
# rule explained and flagged for manual review. Rules the scanner cannot
# evaluate here (OSB-19) are judged by stig-harden.sh's independent checks,
# read from RESULTS' sibling <name>.crosscheck. RESULTS is an XCCDF/ARF
# results file or saved `oscap xccdf eval` output; without it, the gate runs
# a fresh scan with scripts/stig-harden.sh --scan into a scratch directory
# (root, oscap and the SSG content needed).
#
# Release mode (default) is the acceptance gate and refuses to run inside a
# container: run it in an Ubuntu 24.04 VM with systemd and AppArmor.
# --diagnostic is for containers: same comparison, container-only results
# tolerated, and the output says it is not a release result.
# Exit: 0 gate passed; 1 gate failed; 2 could not run.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MODE=release
EXPECT="$HERE/ubuntu2404-stig.expect"
RES=""
while [ $# -gt 0 ]; do
	case "$1" in
	--diagnostic) MODE=diagnostic ;;
	--expect)     EXPECT="${2:?}"; shift ;;
	-h|--help)    sed -n '3,22p' "$0"; exit 0 ;;
	-*)           echo "stig-gate: unknown option $1" >&2; exit 2 ;;
	*)            RES="$1" ;;
	esac
	shift
done

# The release gate needs what a container lacks: systemd as PID 1, AppArmor
# enabled, and not running under a container runtime.
release_env_problem() {
	if [ -e /.dockerenv ] || [ -e /run/.containerenv ] ||
		{ command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt -cq; }; then
		echo "this is a container"; return
	fi
	[ "$(ps -p 1 -o comm= 2>/dev/null)" = systemd ] || { echo "PID 1 is not systemd"; return; }
	[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ] || echo "AppArmor is not enabled"
}
if [ "$MODE" = release ] && [ -z "$RES" ]; then
	why="$(release_env_problem)"
	if [ -n "$why" ]; then
		echo "stig-gate: $why; the release gate must run in an Ubuntu VM with systemd and AppArmor" >&2
		echo "stig-gate: (use --diagnostic here; a diagnostic scan is never a release result)" >&2
		exit 2
	fi
fi

if [ -z "$RES" ]; then
	[ "$(id -u)" -eq 0 ] || { echo "stig-gate: a fresh scan needs root" >&2; exit 2; }
	out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
	bash "$ROOT/scripts/stig-harden.sh" --scan --outdir "$out" || { echo "stig-gate: scan failed" >&2; exit 2; }
	RES="$(find "$out" -name 'baseline-results-*.xml' | head -1)"
	[ -n "$RES" ] || { echo "stig-gate: scan wrote no results" >&2; exit 2; }
fi
python3 -I "$ROOT/scripts/oscap-results.py" gate "$RES" --expect "$EXPECT" --mode "$MODE"
