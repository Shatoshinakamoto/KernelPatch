# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
# shellcheck shell=bash
# Minimal TAP helpers shared by the shell test suites. Source, don't run.
TAP_N=0
TAP_FAIL=0
ok()   { TAP_N=$((TAP_N + 1)); echo "ok $TAP_N - $*"; }
not_ok() { TAP_N=$((TAP_N + 1)); TAP_FAIL=$((TAP_FAIL + 1)); echo "not ok $TAP_N - $*"; }
# check "description" command...   passes when the command exits 0
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else not_ok "$d"; fi; }
# refute "description" command...  passes when the command exits non-zero
refute() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then not_ok "$d"; else ok "$d"; fi; }
skip() { TAP_N=$((TAP_N + 1)); echo "ok $TAP_N - # SKIP $*"; }
tap_done() { echo "1..$TAP_N"; [ "$TAP_FAIL" -eq 0 ]; }
# refute_with "description" "regex" command...
#   passes only when the command fails AND its stderr matches regex, so a
#   rejection for the wrong reason (missing tool, bad path) does not count.
refute_with() {
	local d="$1" re="$2" err; shift 2
	if err="$("$@" 2>&1 >/dev/null)"; then not_ok "$d (command succeeded)"; return; fi
	if printf '%s' "$err" | grep -qE "$re"; then ok "$d"; else
		not_ok "$d (wrong reason: $(printf '%s' "$err" | tail -1))"; fi
}
# eq "description" got want   passes when the two strings are equal
eq() { if [ "$2" = "$3" ]; then ok "$1"; else not_ok "$1 (got '$2', want '$3')"; fi; }
