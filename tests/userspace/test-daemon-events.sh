#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# test-daemon-events.sh - secure-sudod's handling of kernel event records:
# JSON parsing, which records may trigger the root-run cooldown kill and
# TimeVault quarantine, symlink-safe file handling, and records split
# across ring reads. No root, kernel or network needed.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
# The helper wrapper fails on demand, so the failure path can be tested.
cat > "$T/quarantine-wrapper.sh" <<WRAP
#!/bin/sh
[ -e "$T/fail-helper" ] && exit 1
SS_QUARANTINE_DIR="$T/quarantine" exec sh "$ROOT/userspace/daemon/helpers/quarantine.sh" "\$@"
WRAP
chmod 0755 "$T/quarantine-wrapper.sh"

if ! (cd "$ROOT" && ${CC:-cc} -O2 -Wall -Wextra -Werror \
	-DLOGDIR="\"$T/log\"" -DQUARANTINE="\"$T/quarantine\"" \
	-DHELPER_QUAR="\"$T/quarantine-wrapper.sh\"" \
	-DREMOTE_QUEUE="\"$T/remote-queue\"" \
	-o "$T/test-daemon-events" tests/userspace/test-daemon-events.c \
	-lssl -lcrypto); then
	not_ok "daemon event harness builds (-Werror)"
	tap_done
	exit 1
fi
ok "daemon event harness builds (-Werror)"
"$T/test-daemon-events" "$T" > "$T/results" 2>&1
while IFS= read -r line; do
	case "$line" in
		ok\ *) ok "${line#ok * - }" ;;
		"not ok "*) not_ok "${line#not ok * - }" ;;
		1..*) ;;
		*) echo "# $line" ;;
	esac
done < "$T/results"
grep -q '^1\.\.' "$T/results" || not_ok "harness ran to completion"
tap_done
