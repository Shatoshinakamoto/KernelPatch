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
	-DEVENT_CURSOR="\"$T/event-cursor\"" -DHEALTH_FILE="\"$T/daemon.health\"" \
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

# The daemon's chain (C, OpenSSL) against an independent Python one, the
# algorithm evidence-verify uses: every log_checkpoint must match the chain
# value after the lines before it.
if python3 - "$T/log" > "$T/cp" 2>&1 <<'PY'
import hashlib, json, os, sys
d = sys.argv[1]
checked = 0
for name in sorted(os.listdir(d)):
    c = hashlib.sha256(b"secure_sudo-event-chain-v1\t" + name.encode() + b"\n").hexdigest()
    n = 0
    for raw in open(os.path.join(d, name), "rb"):
        line = raw.rstrip(b"\n")
        if b'"event_type":"log_checkpoint"' in line:
            rec = json.loads(line)
            if rec["log"] != name or rec["lines"] != n or rec["chain"] != c:
                sys.exit("checkpoint %r does not match line %d" % (rec, n))
            checked += 1
        c = hashlib.sha256(c.encode() + b"\t" + line + b"\n").hexdigest()
        n += 1
if checked != 2:
    sys.exit("expected 2 checkpoints, found %d" % checked)
PY
then
	ok "the daemon's checkpoints match an independent chain of its log"
else
	not_ok "the daemon's checkpoints match an independent chain of its log ($(cat "$T/cp"))"
fi
tap_done
