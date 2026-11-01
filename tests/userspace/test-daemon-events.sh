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
# Stands in for `secure-sudo` (node-scan): records how it was run, then fails.
cat > "$T/cli-stub.sh" <<STUB
#!/bin/sh
echo "\$* nice=\$(nice)" >> "$T/cli-calls"
sleep 1
exit 3
STUB
chmod 0755 "$T/cli-stub.sh"
# Stands in for apply-net.sh (P1-8): records its arguments, exits with net-rc.
cat > "$T/net-wrapper.sh" <<NETW
#!/bin/sh
echo "\$*" >> "$T/net-calls"
exit "\$(cat "$T/net-rc" 2>/dev/null || echo 0)"
NETW
chmod 0755 "$T/net-wrapper.sh"

if ! (cd "$ROOT" && ${CC:-cc} -O2 -Wall -Wextra -Werror \
	-DLOGDIR="\"$T/log\"" -DQUARANTINE="\"$T/quarantine\"" \
	-DHELPER_QUAR="\"$T/quarantine-wrapper.sh\"" \
	-DREMOTE_QUEUE="\"$T/remote-queue\"" \
	-DEVENT_CURSOR="\"$T/event-cursor\"" -DHEALTH_FILE="\"$T/daemon.health\"" \
	-DSECURE_SUDO_CLI="\"$T/cli-stub.sh\"" \
	-DSYSFS="\"$T/sysfs\"" -DMANIFEST="\"$T/tv-manifest\"" \
	-DHELPER_NET="\"$T/net-wrapper.sh\"" -DNETDIR="\"$T\"" -DNET_REFRESH_SECS=0 \
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
# G2: the same Merkle root from an independent implementation (the one
# evidence-verify uses), and the collector-side check over the daemon's log.
VERIFY="$ROOT/userspace/daemon/helpers/evidence-verify.py"
if python3 - "$VERIFY" "$T/log" "$T/tv-manifest.prev" > "$T/tv" 2>&1 <<'PY'
import hashlib, importlib.util, os, sys
spec = importlib.util.spec_from_file_location("ev", sys.argv[1])
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)
d = sys.argv[2]
recs = []
for name in sorted(os.listdir(d)):
    recs += ev.load_timevault_records(os.path.join(d, name))
base = [r for r in recs if r["event_type"] == "timevault_baseline"]
root = ev.merkle_root(ev.read_timevault_manifest(sys.argv[3]))
if root != base[0]["root"]:
    sys.exit("python root %s != daemon baseline root %s" % (root, base[0]["root"]))
# RFC 6962 shape, by hand for 3 leaves: MTH = H(1 || H(1 || l0 || l1) || l2)
e = {b"/a": b"0" * 64, b"/b": b"1" * 64, b"/c": b"2" * 64}
l = [hashlib.sha256(b"\0" + k + b"\0" + e[k]).digest() for k in sorted(e)]
n01 = hashlib.sha256(b"\1" + l[0] + l[1]).digest()
if ev.merkle_root(e) != hashlib.sha256(b"\1" + n01 + l[2]).hexdigest():
    sys.exit("merkle_root is not the RFC 6962 tree hash")
report, problems = ev.verify_timevault(recs)
# The daemon's own story: two outside changes it caught and undid (warnings),
# a legitimate new baseline after the disengage, then the hand-written v1
# manifest loaded with a different root (a rewrite the collector must flag).
warn = [x for x in report if x.startswith("WARNING: the TimeVault manifest was changed")]
if len(warn) != 2 or len(problems) != 1 or "rewritten" not in problems[0] or "loaded_v1" not in problems[0]:
    sys.exit("unexpected verdict: %r %r" % (report, problems))
# A manifest deleted and the daemon restarted: a second baseline, no disengage.
fake = [dict(base[0]), dict(base[0], reason="no_manifest", root="f" * 64)]
_, p2 = ev.verify_timevault(fake)
if len(p2) != 1 or "new baseline" not in p2[0]:
    sys.exit("re-baseline without disengage not flagged: %r" % p2)
_, p3 = ev.verify_timevault([base[0], dict(base[0], event_type="timevault_merkle", reason="checkpoint")])
if p3:
    sys.exit("a rescan with the same root was flagged: %r" % p3)
print("ok")
PY
then
	ok "G2: evidence-verify's Merkle root matches the daemon's; RFC 6962 shape"
	ok "G2: the collector check passes a rescan and flags a rewritten or re-baselined manifest"
else
	not_ok "G2: evidence-verify's Merkle root matches the daemon's ($(cat "$T/tv"))"
	not_ok "G2: the collector check passes a rescan and flags a rewritten or re-baselined manifest"
fi
tap_done
