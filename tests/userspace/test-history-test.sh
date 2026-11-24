#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-history-test.sh - scripts/history_test.py, the HistoryTest/ recorder
# (CLAUDE.MD section 9). Runs against a throwaway archive (SS_HISTORYTEST_DIR):
#   * run/add create sealed runs with RUN.md, command.txt, environment.md and a
#     manifest chained to the previous run;
#   * secrets, e-mail addresses, home-directory user names and private IPv4
#     addresses never reach the archive (CWE-532, CWE-200, NIST AU-9);
#   * verify accepts a fork from merged branches (each run links an earlier
#     sealed manifest) but catches a changed file, an extra file, a broken chain, unredacted
#     data and a stale index (NIST AU-10); note/invalidate stay append-only;
#   * hostile run ids and areas cannot leave the archive (CWE-22);
#   * HistoryTest/ is never part of a release (scripts/gen-sbom.sh --list).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export SS_HISTORYTEST_DIR="$T/ht"
mkdir -p "$SS_HISTORYTEST_DIR"
printf '# HistoryTest\n\n<!-- history-test:index:begin -->\n<!-- history-test:index:end -->\n' > "$SS_HISTORYTEST_DIR/README.md"
H() { python3 -B "$ROOT/scripts/history_test.py" "$@"; }

# a fake suite that prints TAP plus things that must be redacted
cat > "$T/suite.sh" <<'S'
#!/bin/sh
echo "ok 1 - first"
echo "ok 2 - # SKIP no tool"
echo "not ok 3 - third"
echo "contact admin@example.org, home /home/alice/x, peer 192.168.4.7 and 10.1.2.3, token=abc123"
echo "loopback 127.0.0.1 and doc range 203.0.113.9 stay"
exit 1
S
chmod +x "$T/suite.sh"
r1="$(H run --area unit-demo --commit abcdef1 -- sh "$T/suite.sh" 2>/dev/null)"; rc=$?
eq "run: a failing suite exits 1" "$rc" 1
D1="$SS_HISTORYTEST_DIR/runs/$r1"
check "run: the run id has the documented form" bash -c "[[ '$r1' =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}Z_unit-demo_abcdef1$ ]]"
for f in RUN.md manifest.json command.txt environment.md logs/stdout.log logs/stderr.log results/tap-summary.txt; do
	check "run: has $f" test -f "$D1/$f"
done
for d in results logs artifacts projects/input projects/output; do check "run: has $d/" test -d "$D1/$d"; done
check "run: verdict fail and the failing test are in RUN.md" bash -c "grep -q 'Verdict:\*\* \*\*fail' '$D1/RUN.md' && grep -q 'not ok 3 - third' '$D1/RUN.md'"
check "run: TAP counts are recorded" grep -qx 'ok=2 not_ok=1 skipped=1 exit=1' "$D1/results/tap-summary.txt"
refute "redaction: no e-mail address is stored" grep -rq 'admin@example.org' "$D1"
refute "redaction: no home-directory user name is stored" grep -rq '/home/alice' "$D1"
refute "redaction: no private IPv4 address is stored" grep -rqE '192\.168\.4\.7|10\.1\.2\.3' "$D1"
refute "redaction: no token value is stored" grep -rq 'abc123' "$D1"
check "redaction: loopback and documentation addresses stay readable" grep -q '127.0.0.1 and doc range 203.0.113.9' "$D1/logs/stdout.log"
refute "environment.md names no host" grep -qi "$(hostname)" "$D1/environment.md"
check "manifest: the first run has no predecessor" python3 -c "import json,sys;m=json.load(open(sys.argv[1]));sys.exit(m['previous_run'] is not None)" "$D1/manifest.json"

printf 'ok 1 - a\nok 2 - b\n1..2\n' > "$T/pc.tap"
r2="$(H add --area vm-demo --commit 1234567 --title 'PC run' --verdict pass --where 'owner PC (VM)' --date 2099-01-01T00:00:00Z --command-text 'bash run.sh' --results "$T/pc.tap" --file "$T/pc.tap" 2>/dev/null)"
D2="$SS_HISTORYTEST_DIR/runs/$r2"
check "add: archives received results" test -f "$D2/results/pc.tap"
check "manifest: the second run links the first run's manifest" python3 -c "
import hashlib,json,sys
m=json.load(open(sys.argv[1])); h=hashlib.sha256(open(sys.argv[2],'rb').read()).hexdigest()
sys.exit(not (m['previous_run']==sys.argv[3] and m['previous_manifest_sha256']==h))" "$D2/manifest.json" "$D1/manifest.json" "$r1"
check "index: INDEX.csv lists both runs" bash -c "grep -q '^$r1,' '$SS_HISTORYTEST_DIR/INDEX.csv' && grep -q '^$r2,' '$SS_HISTORYTEST_DIR/INDEX.csv'"
check "index: the README table is generated between the markers" grep -q "runs/$r2/RUN.md" "$SS_HISTORYTEST_DIR/README.md"
check "verify: a clean archive verifies" H verify
r3="$(H add --area zz-late --commit 1234567 --title a --verdict pass --where x --command-text x 2>/dev/null)"
r4="$(H add --area aa-early --commit 1234567 --title b --verdict pass --where x --command-text x 2>/dev/null)"
check "ids sort in archive order even within one second (chain stays valid)" bash -c "[[ '$r3' < '$r4' ]]"
printf '\377\376\0' > "$T/bin.dat"
refute_with "add: a binary file is refused" "binary file refused" H add --area vm-demo --commit 1234567 --title x --verdict pass --where x --command-text x --file "$T/bin.dat"
eq "add: a refused file leaves no half-written run" "$(find "$SS_HISTORYTEST_DIR/runs" -mindepth 1 -maxdepth 1 -type d | wc -l)" 4

H note "$r1" --text "corrected: test 3 failed because of the fake suite (admin@example.org)" >/dev/null
check "note: appends a dated entry" grep -q '^## .* - note' "$D1/NOTES.md"
refute "note: is redacted too" grep -q 'admin@example.org' "$D1/NOTES.md"
check "verify: notes do not break the seal" H verify
H invalidate "$r2" --reason "copied from another commit" >/dev/null
check "invalidate: the index shows invalid" grep -q "^$r2,.*,invalid," "$SS_HISTORYTEST_DIR/INDEX.csv"
check "verify: still verifies after invalidate" H verify

cp "$D1/logs/stdout.log" "$T/keep"; echo "tampered" >> "$D1/logs/stdout.log"
refute_with "verify: a changed file is caught" "changed after the run was sealed" H verify
cp "$T/keep" "$D1/logs/stdout.log"
echo x > "$D1/artifacts/extra.txt"
refute_with "verify: a file outside the manifest is caught" "not in the manifest" H verify
rm "$D1/artifacts/extra.txt"
cp "$D1/manifest.json" "$T/m1"; python3 -c "import json,sys;m=json.load(open(sys.argv[1]));m['verdict']='pass';json.dump(m,open(sys.argv[1],'w'))" "$D1/manifest.json"
refute_with "verify: an edited earlier manifest breaks the chain" "chain broken" H verify
cp "$T/m1" "$D1/manifest.json"
echo "leak user@example.com" >> "$D1/NOTES.md"
refute_with "verify: unredacted data is caught" "must be redacted" H verify
python3 - "$D1/NOTES.md" <<'P'
import sys
p=sys.argv[1]; s=open(p).read().replace("leak user@example.com\n",""); open(p,"w").write(s)
P
echo "junk" >> "$SS_HISTORYTEST_DIR/INDEX.csv"
refute_with "verify: a hand-edited index is caught" "INDEX.csv is out of date" H verify
H index >/dev/null
check "verify: clean again after the index is regenerated" H verify
D4="$SS_HISTORYTEST_DIR/runs/$r4"; cp "$D4/manifest.json" "$T/m4"
relink() { python3 -c "
import hashlib,json,sys
m=json.load(open(sys.argv[1])); m['previous_run']=sys.argv[2]
m['previous_manifest_sha256']=hashlib.sha256(open(sys.argv[3],'rb').read()).hexdigest() if sys.argv[3] else 'f'*64
json.dump(m,open(sys.argv[1],'w'),indent=2)" "$D4/manifest.json" "$@"; }
relink "$r1" "$D1/manifest.json"
check "verify: a merged branch fork (run linked to an earlier run, not the newest) verifies" H verify
relink "nope_run" ""
refute_with "verify: a link to a missing run breaks the chain" "chain broken" H verify
relink "$r1" ""
refute_with "verify: a link with the wrong manifest hash breaks the chain" "chain broken" H verify
cp "$T/m4" "$D4/manifest.json"
check "verify: clean after restoring the manifest" H verify

refute_with "run: a hostile area is refused" "bad area" H run --area '../x' --commit abcdef1 -- true
refute_with "note: a hostile run id is refused" "bad run id" H note '../../etc' --text x
check "release: HistoryTest/ is not in the release file list" bash -c "! bash '$ROOT/scripts/gen-sbom.sh' --list | grep -q '^HistoryTest/'"
tap_done
