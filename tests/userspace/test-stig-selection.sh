#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-stig-selection.sh - datastream and profile selection and the final
# summary of scripts/stig-harden.sh (TODO P3-2). The functions are taken from
# the script and run against a stub oscap and synthetic results, so no root and
# no OpenSCAP are needed. The summary must list every rule that is not at pass
# so a failed, errored or unchecked rule cannot be left out of the report.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
S="$ROOT/scripts/stig-harden.sh"
mkdir -p "$T/bin" "$T/ssg"
PFX=xccdf_org.ssgproject.content_profile_
# stub oscap: "oscap info --profiles DS" prints the profiles listed in DS.profiles
cat > "$T/bin/oscap" <<'EOS'
#!/bin/sh
[ "$1 $2" = "info --profiles" ] && { cat "$3.profiles" 2>/dev/null; exit 0; }
exit 1
EOS
chmod +x "$T/bin/oscap"
info() { :; }
results() { python3 -I "$ROOT/scripts/oscap-results.py" "$@"; }
eval "$(sed -n '/^pick_datastream() {/,/^}/p;/^pick_profile() {/,/^}/p;/^summarize() {/,/^}/p' "$S")"
export PATH="$T/bin:$PATH"

# pick_datastream
SSG_DIR="$T/ssg"; touch "$SSG_DIR/ssg-ubuntu2404-ds.xml" "$SSG_DIR/ssg-ubuntu2204-ds.xml" "$SSG_DIR/ssg-debian12-ds.xml"
ID=ubuntu; VERSION_ID=24.04; VID=24
eq "datastream: the exact release is chosen" "$(pick_datastream)" "$SSG_DIR/ssg-ubuntu2404-ds.xml"
VERSION_ID=25.04
eq "datastream: an unknown release falls back to the newest of the family" "$(pick_datastream)" "$SSG_DIR/ssg-ubuntu2404-ds.xml"
ID=debian; VERSION_ID=12.5; VID=12
eq "datastream: debian uses the major version" "$(pick_datastream)" "$SSG_DIR/ssg-debian12-ds.xml"
ID=arch; eq "datastream: no content for the distro gives nothing" "$(pick_datastream)" ""

# pick_profile: the preference order, strongest first
DS="$T/ds.xml"
profiles() { : > "$DS.profiles"; local p; for p in "$@"; do echo "$PFX$p:Title of $p" >> "$DS.profiles"; done; }
profiles standard ospp cis_level2_server stig
eq "profile: the DISA STIG wins" "$(pick_profile)" "${PFX}stig"
profiles standard cis_level2_server cis
eq "profile: without a STIG, CIS level 2 wins" "$(pick_profile)" "${PFX}cis_level2_server"
profiles standard
eq "profile: only the standard baseline is used when nothing else exists" "$(pick_profile)" "${PFX}standard"
profiles stig_gui stig
eq "profile: stig is preferred over stig_gui" "$(pick_profile)" "${PFX}stig"
profiles my_site_policy
eq "profile: an unknown profile is never picked silently" "$(pick_profile)" ""
profiles stigma
eq "profile: a name that merely starts with stig does not match" "$(pick_profile)" ""

# summarize
xc() { # file "<result> <rule>"...
	local f="$1" r; shift
	{ echo '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult id="xccdf_org.open-scap_testresult_t">'
	  for r in "$@"; do printf '<rule-result idref="xccdf_org.ssgproject.content_rule_%s"><result>%s</result></rule-result>\n' "${r#* }" "${r%% *}"; done
	  echo '</TestResult></Benchmark>'; } > "$f"
}
xc "$T/before.xml" "fail a" "fail b" "pass c" "error d"
xc "$T/after.xml" "pass a" "fail b" "error d" "notchecked e" "unknown f" "notapplicable g" "pass c"
OUTDIR="$T/out"; mkdir -p "$OUTDIR"; TS=T1; PROFILE="${PFX}stig"; TAILORING=""
summarize "$T/before.xml" "$T/after.xml" >/dev/null
SUM="$OUTDIR/summary-T1.md"
check "summary: written" test -s "$SUM"
eq "summary: mode 0600" "$(stat -c %a "$SUM")" 600
check "summary: before and after tallies are both present" bash -c "grep -q '^- Before: .*fail=2' '$SUM' && grep -q '^- After: .*fail=1' '$SUM'"
for want in "fail | b" "error | d" "notchecked | e" "unknown | f"; do
	check "summary: lists '$want'" grep -qF "| $want |" "$SUM"
done
refute "summary: a rule at pass is not listed as a problem" grep -qE '^\| pass \|' "$SUM"
refute "summary: a fixed rule is not listed" grep -qF '| a |' "$SUM"
tap_done
