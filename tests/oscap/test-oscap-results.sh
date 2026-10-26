#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Tests for scripts/oscap-results.py and tests/oscap/stig-gate.sh (TODO P0-2):
# rule-ID comparison, the release/diagnostic split, --skip-rules fix
# stripping, and the recorded container scan (which must FAIL the release
# gate and pass only as a diagnostic). Synthetic inputs; no root, no oscap.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
OR() { python3 -I "$ROOT/scripts/oscap-results.py" "$@"; }
EXP="$HERE/ubuntu2404-stig.expect"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# xccdf <file> "<result> <rule>"...: write an XCCDF 1.2 result file
xccdf() {
	local f="$1" r; shift
	{
		echo '<?xml version="1.0" encoding="UTF-8"?>'
		echo '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult id="xccdf_org.open-scap_testresult_t">'
		for r in "$@"; do
			printf '<rule-result idref="xccdf_org.ssgproject.content_rule_%s" role="full"><result>%s</result></rule-result>\n' "${r#* }" "${r%% *}"
		done
		echo '</TestResult></Benchmark>'
	} > "$f"
}
GOOD=("pass a" "pass b" "notapplicable c" "fail encrypt_partitions"
	"fail is_fips_mode_enabled" "fail service_sssd_enabled"
	"notchecked account_temp_expire_date" "notchecked ensure_sudo_group_restricted"
	"notchecked only_allow_dod_certs" "notchecked ufw_only_required_services"
	"notchecked auditd_audispd_configure_sufficiently_large_partition"
	"pass dir_perms_world_writable_sticky_bits")
gate() { OR gate "$@" --expect "$EXP" > "$T/out" 2>&1; GRC=$?; }
# cross <results.xml> "<result> <rule> <evidence>"...: the independent checks
cross() { local f="${1%.xml}.crosscheck"; shift; printf '%s\n' "$@" > "$f"; }
XOK=("fail encrypt_partitions not on dm-crypt: /(/dev/vda1)"
	"pass dir_perms_world_writable_sticky_bits none found")
out_has() { grep -qF -- "$1" "$T/out"; }

xccdf "$T/good.xml" "${GOOD[@]}"
cross "$T/good.xml" "${XOK[@]}"
check "tally counts every kind" sh -c "python3 -I '$ROOT/scripts/oscap-results.py' tally '$T/good.xml' | grep -qx 'pass=3 fail=3 error=0 notapplicable=1 notchecked=5'"
check "rules --not-pass lists short ids" sh -c "python3 -I '$ROOT/scripts/oscap-results.py' rules '$T/good.xml' --not-pass | grep -qx 'fail encrypt_partitions'"

gate "$T/good.xml"
check "release: the expected result passes" test "$GRC" -eq 0
check "release: notchecked are flagged for manual review" out_has "MANUAL REVIEW NEEDED"

check "release: the independent check is used and named" out_has "independent check agrees (not on dm-crypt"

# OSB-19: the scanner's false pass on an unencrypted disk
FP=("${GOOD[@]/fail encrypt_partitions/pass encrypt_partitions}")
xccdf "$T/fp.xml" "${FP[@]}"
gate "$T/fp.xml"
check "release: a scanner pass the scanner cannot vouch for fails without a cross-check" test "$GRC" -eq 1
check "release: ... and says no independent check was recorded" out_has "pass encrypt_partitions: the scanner cannot evaluate this rule"
gate "$T/fp.xml" --mode diagnostic
check "diagnostic: a missing cross-check is a note, not a failure" out_has "no independent check was recorded"
cross "$T/fp.xml" "${XOK[@]}"
gate "$T/fp.xml"
check "release: with the cross-check the false pass becomes the expected fail" test "$GRC" -eq 0
check "release: ... and the override is reported" out_has "the scanner said pass; the independent check says fail"
cross "$T/fp.xml" "pass encrypt_partitions all 1 filesystem(s) outside /boot are on dm-crypt" "${XOK[1]}"
gate "$T/fp.xml"
check "release: an encrypted disk (cross-check pass) passes: a listed rule passing is no regression" test "$GRC" -eq 0
cross "$T/fp.xml" "${XOK[0]}" "fail dir_perms_world_writable_sticky_bits world-writable without sticky bit: /srv/drop"
gate "$T/fp.xml"
check "release: a cross-check fail the scanner missed fails the gate" test "$GRC" -eq 1
check "release: ... naming the rule" out_has "fail dir_perms_world_writable_sticky_bits: not explained"
cp "$T/fp.xml" "$T/other.xml"; cross "$T/x.xml" "${XOK[@]}"
OR gate "$T/other.xml" --expect "$EXP" --crosscheck "$T/x.crosscheck" > "$T/out" 2>&1; GRC=$?
check "release: --crosscheck FILE names the checks explicitly" test "$GRC" -eq 0
printf 'maybe encrypt_partitions\n' > "$T/bad.crosscheck"
refute "a malformed cross-check file is an error" OR gate "$T/fp.xml" --expect "$EXP" --crosscheck "$T/bad.crosscheck"

xccdf "$T/extra.xml" "${GOOD[@]}" "fail sshd_set_idle_timeout"
cross "$T/extra.xml" "${XOK[@]}"
gate "$T/extra.xml"
check "release: one more fail fails the gate" test "$GRC" -eq 1
check "release: ... and names the rule" out_has "fail sshd_set_idle_timeout: not explained"

SWAP=("${GOOD[@]/fail encrypt_partitions/pass encrypt_partitions}")
xccdf "$T/swap.xml" "${SWAP[@]/pass a/fail a}"
cross "$T/swap.xml" "pass encrypt_partitions all 1 filesystem(s) outside /boot are on dm-crypt" "${XOK[1]}"
gate "$T/swap.xml"
check "release: same totals, different failing rule -> fail (IDs, not totals)" test "$GRC" -eq 1

xccdf "$T/err.xml" "${GOOD[@]}" "error apparmor_configured"
cross "$T/err.xml" "${XOK[@]}"
gate "$T/err.xml"
check "release: error fails even when listed container-only" test "$GRC" -eq 1
check "release: ... saying error is never allowed" out_has "error results are never allowed"
gate "$T/err.xml" --mode diagnostic
check "diagnostic: listed container-only error tolerated" test "$GRC" -eq 0
check "diagnostic: output says it is not a release result" out_has "DIAGNOSTIC (not a release result)"

xccdf "$T/unk.xml" "${GOOD[@]}" "unknown d"
cross "$T/unk.xml" "${XOK[@]}"
gate "$T/unk.xml"; check "release: unknown fails" test "$GRC" -eq 1
gate "$T/unk.xml" --mode diagnostic; check "diagnostic: unexplained unknown fails too" test "$GRC" -eq 1

xccdf "$T/nc.xml" "${GOOD[@]}" "notchecked e"
cross "$T/nc.xml" "${XOK[@]}"
gate "$T/nc.xml"; check "release: unexplained notchecked fails" test "$GRC" -eq 1

xccdf "$T/gone.xml" "pass a" "fail encrypt_partitions" "notchecked account_temp_expire_date" "notchecked ensure_sudo_group_restricted"
cross "$T/gone.xml" "${XOK[@]}"
gate "$T/gone.xml"
check "release: a listed rule missing from the results fails (profile changed)" test "$GRC" -eq 1

xccdf "$T/df.xml" "${GOOD[@]}" "fail x"
cross "$T/df.xml" "${XOK[@]}"
gate "$T/df.xml" --mode diagnostic
check "diagnostic: an unexplained fail still fails" test "$GRC" -eq 1

: > "$T/empty"
gate "$T/empty"; check "no results at all fails" test "$GRC" -eq 1

# oscap console output, with its \r-rewritten lines
printf -- '--- Starting Evaluation ---\n\nTitle\r\tX\nRule\r\txccdf_org.ssgproject.content_rule_a\nResult\r\tpass\n\nRule\r\txccdf_org.ssgproject.content_rule_b\nResult\r\tfail\n' > "$T/eval.txt"
check "reads oscap console output (\\r-rewritten lines)" sh -c "python3 -I '$ROOT/scripts/oscap-results.py' tally '$T/eval.txt' | grep -qx 'pass=1 fail=1 error=0 notchecked=0'"

# --skip-rules fix stripping
cat > "$T/fix.sh" <<'EOF'
#!/bin/bash
# BEGIN fix (1 / 3) for 'xccdf_org.ssgproject.content_rule_keep_one'
echo one
# END fix for 'xccdf_org.ssgproject.content_rule_keep_one'
# BEGIN fix (2 / 3) for 'xccdf_org.ssgproject.content_rule_nftables_table'
nft flush ruleset
# END fix for 'xccdf_org.ssgproject.content_rule_nftables_table'
# BEGIN fix (3 / 3) for 'xccdf_org.ssgproject.content_rule_keep_two'
echo two
# END fix for 'xccdf_org.ssgproject.content_rule_keep_two'
EOF
n="$(OR skip-fix "$T/fix.sh" 'nftables')"
eq "skip-fix: one block dropped" "$n" 1
refute "skip-fix: the matching fix is gone" grep -q 'nft flush' "$T/fix.sh"
check "skip-fix: the other fixes stay" sh -c "grep -q 'echo one' '$T/fix.sh' && grep -q 'echo two' '$T/fix.sh'"
check "skip-fix: dropped rule listed in .skipped" grep -qx 'xccdf_org.ssgproject.content_rule_nftables_table' "$T/fix.sh.skipped"
printf "# BEGIN fix (1 / 1) for 'xccdf_org.ssgproject.content_rule_x'\necho x\n" > "$T/broken.sh"
cp "$T/broken.sh" "$T/broken.orig"
refute "skip-fix: a block without END marker is an error" OR skip-fix "$T/broken.sh" x
check "skip-fix: ... and the file is left unchanged" cmp -s "$T/broken.sh" "$T/broken.orig"

# The recorded container scan: honest about what it is.
REC="$ROOT/docs/stig/results/03-v11-rescan-eval.txt"
if [ -f "$REC" ]; then
	bash "$HERE/stig-gate.sh" "$REC" > "$T/out" 2>&1; rc=$?
	check "recorded container scan FAILS the release gate" test "$rc" -eq 1
	check "... because of the AppArmor error (OSB-13)" out_has "error apparmor_configured"
	bash "$HERE/stig-gate.sh" --diagnostic "$REC" > "$T/out" 2>&1; rc=$?
	check "recorded container scan passes as a diagnostic only" test "$rc" -eq 0
else
	skip "recorded container scan not present"
fi
if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt -cq; then
	bash "$HERE/stig-gate.sh" > "$T/out" 2>&1; rc=$?
	check "release gate refuses to scan inside a container" test "$rc" -eq 2
else
	skip "release-gate container refusal (not in a container)"
fi
tap_done
