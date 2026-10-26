#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# stig-harden.sh - run a DISA STIG (or the closest available hardening)
# OpenSCAP evaluation on this host, and optionally apply the generated
# remediation. Part of secure_sudo (#18, STIG compliance tooling).
#
# WHAT IT DOES, STEP BY STEP
#   1. Detect the distro from /etc/os-release.
#   2. Make sure OpenSCAP (`oscap`) and the SCAP Security Guide content are
#      installed, installing them with the distro package manager if not.
#   3. Pick the SCAP datastream and profile for this distro, preferring the
#      DISA STIG profile and falling back to the strongest profile the distro
#      actually ships (CIS Level 2, then ANSSI high) when no STIG exists for it.
#   4. `oscap xccdf eval` -> an HTML report and an XML result file under
#      /var/log/secure_sudo/stig/ (timestamped).
#   5. With --remediate, generate a bash remediation from THAT result and run
#      it, then re-scan so the before/after is captured honestly.
#
# IMPORTANT, read before --remediate:
#   STIG remediation changes real system configuration (PAM, password policy,
#   login banners, audit, file permissions). On a production box, scan first
#   (default), read the report, and apply in a maintenance window. Some STIG
#   controls (full-disk encryption, smartcard/PKI auth) cannot be remediated by
#   a script and will remain "fail"/"notchecked" - those are documented in
#   docs/STIG.md with the manual step.
#
# USAGE
#   stig-harden.sh [--scan] [--remediate] [--profile <id>] [--datastream <f>]
#                  [--list-profiles] [--outdir <dir>] [--yes]
#                  [--passes <n>] [--skip-rules <regex>] [--post-patch-only]
#
#   --scan           scan only, produce reports (default if nothing given)
#   --remediate      scan, apply the generated fixes, then re-scan (asks first
#                    unless --yes)
#   --profile <id>   force a specific XCCDF profile id (see --list-profiles)
#   --datastream <f> force a specific SSG datastream file
#   --list-profiles  list the profiles in the chosen datastream and exit
#   --outdir <dir>   where to write reports (default /var/log/secure_sudo/stig)
#   --yes            do not prompt before remediating
#   --passes <n>     remediation passes before the final scan (default 2)
#   --skip-rules <re> leave rules whose id matches this regex unremediated
#                    (e.g. 'ufw|nftables|firewalld' when secure_sudo's own nft
#                    network modes manage the firewall); they stay in the report
#   --post-patch-only apply only the known-issue patches (OSB-03..07,
#                    docs/OSCAP_BUGS.md), then rescan
#
set -euo pipefail

OUTDIR=/var/log/secure_sudo/stig
MODE=scan
FORCE_PROFILE=""
FORCE_DS=""
LIST_ONLY=0
ASSUME_YES=0
PASSES=2
SKIP_RULES=""

die()  { echo "stig-harden: $*" >&2; exit 1; }
info() { echo "stig-harden: $*"; }

[ "$(id -u)" -eq 0 ] || die "must run as root"

while [ $# -gt 0 ]; do
	case "$1" in
	--scan)          MODE=scan ;;
	--remediate)     MODE=remediate ;;
	--profile)       FORCE_PROFILE="${2:?}"; shift ;;
	--datastream)    FORCE_DS="${2:?}"; shift ;;
	--list-profiles) LIST_ONLY=1 ;;
	--outdir)        OUTDIR="${2:?}"; shift ;;
	--yes|-y)        ASSUME_YES=1 ;;
	--passes)        PASSES="${2:?}"; shift ;;
	--skip-rules)    SKIP_RULES="${2:?}"; shift ;;
	--post-patch-only) MODE=postpatch ;;
	-h|--help)       sed -n '2,50p' "$0"; exit 0 ;;
	*)               die "unknown option: $1" ;;
	esac
	shift
done

# -- 1. detect distro ------------------------------------------------------
. /etc/os-release
ID="${ID:-linux}"
VERSION_ID="${VERSION_ID:-}"
VID="${VERSION_ID%%.*}"
info "detected $ID ${VERSION_ID:-?}"

pkg_install() {
	# Install the named packages with whatever package manager exists.
	if   command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y "$@"
	elif command -v dnf     >/dev/null; then dnf install -y "$@"
	elif command -v yum     >/dev/null; then yum install -y "$@"
	elif command -v zypper  >/dev/null; then zypper --non-interactive install "$@"
	elif command -v pacman  >/dev/null; then pacman -Sy --noconfirm "$@"
	else die "no supported package manager found"
	fi
}

# -- 2. ensure oscap + SSG content -----------------------------------------
if ! command -v oscap >/dev/null; then
	info "installing OpenSCAP scanner"
	case "$ID" in
	ubuntu|debian) pkg_install openscap-scanner openscap-utils ;;
	fedora|rhel|centos|rocky|almalinux|ol)
		pkg_install openscap-scanner openscap-utils ;;
	opensuse*|sles|sle) pkg_install openscap-utils ;;
	arch)  pkg_install openscap ;;
	*)     pkg_install openscap-scanner || pkg_install openscap ;;
	esac
fi
command -v oscap >/dev/null || die "oscap not available after install"

# SCAP Security Guide content package name differs per distro family.
ssg_pkg() {
	case "$ID" in
	ubuntu)        echo "ssg-debian ssg-debderived" ;;
	debian)        echo "ssg-debian ssg-debderived" ;;
	fedora|rhel|centos|rocky|almalinux|ol)
	               echo "scap-security-guide" ;;
	opensuse*|sles|sle) echo "scap-security-guide" ;;
	arch)          echo "scap-security-guide" ;;
	*)             echo "scap-security-guide" ;;
	esac
}

# Where SSG datastreams land. /usr/share/xml/scap/ssg/content is standard for
# both the Debian ssg-* packages and the Red Hat scap-security-guide package.
SSG_DIR=/usr/share/xml/scap/ssg/content
if [ ! -d "$SSG_DIR" ] || ! ls "$SSG_DIR"/ssg-*-ds.xml >/dev/null 2>&1; then
	info "installing SCAP Security Guide content"
	# shellcheck disable=SC2046
	pkg_install $(ssg_pkg) || true
fi
[ -d "$SSG_DIR" ] || die "SSG content dir $SSG_DIR missing; install scap-security-guide"

# -- 3. choose datastream + profile ----------------------------------------
# Map (distro, version) -> the SSG datastream basename that best matches it.
pick_datastream() {
	local cand=""
	case "$ID" in
	ubuntu)  cand="ssg-ubuntu${VERSION_ID//./}-ds.xml" ;;
	debian)  cand="ssg-debian${VID}-ds.xml" ;;
	fedora)  cand="ssg-fedora-ds.xml" ;;
	rhel|centos|rocky|almalinux)
	         cand="ssg-rhel${VID}-ds.xml" ;;
	ol)      cand="ssg-ol${VID}-ds.xml" ;;
	opensuse*) cand="ssg-opensuse-ds.xml" ;;
	sles|sle)  cand="ssg-sle${VID}-ds.xml" ;;
	*)       cand="" ;;
	esac
	if [ -n "$cand" ] && [ -f "$SSG_DIR/$cand" ]; then
		echo "$SSG_DIR/$cand"; return
	fi
	# Fall back to the newest matching family datastream present.
	ls -1 "$SSG_DIR"/ssg-"${ID}"*-ds.xml 2>/dev/null | sort -V | tail -1
}

DS="${FORCE_DS:-$(pick_datastream)}"
[ -n "$DS" ] && [ -f "$DS" ] || die "no SSG datastream for $ID $VERSION_ID (use --datastream)"
info "datastream: $DS"

if [ "$LIST_ONLY" -eq 1 ]; then
	oscap info --profiles "$DS"
	exit 0
fi

# Preference order of profiles, strongest/most authoritative first.
pick_profile() {
	local p
	for p in \
		xccdf_org.ssgproject.content_profile_stig \
		xccdf_org.ssgproject.content_profile_stig_gui \
		xccdf_org.ssgproject.content_profile_cis_level2_server \
		xccdf_org.ssgproject.content_profile_cis \
		xccdf_org.ssgproject.content_profile_anssi_bp28_high \
		xccdf_org.ssgproject.content_profile_ospp \
		xccdf_org.ssgproject.content_profile_standard
	do
		if oscap info --profiles "$DS" 2>/dev/null | grep -q "^$p:"; then
			echo "$p"; return
		fi
	done
}

PROFILE="${FORCE_PROFILE:-$(pick_profile)}"
[ -n "$PROFILE" ] || die "no usable profile in $DS (try --list-profiles)"
# OSB-18: only claim "no STIG for this distro" when we chose the fallback
# ourselves; a profile forced with --profile is just reported as chosen.
case "$PROFILE" in
*_stig*) info "profile: $PROFILE (DISA STIG)" ;;
*) if [ -n "$FORCE_PROFILE" ]; then
	info "profile: $PROFILE (chosen with --profile)"
   else
	info "profile: $PROFILE (no DISA STIG for this distro; using closest hardening baseline)"
   fi ;;
esac

# -- 4. scan ---------------------------------------------------------------
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"
TS="$(date +%Y%m%d-%H%M%S)"
# scan() writes the XML result path into the global SCAN_RESULT (rather than to
# stdout through a pipe, which would interact badly with set -o pipefail).
SCAN_RESULT=""
scan() {
	local tag="$1"
	local res="$OUTDIR/${tag}-results-${TS}.xml"
	local rep="$OUTDIR/${tag}-report-${TS}.html"
	info "scanning ($tag) -> $rep"
	# oscap returns 2 when some rules fail; that is normal, not an error.
	oscap xccdf eval --profile "$PROFILE" \
		--results "$res" --report "$rep" "$DS" || [ $? -eq 2 ]
	SCAN_RESULT="$res"
	# Print a one-line pass/fail tally to the console, parsed from the XML we
	# just wrote (no second scan, no extra pipe to break).
	local pass fail na nc err
	pass=$(grep -c '<result>pass</result>'          "$res" || true)
	fail=$(grep -c '<result>fail</result>'          "$res" || true)
	na=$(  grep -c '<result>notapplicable</result>' "$res" || true)
	nc=$(  grep -c '<result>notchecked</result>'    "$res" || true)
	err=$( grep -c '<result>error</result>'         "$res" || true)
	info "  pass=$pass fail=$fail notapplicable=$na notchecked=$nc error=$err"
}

# -- known-issue patches (see docs/OSCAP_BUGS.md) ---------------------------
# Each of these is a problem the generated remediation either causes or leaves
# behind, found during the real Ubuntu 24.04 STIG runs. They are applied after
# the remediation passes and before the final scan. Every patch checks that its
# problem is actually present first, so running it on a clean host is a no-op.
post_patch() {
	info "applying known-issue patches"

	# OSB-03: SSG 0.1.78's fix for banner_etc_profiled_ssh_confirm writes the
	# OVAL regex token "(?:[n]+|(?:n)+)" literally instead of newlines, leaving
	# /etc/profile.d/ssh_confirm.sh as one broken line. Restore the newlines.
	local f=/etc/profile.d/ssh_confirm.sh
	if [ -f "$f" ] && grep -qF '(?:[n]+|(?:n)+)' "$f"; then
		cp -p "$f" "$f.pre-patch"
		python3 -I -c 'import sys;p=sys.argv[1];s=open(p).read();open(p,"w").write(s.replace("(?:[n]+|(?:n)+)","\n"))' "$f"
		if bash -n "$f"; then
			info "  OSB-03 fixed: $f restored (backup $f.pre-patch)"
		else
			cp -p "$f.pre-patch" "$f"
			info "  OSB-03: repaired $f failed a syntax check; original restored"
		fi
	fi

	# OSB-04: pwquality `retry` is left commented out ("# retry = 3").
	f=/etc/security/pwquality.conf
	if [ -f "$f" ] && ! grep -qE '^\s*retry\s*=' "$f"; then
		if grep -qE '^\s*#\s*retry\s*=' "$f"; then
			sed -i -E 's/^\s*#\s*retry\s*=.*/retry = 3/' "$f"
		else
			echo "retry = 3" >>"$f"
		fi
		info "  OSB-04 fixed: retry = 3 in $f"
	fi

	# OSB-05: SSSD certificate mapping. The generated fix sets pam_cert_auth,
	# but the rule's OVAL check looks for ldap_user_certificate in the domain
	# section. Only touched when sssd.conf already has a [domain/...] section.
	f=/etc/sssd/sssd.conf
	if [ -f "$f" ] && grep -qE '^\[domain/' "$f" && \
	   ! grep -qE '^\s*ldap_user_certificate\s*=' "$f"; then
		cp -p "$f" "$f.pre-patch"
		sed -i -E '/^\[domain\/[^]]*\]/a ldap_user_certificate = userCertificate;binary' "$f"
		chmod 600 "$f"
		info "  OSB-05 fixed: ldap_user_certificate mapping added to $f (backup $f.pre-patch)"
	fi

	# OSB-06: /var/log must be group-owned by syslog; the rule's fix silently
	# does nothing when the syslog group does not exist yet (no rsyslog).
	if ! getent group syslog >/dev/null 2>&1 && command -v apt-get >/dev/null; then
		info "  OSB-06: syslog group missing; installing rsyslog (STIG requires it)"
		pkg_install rsyslog >/dev/null 2>&1 || info "  OSB-06: rsyslog install failed"
	fi
	if getent group syslog >/dev/null 2>&1 && \
	   [ "$(stat -c %G /var/log)" != "syslog" ]; then
		chgrp syslog /var/log
		info "  OSB-06 fixed: /var/log group -> syslog"
	fi

	# OSB-15: the AppArmor tools (aa-enforce, aa-complain) are Python and use
	# python3-libapparmor, which Ubuntu builds for its own python3 only. If
	# /usr/bin/python3 was switched to another version (alternatives), every
	# aa-* call in the remediation crashes on import and the AppArmor rules
	# stay failed. Enforcing every profile can break applications, so this is
	# detect-and-advise only: it prints the exact command to run by hand.
	if command -v aa-enforce >/dev/null && \
	   ! python3 -c 'import LibAppArmor' >/dev/null 2>&1; then
		local py
		for py in /usr/bin/python3.[0-9]*; do
			case "$py" in *-config) continue ;; esac
			if "$py" -c 'import LibAppArmor' >/dev/null 2>&1; then
				info "  OSB-15: aa-* tools cannot import LibAppArmor under $(python3 --version 2>&1);"
				info "          they work under $py. Review, then run by hand:"
				info "          $py $(command -v aa-enforce) /etc/apparmor.d/*"
				break
			fi
		done
	fi

	# OSB-07: log-file permission drift. Package installs (including the ones
	# remediation itself performs) create new logs with wider modes, so this
	# runs LAST, after every install, right before the final scan.
	local n
	n=$(find /var/log -type f -perm /0137 2>/dev/null | wc -l)
	if [ "$n" -gt 0 ]; then
		find /var/log -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} + 2>/dev/null || true
		info "  OSB-07 fixed: tightened $n log file(s) under /var/log"
	fi
}

# Drop the fix blocks of rules matching $SKIP_RULES from a generated script.
# oscap delimits each rule's fix with "# BEGIN fix ... for '<rule>'" and
# "# END fix for '<rule>'", so whole blocks can be removed safely.
skip_rules() {
	local fix="$1" n
	python3 -I - "$fix" "$SKIP_RULES" <<'PY'
import re, sys
path, pat = sys.argv[1], re.compile(sys.argv[2])
out, skip, dropped = [], False, []
for line in open(path):
    m = re.match(r"# BEGIN fix \(.*\) for '([^']+)'", line)
    if m and pat.search(m.group(1)):
        skip = True
        dropped.append(m.group(1))
    if not skip:
        out.append(line)
    if skip and line.startswith("# END fix for"):
        skip = False
open(path, "w").writelines(out)
open(path + ".skipped", "w").write("\n".join(dropped) + ("\n" if dropped else ""))
PY
	n=$(wc -l <"$fix.skipped")
	info "  --skip-rules: left $n rule(s) unremediated (list: $fix.skipped)"
}

# Write a Markdown summary: before/after tallies + every rule not at pass.
summarize() {
	local before="$1" after="$2" out="$OUTDIR/summary-${TS}.md"
	tally() {
		local r="$1" k
		for k in pass fail notapplicable notchecked error; do
			printf '%s=%s ' "$k" "$(grep -c "<result>$k</result>" "$r" || true)"
		done
	}
	{
		echo "# OpenSCAP summary ($TS)"
		echo
		echo "- Datastream: \`$DS\`"
		echo "- Profile: \`$PROFILE\`"
		echo "- Before: $(tally "$before")"
		echo "- After:  $(tally "$after")"
		echo
		echo "## Rules not at pass after remediation"
		echo
		echo "| Result | Rule |"
		echo "|--------|------|"
		python3 -I - "$after" <<'PY'
import sys, re
s = open(sys.argv[1]).read()
for m in re.finditer(r'<rule-result[^>]*idref="([^"]+)"[^>]*>.*?<result>([a-z]+)</result>', s, re.S):
    rule, res = m.group(1), m.group(2)
    if res not in ("pass", "notapplicable", "notselected"):
        print("| %s | %s |" % (res, rule.replace("xccdf_org.ssgproject.content_rule_", "")))
PY
	} >"$out"
	info "summary: $out"
}

if [ "$MODE" = "postpatch" ]; then
	post_patch
	scan after
	exit 0
fi

scan baseline
BEFORE_RES="$SCAN_RESULT"
info "baseline report in $OUTDIR"

[ "$MODE" = "scan" ] && { info "scan complete"; exit 0; }

# -- 5. remediate ----------------------------------------------------------
if [ "$ASSUME_YES" -ne 1 ]; then
	echo
	echo "About to APPLY STIG remediation to this system (PAM, password policy,"
	echo "banners, audit, permissions will change). Do this in a maintenance"
	echo "window with a root shell open. Type 'yes' to continue:"
	read -r ans
	[ "$ans" = "yes" ] || die "aborted"
fi

# Remediation runs in PASSES. Pass 1 installs packages and creates files that
# some rules only configure on the next pass (seen on Ubuntu 24.04: every
# pwquality rule stayed "fail" after pass 1 and passed after pass 2), so each
# pass regenerates the fix from the latest result and applies it again.
LAST_RES="$BEFORE_RES"
pass_no=1
while [ "$pass_no" -le "$PASSES" ]; do
	FIX="$OUTDIR/remediation-${TS}-pass${pass_no}.sh"
	RID="$(grep -o 'TestResult id="[^"]*"' "$LAST_RES" | head -1 | cut -d'"' -f2)"
	info "pass $pass_no/$PASSES: generating remediation from result $RID"
	oscap xccdf generate fix --fix-type bash --result-id "$RID" \
		--output "$FIX" "$LAST_RES"
	[ -n "$SKIP_RULES" ] && skip_rules "$FIX"
	info "applying $FIX"
	bash "$FIX" >"$FIX.log" 2>&1 || \
		info "remediation returned non-zero (some fixes are environment-specific); log: $FIX.log"
	scan "pass${pass_no}"
	LAST_RES="$SCAN_RESULT"
	pass_no=$((pass_no + 1))
done

post_patch
scan after
summarize "$BEFORE_RES" "$SCAN_RESULT"
info "remediation complete; before/after reports + summary in $OUTDIR"
info "review remaining fails in the 'after' report - some controls need manual"
info "steps on the target (see docs/STIG.md and docs/OSCAP_BUGS.md)."
