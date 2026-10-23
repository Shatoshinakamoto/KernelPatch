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
#
#   --scan           scan only, produce reports (default if nothing given)
#   --remediate      scan, apply the generated fixes, then re-scan (asks first
#                    unless --yes)
#   --profile <id>   force a specific XCCDF profile id (see --list-profiles)
#   --datastream <f> force a specific SSG datastream file
#   --list-profiles  list the profiles in the chosen datastream and exit
#   --outdir <dir>   where to write reports (default /var/log/secure_sudo/stig)
#   --yes            do not prompt before remediating
#
set -euo pipefail

OUTDIR=/var/log/secure_sudo/stig
MODE=scan
FORCE_PROFILE=""
FORCE_DS=""
LIST_ONLY=0
ASSUME_YES=0

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
	-h|--help)       sed -n '2,40p' "$0"; exit 0 ;;
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
case "$PROFILE" in
*_stig*) info "profile: $PROFILE (DISA STIG)" ;;
*)       info "profile: $PROFILE (no DISA STIG for this distro; using closest hardening baseline)" ;;
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

FIX="$OUTDIR/remediation-${TS}.sh"
RID="$(grep -o 'TestResult id="[^"]*"' "$BEFORE_RES" | head -1 | cut -d'"' -f2)"
info "generating remediation from result $RID"
oscap xccdf generate fix --fix-type bash --result-id "$RID" \
	--output "$FIX" "$BEFORE_RES"
info "applying $FIX"
bash "$FIX" || info "remediation script returned non-zero (some fixes are environment-specific)"

scan after
info "remediation complete; before/after reports in $OUTDIR"
info "review remaining fails in the 'after' report - some STIG controls need"
info "manual steps (see docs/STIG.md)."
