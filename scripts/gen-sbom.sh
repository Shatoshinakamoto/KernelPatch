#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# gen-sbom.sh - SPDX 2.3 JSON software bill of materials for a secure_sudo
# build (TODO P0-4): every secure_sudo source file with its SHA-256, the
# verified kernel source archive, the toolchain, and the libraries the
# userspace links against, with versions from the package manager.
#
# Usage:
#   scripts/gen-sbom.sh --tree-hash
#       print one SHA-256 over every tracked secure_sudo source file
#   scripts/gen-sbom.sh --list
#       print the source file list itself (what a release contains)
#   scripts/gen-sbom.sh [--build-info FILE] [--out FILE]
#       write the SBOM (default: stdout). FILE is install.sh's
#       build-metadata/build-info.txt; without it the kernel package is
#       described as "not built".
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
INFO=""
OUT=""
MODE=sbom

while [ $# -gt 0 ]; do
	case "$1" in
	--tree-hash)  MODE="hash"; shift ;;
	--list)       MODE="list"; shift ;;
	--build-info) INFO="$2"; shift 2 ;;
	--out)        OUT="$2"; shift 2 ;;
	-h|--help)    sed -n '3,18p' "$0"; exit 0 ;;
	*) echo "gen-sbom: unknown argument $1" >&2; exit 2 ;;
	esac
done

# Source files only: generated reports, build output and VCS data are not
# inputs. Sorted with LC_ALL=C so the hash is stable across machines.
# SECURITY: an operator's Ansible inventory and group/host vars name their own
# hosts; they are never part of a release or its hash (CWE-200).
list_sources() {
	(cd "$ROOT" && find . -type f \
		! -path './.git/*' ! -path './HistoryTest/*' ! -path './docs/stig/results/*' ! -name 'build-gate-record.txt' \
		! -name '*.o' ! -name '*.so' ! -name '*.ko' ! -name '*.html' \
		! -path './userspace/cli/secure-sudo' ! -path './userspace/daemon/secure-sudod' \
		! -path './userspace/otp/secure-sudo-otp' \
		! -path './userspace/pheonixbox/secure-sudo-pheonixbox' \
		! -path './install/ansible/inventory.ini' ! -path './install/ansible/group_vars/secure_sudo.yml' \
		! -path './install/ansible/host_vars/*' \
		-printf '%P\n' | LC_ALL=C sort)
}

tree_hash() {
	list_sources | while IFS= read -r f; do
		printf '%s  %s\n' "$(sha256sum "$ROOT/$f" | cut -d' ' -f1)" "$f"
	done | sha256sum | cut -d' ' -f1
}

if [ "$MODE" = hash ]; then tree_hash; exit 0; fi
if [ "$MODE" = list ]; then list_sources; exit 0; fi

json() { # JSON string literal
	local s="$1"
	s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
	s="${s//$'\t'/\\t}"; s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"
	printf '"%s"' "$s"
}
# SPDX ids allow only [A-Za-z0-9.-]; a path hash keeps sanitised ids unique.
spdxid() {
	printf 'SPDXRef-%s-%s' "$(printf '%s' "$1" | tr -c 'A-Za-z0-9.-' '-')" \
		"$(printf '%s' "$1" | sha1sum | cut -c1-8)"
}
info() { if [ -n "$INFO" ]; then sed -n "s/^$1=//p" "$INFO" | head -1; fi; }

pkg_version() { # distro package version, or empty
	if command -v dpkg-query >/dev/null 2>&1; then
		dpkg-query -W -f='${Version}' "$1" 2>/dev/null || true
	elif command -v rpm >/dev/null 2>&1; then
		rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null | grep -v 'not installed' || true
	elif command -v pacman >/dev/null 2>&1; then
		pacman -Q "$1" 2>/dev/null | awk '{print $2}' || true
	fi
}
first_pkg_version() {
	local p v
	for p in "$@"; do
		v="$(pkg_version "$p")"
		if [ -n "$v" ]; then printf '%s' "$v"; return 0; fi
	done
	return 0
}

version="$(cat "$ROOT/VERSION" 2>/dev/null || echo unknown)"
# Honour SOURCE_DATE_EPOCH so a release SBOM is reproducible too.
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
	now="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
else
	now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi
th="$(tree_hash)"
ns="https://secure-sudo.invalid/spdx/secure_sudo-$version-$th"

pkgs=()
rels=()
add_pkg() { # id name version supplier download sha256 comment purpose
	local id="$1" p
	p="{\"SPDXID\":$(json "$id"),\"name\":$(json "$2"),\"versionInfo\":$(json "${3:-NOASSERTION}"),"
	p+="\"supplier\":$(json "${4:-NOASSERTION}"),\"downloadLocation\":$(json "${5:-NOASSERTION}"),"
	p+="\"filesAnalyzed\":false,\"licenseConcluded\":\"NOASSERTION\",\"licenseDeclared\":\"NOASSERTION\","
	p+="\"copyrightText\":\"NOASSERTION\",\"primaryPackagePurpose\":$(json "${8:-LIBRARY}")"
	if [ -n "${6:-}" ]; then
		p+=",\"checksums\":[{\"algorithm\":\"SHA256\",\"checksumValue\":$(json "$6")}]"
	fi
	if [ -n "${7:-}" ]; then p+=",\"comment\":$(json "$7")"; fi
	pkgs+=("$p}")
}
rel() { rels+=("{\"spdxElementId\":$(json "$1"),\"relationshipType\":$(json "$2"),\"relatedSpdxElement\":$(json "$3")}"); }

# secure_sudo itself, with every source file.
files=()
while IFS= read -r f; do
	fid="$(spdxid "File-$f")"
	# SPDX 2.3 requires SHA1 on every file; SHA256 is the one to trust.
	files+=("{\"SPDXID\":$(json "$fid"),\"fileName\":$(json "./$f"),\"checksums\":[{\"algorithm\":\"SHA1\",\"checksumValue\":\"$(sha1sum "$ROOT/$f" | cut -d' ' -f1)\"},{\"algorithm\":\"SHA256\",\"checksumValue\":\"$(sha256sum "$ROOT/$f" | cut -d' ' -f1)\"}],\"licenseConcluded\":\"NOASSERTION\",\"copyrightText\":\"NOASSERTION\"}")
	rel "SPDXRef-Package-secure-sudo" CONTAINS "$fid"
done < <(list_sources)
pkgs+=("{\"SPDXID\":\"SPDXRef-Package-secure-sudo\",\"name\":\"secure_sudo\",\"versionInfo\":$(json "$version"),\"supplier\":\"NOASSERTION\",\"downloadLocation\":\"NOASSERTION\",\"filesAnalyzed\":true,\"packageVerificationCode\":{\"packageVerificationCodeValue\":\"$(list_sources | while IFS= read -r f; do sha1sum "$ROOT/$f" | cut -d' ' -f1; done | LC_ALL=C sort | tr -d '\n' | sha1sum | cut -d' ' -f1)\"},\"licenseConcluded\":\"NOASSERTION\",\"licenseDeclared\":\"Apache-2.0 AND (GPL-2.0-only OR Apache-2.0)\",\"copyrightText\":\"Copyright 2026 Johnathan Edward Brown\",\"primaryPackagePurpose\":\"SOURCE\",\"comment\":$(json "source tree sha256 $th")}")
rel SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-secure-sudo

# The kernel source, as verified by scripts/verify-kernel-source.sh.
krel="$(info kernel_release)"
if [ -n "$krel" ]; then
	add_pkg SPDXRef-Package-linux-source "linux" "$krel" "Organization: kernel.org" \
		"https://cdn.kernel.org/pub/linux/kernel/v${krel%%.*}.x/$(info archive)" \
		"$(info archive_sha256)" \
		"signature verified; signer $(info signer_primary_fpr) on $(info signature_date); config sha256 $(info kernel_config_sha256); CONFIG_LSM=$(info config_lsm)" \
		SOURCE
	add_pkg SPDXRef-Package-linux-image "linux-image-secure_sudo" "$(info kernel_release_built)" \
		"NOASSERTION" NOASSERTION "" "built with KBUILD_BUILD_TIMESTAMP=$(info kbuild_build_timestamp)" OPERATING-SYSTEM
	rel SPDXRef-Package-linux-image GENERATED_FROM SPDXRef-Package-linux-source
	rel SPDXRef-Package-linux-image GENERATED_FROM SPDXRef-Package-secure-sudo
	rel SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-linux-image
else
	add_pkg SPDXRef-Package-linux-source "linux" "NOASSERTION" "Organization: kernel.org" \
		NOASSERTION "" "kernel not built in this run (no --build-info)" SOURCE
fi
rel SPDXRef-Package-secure-sudo DEPENDS_ON SPDXRef-Package-linux-source

# Toolchain (build tools) and linked libraries.
tool() { # id name version-command
	local v; v="$(eval "$3" 2>/dev/null | head -1 || true)"
	add_pkg "SPDXRef-Tool-$1" "$2" "${v:-NOASSERTION}" "" "" "" "" APPLICATION
	rel "SPDXRef-Tool-$1" BUILD_TOOL_OF SPDXRef-Package-secure-sudo
}
tool gcc gcc "gcc -dumpfullversion"
tool binutils binutils "ld --version | sed -n '1s/.* //p'"
tool make make "make --version | sed -n '1s/.* //p'"
tool pahole pahole "pahole --version"
tool gnupg gnupg "gpgv --version | sed -n '1s/.* //p'"
lib() { # id name pkg...
	local id="$1" name="$2" v; shift 2
	v="$(first_pkg_version "$@")"
	add_pkg "SPDXRef-Lib-$id" "$name" "${v:-NOASSERTION}" "" "" "" "package: $*" LIBRARY
	rel SPDXRef-Package-secure-sudo DEPENDS_ON "SPDXRef-Lib-$id"
}
lib pam linux-pam libpam0g pam
lib openssl openssl libssl3t64 libssl3 openssl-libs openssl
lib qrencode libqrencode libqrencode4 qrencode-libs qrencode
lib zlib zlib zlib1g zlib
lib crypt libxcrypt libcrypt1 libxcrypt

{
	printf '{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",'
	printf '"name":%s,"documentNamespace":%s,' "$(json "secure_sudo-$version")" "$(json "$ns")"
	printf '"creationInfo":{"created":"%s","creators":["Tool: secure_sudo-gen-sbom"]},' "$now"
	printf '"packages":['; (IFS=,; printf '%s' "${pkgs[*]}"); printf '],'
	printf '"files":[';    (IFS=,; printf '%s' "${files[*]}"); printf '],'
	printf '"relationships":['; (IFS=,; printf '%s' "${rels[*]}"); printf ']}\n'
} > "${OUT:-/dev/stdout}"
