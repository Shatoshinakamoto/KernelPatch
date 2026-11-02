#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# fetch-kernel-source.sh - get an upstream kernel tree through the Ubuntu
# archive for the distro VM test, with a provenance record install.sh accepts
# (SS_KERNEL_TREE / SS_KERNEL_TREE_PROVENANCE).
#
# Where kernel.org cannot be reached, the Ubuntu source package's .orig
# tarball (the upstream release, unpatched) is the next best source: apt
# checks the archive's signed InRelease, and every downloaded file's hash
# against the Sources index it lists. This script then checks the .orig
# tarball's SHA-256 against the .dsc again and extracts ONLY the .orig, so
# the tree is upstream source without Ubuntu's patches.
#
# Usage: fetch-kernel-source.sh OUTDIR [SOURCE-PACKAGE[=VERSION]]
#   default package: linux-hwe-6.14 (upstream 6.14) from noble-updates.
# Prints the tree path and writes OUTDIR/kernel-source.txt.
set -euo pipefail

out="${1:?usage: $0 OUTDIR [SOURCE-PACKAGE[=VERSION]]}"
pkg="${2:-linux-hwe-6.14}"
mkdir -p "$out"; out="$(cd "$out" && pwd)"
cd "$out"

grep -rqs '^Types:.*deb-src\|^deb-src' /etc/apt/sources.list /etc/apt/sources.list.d/ || {
	echo "no deb-src entries: enable source packages in /etc/apt/sources.list.d/ubuntu.sources" >&2; exit 1; }
apt-get source --download-only "$pkg" > apt-source.log 2>&1 || { cat apt-source.log >&2; exit 1; }

dsc="$(ls ./*.dsc | head -1)"
orig="$(ls ./*.orig.tar.* | head -1)"
want="$(awk '/^Checksums-Sha256:/ {f=1; next} /^[^ ]/ {f=0} f && $3 ~ /\.orig\.tar\./ {print $1}' "$dsc")"
have="$(sha256sum "$orig" | cut -d' ' -f1)"
[ -n "$want" ] && [ "$want" = "$have" ] || { echo "orig tarball hash $have does not match $dsc ($want)" >&2; exit 1; }

top="$({ tar -tzf "$orig" || true; } | head -1 | cut -d/ -f1)"	# tar dies of SIGPIPE
rm -rf "src"; mkdir src
tar --no-same-owner -xzf "$orig" -C src
tree="$out/src/$top"
[ -f "$tree/Makefile" ] || { echo "no kernel tree in $orig" >&2; exit 1; }
kv="$(make -s -C "$tree" kernelversion)"

{
	echo "verified_by=apt-get source $pkg (Ubuntu archive: InRelease signature, Sources hashes) + .dsc SHA-256 recheck"
	echo "archive=$(basename "$orig")"
	echo "archive_sha256=$have"
	echo "dsc=$(basename "$dsc") sha256=$(sha256sum "$dsc" | cut -d' ' -f1)"
	echo "patches_applied=none (upstream .orig only)"
	echo "kernel_version=$kv"
	echo "signature_epoch=$(tar -tvzf "$orig" "$top/Makefile" --full-time 2>/dev/null | awk '{print $4" "$5}' | xargs -I{} date -u -d {} +%s)"
} > kernel-source.txt
echo "$tree"
