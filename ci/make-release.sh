#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# make-release.sh - build the release tarball reproducibly (TODO P0-1/P0-4).
#
# Same inputs give a byte-identical archive: files are listed in a fixed
# order, owners/timestamps are normalised to ci/release-epoch, gzip stores no
# name or time, and file modes are set explicitly (0755 for anything with a
# shebang, 0644 otherwise) so the archive never depends on whether the
# checkout - or a network share it sits on - kept executable bits. Earlier
# packages were built from such a share and shipped every script as 0644.
#
# Writes <out>/<name>.tar.gz, <name>.tar.gz.sha256 and <name>.spdx.json.
#
# Usage: ci/make-release.sh [--out DIR] [--name NAME] [--prefix DIR]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION")"
OUT="$ROOT/dist"
NAME="secure_sudo-$VERSION"
PREFIX="KernelPatch-merged"

while [ $# -gt 0 ]; do
	case "$1" in
	--out)    OUT="$2"; shift 2 ;;
	--name)   NAME="$2"; shift 2 ;;
	--prefix) PREFIX="$2"; shift 2 ;;
	-h|--help) sed -n '3,16p' "$0"; exit 0 ;;
	*) echo "make-release: unknown argument $1" >&2; exit 2 ;;
	esac
done

EPOCH="${SOURCE_DATE_EPOCH:-$(head -1 "$HERE/release-epoch" | tr -dc '0-9')}"
[ -n "$EPOCH" ] || { echo "make-release: no epoch in ci/release-epoch" >&2; exit 1; }
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
stage="$work/$PREFIX"

# Sources plus the recorded scan/test evidence under docs/*/results/.
{
	bash "$ROOT/scripts/gen-sbom.sh" --list
	(cd "$ROOT" && find docs -path '*/results/*' -type f -printf '%p\n' 2>/dev/null)
} | LC_ALL=C sort -u > "$work/files"

: > "$work/exec"
while IFS= read -r f; do
	install -D -m0644 "$ROOT/$f" "$stage/$f"
	if head -c2 "$stage/$f" | grep -q '^#!'; then
		chmod 0755 "$stage/$f"; echo "$PREFIX/$f" >> "$work/exec"
	fi
done < "$work/files"
find "$stage" -type d -exec chmod 0755 {} +

(cd "$work" && tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner \
	--mtime="@$EPOCH" -cf - "$PREFIX") | gzip -9n > "$OUT/$NAME.tar.gz"

# Every program (anything with a shebang) must be executable in the archive.
tar -tvzf "$OUT/$NAME.tar.gz" | awk '$1 ~ /^-rwx/ {print $NF}' | LC_ALL=C sort > "$work/exec-in-tar"
bad="$(LC_ALL=C sort "$work/exec" | comm -23 - "$work/exec-in-tar")"
if [ -n "$bad" ]; then
	echo "make-release: programs without exec bit:" >&2; echo "$bad" >&2; exit 1
fi

(cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
SOURCE_DATE_EPOCH="$EPOCH" bash "$ROOT/scripts/gen-sbom.sh" --out "$OUT/$NAME.spdx.json"
echo "make-release: $OUT/$NAME.tar.gz ($(wc -l < "$work/files") files) $(cut -d' ' -f1 "$OUT/$NAME.tar.gz.sha256")"
