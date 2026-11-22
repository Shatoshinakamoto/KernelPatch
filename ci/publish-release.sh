#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# publish-release.sh - publish a release as a GitHub Release with gh.
#
# Builds locally (ci/make-release.sh), optionally signs the SHA-256 file with
# gpg, then uploads the archive, checksum, SBOM and signature with
# `gh release create`. The release is created as a DRAFT unless --publish is
# given, so the tag and notes can be reviewed on GitHub first. Nothing is
# published without --publish.
#
# Usage: ci/publish-release.sh --notes FILE [--tag vX.Y.Z] [--target BRANCH]
#                              [--sign KEYID] [--publish] [--dry-run]
#   --tag     default: v$(cat VERSION)
#   --target  default: main (the tag is created there by GitHub)
#   --sign    gpg key id; writes <name>.tar.gz.sha256.asc (detached, armored)
#   --dry-run build and print the gh command; call gh for nothing
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION")"
TAG="v$VERSION"; TARGET=main; NOTES=""; KEY=""; PUBLISH=0; DRY=0
REPO="${SS_RELEASE_REPO:-Shatoshinakamoto/KernelPatch}"

while [ $# -gt 0 ]; do
	case "$1" in
	--tag)     TAG="$2"; shift 2 ;;
	--target)  TARGET="$2"; shift 2 ;;
	--notes)   NOTES="$2"; shift 2 ;;
	--sign)    KEY="$2"; shift 2 ;;
	--publish) PUBLISH=1; shift ;;
	--dry-run) DRY=1; shift ;;
	-h|--help) sed -n '3,19p' "$0"; exit 0 ;;
	*) echo "publish-release: unknown argument $1" >&2; exit 2 ;;
	esac
done

[ -n "$NOTES" ] && [ -f "$NOTES" ] || { echo "publish-release: --notes FILE is required" >&2; exit 2; }
case "$TAG" in v[0-9]*) ;; *) echo "publish-release: tag must look like v1.2.3" >&2; exit 2 ;; esac
[ "$TAG" = "v$VERSION" ] || echo "publish-release: warning: tag $TAG differs from VERSION $VERSION" >&2

out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
bash "$HERE/make-release.sh" --out "$out"
name="secure_sudo-$VERSION"
(cd "$out" && sha256sum -c "$name.tar.gz.sha256")
assets=("$out/$name.tar.gz" "$out/$name.tar.gz.sha256" "$out/$name.spdx.json")
if [ -n "$KEY" ]; then
	gpg --batch --yes --armor --local-user "$KEY" --detach-sign -o "$out/$name.tar.gz.sha256.asc" "$out/$name.tar.gz.sha256"
	gpg --verify "$out/$name.tar.gz.sha256.asc" "$out/$name.tar.gz.sha256"
	assets+=("$out/$name.tar.gz.sha256.asc")
fi

cmd=(gh release create "$TAG" --repo "$REPO" --target "$TARGET" --title "secure_sudo $VERSION" --notes-file "$NOTES")
[ "$PUBLISH" = 1 ] || cmd+=(--draft)
cmd+=("${assets[@]}")
if [ "$DRY" = 1 ]; then printf 'publish-release: dry run:'; printf ' %q' "${cmd[@]}"; echo; exit 0; fi
"${cmd[@]}"
[ "$PUBLISH" = 1 ] && echo "publish-release: $TAG is public" || echo "publish-release: $TAG created as a DRAFT; review it, then publish"
