#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# quarantine.sh <file>
#
# Moves a file that appeared or changed under TimeVault into a zip in
# /var/lib/secure_sudo/quarantine/, together with a metadata sidecar recording
# where it came from and its hash, then removes the original. This is the
# non-destructive alternative to the TODO's "wipe": the evidence is preserved
# for later debugging, which a wipe would destroy. (vault_action=wipe in the
# config skips this helper entirely and the daemon unlinks instead.)
#
# The original is removed only after the archive has been written and checked
# to contain it. If archiving fails (disk full, zip missing and tar failing)
# the file is left where it is and the script exits non-zero. Earlier
# versions removed it regardless, destroying the evidence they were meant to
# keep. Each quarantine gets a unique name, so two files with the same name
# in the same second no longer land in (and overwrite each other in) one zip.
#
# Environment (tests only): SS_QUARANTINE_DIR overrides the quarantine dir.
set -eu

FILE="${1:?usage: quarantine.sh <file>}"
QDIR="${SS_QUARANTINE_DIR:-/var/lib/secure_sudo/quarantine}"
mkdir -p "$QDIR"
chmod 700 "$QDIR"

[ -f "$FILE" ] || exit 0
case "$FILE" in /*) ;; *) FILE="./$FILE" ;; esac	# never parsed as an option

TS="$(date +%Y%m%dT%H%M%S)"
BASE="$(basename -- "$FILE")"
# Reserve a unique stem; the reservation file is removed at the end.
RESERVE="$(mktemp "$QDIR/${TS}-XXXXXXXX")"
# The archive is named with a sanitised copy of the name; the real name is
# kept inside it and in the metadata.
STAMP="${RESERVE}-$(printf '%s' "$BASE" | tr -c 'A-Za-z0-9._-' '_')"
META="${STAMP}.meta"

# Record provenance before touching the file. The path goes through printf %s
# with newlines shown as \n, so a crafted file name cannot forge meta lines.
{
  printf 'original_path: %s\n' "$(printf '%s' "$FILE" | sed ':a;N;$!ba;s/\n/\\n/g')"
  echo "quarantined_at: $(date -Is)"
  echo "sha256: $(sha256sum < "$FILE" | awk '{print $1}')"
  ls -ln -- "$FILE" 2>/dev/null | awk '{print "stat: "$0}' | head -1
} > "$META"

fail() {
  echo "quarantine.sh: $*; $FILE left in place" >&2
  rm -f -- "$META" "$RESERVE"
  exit 1
}

# Package the file + metadata, verify, and only then remove the original.
if command -v zip >/dev/null 2>&1; then
  OUT="${STAMP}.zip"
  zip -j -q "$OUT" "$FILE" "$META" || { rm -f -- "$OUT"; fail "zip failed"; }
  unzip -l "$OUT" 2>/dev/null | grep -qF -- "$BASE" || { rm -f -- "$OUT"; fail "zip check failed"; }
else
  # Fallback if zip is not installed: a tar.gz instead.
  OUT="${STAMP}.tar.gz"
  tar -czf "$OUT" -C "$(dirname -- "$FILE")" "./$BASE" \
      -C "$QDIR" "./$(basename -- "$META")" || { rm -f -- "$OUT"; fail "tar failed"; }
  tar -tzf "$OUT" 2>/dev/null | grep -qxF -- "./$BASE" || { rm -f -- "$OUT"; fail "tar check failed"; }
fi

rm -f -- "$META" "$RESERVE"
rm -f -- "$FILE"
echo "quarantine.sh: quarantined $FILE -> $OUT"
