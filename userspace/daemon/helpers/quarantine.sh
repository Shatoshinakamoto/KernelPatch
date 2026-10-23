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
set -eu

FILE="${1:?usage: quarantine.sh <file>}"
QDIR="/var/lib/secure_sudo/quarantine"
mkdir -p "$QDIR"
chmod 700 "$QDIR"

[ -f "$FILE" ] || exit 0

TS="$(date +%Y%m%dT%H%M%S)"
BASE="$(basename "$FILE")"
STAMP="$QDIR/${TS}-${BASE}"
META="${STAMP}.meta"
ZIP="${STAMP}.zip"

# Record provenance before touching the file.
{
  echo "original_path: $FILE"
  echo "quarantined_at: $(date -Is)"
  echo "sha256: $(sha256sum -- "$FILE" 2>/dev/null | awk '{print $1}')"
  ls -ln -- "$FILE" 2>/dev/null | awk '{print "stat: "$0}'
} > "$META"

# Package the file + metadata, then remove the original (the "move").
if command -v zip >/dev/null 2>&1; then
  zip -j -q "$ZIP" -- "$FILE" "$META" && rm -f -- "$META"
else
  # Fallback if zip is not installed: keep a tar.gz instead of failing.
  tar -czf "${STAMP}.tar.gz" -C "$(dirname "$FILE")" "$BASE" \
      -C "$QDIR" "$(basename "$META")" && rm -f -- "$META"
fi

rm -f -- "$FILE"
echo "quarantine.sh: quarantined $FILE -> $QDIR"
