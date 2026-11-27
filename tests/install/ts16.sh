#!/usr/bin/env bash
# Trace test 16 directly.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
. "$ROOT/tests/lib/tap.sh"
MP="$ROOT/install/ubuntu-modprobe.sh"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
LOG="$T/calls.log"

mkdir -p "$T/e1/a"; echo x > "$T/e1/a/f"
tar -C "$T/e1" -czf "$T/dotdot.tar.gz" --transform 's|^a/f|a/../../escape|' a/f
(cd "$T" && sha256sum dotdot.tar.gz > dotdot.tar.gz.sha256)
echo "checksum file:"; cat "$T/dotdot.tar.gz.sha256"

: > "$LOG"
bash "$MP" --archive "$T/dotdot.tar.gz" --dest "$T/opt5" --yes > "$T/out" 2>&1
echo "wrapper rc=$?"
echo "--- out ---"; cat "$T/out"
echo "--- log ---"; cat "$LOG"
echo "--- install.sh [ lines ---"; sed -n 's/^install.sh \[//p' "$LOG" | head -3
echo "--- opt5 exists? ---"; ls -d "$T/opt5" 2>/dev/null || echo "not present"
echo "--- grep test ---"; grep -q 'install.sh \[' "$LOG" && test ! -e "$T/opt5"; echo "compound rc=$?"
