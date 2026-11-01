#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# test-pheonixbox.sh - PheonixBox (#21): snapshot, tamper detection, repair
# and permission restore, run against the real helper (TODO P1-5: every
# control mapped to a test, docs/THREAT_MODEL.md).
#
# Part 1 needs no root: the helper refuses to run unprivileged. Part 2 is
# ROOT-ONLY: the helper writes /etc/secure_sudo and /var/lib/secure_sudo, so
# it runs in a private mount namespace where /etc and /var/lib are overlays
# whose upper layers are scratch directories. Nothing it writes reaches the
# host. Skipped when not root.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

T="$(mktemp -d)"
NS=""
cleanup() { [ -n "$NS" ] && kill "$NS" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

if ! gcc -O2 -Wall -Wextra -Werror -o "$T/pb" "$ROOT/userspace/pheonixbox/pheonixbox.c" \
	-lcrypto -lz 2> "$T/build.err"; then
	not_ok "PheonixBox helper builds ($(head -1 "$T/build.err"))"
	tap_done; exit 1
fi
ok "PheonixBox helper builds with -Werror"

echo "# part 1: no root needed"
if [ "$(id -u)" -ne 0 ]; then
	refute_with "refuses to run without root" 'must run as root' "$T/pb" status
elif command -v setpriv >/dev/null; then
	refute_with "refuses to run without root" 'must run as root' \
		setpriv --reuid=65534 --regid=65534 --clear-groups "$T/pb" status
else
	skip "refuses to run without root (needs setpriv)"
fi

echo "# part 2: ROOT-ONLY - the real helper in a private mount namespace"
if [ "$(id -u)" -ne 0 ] || ! command -v unshare >/dev/null || ! command -v nsenter >/dev/null; then
	skip "snapshot, tamper, repair (needs root, unshare and nsenter)"
	tap_done; exit $?
fi

# One long-lived namespace, entered for each step, so the overlays persist.
unshare -m --propagation private sleep 600 & NS=$!
for _ in $(seq 50); do
	[ "$(readlink "/proc/$NS/ns/mnt" 2>/dev/null)" != "$(readlink /proc/self/ns/mnt)" ] && break
	sleep 0.1
done
in_ns() { nsenter -t "$NS" -m -- "$@"; }
mkdir -p "$T"/{etc.u,etc.w,lib.u,lib.w,cwd}
if ! in_ns mount -t overlay overlay -o "lowerdir=/etc,upperdir=$T/etc.u,workdir=$T/etc.w" /etc ||
   ! in_ns mount -t overlay overlay -o "lowerdir=/var/lib,upperdir=$T/lib.u,workdir=$T/lib.w" /var/lib; then
	skip "snapshot, tamper, repair (overlay mounts not available here)"
	tap_done; exit $?
fi
pb() { (cd "$T/cwd" && in_ns "$T/pb" "$@"); }
STORE=/var/lib/secure_sudo/pheonixbox

D="$T/data"
mkdir -p "$D/sub"
printf 'alpha\n' > "$D/a.conf"; chmod 0640 "$D/a.conf"
printf 'beta\n' > "$D/sub/b.conf"; chmod 0600 "$D/sub/b.conf"
# A name its directory's owner could choose. Before SECURITY_REVIEW #55 it
# was pasted into a shell line and ran "touch pwned" as root.
# shellcheck disable=SC2016
Q="$D/x';touch\${IFS}pwned;'"
printf 'quote\n' > "$Q"
NL="$D/new"$'\n'"line"
printf 'nl\n' > "$NL"
command -v getfacl >/dev/null && echo "# getfacl present: the ACL path is exercised" ||
	echo "# getfacl absent: the ACL path is skipped"

pb add "$D" > "$T/out" 2>&1
check "add a directory to the protected set" grep -q "^added $D" "$T/out"
check "the config lands in /etc/secure_sudo (inside the namespace only)" \
	in_ns grep -qx "$D" /etc/secure_sudo/pheonixbox.conf
check "the write went to the scratch overlay, not the host's /etc" \
	test -f "$T/etc.u/secure_sudo/pheonixbox.conf"

pb on > "$T/on.out" 2> "$T/on.err"; RC=$?
eq "on succeeds" "$RC" 0
check "on reports ENABLED" grep -q 'ENABLED' "$T/on.out"
check "a name with a newline is skipped, not stored" grep -q 'control character' "$T/on.err"
check "no command ran from a file name" test ! -e "$T/cwd/pwned"
eq "the store is root-only (0700)" "$(in_ns stat -c %a "$STORE")" 700
eq "files are locked read-only" "$(stat -c %a "$D/a.conf")" 440
eq "every file is locked, recursively" "$(stat -c %a "$D/sub/b.conf")" 400
eq "the manifest has one line per stored file (3)" "$(in_ns cat "$STORE/manifest" | wc -l)" 3

chmod 0644 "$D/a.conf"; printf 'evil\n' > "$D/a.conf"
rm -f "$D/sub/b.conf"
pb scan > "$T/scan.out" 2>&1; RC=$?
eq "scan succeeds" "$RC" 0
check "scan reports the repairs" grep -q 'repaired 2' "$T/scan.out"
eq "a rewritten file gets its contents back" "$(cat "$D/a.conf")" alpha
eq "a deleted file comes back" "$(cat "$D/sub/b.conf" 2>/dev/null)" beta
eq "a repaired file is locked read-only again" "$(stat -c %a "$D/a.conf")" 440
pb scan > "$T/scan2.out" 2>&1
check "a second scan finds nothing to repair" grep -q 'repaired 0' "$T/scan2.out"
check "no command ran from a file name during scans" test ! -e "$T/cwd/pwned"

pb status > "$T/status.out" 2>&1
check "status says ENABLED with 3 snapshot entries" \
	sh -c "grep -q ENABLED '$T/status.out' && grep -q 'snapshot entries: 3' '$T/status.out'"
refute_with "snapshot while enabled is refused" 'disable first' pb snapshot

pb off > "$T/off.out" 2>&1; RC=$?
eq "off succeeds" "$RC" 0
eq "off restores the original mode (0640)" "$(stat -c %a "$D/a.conf")" 640
eq "off restores the original mode (0600)" "$(stat -c %a "$D/sub/b.conf")" 600
pb scan > "$T/scan3.out" 2>&1
printf 'changed\n' > "$D/a.conf"
pb scan > "$T/scan3.out" 2>&1
eq "while off, scan repairs nothing" "$(cat "$D/a.conf")" changed

tap_done
