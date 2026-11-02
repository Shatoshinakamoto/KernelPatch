#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
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
if [ "$(readlink "/proc/$NS/ns/mnt" 2>/dev/null)" = "$(readlink /proc/self/ns/mnt)" ]; then
	skip "snapshot, tamper, repair (no private mount namespace)"
	tap_done; exit $?
fi
mkdir -p "$T"/{etc.u,etc.w,lib.u,lib.w,cwd}
if ! in_ns mount -t overlay overlay -o "lowerdir=/etc,upperdir=$T/etc.u,workdir=$T/etc.w" /etc ||
   ! in_ns mount -t overlay overlay -o "lowerdir=/var/lib,upperdir=$T/lib.u,workdir=$T/lib.w" /var/lib; then
	skip "snapshot, tamper, repair (overlay mounts not available here)"
	tap_done; exit $?
fi
pb() { (cd "$T/cwd" && in_ns "$T/pb" "$@"); }
# Start as a machine where nothing has made /etc/secure_sudo yet (a CI runner
# is one; this box may not be). The move happens in the overlay's upper layer.
if in_ns test -e /etc/secure_sudo; then
	in_ns mv /etc/secure_sudo /etc/secure_sudo.pbtest-hidden
fi
check "the test starts without /etc/secure_sudo (inside the namespace)" in_ns test ! -e /etc/secure_sudo
check "... and the host still has its own" sh -c "[ ! -e /etc/secure_sudo.pbtest-hidden ]"
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
eq "the manifest has one line per stored file (3)" "$(in_ns grep -vc '^acl ' "$STORE/manifest")" 3

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

echo "# adversarial (TODO P2-2 part 3)"
check "the rewritten file's bytes were kept as evidence before the repair" \
	sh -c "in_ns() { nsenter -t $NS -m -- \"\$@\"; }; [ \"\$(in_ns sh -c 'ls $STORE/evidence/*.z' | wc -l)\" -ge 1 ]"
# a symlink planted where a protected file was: the repair replaces the
# link, it never writes through it (it used to: open(O_TRUNC) followed it)
printf 'victim\n' > "$T/victim"; chmod 0644 "$T/victim"
rm -f "$D/a.conf"; ln -s "$T/victim" "$D/a.conf"
pb scan > "$T/scan.out" 2>&1
check "a symlink planted at a protected path is replaced by the real file" sh -c "
	[ ! -L '$D/a.conf' ] && [ \"\$(cat '$D/a.conf')\" = alpha ]"
check "... and the file it pointed at is untouched (contents and mode)" sh -c "
	[ \"\$(cat '$T/victim')\" = victim ] && [ \"\$(stat -c %a '$T/victim')\" = 644 ]"
# a snapshot blob swapped for other bytes is never written back
for b in $(in_ns sh -c "ls $STORE/blobs/*.z"); do
	in_ns cp "$b" "$b.keep"
	in_ns python3 -c 'import struct,sys,zlib; d=b"attacker\n"; open(sys.argv[1],"wb").write(struct.pack("<Q",len(d))+zlib.compress(d))' "$b"
done
chmod 0644 "$D/a.conf"; printf 'evil2\n' > "$D/a.conf"
pb scan > "$T/scan.out" 2>&1
check "a swapped snapshot blob is refused: the file is not overwritten with it" sh -c "
	[ \"\$(cat '$D/a.conf')\" = evil2 ] && grep -q 'FAILED to repair' '$T/scan.out'"
for b in $(in_ns sh -c "ls $STORE/blobs/*.z"); do in_ns mv "$b.keep" "$b"; done
pb scan > /dev/null 2>&1
eq "... and the real snapshot repairs it" "$(cat "$D/a.conf")" alpha
# a manifest line naming a path with a .. component is ignored
in_ns cp "$STORE/manifest" "$T/manifest.keep"
H="$(sha256sum "$D/a.conf" | cut -d' ' -f1)"
in_ns sh -c "echo '$H 644 0 0 $D/../victim2' >> $STORE/manifest"
printf 'v2\n' > "$T/victim2"
pb scan > "$T/scan.out" 2>&1
check "an edited manifest entry with a .. component is never acted on" sh -c "
	[ \"\$(cat '$T/victim2')\" = v2 ] && grep -q 'repaired 0' '$T/scan.out'"
in_ns cp "$T/manifest.keep" "$STORE/manifest"
# no room to keep the evidence: the tampered file is left, not overwritten
in_ns mkdir -p "$STORE/evidence"
in_ns mount -t tmpfs -o size=16k tmpfs "$STORE/evidence"
chmod 0644 "$D/a.conf"; head -c 200000 /dev/urandom > "$D/a.conf"; BIGH="$(sha256sum "$D/a.conf")"
pb scan > "$T/scan.out" 2>&1
check "with no room for the evidence copy, the tampered file is not overwritten" sh -c "
	[ \"\$(sha256sum '$D/a.conf')\" = '$BIGH' ] && grep -q 'NOT repaired' '$T/scan.out'"
in_ns umount "$STORE/evidence"
pb scan > /dev/null 2>&1
eq "... and is repaired once there is room" "$(cat "$D/a.conf")" alpha
# disable with a symlink in place: its target's permissions are not changed
rm -f "$D/sub/b.conf"; ln -s "$T/victim" "$D/sub/b.conf"; chmod 0600 "$T/victim"

pb status > "$T/status.out" 2>&1
check "status says ENABLED with 3 snapshot entries" \
	sh -c "grep -q ENABLED '$T/status.out' && grep -q 'snapshot entries: 3' '$T/status.out'"
refute_with "snapshot while enabled is refused" 'disable first' pb snapshot

pb off > "$T/off.out" 2>&1; RC=$?
eq "off succeeds" "$RC" 0
eq "off restores the original mode (0640)" "$(stat -c %a "$D/a.conf")" 640
check "off does not change permissions through a planted symlink" sh -c "
	[ \"\$(stat -c %a '$T/victim')\" = 600 ] && [ -L '$D/sub/b.conf' ]"
rm -f "$D/sub/b.conf"; printf 'beta\n' > "$D/sub/b.conf"; chmod 0600 "$D/sub/b.conf"
pb scan > "$T/scan3.out" 2>&1
printf 'changed\n' > "$D/a.conf"
pb scan > "$T/scan3.out" 2>&1
eq "while off, scan repairs nothing" "$(cat "$D/a.conf")" changed

echo "# check-config (TODO P2-2)"
pb check-config > "$T/cc.out" 2>&1; rc=$?
check "check-config passes on the config add/remove wrote" sh -c "[ $rc = 0 ] && grep -q 'configuration OK' '$T/cc.out'"
in_ns sh -c "printf 'relative/path\n$D\n/a/../b\n' >> /etc/secure_sudo/pheonixbox.conf"
pb check-config > "$T/cc.out" 2>&1; rc=$?
check "check-config: a relative path, a duplicate and a .. component (3 problems)" sh -c "
	[ $rc = 1 ] && grep -q 'not an absolute path' '$T/cc.out' && grep -q 'listed twice' '$T/cc.out' &&
	grep -q '\./\.\. component' '$T/cc.out' && grep -q '^3 configuration problem' '$T/cc.out'"
pb on > "$T/on.out" 2>&1; rc=$?
check "on refuses while the config has an error (78)" sh -c "[ $rc = 78 ] && grep -q 'on refused' '$T/on.out'"
pb snapshot > "$T/on.out" 2>&1; rc=$?
eq "... and so does snapshot" "$rc" 78
in_ns sh -c "grep -vx -e relative/path -e /a/../b /etc/secure_sudo/pheonixbox.conf | awk '!s[\$0]++' > /etc/secure_sudo/pb.new && mv /etc/secure_sudo/pb.new /etc/secure_sudo/pheonixbox.conf && chmod 0664 /etc/secure_sudo/pheonixbox.conf"
pb check-config > "$T/cc.out" 2>&1; rc=$?
check "check-config: a group-writable config is an error" sh -c "[ $rc = 1 ] && grep -q 'writable by group or others' '$T/cc.out'"

echo "# signed snapshot (TODO P2-2: baseline trust)"
KEY=/etc/secure_sudo/addons/baseline-signing.pub
in_ns sh -c "printf '%s\n' '$D' > /etc/secure_sudo/pheonixbox.conf && chmod 0644 /etc/secure_sudo/pheonixbox.conf"
chmod 0644 "$D/a.conf"; printf 'alpha\n' > "$D/a.conf"; chmod 0640 "$D/a.conf"
in_ns sh -c "echo 'trust = sgned' >> /etc/secure_sudo/pheonixbox.conf"
pb check-config > "$T/cc.out" 2>&1; rc=$?
check "check-config: an unknown trust value is an error" sh -c "[ $rc = 1 ] && grep -q 'trust must be local or signed' '$T/cc.out'"
in_ns sed -i 's/^trust = sgned$/trust = signed/' /etc/secure_sudo/pheonixbox.conf
pb check-config > "$T/cc.out" 2>&1; rc=$?
check "check-config: trust = signed without a signing key is an error" sh -c "[ $rc = 1 ] && grep -q 'trust = signed, but' '$T/cc.out'"
openssl genpkey -algorithm ed25519 -out "$T/k.pem" 2>/dev/null
in_ns mkdir -p /etc/secure_sudo/addons
in_ns sh -c "openssl pkey -in '$T/k.pem' -pubout > $KEY && chmod 0644 $KEY"
pb check-config > "$T/cc.out" 2>&1
check "check-config passes with trust = signed and a key" grep -q 'configuration OK' "$T/cc.out"
pb on > "$T/on.out" 2>&1
check "on with trust = signed says nothing is repaired until it is signed" grep -q 'nothing is repaired until' "$T/on.out"
pb status > "$T/st.out" 2>&1
check "status: an unsigned snapshot is NOT TRUSTED" grep -q 'snapshot trust: signed - NOT TRUSTED: the snapshot is not signed' "$T/st.out"
if command -v getfacl >/dev/null; then
	check "the manifest records a hash for each captured ACL file" in_ns grep -q "^acl [0-9a-f]\{64\} $D/a.conf\$" "$STORE/manifest"
else
	skip "ACL hashes in the manifest (no getfacl)"
fi
EV0="$(in_ns sh -c "ls $STORE/evidence 2>/dev/null | wc -l")"
chmod 0644 "$D/a.conf"; printf 'evil3\n' > "$D/a.conf"
pb scan > "$T/scan.out" 2>&1
check "unsigned snapshot: tampering is reported, not repaired" sh -c "
	[ \"\$(cat '$D/a.conf')\" = evil3 ] && grep -q 'would repair $D/a.conf' '$T/scan.out' &&
	grep -q 'NOT TRUSTED: reporting only' '$T/scan.out'"
EV1="$(in_ns sh -c "ls $STORE/evidence | wc -l")"
check "... and its bytes are kept as evidence" test "$EV1" -gt "$EV0"
pb scan > "$T/scan.out" 2>&1
check "the next scan does not report (or copy) the same change again" sh -c "
	! grep -q 'would repair' '$T/scan.out' && [ \"\$(nsenter -t $NS -m -- sh -c 'ls $STORE/evidence | wc -l')\" = $EV1 ]"
in_ns openssl pkeyutl -sign -rawin -inkey "$T/k.pem" -in "$STORE/manifest" -out "$STORE/manifest.sig"
pb status > "$T/st.out" 2>&1
check "status: once the operator signs it, the snapshot is trusted" grep -q 'snapshot trust: signed - signature valid' "$T/st.out"
pb scan > "$T/scan.out" 2>&1
eq "a signed snapshot repairs" "$(cat "$D/a.conf")" alpha
# an edited manifest (here: a.conf's mode set to setuid) breaks the signature
in_ns cp "$STORE/manifest" "$T/manifest.signed"
in_ns sed -i "s#^\([0-9a-f]\{64\}\) [0-7]* \([0-9]* [0-9]* $D/a.conf\)\$#\1 4755 \2#" "$STORE/manifest"
check "(the test edited the manifest)" in_ns grep -q " 4755 .* $D/a.conf\$" "$STORE/manifest"
chmod 0644 "$D/a.conf"; printf 'evil4\n' > "$D/a.conf"
pb scan > "$T/scan.out" 2>&1
check "an edited manifest is not trusted: nothing is written back" sh -c "
	[ \"\$(cat '$D/a.conf')\" = evil4 ] && grep -q 'does not verify' '$T/scan.out'"
in_ns sh -c "echo 'garbage' > $STORE/manifest.sig"
pb status > "$T/st.out" 2>&1
check "a forged signature is not trusted either" grep -q 'NOT TRUSTED: the manifest.s signature does not verify' "$T/st.out"
in_ns cp "$T/manifest.signed" "$STORE/manifest"
in_ns openssl pkeyutl -sign -rawin -inkey "$T/k.pem" -in "$STORE/manifest" -out "$STORE/manifest.sig"
pb scan > /dev/null 2>&1
eq "... and the signed manifest repairs it again" "$(cat "$D/a.conf")" alpha
# trust lowered from signed to local is said out loud
in_ns sed -i 's/^trust = signed$/trust = local/' /etc/secure_sudo/pheonixbox.conf
pb scan > "$T/scan.out" 2>&1
check "a scan notices trust lowered from signed to local" grep -q 'trust LOWERED from signed to local' "$T/scan.out"
in_ns sed -i 's/^trust = local$/trust = signed/' /etc/secure_sudo/pheonixbox.conf
pb scan > /dev/null 2>&1
# off with an unsigned edit to the manifest: the setuid mode it names is not applied
in_ns sed -i "s#^\([0-9a-f]\{64\}\) [0-7]* \([0-9]* [0-9]* $D/a.conf\)\$#\1 4755 \2#" "$STORE/manifest"
pb off > "$T/off.out" 2>&1; rc=$?
check "off with an untrusted manifest only unlocks (and says so)" sh -c "
	[ $rc = 0 ] && grep -q 'files are only unlocked' '$T/off.out'"
M="$(stat -c %a "$D/a.conf")"
check "... the setuid mode the edited manifest names is not applied (mode $M)" sh -c "[ \$(( 0$M & 04000 )) = 0 ]"
check "... and the file is writable by its owner again" sh -c "[ \$(( 0$M & 0200 )) != 0 ]"
in_ns cp "$T/manifest.signed" "$STORE/manifest"
in_ns openssl pkeyutl -sign -rawin -inkey "$T/k.pem" -in "$STORE/manifest" -out "$STORE/manifest.sig"
if command -v getfacl >/dev/null && command -v setfacl >/dev/null &&
   setfacl -m u:nobody:r "$D/a.conf" 2>/dev/null; then
	pb on > /dev/null 2>&1
	in_ns openssl pkeyutl -sign -rawin -inkey "$T/k.pem" -in "$STORE/manifest" -out "$STORE/manifest.sig"
	pb off > /dev/null 2>&1
	check "off applies a captured ACL whose hash is in the signed manifest" sh -c "getfacl -p '$D/a.conf' 2>/dev/null | grep -q '^user:nobody:r--'"
	pb on > /dev/null 2>&1
	AP="$(in_ns sh -c "grep -l '^# file: $D/a.conf\$' $STORE/acls/*.acl" | head -1)"
	in_ns sh -c "printf '# file: $D/a.conf\nuser::rw-\nuser:nobody:rwx\ngroup::r--\nmask::rwx\nother::---\n' > '$AP'"
	in_ns openssl pkeyutl -sign -rawin -inkey "$T/k.pem" -in "$STORE/manifest" -out "$STORE/manifest.sig"
	pb off > /dev/null 2>&1
	check "a rewritten ACL file (hash not in the manifest) is not applied by off" sh -c "! getfacl -p '$D/a.conf' 2>/dev/null | grep -q '^user:nobody:rwx'"
else
	skip "captured ACLs applied only when their hash matches (needs getfacl, setfacl, ACL support)"
fi

tap_done
