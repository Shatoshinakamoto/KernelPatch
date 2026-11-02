#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests for scripts/verify-kernel-source.sh and install.sh's fetch_kernel
# (TODO P0-4): a good archive passes; tampered, truncated, unsigned,
# wrong-file and unpinned-signer archives are rejected, and install.sh never
# extracts a rejected archive. Uses a throwaway signing key; needs no root and
# no network.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
# Called through bash so the tests do not depend on the exec bit.
V() { bash "$ROOT/scripts/verify-kernel-source.sh" "$@"; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export GNUPGHOME="$T/signer"; mkdir -m 0700 "$GNUPGHOME"
gen() { gpg --batch --quiet --passphrase '' --quick-gen-key "$1" ed25519 sign never; }
fpr_of() { gpg --batch --with-colons --list-keys "$1" | awk -F: '$1=="fpr"{print $10; exit}'; }
gen 'Test Release Signer <release@example.invalid>'
gen 'Unpinned Signer <other@example.invalid>'
GOOD="$(fpr_of release@example.invalid)"; BAD="$(fpr_of other@example.invalid)"

# A pinned keyring dir containing only the good signer, plus a dir that ships
# the unpinned key too (to prove shipping a key is not the same as pinning it).
mkdir -p "$T/keys" "$T/keys2"
gpg --batch --armor --export "$GOOD" > "$T/keys/test.asc"
echo "$GOOD" > "$T/keys/release-signers.txt"
cp "$T/keys/"* "$T/keys2/"; gpg --batch --armor --export "$BAD" > "$T/keys2/other.asc"

# Fake release archive: linux-9.9.9/{Makefile,README}.
mkdir -p "$T/src/linux-9.9.9"; echo 'VERSION = 9' > "$T/src/linux-9.9.9/Makefile"; echo hi > "$T/src/linux-9.9.9/README"
tar -C "$T/src" -cf "$T/linux-9.9.9.tar" linux-9.9.9
gpg --batch --quiet --local-user "$GOOD" --armor --detach-sign -o "$T/linux-9.9.9.tar.sign" "$T/linux-9.9.9.tar"
gpg --batch --quiet --local-user "$BAD"  --armor --detach-sign -o "$T/unpinned.tar.sign" "$T/linux-9.9.9.tar"
xz -k "$T/linux-9.9.9.tar"
# Tampered: same name, one byte of content changed, original signature.
mkdir -p "$T/evil/linux-9.9.9"; cp "$T/src/linux-9.9.9/"* "$T/evil/linux-9.9.9/"; echo 'VERSION = 8' > "$T/evil/linux-9.9.9/Makefile"
mkdir -p "$T/tampered"; tar -C "$T/evil" -cf - linux-9.9.9 | xz > "$T/tampered/linux-9.9.9.tar.xz"
cp "$T/linux-9.9.9.tar.sign" "$T/tampered/"
head -c "$(( $(stat -c %s "$T/linux-9.9.9.tar.xz") / 2 ))" "$T/linux-9.9.9.tar.xz" > "$T/truncated.tar.xz"
echo "other" > "$T/other.txt"
gpg --batch --quiet --local-user "$GOOD" --armor --detach-sign -o "$T/other.sign" "$T/other.txt"
unset GNUPGHOME

check  "good archive + pinned signer verifies" \
	V --keys "$T/keys" --metadata "$T/meta" "$T/linux-9.9.9.tar.xz" "$T/linux-9.9.9.tar.sign"
check  "metadata records the signer fingerprint" grep -qx "signer_primary_fpr=$GOOD" "$T/meta"
check  "metadata records the archive sha256" \
	grep -qx "archive_sha256=$(sha256sum "$T/linux-9.9.9.tar.xz" | cut -d' ' -f1)" "$T/meta"
check  "metadata records the release" grep -qx "kernel_release=9.9.9" "$T/meta"
refute_with "tampered archive is rejected" "BAD or untrusted signature" \
	V --keys "$T/keys" "$T/tampered/linux-9.9.9.tar.xz" "$T/tampered/linux-9.9.9.tar.sign"
refute_with "truncated archive is rejected" "corrupt or truncated" \
	V --keys "$T/keys" "$T/truncated.tar.xz" "$T/linux-9.9.9.tar.sign"
refute_with "missing signature is rejected" "signature missing" \
	V --keys "$T/keys" "$T/linux-9.9.9.tar.xz" "$T/does-not-exist.sign"
: > "$T/empty.sign"
refute_with "empty signature is rejected" "signature missing or empty" \
	V --keys "$T/keys" "$T/linux-9.9.9.tar.xz" "$T/empty.sign"
refute_with "signature of a different file is rejected" "BAD or untrusted signature" \
	V --keys "$T/keys" "$T/linux-9.9.9.tar.xz" "$T/other.sign"
refute_with "signer whose key is not shipped is rejected" "not in the pinned keyring" \
	V --keys "$T/keys" "$T/linux-9.9.9.tar.xz" "$T/unpinned.tar.sign"
refute_with "shipped but unpinned signer is rejected" "BAD or untrusted|not pinned" \
	V --keys "$T/keys2" "$T/linux-9.9.9.tar.xz" "$T/unpinned.tar.sign"
mkdir -p "$T/nopin"; cp "$T/keys/test.asc" "$T/nopin/"; echo '# none' > "$T/nopin/release-signers.txt"
refute_with "empty pinned list is rejected" "no valid fingerprints" \
	V --keys "$T/nopin" "$T/linux-9.9.9.tar.xz" "$T/linux-9.9.9.tar.sign"

# install.sh end to end: fetch_kernel must not extract a rejected archive.
run_fetch() { # <tarball> <sig>
	rm -rf "$T/build"; mkdir -p "$T/build"
	( SS_INSTALL_LIB=1 KVER=9.9.9 BUILD_ROOT="$T/build" KERNEL_TARBALL="$1" \
	  KERNEL_SIGNATURE="$2" SS_KEYDIR="$T/keys" \
	  bash -c '. "$0"; fetch_kernel' "$ROOT/install/install.sh" ) >"$T/fetch.log" 2>&1
}
if run_fetch "$T/tampered/linux-9.9.9.tar.xz" "$T/tampered/linux-9.9.9.tar.sign"; then
	not_ok "install.sh fetch_kernel refuses a tampered archive"
else
	ok "install.sh fetch_kernel refuses a tampered archive"
fi
refute "install.sh did not extract the tampered archive" test -e "$T/build/linux-9.9.9"
check  "install.sh fetch_kernel accepts the good archive" \
	run_fetch "$T/linux-9.9.9.tar.xz" "$T/linux-9.9.9.tar.sign"
check  "install.sh extracted the verified tree" test -f "$T/build/linux-9.9.9/Makefile"
check  "install.sh wrote source provenance metadata" \
	grep -qx "signer_primary_fpr=$GOOD" "$T/build/build-metadata/kernel-source.txt"
# A tree left over from an older or tampered run must not be reused blindly.
echo 'VERSION = 7' > "$T/build/linux-9.9.9/Makefile"
echo "0000" > "$T/build/linux-9.9.9/.secure_sudo-source-sha256"
check  "install.sh re-extracts a tree whose marker does not match" \
	run_fetch "$T/linux-9.9.9.tar.xz" "$T/linux-9.9.9.tar.sign"
check  "re-extracted tree has the verified content" grep -qx 'VERSION = 9' "$T/build/linux-9.9.9/Makefile"

[ -n "${KEEP:-}" ] && { echo "kept $T"; trap - EXIT; }
tap_done
