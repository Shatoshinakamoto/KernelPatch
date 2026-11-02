#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# verify-kernel-source.sh - check a kernel.org release archive against its
# detached OpenPGP signature BEFORE anything extracts it (TODO P0-4).
#
# kernel.org signs the uncompressed .tar, so the archive is decompressed into
# gpgv as a stream; nothing is written to disk. Fails closed: a missing or
# unreadable signature, a bad signature, a signer whose primary fingerprint is
# not pinned in install/keys/release-signers.txt, a revoked/expired key, or a
# corrupt archive all exit non-zero. There is no override.
#
# Usage:
#   scripts/verify-kernel-source.sh [--keys DIR] [--fetch-missing]
#                                   [--metadata FILE] ARCHIVE SIGNATURE
#
#   --keys DIR       pinned keyring dir (default: install/keys)
#   --fetch-missing  if the signer's key is not shipped, fetch it via WKD
#                    (gpg --locate-keys); it is still only accepted when its
#                    fingerprint is pinned
#   --metadata FILE  write verified provenance (key=value) to FILE
#
# Exit: 0 verified; 1 verification failed; 2 usage/tooling error.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYDIR="$HERE/../install/keys"
FETCH=0
META=""
ARGS=()

die()  { printf 'verify-kernel-source: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '3,24p' "$0" >&2; exit 2; }

while [ $# -gt 0 ]; do
	case "$1" in
	--keys)          KEYDIR="$2"; shift 2 ;;
	--fetch-missing) FETCH=1; shift ;;
	--metadata)      META="$2"; shift 2 ;;
	-h|--help)       usage ;;
	--*)             usage ;;
	*)               ARGS+=("$1"); shift ;;
	esac
done
[ "${#ARGS[@]}" -eq 2 ] || usage
archive="${ARGS[0]}"; sig="${ARGS[1]}"

for t in gpg gpgv sha256sum; do
	command -v "$t" >/dev/null 2>&1 || { echo "verify-kernel-source: missing $t" >&2; exit 2; }
done
[ -f "$archive" ] || die "archive not found: $archive"
[ -s "$sig" ]     || die "signature missing or empty: $sig (refusing to continue)"
pinned="$KEYDIR/release-signers.txt"
[ -f "$pinned" ]  || die "pinned signer list not found: $pinned"

case "$archive" in
*.tar.xz) decomp=(xz -dc) ;;
*.tar.gz) decomp=(gzip -dc) ;;
*.tar)    decomp=(cat) ;;
*) die "unsupported archive type: $archive" ;;
esac
command -v "${decomp[0]}" >/dev/null 2>&1 || { echo "verify-kernel-source: missing ${decomp[0]}" >&2; exit 2; }

mapfile -t FPRS < <(sed 's/#.*//' "$pinned" | tr -d ' \t' | tr 'a-f' 'A-F' | grep -E '^[0-9A-F]{40}$')
[ "${#FPRS[@]}" -gt 0 ] || die "no valid fingerprints in $pinned"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export GNUPGHOME="$work/gnupg"
mkdir -m 0700 "$GNUPGHOME"

# Import only shipped keys whose primary fingerprint is pinned.
shopt -s nullglob
for k in "$KEYDIR"/*.asc; do
	gpg --batch --quiet --import "$k" 2>/dev/null || true
done
shopt -u nullglob

signer_keyid() {
	gpg --batch --list-packets "$sig" 2>/dev/null |
		sed -n 's/.*issuer fpr v[45] \([0-9A-Fa-f]*\).*/\1/p; s/.*keyid \([0-9A-Fa-f]\{16\}\).*/\1/p' | head -1
}
have_key() { gpg --batch --list-keys "$1" >/dev/null 2>&1; }

kid="$(signer_keyid)"
[ -n "$kid" ] || die "cannot read a signature packet from $sig"
if ! have_key "$kid"; then
	if [ "$FETCH" -eq 1 ]; then
		for email in gregkh@kernel.org torvalds@kernel.org; do
			gpg --batch --quiet --auto-key-locate clear,wkd --locate-keys "$email" >/dev/null 2>&1 || true
		done
	fi
	have_key "$kid" || die "signer key $kid is not in the pinned keyring (try --fetch-missing)"
fi

# Keep only pinned primary keys in the keyring gpgv will trust.
kr="$work/trusted.gpg"
gpg --batch --export "${FPRS[@]}" > "$kr" 2>/dev/null
[ -s "$kr" ] || die "none of the pinned keys are available"

status="$work/status"
"${decomp[@]}" "$archive" | gpgv --status-fd 3 --keyring "$kr" "$sig" - 3>"$status" >/dev/null 2>"$work/gpgv.err"
rc=("${PIPESTATUS[@]}")
if [ "${rc[0]}" -ne 0 ]; then
	die "archive is corrupt or truncated (${decomp[0]} exit ${rc[0]})"
fi
if [ "${rc[1]}" -ne 0 ]; then
	sed 's/^/  gpgv: /' "$work/gpgv.err" >&2
	die "BAD or untrusted signature for $archive"
fi
if grep -qE '^\[GNUPG:\] (BADSIG|ERRSIG|EXPKEYSIG|REVKEYSIG|EXPSIG|NO_PUBKEY)' "$status"; then
	die "signature status rejected: $(grep -E 'BADSIG|ERRSIG|EXPKEYSIG|REVKEYSIG|EXPSIG|NO_PUBKEY' "$status" | head -1)"
fi
[ "$(grep -c '^\[GNUPG:\] VALIDSIG ' "$status")" -eq 1 ] ||
	die "expected exactly one valid signature"

# VALIDSIG <fpr> <date> <ts> <expire> <ver> <rsvd> <pkalgo> <hash> <class> <primary-fpr>
read -r _ _ sigfpr sigdate sigts _ _ _ _ _ _ primary < <(grep '^\[GNUPG:\] VALIDSIG ' "$status")
primary="${primary:-$sigfpr}"
ok=0
for f in "${FPRS[@]}"; do [ "$f" = "$primary" ] && ok=1; done
[ "$ok" -eq 1 ] || die "signer $primary is not pinned in $pinned"

arch_sha="$(sha256sum "$archive" | cut -d' ' -f1)"
sig_sha="$(sha256sum "$sig" | cut -d' ' -f1)"
base="$(basename "$archive")"
release="$(printf '%s' "$base" | sed -n 's/^linux-\(.*\)\.tar\(\.[a-z]*\)\{0,1\}$/\1/p')"

echo "verify-kernel-source: OK $base signed by $primary on $sigdate"
if [ -n "$META" ]; then
	{
		echo "kernel_release=${release:-unknown}"
		echo "archive=$base"
		echo "archive_sha256=$arch_sha"
		echo "signature_sha256=$sig_sha"
		echo "signer_primary_fpr=$primary"
		echo "signing_subkey_fpr=$sigfpr"
		echo "signature_date=$sigdate"
		echo "signature_epoch=$sigts"
		echo "verified_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "verifier=$(gpgv --version | head -1)"
	} > "$META"
fi
exit 0
