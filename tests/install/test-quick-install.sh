#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-quick-install.sh - tests for install/quick-install.sh: an archive is
# only used after its SHA-256 (and, when given, its signature from the pinned
# key) checks out; unsafe archives are refused before anything is unpacked;
# the preflight runs first and a blocker stops it; options reach install.sh
# as the documented variables; bad option values are refused.
#
# The archives here carry a stub install/install.sh that records how it was
# called, so nothing is installed. ROOT-ONLY: quick-install.sh refuses to run
# as anyone else (it installs a kernel), so the whole suite needs root.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
QI="$ROOT/install/quick-install.sh"

if [ "$(id -u)" -ne 0 ]; then skip "ROOT-ONLY: quick-install.sh runs as root only"; tap_done; exit 0; fi
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
LOG="$T/calls.log"

# mkarchive NAME [preflight-rc]: a release-shaped archive whose install.sh
# logs "install.sh [<args>] SS_TPM_LOCKOUT=<v> STIG=<v>" to $LOG.
mkarchive() {
	local name="$1" prc="${2:-0}" d="$T/src-$1"
	rm -rf "$d"; mkdir -p "$d/KernelPatch-merged/install" "$d/KernelPatch-merged/temporary"
	cat > "$d/KernelPatch-merged/install/install.sh" <<EOF
#!/bin/sh
echo "install.sh [\$*] SS_TPM_LOCKOUT=\${SS_TPM_LOCKOUT-unset} STIG=\${STIG-unset}" >> "$LOG"
if [ "\${1:-}" = preflight ]; then echo "preflight: stub"; exit $prc; fi
exit 0
EOF
	printf '#!/bin/sh\necho "install-temporary.sh $*" >> "%s"\n' "$LOG" > "$d/KernelPatch-merged/temporary/install-temporary.sh"
	tar -C "$d" -czf "$T/$name.tar.gz" KernelPatch-merged
	(cd "$T" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
}
run() { : > "$LOG"; bash "$QI" "$@" > "$T/out" 2>&1; }
calls() { cat "$LOG" 2>/dev/null; }

# ------------------------------------------------------------ good archive
mkarchive secure_sudo-9.9.9
run --archive "$T/secure_sudo-9.9.9.tar.gz" --dest "$T/opt" --yes; rc=$?
eq "a verified archive installs (exit 0)" "$rc" 0
check "the SHA-256 is reported as checked" grep -q 'SHA-256 ok' "$T/out"
eq "preflight runs first, then the full install" "$(calls | cut -d' ' -f1-2 | tr '\n' '|')" "install.sh [preflight]|install.sh []|"
check "it is unpacked under --dest/<archive name>" test -f "$T/opt/secure_sudo-9.9.9/KernelPatch-merged/install/install.sh"
check "the next steps name verify --commit" grep -q 'verify --commit' "$T/out"
run --archive "$T/secure_sudo-9.9.9.tar.gz" --dest "$T/opt" --yes
check "an existing unpack directory is refused, not overwritten" grep -q 'already exists' "$T/out"

# ---------------------------------------------------------------- dry run
run --archive "$T/secure_sudo-9.9.9.tar.gz" --dest "$T/opt2" --dry-run; rc=$?
eq "--dry-run passes (exit 0)" "$rc" 0
eq "--dry-run only runs the preflight" "$(calls | cut -d' ' -f1-2)" "install.sh [preflight]"
check "--dry-run leaves --dest alone" test ! -e "$T/opt2"

# ------------------------------------------------------------ integrity
mkarchive secure_sudo-9.9.8
printf 'x' >> "$T/secure_sudo-9.9.8.tar.gz"
run --archive "$T/secure_sudo-9.9.8.tar.gz" --dest "$T/opt3" --yes; rc=$?
check "a tampered archive is refused (SHA-256 mismatch)" sh -c "[ $rc -eq 1 ] && grep -q 'SHA-256 MISMATCH' '$T/out'"
eq "... and its install.sh never runs" "$(calls)" ""
check "... and nothing is unpacked" test ! -e "$T/opt3"
rm -f "$T/secure_sudo-9.9.8.tar.gz.sha256"
run --archive "$T/secure_sudo-9.9.8.tar.gz" --dest "$T/opt3" --yes
check "an archive without its .sha256 file is refused" grep -q 'no checksum file' "$T/out"
printf 'not-a-hash  x\n' > "$T/bad.sha256"
run --archive "$T/secure_sudo-9.9.9.tar.gz" --sha256 "$T/bad.sha256" --dest "$T/opt3" --yes
check "a checksum file without a SHA-256 is refused" grep -q 'does not start with a SHA-256' "$T/out"

# ----------------------------------------------------- unsafe archive shapes
evil() { # NAME: hash the archive at $T/NAME.tar.gz, then run on it
	(cd "$T" && sha256sum "$1.tar.gz" > "$1.tar.gz.sha256")
	run --archive "$T/$1.tar.gz" --dest "$T/opt4" --yes
}
mkdir -p "$T/e1/a"; echo x > "$T/e1/a/f"
tar -C "$T/e1" -czf "$T/dotdot.tar.gz" --transform 's|^a/f|a/../../escape|' a/f
evil dotdot
check "an archive with a '..' member is refused" grep -q "absolute or '..' member" "$T/out"
mkdir -p "$T/e2/a"; ln -s /etc/shadow "$T/e2/a/link"
tar -C "$T/e2" -czf "$T/abslink.tar.gz" a
evil abslink
check "an archive with a link pointing outside is refused" grep -q 'link pointing outside' "$T/out"
mkdir -p "$T/e3/a" "$T/e3/b"; echo x > "$T/e3/a/f"; echo y > "$T/e3/b/g"
tar -C "$T/e3" -czf "$T/twotop.tar.gz" a b
evil twotop
check "an archive with two top directories is refused" grep -q 'exactly one top directory' "$T/out"
eq "... none of them ran anything" "$(calls)" ""
check "... and none was unpacked" test ! -e "$T/opt4"

# ------------------------------------------------------------- signatures
if command -v gpg >/dev/null; then
	export GNUPGHOME="$T/gpghome"; mkdir -m 0700 "$GNUPGHOME"
	gpg --batch --quiet --passphrase '' --quick-gen-key 'qi-test <qi@example.invalid>' ed25519 sign never 2>/dev/null
	fpr="$(gpg --batch --with-colons --fingerprint 'qi@example.invalid' | awk -F: '$1=="fpr" {print $10; exit}')"
	gpg --batch --armor --export "$fpr" > "$T/signer.asc"
	gpg --batch --armor --detach-sign -o "$T/secure_sudo-9.9.9.tar.gz.sha256.asc" "$T/secure_sudo-9.9.9.tar.gz.sha256"
	unset GNUPGHOME
	SIGARGS=(--signature "$T/secure_sudo-9.9.9.tar.gz.sha256.asc" --signer-key "$T/signer.asc")
	run --archive "$T/secure_sudo-9.9.9.tar.gz" "${SIGARGS[@]}" --signer-fpr "$fpr" --dest "$T/opt5" --dry-run; rc=$?
	check "a good signature from the pinned fingerprint passes" sh -c "[ $rc -eq 0 ] && grep -q 'signature ok' '$T/out'"
	run --archive "$T/secure_sudo-9.9.9.tar.gz" "${SIGARGS[@]}" --signer-fpr "$(printf '%040d' 0)" --dest "$T/opt5" --dry-run; rc=$?
	check "a signature by any other fingerprint is refused" sh -c "[ $rc -eq 1 ] && grep -q 'signature check FAILED' '$T/out'"
	cp "$T/secure_sudo-9.9.9.tar.gz.sha256" "$T/sha.orig"
	echo "# appended" >> "$T/secure_sudo-9.9.9.tar.gz.sha256"
	run --archive "$T/secure_sudo-9.9.9.tar.gz" "${SIGARGS[@]}" --signer-fpr "$fpr" --dest "$T/opt5" --dry-run; rc=$?
	check "a checksum file changed after signing is refused" sh -c "[ $rc -eq 1 ] && grep -q 'signature check FAILED' '$T/out'"
	cp "$T/sha.orig" "$T/secure_sudo-9.9.9.tar.gz.sha256"
	run --archive "$T/secure_sudo-9.9.9.tar.gz" --signature "$T/secure_sudo-9.9.9.tar.gz.sha256.asc" --dest "$T/opt5" --dry-run; rc=$?
	eq "--signature without --signer-key/--signer-fpr is a usage error" "$rc" 2
else
	skip "signature checks need gpg"
fi

# ---------------------------------------------- preflight blocker, options
mkarchive secure_sudo-9.9.7 3
run --archive "$T/secure_sudo-9.9.7.tar.gz" --dest "$T/opt6" --yes; rc=$?
check "a preflight blocker stops it" sh -c "[ $rc -eq 1 ] && grep -q 'preflight found a blocker' '$T/out'"
eq "... before the install step" "$(calls | cut -d' ' -f1-2)" "install.sh [preflight]"

mkarchive secure_sudo-9.9.6
run --archive "$T/secure_sudo-9.9.6.tar.gz" --dest "$T/opt7" --yes --no-tpm-lockout --stig scan --with-addons --initramfs
check "--no-tpm-lockout and --stig reach install.sh as SS_TPM_LOCKOUT=0 STIG=scan" \
	sh -c "calls() { cat '$LOG'; }; calls | grep -qx 'install.sh \[\] SS_TPM_LOCKOUT=0 STIG=scan'"
check "--with-addons --initramfs runs install-temporary.sh --initramfs" grep -qx 'install-temporary.sh --initramfs' "$LOG"

mkarchive secure_sudo-9.9.5
: > "$LOG"; setsid bash "$QI" --archive "$T/secure_sudo-9.9.5.tar.gz" --dest "$T/opt8" < /dev/null > "$T/out" 2>&1
check "without --yes and without a terminal it stops before installing" grep -q 'no terminal to ask on' "$T/out"
eq "... after the preflight only" "$(calls | cut -d' ' -f1-2)" "install.sh [preflight]"
check "... and --dest is not written (nothing was changed)" test ! -e "$T/opt8"

run --stig harden; eq "--stig with another value is a usage error" "$?" 2
run --dest relative/dir --dry-run; eq "a relative --dest is a usage error" "$?" 2
run --dest /opt/../etc --dry-run; eq "a --dest with '..' is a usage error" "$?" 2
run --initramfs --dry-run; eq "--initramfs without --with-addons is a usage error" "$?" 2
run --bogus; eq "an unknown option is a usage error" "$?" 2
run --archive; eq "an option missing its value is a usage error" "$?" 2
refute "it never downloads anything (no curl or wget)" grep -qE '\b(curl|wget)\b' "$QI"

tap_done
