#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-ubuntu-modprobe.sh - behaviour of install/ubuntu-modprobe.sh, the
# Ubuntu modprobe-compatible install method.
#
# The archives here carry a stub install.sh that records how it was called,
# so the whole suite exercises verification, the preflight, the options and
# the ordering - nothing is installed (it runs on a checkout, same as
# test-quick-install.sh). ROOT-ONLY: ubuntu-modprobe.sh refuses to run as
# anyone but root, so the whole suite needs root.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
MP="$ROOT/install/ubuntu-modprobe.sh"

if [ "$(id -u)" -ne 0 ]; then skip "ROOT-ONLY: ubuntu-modprobe.sh runs as root only"; tap_done; exit 0; fi
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
LOG="$T/calls.log"

# mkarchive NAME [preflight-rc]: a release-shaped archive whose install.sh
# logs "install.sh [<args>] SS_TPM_LOCKOUT=<v> STIG=<v>" to $LOG. install.sh
# prints a banner with the words the checks below look for.
mkarchive() {
	local name="$1" prc="${2:-0}" d="$T/src-$1"
	rm -rf "$d"; mkdir -p "$d/KernelPatch-merged/install" "$d/KernelPatch-merged/temporary"
	cat > "$d/KernelPatch-merged/install/install.sh" <<EOF
#!/bin/sh
echo "install.sh [\$*] SS_TPM_LOCKOUT=\${SS_TPM_LOCKOUT-unset} STIG=\${STIG-unset}" >> "$LOG"
if [ "\${1:-}" = preflight ]; then echo "banner: preflight ok" >> "$LOG"; fi
if [ "\${1:-}" = preflight ]; then exit $prc; fi
echo "banner: install ok" >> "$LOG"
exit 0
EOF
	printf '#!/bin/sh\necho "install-temporary.sh \$*" >> "%s"\n' "$LOG" > "$d/KernelPatch-merged/temporary/install-temporary.sh"
	tar -C "$d" -czf "$T/$name.tar.gz" KernelPatch-merged
	(cd "$T" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
}
run() { : > "$LOG"; bash "$MP" "$@" > "$T/out" 2>&1; }
reads() { cat "$LOG" 2>/dev/null; }

# ------------------------------------------------------------- good archive
mkarchive secure_sudo-9.9.9
run --archive "$T/secure_sudo-9.9.9.tar.gz" --dest "$T/opt" --yes; rc=$?
eq "a verified archive installs (exit 0)" "$rc" 0
check "SHA-256 is reported as checked" grep -q 'SHA-256 ok' "$T/out"
check "preflight runs first" grep -q 'banner: preflight ok' "$LOG"
eq "the numbered steps run in order" "$(sed -n 's/^banner: //p' "$LOG" | tr '\n' ' ' | sed 's/[[:space:]]*$//')" "preflight ok install ok"
check "it is unpacked under --dest/<archive name>" test -f "$T/opt/secure_sudo-9.9.9/KernelPatch-merged/install/install.sh"
check "the next steps name verify --commit" grep -q 'verify --commit' "$T/out"

# --------------------------------------------------- modprobe check option
run --archive "$T/secure_sudo-9.9.9.tar.gz" --dest "$T/opt2" --with-modprobe-check --yes
eq "--with-modprobe-check runs (exit 0)" "$?" 0
check "--with-modprobe-check ran" grep -q 'modprobe compatibility check' "$T/out"

# ------------------------------------------------------------- dry run
run --archive "$T/secure_sudo-9.9.9.tar.gz" --dest "$T/opt3" --dry-run; rc=$?
eq "--dry-run passes (exit 0)" "$rc" 0
eq "--dry-run only runs preflight" "$(sed -n 's/^install.sh \[//p' "$LOG" | head -1)" "preflight] SS_TPM_LOCKOUT=1 STIG=unset"
check "--dry-run leaves --dest alone" test ! -e "$T/opt3"

# ------------------------------------------------------- integrity controls
mkarchive secure_sudo-9.9.8
printf 'x' >> "$T/secure_sudo-9.9.8.tar.gz"
run --archive "$T/secure_sudo-9.9.8.tar.gz" --dest "$T/opt4" --yes; rc=$?
check "a tampered archive is refused" sh -c "[ $rc -eq 1 ] && grep -q 'SHA-256 MISMATCH' '$T/out'"
eq "... and its install.sh never runs" "$(sed -n 's/^install.sh \[//p' "$LOG" | head -1)" ""
check "... and nothing is unpacked" test ! -e "$T/opt4"

# ----------------------------------------------------------- unsafe archive
mkdir -p "$T/e1/a"; echo x > "$T/e1/a/f"
tar -C "$T/e1" -czf "$T/dotdot.tar.gz" --transform 's|^a/f|a/../../escape|' a/f
# The ".." member is refused by the wrapper AFTER the checksum check, so the
# archive must carry a checksum file for the "--archive" path to start.
(cd "$T" && sha256sum dotdot.tar.gz > dotdot.tar.gz.sha256)
run --archive "$T/dotdot.tar.gz" --dest "$T/opt5" --yes
check "an archive with a '..' member is refused" grep -q "absolute or '..' member" "$T/out"
run --archive "$T/dotdot.tar.gz" --dest "$T/opt5" --yes
check "... and nothing ran" sh -c '! grep -q "install.sh \[" "$LOG" && test ! -e "$T/opt5"'

# ------------------------------------------------------------ signatures
if command -v gpg >/dev/null; then
	export GNUPGHOME="$T/gpghome"; mkdir -m 0700 "$GNUPGHOME"
	gpg --batch --quiet --passphrase '' --quick-gen-key 'qi-test <qi@example.invalid>' ed25519 sign never 2>/dev/null
	fpr="$(gpg --batch --with-colons --fingerprint 'qi@example.invalid' | awk -F: '$1=="fpr" {print $10; exit}')"
	gpg --batch --armor --export "$fpr" > "$T/signer.asc"
	gpg --batch --armor --detach-sign -o "$T/secure_sudo-9.9.9.tar.gz.sha256.asc" "$T/secure_sudo-9.9.9.tar.gz.sha256"
	unset GNUPGHOME
	run --archive "$T/secure_sudo-9.9.9.tar.gz" --signature "$T/secure_sudo-9.9.9.tar.gz.sha256.asc" \
	    --signer-key "$T/signer.asc" --signer-fpr "$fpr" --dest "$T/opt6" --dry-run; rc=$?
	check "a good signature from the pinned fingerprint passes" sh -c "[ $rc -eq 0 ] && grep -q 'signature ok' '$T/out'"
	run --archive "$T/secure_sudo-9.9.9.tar.gz" --signature "$T/secure_sudo-9.9.9.tar.gz.sha256.asc" \
	    --signer-key "$T/signer.asc" --signer-fpr "$(printf '%040d' 0)" --dest "$T/opt6" --dry-run; rc=$?
	check "a signature by any other fingerprint is refused" sh -c "[ $rc -eq 1 ] && grep -q 'signature check FAILED' '$T/out'"
	cp "$T/secure_sudo-9.9.9.tar.gz.sha256" "$T/sha.orig"
	echo "# appended" >> "$T/secure_sudo-9.9.9.tar.gz.sha256"
	run --archive "$T/secure_sudo-9.9.9.tar.gz" --signature "$T/secure_sudo-9.9.9.tar.gz.sha256.asc" \
	    --signer-key "$T/signer.asc" --signer-fpr "$fpr" --dest "$T/opt6" --dry-run; rc=$?
	check "a checksum file changed after signing is refused" sh -c "[ $rc -eq 1 ] && grep -q 'signature check FAILED' '$T/out'"
	cp "$T/sha.orig" "$T/secure_sudo-9.9.9.tar.gz.sha256"
else
	skip "signature checks need gpg"
fi

# ------------------------------------------------- option value controls
run --archive "$T/secure_sudo-9.9.9.tar.gz" --dest "$T/opt7" --yes --stig harden
eq "--stig with another value is a usage error" "$?" 2
run --dest relative/dir --dry-run
eq "a relative --dest is a usage error" "$?" 2
run --dest /opt/../etc --dry-run
eq "a --dest with '..' is a usage error" "$?" 2
run --initramfs --dry-run
eq "--initramfs without --with-addons is a usage error" "$?" 2
run --bogus; eq "an unknown option is a usage error" "$?" 2

tap_done
