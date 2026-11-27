#!/usr/bin/env bash
# Generate a GPG key and signer files for the modprobe test suite.
set -u
export GNUPGHOME="${GNUPGHOME:-/tmp/gpghome}"
mkdir -m 0700 "$GNUPGHOME"
gpg --batch --homedir "$GNUPGHOME" --quiet --passphrase '' \
    --quick-gen-key 'qi-test <qi@example.invalid>' ed25519 sign never 2>/dev/null
fpr="$(gpg --batch --homedir "$GNUPGHOME" --with-colons --fingerprint 'qi@example.invalid' | awk -F: '$1=="fpr" {print $10; exit}')"
gpg --batch --homedir "$GNUPGHOME" --armor --export "$fpr" > /worktree/signer.asc
gpg --batch --homedir "$GNUPGHOME" --armor --detach-sign \
    -o /worktree/secure_sudo-9.9.9.tar.gz.sha256.asc /worktree/secure_sudo-9.9.9.tar.gz.sha256
echo "$fpr"
