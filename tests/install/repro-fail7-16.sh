#!/usr/bin/env bash
# Repro of failing tests 4, 7, 16 with trace.
set -u
cd /worktree || exit 1
export GNUPGHOME=/tmp/gpghome
mkdir -m 0700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-gen-key 'qi-test <qi@example.invalid>' ed25519 sign never 2>/dev/null
fpr="$(gpg --batch --with-colons --fingerprint 'qi@example.invalid' | awk -F: '$1=="fpr" {print $10; exit}')"
gpg --batch --armor --export "$fpr" > signer.asc
gpg --batch --armor --detach-sign -o secure_sudo-9.9.9.tar.gz.sha256.asc secure_sudo-9.9.9.tar.gz.sha256
echo "FPR=$fpr"

echo
echo "######## TEST 4 ########"
: > calls.log
bash install/ubuntu-modprobe.sh --archive secure_sudo-9.9.9.tar.gz --dest /tmp/t4opt --yes > out4 2>&1
echo "wrapper rc=$?"
echo "--- out4 ---"; cat out4
echo "--- banner lines ---"; sed -n 's/^banner: //p' calls.log | tr '\n' ' '; echo
echo "--- install.sh [ lines ---"; sed -n 's/^install.sh \[//p' calls.log | head -3

echo
echo "######## TEST 7 ########"
: > calls.log
bash install/ubuntu-modprobe.sh --archive secure_sudo-9.9.9.tar.gz --dest /tmp/t7opt --with-modprobe-check --yes > out7 2>&1
echo "wrapper rc=$?"
echo "--- out7 ---"; cat out7
echo "--- modprobe-related lines in out7 ---"
grep -nE "modprobe compatibility|make|modprobe --test|sign-file|unsigned|kernel build" out7 | head -20

echo
echo "######## TEST 16 ########"
mkdir -p /tmp/t16e1/a
echo x > /tmp/t16e1/a/f
tar -C /tmp/t16e1 -czf /tmp/t16e1/dotdot.tar.gz --transform 's|^a/f|a/../../escape|' a/f
: > calls.log
bash install/ubuntu-modprobe.sh --archive /tmp/t16e1/dotdot.tar.gz --dest /tmp/t16/opt5 --yes > out16 2>&1
echo "wrapper rc=$?"
echo "--- out16 ---"; cat out16
echo "--- log install.sh [ counts ---"; grep -c "install.sh \[" calls.log
echo "--- opt5 exists ---"; ls -d /tmp/t16/opt5 2>/dev/null || echo "not present"
