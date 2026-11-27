#!/usr/bin/env bash
# Combined repro of the four remaining failing tests in test-ubuntu-modprobe.sh.
set -u
cd "$(dirname "$0")/.." || exit 1
WRAPPER=../install/ubuntu-modprobe.sh
T=/tmp/t-all; rm -rf "$T"; mkdir -p "$T/src/KernelPatch-merged/install" "$T/src/KernelPatch-merged/temporary"
: > "$T/calls.log"

cat > "$T/src/KernelPatch-merged/install/install.sh" <<'INNEOF'
#!/bin/sh
echo "install.sh [\$*] SS_TPM_LOCKOUT=\${SS_TPM_LOCKOUT-unset} STIG=\${STIG-unset}" >> "/tmp/t-all/calls.log"
echo "banner: preflight ok" >> "/tmp/t-all/calls.log"
if [ "\${1:-}" = preflight ]; then exit 0; fi
echo "banner: install ok" >> "/tmp/t-all/calls.log"
exit 0
INNEOF
printf '#!/bin/sh\necho "install-temporary.sh \$*" >> "/tmp/t-all/calls.log"\n' > "$T/src/KernelPatch-merged/temporary/install-temporary.sh"
tar -C "$T/src" -czf "$T/secure_sudo-9.9.9.tar.gz" KernelPatch-merged

echo "##### TEST 4: numbered steps run in order #####"
: > "$T/calls.log"
bash "$WRAPPER" --archive "$T/secure_sudo-9.9.9.tar.gz" --dest "$T/opt" --yes > "$T/out" 2>&1
echo "wrapper rc=$?"
echo "--- out ---"; cat "$T/out"
echo "--- banner lines ---"
sed -n 's/^banner: //p' "$T/calls.log" | tr '\n' ' '; echo
echo "--- install.sh [ line ---"
sed -n 's/^install.sh \[//p' "$T/calls.log" | head -1

echo
echo "##### TEST 7: --with-modprobe-check #####"
: > "$T/calls.log"
bash "$WRAPPER" --archive "$T/secure_sudo-9.9.9.tar.gz" --dest "$T/opt2" --with-modprobe-check --yes > "$T/out2" 2>&1
echo "wrapper rc=$?"
echo "--- out ---"; cat "$T/out2"
grep -nE "modprobe compatibility|make|modprobe --test|sign-file" "$T/out2" | head -10

echo
echo "##### TEST 10: --dry-run only runs preflight #####"
: > "$T/calls.log"
bash "$WRAPPER" --archive "$T/secure_sudo-9.9.9.tar.gz" --dest "$T/opt3" --dry-run > "$T/out3" 2>&1
echo "wrapper rc=$?"
echo "--- out ---"; cat "$T/out3"
echo "--- first install.sh [ line ---"
sed -n 's/^install.sh \[//p' "$T/calls.log" | head -1

echo
echo "##### TESTS 15/16: '..' member archive #####"
mkdir -p "$T/e1/a"; echo x > "$T/e1/a/f"
tar -C "$T/e1" -czf "$T/dotdot.tar.gz" --transform 's|^a/f|a/../../escape|' a/f
: > "$T/calls.log"
bash "$WRAPPER" --archive "$T/dotdot.tar.gz" --dest "$T/opt5" --yes > "$T/out4" 2>&1
echo "wrapper rc=$?"
echo "--- out ---"; cat "$T/out4"
echo "--- contains 'absolute or ..' member? ---"
grep -c "absolute or '..' member" "$T/out4"
echo "--- log has install.sh [? ---"
grep -c "install.sh \[" "$T/calls.log"
echo "--- opt5 exists? ---"
ls -d "$T/opt5" 2>/dev/null || echo "not present"
