#!/usr/bin/env bash
# Repro of the failing test 4 (numbered steps run in order).
set -u
cd "$(dirname "$0")/.." || exit 1
WRAPPER=../install/ubuntu-modprobe.sh
rm -rf /tmp/t4 && mkdir -p /tmp/t4/src/KernelPatch-merged/install /tmp/t4/src/KernelPatch-merged/temporary
cat > /tmp/t4/src/KernelPatch-merged/install/install.sh <<'INNEOF'
#!/bin/sh
echo "install.sh [\$*] SS_TPM_LOCKOUT=\${SS_TPM_LOCKOUT-unset} STIG=\${STIG-unset}" >> /tmp/t4/calls.log
echo "banner: preflight ok" >> /tmp/t4/calls.log
if [ "\${1:-}" = preflight ]; then exit 0; fi
echo "banner: install ok" >> /tmp/t4/calls.log
exit 0
INNEOF
printf '#!/bin/sh\necho "install-temporary.sh \$*" >> "/tmp/t4/calls.log"\n' > /tmp/t4/src/KernelPatch-merged/temporary/install-temporary.sh
tar -C /tmp/t4/src -czf /tmp/t4/secure_sudo-9.9.9.tar.gz KernelPatch-merged
: > /tmp/t4/calls.log
bash "$WRAPPER" --archive /tmp/t4/secure_sudo-9.9.9.tar.gz --dest /tmp/t4/opt --yes > /tmp/t4/out 2>&1
echo "=== WRAPPER OUT ==="
cat /tmp/t4/out
echo "=== CALLS.LOG ==="
cat /tmp/t4/calls.log
echo "=== banner lines as test sees them (sed s/^banner: //p | tr) ==="
sed -n 's/^banner: //p' /tmp/t4/calls.log | tr '\n' ' '
echo ""
echo "=== install.sh [ line (test expects 'preflight') ==="
sed -n 's/^install.sh \[//p' /tmp/t4/calls.log | head -1
