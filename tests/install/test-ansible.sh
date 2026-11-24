#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-ansible.sh - checks for the Ansible playbook and role in
# install/ansible/: it parses, runs its steps in the safe order (preflight
# before the kernel, the trial boot before the commit), rolls out one host at
# a time and stops at the first failure, refuses bad variable values before
# touching a host, never builds shell strings, ships no active host in its
# example inventory, and keeps an operator's inventory out of the release.
#
# Static checks need nothing. The ansible-playbook checks are skipped when
# Ansible is not installed; they never contact or change a host (syntax check,
# task listing, and the validation tasks alone against an inventory host that
# uses the local connection with every other task skipped).
# The real rollout is exercised in a VM (docs/INSTALL.md, "Tested").
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
A="$ROOT/install/ansible"
R="$A/roles/secure_sudo"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# ------------------------------------------------------------ static checks
check "the playbook and every role file exist" test -f "$A/secure_sudo.yml" -a -f "$R/tasks/main.yml" -a -f "$R/defaults/main.yml" -a -f "$R/handlers/main.yml"
refute "the role never uses the shell module (no shell strings, CWE-78)" grep -rqE 'ansible\.builtin\.shell|^\s*shell:|^\s*raw:' "$A/roles" "$A/secure_sudo.yml"
refute "no install step hides its failure (failed_when: false only on read-only checks)" \
	grep -lE 'failed_when: false' "$R/tasks/install.yml" "$R/tasks/trial_boot.yml"
check "the play rolls out one host at a time by default" grep -qE 'serial: "\{\{ secure_sudo_serial \| default\(1\) \}\}"' "$A/secure_sudo.yml"
check "the play stops at the first failed host" grep -qx '  max_fail_percentage: 0' "$A/secure_sudo.yml"
refute "the example inventory lists no active host" grep -vE '^\s*(#|$|\[)' "$A/inventory.ini.example"
refute "the example inventory never targets the controller" grep -qE '^[^#]*ansible_connection=local' "$A/inventory.ini.example"
check "the role checks the archive's SHA-256 on the target before unpacking" \
	awk '/Refuse an archive whose hash/ {a=NR} /Unpack the verified archive/ {u=NR} END {exit !(a && u && a < u)}' "$R/tasks/source.yml"
check "main.yml: preflight/install comes before the trial boot" \
	awk '/install.yml/ {i=NR} /trial_boot.yml/ {t=NR} END {exit !(i && t && i < t)}' "$R/tasks/main.yml"
check "install.yml: preflight comes before the kernel install" \
	awk "/name: Preflight \(changes nothing\)/ {p=NR} /ss_install }}\", install-kernel,/ {k=NR} END {exit !(p && k && p < k)}" "$R/tasks/install.yml"
check "trial_boot.yml: reboot, then the kernel check, then verify --commit" \
	awk '/ansible.builtin.reboot/ {r=NR} /came back on another kernel/ {c=NR} /verify, --commit/ {m=NR} END {exit !(r && c && m && r < c && c < m)}' "$R/tasks/trial_boot.yml"
check "the TPM lockout password is never set by the role (it would land in logs)" grep -q "SS_TPM_LOCKOUT': '0'" "$R/tasks/install.yml"
check "every variable in defaults is documented" bash -c '
	for v in $(grep -oE "^secure_sudo_[a-z0-9_]+" "'"$R"'/defaults/main.yml"); do
		grep -q "\`$v\`" "'"$ROOT"'/docs/configuration/ansible-vars.md" || { echo "undocumented: $v"; exit 1; }
	done'

# An operator's inventory names real hosts: never part of a release (CWE-200).
cp -a "$ROOT" "$T/tree" 2>/dev/null || cp -r "$ROOT" "$T/tree"
before="$(bash "$T/tree/scripts/gen-sbom.sh" --tree-hash)"
printf '[secure_sudo]\nprod-db1 ansible_host=192.0.2.50\n' > "$T/tree/install/ansible/inventory.ini"
mkdir -p "$T/tree/install/ansible/host_vars"; echo 'x: 1' > "$T/tree/install/ansible/host_vars/prod-db1.yml"
echo 'secure_sudo_net_mode: host' > "$T/tree/install/ansible/group_vars/secure_sudo.yml"
after="$(bash "$T/tree/scripts/gen-sbom.sh" --tree-hash)"
eq "an operator's inventory, group_vars and host_vars do not change the tree hash" "$after" "$before"
refute "... and are not listed as release sources" sh -c "bash '$T/tree/scripts/gen-sbom.sh' --list | grep -qE 'inventory\.ini$|host_vars/|group_vars/secure_sudo\.yml$'"

# ----------------------------------------------------- ansible-playbook checks
if ! command -v ansible-playbook >/dev/null 2>&1; then
	skip "ansible-playbook checks need ansible-core (apt install ansible-core)"
	tap_done; exit $?
fi
export ANSIBLE_NOCOLOR=1 ANSIBLE_RETRY_FILES_ENABLED=0 ANSIBLE_LOCAL_TEMP="$T/ans-local" ANSIBLE_REMOTE_TEMP="$T/ans-remote"
INV="$T/inv.ini"
printf '[secure_sudo]\nself ansible_connection=local ansible_python_interpreter=%s\n' "$(command -v python3)" > "$INV"
check "the playbook passes ansible-playbook --syntax-check" ansible-playbook -i "$INV" --syntax-check "$A/secure_sudo.yml"
ansible-playbook -i "$INV" --list-tasks "$A/secure_sudo.yml" > "$T/tasks" 2>&1
check "the task list names the trial boot and commit" grep -q 'Verify on the new kernel and commit it' "$T/tasks"

# Only the validation tasks: everything else (including "always") is skipped,
# and become is off, so this changes nothing on the machine running the test.
V=(ansible-playbook -i "$INV" "$A/secure_sudo.yml" --tags validate --skip-tags always -e ansible_become=false)
check "valid settings pass the validation" "${V[@]}"
refute "an unknown net_mode is refused before any host is touched" "${V[@]}" -e secure_sudo_net_mode=open
refute "a relative remote dir is refused" "${V[@]}" -e secure_sudo_remote_dir=opt/ss
refute "a remote dir with '..' is refused" "${V[@]}" -e secure_sudo_remote_dir=/opt/../etc
refute "source=archive without a SHA-256 is refused" "${V[@]}" -e secure_sudo_source=archive -e secure_sudo_archive=/x.tar.gz
refute "kernel=prebuilt without a directory is refused" "${V[@]}" -e secure_sudo_kernel=prebuilt
refute "add-on initramfs without the add-ons is refused" "${V[@]}" -e secure_sudo_addons_initramfs=true
refute "a malformed kver is refused" "${V[@]}" -e 'secure_sudo_kver=6.12;reboot'

tap_done
