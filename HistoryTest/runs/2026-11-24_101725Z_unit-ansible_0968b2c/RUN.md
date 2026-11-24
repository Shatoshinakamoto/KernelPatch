# Ansible role checks (ansible-core 2.16.3)

- **Run id:** `2026-11-24_101725Z_unit-ansible_0968b2c`
- **Area:** unit-ansible
- **Commit:** `0968b2c`
- **Date (UTC):** 2026-11-24T10:48:00+00:00
- **Where:** owner PC (Docker container)
- **Verdict:** **pass**

## What was tested and why
install/ansible: step order, one host at a time, stop at the first failure, validation of every variable, no shell module, example inventory has no host, operator inventory kept out of the tree hash; ansible-playbook syntax check and validation-only runs.

## How
See command.txt.

## Results
ok 1 - the playbook and every role file exist
ok 2 - the role never uses the shell module (no shell strings, CWE-78)
ok 3 - no install step hides its failure (failed_when: false only on read-only checks)
ok 4 - the play rolls out one host at a time by default
ok 5 - the play stops at the first failed host
ok 6 - the example inventory lists no active host
ok 7 - the example inventory never targets the controller
ok 8 - the role checks the archive's SHA-256 on the target before unpacking
ok 9 - main.yml: preflight/install comes before the trial boot
ok 10 - install.yml: preflight comes before the kernel install
ok 11 - trial_boot.yml: reboot, then the kernel check, then verify --commit
ok 12 - the TPM lockout password is never set by the role (it would land in logs)
ok 13 - every variable in defaults is documented
ok 14 - an operator's inventory, group_vars and host_vars do not change the tree hash
ok 15 - ... and are not listed as release sources
ok 16 - the playbook passes ansible-playbook --syntax-check
ok 17 - the task list names the trial boot and commit
ok 18 - valid settings pass the validation
ok 19 - an unknown net_mode is refused before any host is touched
ok 20 - a relative remote dir is refused
ok 21 - a remote dir with '..' is refused
ok 22 - source=archive without a SHA-256 is refused
ok 23 - kernel=prebuilt without a directory is refused
ok 24 - add-on initramfs without the add-ons is refused
ok 25 - a malformed kver is refused
1..25

## Failures
None.

## Reproduce
See command.txt.
