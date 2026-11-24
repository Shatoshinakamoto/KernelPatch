# Ansible role and quick-install on a fresh Ubuntu 24.04 VM

- **Run id:** `2026-11-24_101726Z_vm-ansible_0968b2c`
- **Area:** vm-ansible
- **Commit:** `0968b2c`
- **Date (UTC):** 2026-11-24T10:05:00+00:00
- **Where:** owner PC (Docker, QEMU TCG)
- **Verdict:** **partial**

## What was tested and why
The Ansible role install/ansible/roles/secure_sudo and install/quick-install.sh, end to end on a fresh Ubuntu 24.04 cloud-image guest, before they are merged (owner's request: installation methods proven before the final merge). The kernel is prebuilt once on a "build host" from this tree (6.12.114, signature-verified source) and installed by the role, which then reboots into the trial boot, checks the kernel, commits, sets net_mode and loads the policy. A second run must leave the committed host alone.

## How
See command.txt.

## Results
ok 1 - build host: kernel package built from this tree
ok 2 - build host: userspace staged
ok 3 - fresh guest boots
ok 4 - ansible-playbook run 1 (install, trial boot, commit, config) succeeds
# run 1 recap: guest                      : ok=43   changed=12   unreachable=0    failed=0    skipped=12   rescued=0    ignored=0   
ok 5 - the guest runs the secure_sudo kernel after the role
ok 6 - secure_sudo is an active LSM
ok 7 - secure-sudod is active
ok 8 - install.sh verify: OK and the kernel is committed
ok 9 - run 1 went through the trial reboot and the commit task
ok 10 - ansible-playbook run 2 succeeds
# run 2 recap: guest                      : ok=25   changed=3    unreachable=0    failed=0    skipped=30   rescued=0    ignored=0   
not ok 11 - run 2 sees the committed kernel and skips install and reboot (idempotent)
ok 12 - quick-install.sh --dry-run on the guest: archive verified, preflight passes
# quick-install: SHA-256 ok: cac4361547ce75578b532da7ca9280988ecf56901213354779a1ad3693e13990
# preflight: OK
# quick-install: dry run: verification and preflight passed; nothing was changed.
ok 13 - ... and --dry-run changed nothing (/opt/qi not created)
ok 14 - quick-install.sh refuses a tampered archive on the guest
1..14
0
1

## Failures
not ok 11 ("run 2 ... skips install and reboot") is a fault in the driver's check, not in the role: the check required that the text "TASK [secure_sudo : Reboot into the new kernel" not appear in run 2's log, but Ansible prints the header of a skipped task too. The log shows the task as "skipping: [guest]" and the state message above, so run 2 was idempotent. A first attempt on the same day (not archived separately) found a real role bug that this run proves fixed: with a prebuilt kernel the role ran the full "install.sh preflight", which blocked on the 20 GB kernel build space a prebuilt install does not need; the role now runs only "preflight install-kernel" and "preflight userspace --prebuilt DIR" (and "build-kernel" when building).

## Reproduce
On Linux with QEMU (KVM optional) and ansible-core 2.14+: build the kernel and stage userspace as in A, start a guest with tests/vm/distro/vm.sh up (VM_DISK=40G), point install/ansible/inventory.ini at it (root over SSH with the guest key), set the group_vars above, and run ansible-playbook -i inventory.ini secure_sudo.yml twice. The tree differs from the commit only in docs/INSTALL.md's "Tested" table (VM-run tree hash 21786aa735653bb6c4530e7b8107d34f441496352f7a5ca0859d363178c6921e).
