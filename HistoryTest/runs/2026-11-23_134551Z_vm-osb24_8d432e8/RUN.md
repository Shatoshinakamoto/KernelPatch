# OSB-24 nftables drop-in VM check

- **Run id:** `2026-11-23_134551Z_vm-osb24_8d432e8`
- **Area:** vm-osb24
- **Commit:** `8d432e8`
- **Date (UTC):** 2026-11-23T13:45:51+00:00
- **Where:** PC Docker container (QEMU TCG, no KVM), Ubuntu 24.04 guest
- **Verdict:** **pass**

## What was tested and why
Checks that restarting or stopping nftables.service keeps inet secure_sudo after cis-nftables.sh --apply, before and after a reboot (OSB-24 fix from PR #59).

## How
Fresh guest, install-kernel + userspace, net_mode lan-only, cis-nftables.sh --apply, then systemctl restart / stop+start with table checks run immediately after each call, SSH check, reboot, repeat.

## Results
21/21 ok

## Failures
none

## Reproduce
Same VM harness as docs/vm/results/13-pc-cis-l2-2026-11-23, on main 8d432e8 or later; reuses the 6.12.114-secure-sudo kernel build.
