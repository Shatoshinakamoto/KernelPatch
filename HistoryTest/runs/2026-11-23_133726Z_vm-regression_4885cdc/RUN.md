# VM regression, main 4885cdc

- **Run id:** `2026-11-23_133726Z_vm-regression_4885cdc`
- **Area:** vm-regression
- **Commit:** `4885cdc`
- **Date (UTC):** 2026-11-23T07:55:00+00:00
- **Where:** owner PC (Docker, QEMU TCG)
- **Verdict:** **pass**

## What was tested and why
Release VM gate on the current main: kernel build, install, STIG release gate and add-on units.

## How
See command.txt.

## Results
build-kernel 6.12.114: OK (08:01Z)
run-install-test.sh: 71/71 ok (08:01-08:37Z)
run-stig-test.sh: 16/16 ok, gate pass: pass=214 fail=3 (all allowed: encrypt_partitions, is_fips_mode_enabled, service_sssd_enabled) error=0 notapplicable=8 notchecked=5 (08:38-10:08Z)
run-addon-units-test.sh: 22/22 ok (finished 10:50:42Z, rc=0)

## Failures
None. BootGuard BIOS/UEFI not rerun (owner's call; unchanged since b90ca80, where both were 18/18).

## Reproduce
On the owner's PC (kp-vm), main 4885cdc, tests/vm/distro:
  build-kernel 6.12.114 (kernel.org signature verified)
  bash run-install-test.sh   (VM_TPM=1)
  bash run-stig-test.sh      (SSG 0.1.78, datastream pinned by sha256)
  bash run-addon-units-test.sh
  (BootGuard BIOS/UEFI dropped at the owner's request: passed 18/18 and 18/18 on b90ca80, unchanged since)
