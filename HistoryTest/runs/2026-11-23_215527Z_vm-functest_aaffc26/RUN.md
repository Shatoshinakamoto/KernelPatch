# 6.12.114 boot + ss-functest (E2BIG lists)

- **Run id:** `2026-11-23_215527Z_vm-functest_aaffc26`
- **Area:** vm-functest
- **Commit:** `aaffc26`
- **Date (UTC):** 2026-11-23T21:55:27+00:00
- **Where:** Pheonix's PC, Docker container on WSL2, QEMU TCG (no KVM)
- **Verdict:** **pass**

## What was tested and why
In-kernel functional tests on a 6.12.114 kernel built with the over-long-list fix, including t_list_limits

## How
tests/vm/build-test-kernel.sh, then tests/vm/boot-test.sh

## Results
305 ok, 0 not ok; t_list_limits 32/32; no kernel problems

## Failures
none

## Reproduce
On the PC: tests/vm/build-test-kernel.sh and tests/vm/boot-test.sh on branch kernel/policy-list-e2big
