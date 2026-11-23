# tests/userspace/test-history-test.sh

- **Run id:** `2026-11-23_133545Z_unit-history-test_3ff68f6`
- **Area:** unit-history-test
- **Commit:** `3ff68f6`
- **Date (UTC):** 2026-11-23T13:35:45+00:00
- **Where:** cloud container (Ubuntu 24.04, root, no KVM)
- **Verdict:** **pass**

## What was tested and why
Regression suite for the HistoryTest recorder and the P3-2 STIG/CIS work, run before merging.

## How
`timeout 300 bash tests/userspace/test-history-test.sh` (exit code 0).

## Results
44 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `3ff68f6`:

```
timeout 300 bash tests/userspace/test-history-test.sh
```
