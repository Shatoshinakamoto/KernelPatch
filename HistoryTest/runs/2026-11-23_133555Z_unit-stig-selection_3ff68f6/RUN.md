# tests/userspace/test-stig-selection.sh

- **Run id:** `2026-11-23_133555Z_unit-stig-selection_3ff68f6`
- **Area:** unit-stig-selection
- **Commit:** `3ff68f6`
- **Date (UTC):** 2026-11-23T13:35:55+00:00
- **Where:** cloud container (Ubuntu 24.04, root, no KVM)
- **Verdict:** **pass**

## What was tested and why
Regression suite for the HistoryTest recorder and the P3-2 STIG/CIS work, run before merging.

## How
`timeout 300 bash tests/userspace/test-stig-selection.sh` (exit code 0).

## Results
23 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `3ff68f6`:

```
timeout 300 bash tests/userspace/test-stig-selection.sh
```
