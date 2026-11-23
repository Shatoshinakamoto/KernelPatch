# tests/userspace/test-history-test.sh (after the id-order fix)

- **Run id:** `2026-11-23_133728Z_unit-history-test_3ff68f6`
- **Area:** unit-history-test
- **Commit:** `3ff68f6`
- **Date (UTC):** 2026-11-23T13:37:27+00:00
- **Where:** cloud container (Ubuntu 24.04, root, no KVM)
- **Verdict:** **pass**

## What was tested and why
Recorder suite after making run ids sort in archive order.

## How
`bash tests/userspace/test-history-test.sh` (exit code 0).

## Results
45 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `3ff68f6`:

```
bash tests/userspace/test-history-test.sh
```
