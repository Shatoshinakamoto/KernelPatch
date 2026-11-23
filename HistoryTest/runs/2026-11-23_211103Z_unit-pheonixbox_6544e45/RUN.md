# test-pheonixbox.sh

- **Run id:** `2026-11-23_211103Z_unit-pheonixbox_6544e45`
- **Area:** unit-pheonixbox
- **Commit:** `6544e45`
- **Date (UTC):** 2026-11-23T21:11:03+00:00
- **Where:** cloud container (Ubuntu), no root kernel
- **Verdict:** **pass**

## What was tested and why
tests/userspace/test-pheonixbox.sh after the docs/configuration change

## How
`bash tests/userspace/test-pheonixbox.sh` (exit code 0).

## Results
61 ok, 0 not ok, 2 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `6544e45`:

```
bash tests/userspace/test-pheonixbox.sh
```
