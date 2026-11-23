# test-cli.sh (lint list checks)

- **Run id:** `2026-11-23_212209Z_unit-cli_cc21580`
- **Area:** unit-cli
- **Commit:** `cc21580`
- **Date (UTC):** 2026-11-23T21:22:09+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **pass**

## What was tested and why
tests/userspace/test-cli.sh with the new list-limit and TimeVault grammar lint checks

## How
`bash tests/userspace/test-cli.sh` (exit code 0).

## Results
180 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `cc21580`:

```
bash tests/userspace/test-cli.sh
```
