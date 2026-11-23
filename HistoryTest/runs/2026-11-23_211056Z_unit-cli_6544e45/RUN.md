# test-cli.sh

- **Run id:** `2026-11-23_211056Z_unit-cli_6544e45`
- **Area:** unit-cli
- **Commit:** `6544e45`
- **Date (UTC):** 2026-11-23T21:10:56+00:00
- **Where:** cloud container (Ubuntu), no root kernel
- **Verdict:** **pass**

## What was tested and why
tests/userspace/test-cli.sh after the docs/configuration change

## How
`bash tests/userspace/test-cli.sh` (exit code 0).

## Results
169 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `6544e45`:

```
bash tests/userspace/test-cli.sh
```
