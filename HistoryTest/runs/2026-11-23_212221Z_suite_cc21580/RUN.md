# tests/run-all.sh

- **Run id:** `2026-11-23_212221Z_suite_cc21580`
- **Area:** suite
- **Commit:** `cc21580`
- **Date (UTC):** 2026-11-23T21:22:21+00:00
- **Where:** cloud container (Ubuntu); this sandbox puts a refusing rm wrapper first in PATH
- **Verdict:** **fail**

## What was tested and why
the whole non-VM test suite after the lint and docs changes

## How
`bash tests/run-all.sh` (exit code 1).

## Results
1349 ok, 2 not ok, 6 skipped (TAP lines in logs/stdout.log).

## Failures
- `not ok 52 - quar: without zip falls back to tar.gz (got '127', want '0')`
- `not ok 54 - quar: tar fallback removed the original`

## Reproduce
From the repository root at commit `cc21580`:

```
bash tests/run-all.sh
```
