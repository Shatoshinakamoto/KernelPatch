# all host-side suites

- **Run id:** `2026-11-24_093100Z_suite_3c5c375`
- **Area:** suite
- **Commit:** `3c5c375`
- **Date (UTC):** 2026-11-24T09:31:00+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **fail**

## What was tested and why
tests/run-all.sh after the docs pages, the command-docs check and the NOTICE rename. Known sandbox-only failures: test-helpers.sh 52 and 54 (rm-guard wrapper).

## How
`bash tests/run-all.sh` (exit code 1).

## Results
1382 ok, 2 not ok, 6 skipped (TAP lines in logs/stdout.log).

## Failures
- `not ok 52 - quar: without zip falls back to tar.gz (got '127', want '0')`
- `not ok 54 - quar: tar fallback removed the original`

## Reproduce
From the repository root at commit `3c5c375`:

```
bash tests/run-all.sh
```
