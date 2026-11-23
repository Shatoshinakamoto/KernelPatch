# all host-side suites

- **Run id:** `2026-11-23_220703Z_suite_2894faf`
- **Area:** suite
- **Commit:** `2894faf`
- **Date (UTC):** 2026-11-23T22:07:03+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **fail**

## What was tested and why
tests/run-all.sh after add-on TLS log shipping. Known sandbox-only failures: test-helpers.sh 52 and 54 (harness rm-guard wrapper first in PATH; also on main).

## How
`bash tests/run-all.sh` (exit code 1).

## Results
1374 ok, 2 not ok, 6 skipped (TAP lines in logs/stdout.log).

## Failures
- `not ok 52 - quar: without zip falls back to tar.gz (got '127', want '0')`
- `not ok 54 - quar: tar fallback removed the original`

## Reproduce
From the repository root at commit `2894faf`:

```
bash tests/run-all.sh
```
