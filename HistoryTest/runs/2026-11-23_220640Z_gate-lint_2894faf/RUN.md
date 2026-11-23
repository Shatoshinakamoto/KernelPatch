# build-gate lint stage

- **Run id:** `2026-11-23_220640Z_gate-lint_2894faf`
- **Area:** gate-lint
- **Commit:** `2894faf`
- **Date (UTC):** 2026-11-23T22:06:40+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **pass**

## What was tested and why
lint stage after add-on TLS log shipping (check-config-docs covers the new logging.conf keys)

## How
`bash ci/build-gate.sh --stages lint` (exit code 0).

## Results
1 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `2894faf`:

```
bash ci/build-gate.sh --stages lint
```
