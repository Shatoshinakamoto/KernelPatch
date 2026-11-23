# build-gate lint stage

- **Run id:** `2026-11-23_213003Z_gate-lint_cc21580`
- **Area:** gate-lint
- **Commit:** `cc21580`
- **Date (UTC):** 2026-11-23T21:30:03+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **pass**

## What was tested and why
ci/build-gate.sh --stages lint with the extended check-config-docs.py

## How
`bash ci/build-gate.sh --stages lint` (exit code 0).

## Results
1 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `cc21580`:

```
bash ci/build-gate.sh --stages lint
```
