# build-gate lint stage

- **Run id:** `2026-11-23_213450Z_gate-lint_4b76813`
- **Area:** gate-lint
- **Commit:** `4b76813`
- **Date (UTC):** 2026-11-23T21:34:50+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **pass**

## What was tested and why
ci/build-gate.sh --stages lint with the add-on doc checks

## How
`bash ci/build-gate.sh --stages lint` (exit code 0).

## Results
1 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `4b76813`:

```
bash ci/build-gate.sh --stages lint
```
