# build-gate lint stage

- **Run id:** `2026-11-23_211112Z_gate-lint_6544e45`
- **Area:** gate-lint
- **Commit:** `6544e45`
- **Date (UTC):** 2026-11-23T21:11:12+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **pass**

## What was tested and why
ci/build-gate.sh --stages lint, including the new check-config-docs.py

## How
`bash ci/build-gate.sh --stages lint` (exit code 0).

## Results
1 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `6544e45`:

```
bash ci/build-gate.sh --stages lint
```
