# build-gate lint stage

- **Run id:** `2026-11-23_214119Z_gate-lint_e82717f`
- **Area:** gate-lint
- **Commit:** `e82717f`
- **Date (UTC):** 2026-11-23T21:41:19+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **pass**

## What was tested and why
lint stage after the kernel E2BIG change

## How
`bash ci/build-gate.sh --stages lint` (exit code 0).

## Results
1 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `e82717f`:

```
bash ci/build-gate.sh --stages lint
```
