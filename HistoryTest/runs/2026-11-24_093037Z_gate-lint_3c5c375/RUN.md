# build-gate lint stage

- **Run id:** `2026-11-24_093037Z_gate-lint_3c5c375`
- **Area:** gate-lint
- **Commit:** `3c5c375`
- **Date (UTC):** 2026-11-24T09:30:36+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **pass**

## What was tested and why
lint stage with the new command-docs check, after splitting COMMANDS.md and SCRIPTS.md into pages and adding docs/features/

## How
`bash ci/build-gate.sh --stages lint` (exit code 0).

## Results
1 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `3c5c375`:

```
bash ci/build-gate.sh --stages lint
```
