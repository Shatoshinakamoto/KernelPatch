# gate lint on merge of main

- **Run id:** `2026-11-24_103222Z_gate-lint_db69a49`
- **Area:** gate-lint
- **Commit:** `db69a49`
- **Date (UTC):** 2026-11-24T10:32:22+00:00
- **Where:** local
- **Verdict:** **pass**

## What was tested and why
See the command.

## How
`bash ci/build-gate.sh --stages lint` (exit code 0).

## Results
1 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `db69a49`:

```
bash ci/build-gate.sh --stages lint
```
