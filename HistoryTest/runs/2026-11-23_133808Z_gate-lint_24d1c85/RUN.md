# ci/build-gate.sh --stages lint (includes history_test.py verify)

- **Run id:** `2026-11-23_133808Z_gate-lint_24d1c85`
- **Area:** gate-lint
- **Commit:** `24d1c85`
- **Date (UTC):** 2026-11-23T13:38:08+00:00
- **Where:** cloud container (Ubuntu 24.04, root, no KVM)
- **Verdict:** **pass**

## What was tested and why
The gate's lint stage with the new HistoryTest integrity check, before merging the recorder.

## How
`bash ci/build-gate.sh --stages lint --record /tmp/rl2.txt` (exit code 0).

## Results
1 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `24d1c85`:

```
bash ci/build-gate.sh --stages lint --record /tmp/rl2.txt
```
