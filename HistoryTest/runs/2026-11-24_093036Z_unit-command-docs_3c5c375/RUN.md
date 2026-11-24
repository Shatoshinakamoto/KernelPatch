# command and feature page check

- **Run id:** `2026-11-24_093036Z_unit-command-docs_3c5c375`
- **Area:** unit-command-docs
- **Commit:** `3c5c375`
- **Date (UTC):** 2026-11-24T09:30:36+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **pass**

## What was tested and why
New ci/check-command-docs.py: passes on the repo and fails on each kind of drift.

## How
`bash tests/userspace/test-command-docs.sh` (exit code 0).

## Results
8 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `3c5c375`:

```
bash tests/userspace/test-command-docs.sh
```
