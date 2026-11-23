# test-config-docs.sh

- **Run id:** `2026-11-23_211054Z_unit-config-docs_6544e45`
- **Area:** unit-config-docs
- **Commit:** `6544e45`
- **Date (UTC):** 2026-11-23T21:10:54+00:00
- **Where:** cloud container (Ubuntu), no root kernel
- **Verdict:** **pass**

## What was tested and why
tests/userspace/test-config-docs.sh after the docs/configuration change

## How
`bash tests/userspace/test-config-docs.sh` (exit code 0).

## Results
14 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `6544e45`:

```
bash tests/userspace/test-config-docs.sh
```
