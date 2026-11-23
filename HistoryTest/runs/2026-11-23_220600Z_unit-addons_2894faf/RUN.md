# add-on guardrail suite with libssl linked

- **Run id:** `2026-11-23_220600Z_unit-addons_2894faf`
- **Area:** unit-addons
- **Commit:** `2894faf`
- **Date (UTC):** 2026-11-23T22:06:00+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **pass**

## What was tested and why
test-addons.sh after the add-ons started linking ssaddon_tls.c and libssl.

## How
`bash tests/userspace/test-addons.sh` (exit code 0).

## Results
163 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `2894faf`:

```
bash tests/userspace/test-addons.sh
```
