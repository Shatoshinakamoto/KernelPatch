# test-cis-firewall.sh as root from a 0700 copy

- **Run id:** `2026-11-23_213829Z_unit-cis-firewall_d457f1f`
- **Area:** unit-cis-firewall
- **Commit:** `d457f1f`
- **Date (UTC):** 2026-11-23T21:38:29+00:00
- **Where:** cloud container (Ubuntu), as root
- **Verdict:** **pass**

## What was tested and why
Reproduces the gate condition (root, tree copied into a 0700 mktemp dir) with the fixed test

## How
`bash /tmp/tmp.Z7NlkUZhma/src/tests/userspace/test-cis-firewall.sh` (exit code 0).

## Results
29 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `d457f1f`:

```
bash /tmp/tmp.Z7NlkUZhma/src/tests/userspace/test-cis-firewall.sh
```
