# modprobe test suite

- **Run id:** `2026-11-27_091614Z_modprobe_a5f2f77`
- **Area:** modprobe
- **Commit:** `a5f2f77`
- **Date (UTC):** 2026-11-27T09:16:14+00:00
- **Where:** owner PC (Docker container, root)
- **Verdict:** **fail**

## What was tested and why
tests/install/test-ubuntu-modprobe.sh — Ubuntu modprobe-compatible install (Method 7)

## How
`timeout 300 bash tests/install/test-ubuntu-modprobe.sh` (exit code 1).

## Results
0 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `a5f2f77`:

```
timeout 300 bash tests/install/test-ubuntu-modprobe.sh
```
