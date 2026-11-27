# modprobe test suite

- **Run id:** `2026-11-27_092117Z_modprobe_a5f2f77`
- **Area:** modprobe
- **Commit:** `a5f2f77`
- **Date (UTC):** 2026-11-27T00:00:00
- **Where:** owner PC (Docker container, root)
- **Verdict:** **pass**

## What was tested and why
tests/install/test-ubuntu-modprobe.sh - Ubuntu modprobe-compatible install (Method 7)

## How
See command.txt.

## Results
/proc/2077/fd/63

## Failures
None.

## Reproduce
From the repository root at commit a5f2f77: bash tests/install/test-ubuntu-modprobe.sh
