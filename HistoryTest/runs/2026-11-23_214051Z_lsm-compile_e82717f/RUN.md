# lsm-compile-check against 6.14.0-37 headers

- **Run id:** `2026-11-23_214051Z_lsm-compile_e82717f`
- **Area:** lsm-compile
- **Commit:** `e82717f`
- **Date (UTC):** 2026-11-23T21:40:51+00:00
- **Where:** cloud container (Ubuntu), linux-headers-6.14.0-37-generic from the Ubuntu archive
- **Verdict:** **pass**

## What was tested and why
Compile every LSM file with -Werror against distro headers after the E2BIG change

## How
`bash ci/lsm-compile-check.sh /usr/src/linux-headers-6.14.0-37-generic` (exit code 0).

## Results
0 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `e82717f`:

```
bash ci/lsm-compile-check.sh /usr/src/linux-headers-6.14.0-37-generic
```
