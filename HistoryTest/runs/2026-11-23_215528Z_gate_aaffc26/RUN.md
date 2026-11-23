# PC build gate (as root)

- **Run id:** `2026-11-23_215528Z_gate_aaffc26`
- **Area:** gate
- **Commit:** `aaffc26`
- **Date (UTC):** 2026-11-23T21:55:27+00:00
- **Where:** Pheonix's PC, Docker container on WSL2, QEMU TCG (no KVM)
- **Verdict:** **pass**

## What was tested and why
Full local release gate on the E2BIG branch

## How
ci/build-gate.sh as root, SS_REQUIRE_SWTPM=1, all stages, verified 6.12.114 tree

## Results
overall=pass, tests 1403 checks; lsm-headers skip (only 6.8 headers)

## Failures
none

## Reproduce
On the PC: ci/build-gate.sh with the same options on aaffc26
