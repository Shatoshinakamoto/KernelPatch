# PC build gate (as root)

- **Run id:** `2026-11-23_224258Z_gate_20f89d5`
- **Area:** gate
- **Commit:** `20f89d5`
- **Date (UTC):** 2026-11-23T22:42:58+00:00
- **Where:** Pheonix's PC, Docker container on WSL2
- **Verdict:** **pass**

## What was tested and why
Full local release gate on the add-on TLS log shipping branch (PR 67)

## How
ci/build-gate.sh as root, SS_REQUIRE_SWTPM=1, all stages, verified 6.12.114 tree

## Results
overall=pass, tests 1423 checks, 0 not ok; test-addon-log-tls 20/20; lsm-headers skip (only 6.8 headers)

## Failures
none

## Reproduce
On the PC: ci/build-gate.sh with the same options on 20f89d5
