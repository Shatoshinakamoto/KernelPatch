# PC build gate (twice, as root)

- **Run id:** `2026-11-23_213828Z_gate_4b5474f`
- **Area:** gate
- **Commit:** `4b5474f`
- **Date (UTC):** 2026-11-23T21:38:28+00:00
- **Where:** Pheonix's PC, Docker container on WSL2 (QEMU TCG for VM stages)
- **Verdict:** **fail**

## What was tested and why
Full local release gate on main after #60/#61, run twice for reproducibility

## How
ci/build-gate.sh as root, SS_REQUIRE_SWTPM=1, all stages, --kernel-tree = signature-verified 6.12.114

## Results
lint, userspace, addons, lsm-tree (6 variants) and package pass; lsm-headers skip (only 6.8 headers); tests 1 failing; package and tree hash identical across both runs

## Failures
test-cis-firewall.sh check 8 fails only as root from a 0700 copy (test bug, not product code); fixed in commit d457f1f

## Reproduce
On the PC: ci/build-gate.sh as root with the same options on 4b5474f
