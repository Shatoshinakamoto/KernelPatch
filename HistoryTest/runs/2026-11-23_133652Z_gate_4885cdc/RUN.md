# Build gate, run twice, main 4885cdc

- **Run id:** `2026-11-23_133652Z_gate_4885cdc`
- **Area:** gate
- **Commit:** `4885cdc`
- **Date (UTC):** 2026-11-23T03:44:30+00:00
- **Where:** owner PC (Docker, kp-vm)
- **Verdict:** **pass**

## What was tested and why
Full build gate twice on the same commit, to prove the PR #54 fix: the recorded source tree hash and the package hash must be identical across runs and equal the clean checkout.

## How
See command.txt.

## Results
Run 1 03:44:30-03:48:45Z, run 2 03:48:45-03:53:05Z. Records identical apart from date.
source_tree_sha256 = b431477fa4ea8fcf83dbbec8a8e38d65eb3e41269b008a6359d49305557e44c3 in both runs,
equal to scripts/gen-sbom.sh --tree-hash on the clean checkout before and after.
Package sha256 8b621c9599a4841e (both runs).
stage_lint=pass (63 shell scripts)
stage_userspace=pass (6 components, -Werror)
stage_addons=pass (7 components, -Werror)
stage_lsm-headers=skip (no supported kernel headers installed; unsupported, not compiled: 6.8.0)
stage_lsm-tree=pass (6.12.114, 6 variants)
stage_tests=pass (1255 checks)
stage_package=pass (reproducible, sha256 8b621c9599a4841e)
overall=pass
kernel_variant_config_sha256 default 50aa43e6711974dfcea6851b6299dde536d22b93ed0f7fd352069d726d222222
kernel_variant_config_sha256 modsig 1eadf83f327a15e351622776d82d1e782d3116e03aeb4fd1f396375ab145d1df
kernel_variant_config_sha256 no-audit a9ee7d25d281378bd4dfc9a7321057da34b922ce296b552f664df3517abe2d16
kernel_variant_config_sha256 no-bpf df735b7ef76c915ff50e0b0f9085301e481e19cc8b01d096595d02a7adaeb2b4
kernel_variant_config_sha256 no-modules f9cd2c6a30d1ad267a43fbca19b97fba010c99b3c40d9ba4e493862f6c60f2e0
kernel_variant_config_sha256 stack-apparmor 7b5041dd0cbcfd8ee8226699f6b9f9870c10259f059bfbf98524b782ab2a6e03
host=ubuntu 24.04 x86_64; cc=gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0; make=GNU Make 4.3; shellcheck=0.9.0

## Failures
None. lsm-headers was a skip, not a pass: the PC only has Ubuntu 6.8 headers, which are unsupported.

## Reproduce
On the owner's PC, Docker container kp-vm, as root, clean checkout of main 4885cdc,
all gate-job packages installed, kernel tree = fresh extract of the
signature-verified linux-6.12.114 tarball (sha256 7a858991...4af3):
  SS_REQUIRE_SWTPM=1 bash ci/build-gate.sh --kernel-tree <extract>/linux-6.12.114   (run 1)
  the same again                                                                  (run 2)
  bash scripts/gen-sbom.sh --tree-hash   (before and after both runs)
