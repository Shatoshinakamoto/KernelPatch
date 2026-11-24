# Compatibility and release-support matrix (TODO P3-1)

Release: 0.12.0
Matrix reviewed: 2026-11-24

What the project builds and tests, and what it only expects to work. Every row
says one of:

* **tested**: a recorded run, with its date and what was run. The evidence is
  named so it can be repeated.
* **compile-checked**: the LSM compiles against that kernel's headers or tree.
  Nothing was booted.
* **expected**: code for it exists (a shim, an installer branch) but no run is
  recorded. Do not rely on it.
* **unsupported**: refused by the installer or known not to work.

"Tested" never means "tested on hardware" unless the row says so. All VM runs
are QEMU, mostly without KVM (software emulation) on the owner's PC; the project does
not use GitHub Actions, so the dates below are from local and PC runs. See
[ROADMAP_STATUS.md](ROADMAP_STATUS.md) for the full evidence per item.

## 1. Kernels

| Kernel | Status | Evidence |
|---|---|---|
| 6.12.114 (LTS, the target) | tested | built in-tree from the signature-verified kernel.org tarball in six configs (`ci/kconfig`); booted: in-kernel checks 305/0 (PC, 2026-11-23, `HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`), install test 71/71, STIG release gate 16/16 and add-on units 22/22 (PC, 2026-11-23, main 4885cdc), BootGuard initramfs 18/18 BIOS and UEFI (PC, 2026-11-22) |
| 6.14 (Ubuntu 6.14 source) | tested | install/trial/fallback run and in-kernel checks 246/246 (2026-11-01) |
| 6.11, 6.17 | compile-checked | `ci/lsm-compile-check.sh` against distro header trees, 21/21 files (2026-11-15) |
| 7.0 (a GitHub runner kernel) | compile-checked | build gate against the runner's headers (CI, 2026-10-31) |
| 6.16, 6.18, 6.19 | expected | API shims in `secure_sudo.h` (bpf hook argument, `sha256_ctx`, `clone_flags`, `lsm_info.id`); no recorded compile |
| older than 6.11 | unsupported | not built or tested |

Required kernel options: `CONFIG_SECURITY`, `CONFIG_SECURITYFS`,
`CONFIG_SECURITY_NETWORK`, `CONFIG_SECURITY_PATH` (selected by
`CONFIG_SECURITY_SECURE_SUDO`), `CONFIG_CRYPTO_LIB_SHA256`, and `secure_sudo`
in `CONFIG_LSM`. Optional paths that compile out cleanly (each checked in
`ci/kconfig`): no audit, no BPF, no modules, module signing, AppArmor stacked
first. `CONFIG_TCG_TPM` is needed for the TPM guard and policy measurement
(`CONFIG_SECURITY_SECURE_SUDO_MEASURE_PCR`, default PCR 13).

## 2. Distributions and architectures

| Target | Status | Evidence |
|---|---|---|
| Ubuntu 24.04 LTS, x86_64 | tested | transactional install with trial boot, fallback, commit, rollback and removal; software TPM; STIG gate; add-ons under real systemd (PC, 2026-11-07, 2026-11-22 and 2026-11-23); CIS Level 2 remediation with the CIS firewall next to secure_sudo's table (PC, 2026-11-23) |
| Debian | expected | `install.sh` has the branch; simulated only |
| Fedora / RHEL family | expected | `install.sh` branch (`binrpm-pkg`); simulated only; no initramfs hook (dracut not supported, see section 3) |
| Arch | expected | `install.sh` branch; simulated only |
| openSUSE | expected | `install.sh` branch; simulated only |
| any non-x86_64 architecture | unsupported | the installer refuses it |

## 3. Boot methods

| Method | Status | Evidence |
|---|---|---|
| GRUB, BIOS, separate ESP mounted | tested | `run-bootguard-initramfs-test.sh`, 18/18 (PC, 2026-11-22) |
| GRUB, UEFI (OVMF), separate ESP | tested | same test with `VM_UEFI=1`, 18/18 (PC, 2026-11-22) |
| initramfs-tools restore stage | tested | same runs (PC, 2026-11-22) |
| encrypted (LUKS) root | expected | not run; see [BOOT_ASSURANCE.md](BOOT_ASSURANCE.md) |
| systemd-boot, other bootloaders | expected | not run |
| dracut initramfs (Fedora/RHEL) | unsupported | no hook shipped; the systemd restore unit is the path |
| real hardware (TPM, firmware tables) | expected | readers are unit-tested against fake trees; `HARDWARE_SMOKE_TEST.md` is the procedure; no hardware run recorded yet (2026-11-24) |

## 4. Toolchain

| Item | Status | Evidence |
|---|---|---|
| GCC 13.3 (Ubuntu 24.04) | tested | build gate, kernel and userspace, `-Werror` (2026-11-15) |
| other GCC versions, Clang | expected | not run |
| OpenSSL, zlib, PAM, TSS2 development packages | tested | Ubuntu 24.04 package versions (2026-11-22) |

## 5. End-of-support policy

**Confirmed by the owner on 2026-11-24.** It is what
`ci/check-support-matrix.py` and the release checklist assume.

* **Kernels.** A kernel series is supported while kernel.org lists it as
  maintained and the release gate (in-tree build and boot test) passes on it.
  When upstream ends a series it becomes **unsupported** in the next release,
  and the matrix says so for one release first.
* **New kernels** start as **expected**, become **compile-checked** when the
  header check passes, and **tested** only after a recorded boot run.
* **Distributions** are **tested** only with a recorded install run. A distro
  release the vendor no longer maintains is **unsupported** in the next release.
* **Releases.** Only the latest release gets fixes. The previous release
  gets security fixes for 90 days after its successor ships, then is
  unsupported. The matrix names both.

## 6. Release checklist for this matrix

1. Update the `Release:` and `Matrix reviewed:` lines above. They must match
   the `VERSION` file and be a real date.
2. For every row you re-ran, replace its evidence and date. A row whose run is
   not recorded stays **expected**.
3. Run `python3 ci/check-support-matrix.py .`. The build gate runs it in the
   lint stage and fails the release when the release line is stale, a status is
   unknown, or a **tested** row has no date.
4. Re-run the tests in section 1 to 3 that the release changed; do not promote
   a row without the run.
