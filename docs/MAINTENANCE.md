# Maintenance and disclosure process (TODO P3-3)

How a kernel regression, a vulnerability report or a dependency problem turns
into a tracked, tested release. The reporting channel and response targets are
in [SECURITY.md](../SECURITY.md); the supported kernels, distributions and
the end-of-support policy are in [SUPPORT.md](SUPPORT.md). Targets in this
file marked *proposed* are for the owner to confirm.

Evidence rules that apply to every step: This project does not use GitHub
Actions; everything is built and tested locally, so "tested" means the local gate plus the VM runs on
the owner's PC (see [ROADMAP_STATUS.md](ROADMAP_STATUS.md)); say which runs
you did on the pull request. Pull requests go against `main`, one at a time.

## 1. Vulnerability triage

1. **Acknowledge** within 3 days (proposed) in the private advisory.
2. **Reproduce** on a clean install of a supported release. Write the failing
   test first: a unit test, a `tests/userspace` suite, an in-kernel test
   (`tests/vm`) or a VM guest check. A report that cannot be reproduced is
   answered with what was tried.
3. **Classify** using the table in SECURITY.md. Record the class, the affected
   releases and the control it weakens in the advisory.
4. **Fix** on a private branch (the advisory's temporary private fork, if
   enabled). The fix includes the test, a `docs/SECURITY_REVIEW.md` entry
   written after the fix is public, and updates to every doc that described the
   old behaviour (a doc that promised more than the code is a feature to build,
   not text to delete).
5. **Verify**: local gate; for kernel changes the in-tree build in every
   `ci/kconfig` variant and the boot test on 6.12.114; for installer, boot or
   add-on changes the matching VM test on the PC.
6. **Release** (section 2), **publish** the advisory with the fixed version and
   credit, and add the entry to the review log.

## 2. Security-fix release process

1. Branch from `main`; one fix per pull request.
2. Bump `VERSION` (patch release for a fix) and `ci/release-epoch`; update the
   `Release:` and `Matrix reviewed:` lines in `docs/SUPPORT.md`. The gate
   (`ci/check-support-matrix.py`) fails if the matrix is for another version.
3. Run the gate (`ci/build-gate.sh`) and the VM tests the change calls for;
   attach the results to the pull request as evidence, with dates.
4. Build the release archive with `ci/make-release.sh` and check that it is
   reproducible (the gate's package stage builds it twice and compares).
5. Merge, then publish the release as a public GitHub Release from the
   owner's PC with `ci/publish-release.sh --notes NOTES.md [--sign KEYID]`. It
   builds locally, checks the SHA-256, optionally signs the checksum file, and
   uploads the archive, checksum, SBOM and signature with `gh release create`.
   It creates a DRAFT; the owner reviews the tag and notes on GitHub and gives
   a go before it is published (`--publish`). Then publish the advisory. Tell supported users which release to take and whether any
   action beyond upgrading is needed.
6. If the fix cannot be backported to the previous supported release, say so in
   the advisory and tell users to upgrade.

## 3. Kernel API and LTS tracking

* The target is the 6.12 LTS series; the pinned point release is `KVER` in
  `install/install.sh` (now 6.12.114). Kernel sources are verified against the
  pinned signing keys in `install/keys/` before extraction; there is no bypass.
* **LTS point releases:** when kernel.org publishes one, bump `KVER`, rebuild
  and boot-test it (the six `ci/kconfig` variants plus the boot test), and
  update the kernel row in SUPPORT.md. Target: within 14 days (proposed), 3 days
  if the point release fixes a vulnerability in a subsystem secure_sudo hooks.
* **New mainline releases:** run `ci/lsm-compile-check.sh` against the new
  headers. A new kernel starts as *expected* in SUPPORT.md, becomes
  *compile-checked* when that passes, and *tested* after a boot run. API
  changes get a shim in `secure_sudo.h` (the existing ones are listed in
  SUPPORT.md) and a note in the commit.
* **Kernel regression** (secure_sudo breaks boot or a kernel feature): treat as
  high severity. Reproduce with the boot test, fix, and tell users how to boot
  the previous kernel (the installer keeps it as the fallback; docs/RECOVERY.md).
* **End of a series:** follow the end-of-support policy in SUPPORT.md.

## 4. Dependency updates

| Dependency | Pinned or checked how | Update when |
|---|---|---|
| Linux kernel sources | `KVER` plus signing keys in `install/keys/` | per section 3 |
| kernel.org signing keys | fingerprints in `install/keys/release-signers.txt` | the signer changes; verify the new fingerprint through a second channel before pinning |
| Ubuntu cloud image (VM tests) | keyring and SHA256SUMS signature in the workflow | a new LTS point image, or a vendor security notice for the image |
| STIG content (SCAP Security Guide) | datastream pinned by sha256 in the STIG run | a new release; re-run the gate and record differences (docs/STIG.md) |
| OpenSSL, zlib, PAM, TSS2, qrencode (build dependencies) | distribution packages | a security advisory for one of them, and each release; rebuild and re-run the gate |
| swtpm, QEMU, OVMF (test tools) | distribution packages | when a test needs a fix; record versions in the results |

Review the table before every release and when a dependency advisory is
published. An update is a normal pull request with the gate and the VM runs it
affects.

## 5. Deprecation policy

* A feature, config key, command or file format is deprecated in one release
  and removed no earlier than the next release after that, unless it is a
  security risk (then removal may be immediate, with an advisory).
* Deprecation is announced in the release notes, in the relevant doc, and by a
  warning where the code can give one (`check-config`, `lint`, the CLI).
* Removed code moves to `deprecated/` rather than being deleted, so it can be
  restored; the config checkers keep rejecting the old key with a message that
  names its replacement.
* Anything a doc promises is built or listed as "not built yet": a deprecation
  never removes a protection silently.

## 6. Keeping the process testable

`ci/check-process-docs.py` (in the gate's lint stage) fails if SECURITY.md or
this file loses a section, the reporting channel, the response targets, or the
links the process depends on. It checks that the process exists and is
complete; it cannot check that people follow it, so each security-fix release
records its steps in the pull request.
