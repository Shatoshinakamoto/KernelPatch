# secure_sudo — where the Strategic TODO stands

Status of every item in [TODO.md](../TODO.md) for release **0.12.0**
(2026-10-26), with the evidence behind each claim and what is still missing.
"Done" below means the item's own *Done when* is met by something that ran
and can be re-run; anything short of that is "partly" or "not started", with
the reason.

Two limits of the build environment shape this release and are named
wherever they matter:

* **kernel.org, GitHub and the Debian archive were not reachable.** The
  installer's default kernel (6.12.114) was therefore compiled only against
  its headers here, never built as a whole tree or booted. Every boot test
  used **upstream 6.14** (Ubuntu's unpatched `.orig` tarball, fetched through
  the signed Ubuntu archive).
* **No KVM.** All VMs ran under TCG emulation with BIOS firmware (SeaBIOS),
  so nothing was tested under UEFI or Secure Boot, and nothing ran on real
  hardware.

The GitHub workflow (`.github/workflows/build-gate.yml`) is written and
syntax-checked but has **never run on GitHub**: per the project rule,
nothing is pushed from here.

| Item | Status | One line |
|---|---|---|
| P0-1 build + CI gate | partly | `ci/build-gate.sh` passes from a clean copy; not yet required in CI, 6.12 not built as a tree |
| P0-2 tests | partly | 421 host checks and 118/118 in-kernel checks pass; STIG gate compares rule IDs; not yet required in CI |
| P0-3 boot proof | partly | boots and runs on upstream 6.14 in Ubuntu 24.04 VMs (install 51/51, STIG run classified); not 6.12, UEFI, other distros or hardware |
| P0-4 source provenance | done | signature-verified before extraction, tamper test, SBOM, reproducible archive |
| P0-5 transactional install | done (Ubuntu 24.04) | trial boot, automatic fallback, commit, rollback and byte-clean removal proven in a VM; other distros simulated only |
| P0-6 policy validation + recovery | done | lint/load refuse bad policy before anything is applied; four recovery drills pass on the real kernel in a VM |
| P1-1 … P1-8 | not started | groundwork only (listed below) |
| P2-1 … P2-5 | not started | |
| P3-1 … P3-3 | partly (P3-2) | evidence and docs updated with this release; no matrix or disclosure process yet |

---

## P0 — release blockers

### P0-4 Source provenance — done

* `scripts/verify-kernel-source.sh` checks the kernel.org detached signature
  of the *uncompressed* tarball **before** anything is extracted. Only
  signers whose primary fingerprint is pinned in
  `install/keys/release-signers.txt` (Greg Kroah-Hartman's and Linus
  Torvalds's) are accepted; Greg's key is shipped, others can be fetched by
  WKD and are still checked against the pin. A missing, empty or bad
  signature, an unpinned or revoked key, or a corrupt archive fails, with no
  override. `install.sh build-kernel` uses it for every download.
* The signer fingerprint, archive SHA-256 and release go into
  `kernel-source.txt`; `build-info.txt` adds the compiler, `make`, config
  hash and LSM list; `secure_sudo.spdx.json` is an SPDX SBOM; all are
  installed under `/usr/share/doc/secure-sudo/build/<release>/`.
* A tree that did not come from kernel.org (`SS_KERNEL_TREE`) is refused
  unless it has a provenance record with a `verified_by=` line, which becomes
  the build's `kernel-source.txt`. The VM kernel used this route: apt checked
  the Ubuntu archive's signed `InRelease` and the `Sources` hashes, and
  `fetch-kernel-source.sh` re-checked the `.orig` tarball against the `.dsc`
  (SHA-256 `a6dd4538…d911e`).
* Tests: `tests/provenance/` (19 checks): a tampered or truncated archive, a
  missing, empty or mismatched signature, and an unshipped or unpinned signer
  are each rejected, and `install.sh` does not extract a rejected archive.
* `ci/make-release.sh` builds a byte-identical archive from the same inputs
  (checked twice in the gate).

Gaps: toolchain versions are recorded, not pinned. A byte-identical rebuild
of the *kernel package* from its record has not been demonstrated (the
build takes its timestamp from the source's signature time and fixes the
build user and host, which removes the usual differences, but nobody has
compared two builds).

### P0-1 Build and CI gate — partly

Done:

* `ci/build-gate.sh` runs, from a clean copy of the tree: shell/Python lint,
  the userspace (5 components) and add-ons (6) with `-Werror`, the LSM
  against three header trees (6.11 and 6.14 through kbuild, **6.12.114**
  directly), the LSM inside a real kernel tree in six configurations
  (default, module signing, no audit, no BPF, no modules, AppArmor stacked),
  every host test suite, `ci/check-lsm-hooks.sh` (no hook registered twice),
  and the reproducible package. It writes a record (compiler, tree hash,
  config hashes, per-stage result).
* It found a real break: `ss_bpf.c` did not compile for 6.12
  (SECURITY_REVIEW #41).
* `.github/workflows/build-gate.yml` runs the same gate on every push and
  pull request against the installer's default kernel, fetched and verified
  from kernel.org, plus a nightly distro VM job: the installer builds the
  kernel package, then the install/recovery/removal scenario and the STIG
  release gate run on fresh Ubuntu 24.04 guests.

Missing:

* The workflow has not run on GitHub, so "required in CI" is not yet true.
  The first push will show whether it works as written.
* The in-tree builds used 6.14; 6.12.114 was compiled against headers only.
  The workflow builds 6.12.114 as a full tree, which is the first time that
  will happen.
* The TODO names `6.12.48`; the installer default is now `6.12.114`, the
  newest 6.12 LTS point release available when this was done.

### P0-2 Automated tests — partly

Host suites (`tests/run-all.sh`, TAP; root-only parts marked and skipped
without root):

| Suite | Checks | Covers |
|---|---|---|
| `tests/userspace/test-otp.sh` | 66 | RFC 4226/6238 vectors, secret at rest, prefix, replay refusal |
| `tests/userspace/test-pam.sh` | 50 | both PAM modules through libpam, the documented stacks, real `pam_unix` + `pam_faillock` (root, private mount namespace) |
| `tests/userspace/test-helpers.sh` | 74 | `apply-net.sh` with real `nft` in network namespaces (all four modes, IPv4 + IPv6, DHCP/DNS), `quarantine.sh` (archive before delete) |
| `tests/userspace/test-cli.sh` | 67 | config parsing, `lint`, `load` reporting, against stand-in knob and list files |
| `tests/oscap/` | 39 | result parsing and the STIG gate's rule-by-rule comparison, release vs diagnostic mode, independent checks (OSB-19) |
| `tests/provenance/` | 19 | P0-4 above |
| `tests/install/test-install.sh` | 106 | P0-5 below |

In-kernel tests (`tests/vm/ss-functest.c`, run as PID 1 of an initramfs by
`tests/vm/boot-test.sh`): **118/118** on upstream 6.14, and again 118/118
with AppArmor stacked. They cover registration and stacking, knob defaults,
modes and bounds, setid/setgroups/userns, setuid-exec allowlist, command
blacklist (incl. hard links), `/tmp` and memfd exec, `/dev/mem`, packet
sockets, BPF and perf, SysctlGuard and binfmt_misc, Process Runtime Guard,
`finit_module` and `init_module` with name and hash blacklists, concurrent
list rewrites during exec, the event ring wrap and loss counter, and the
one-way lock (every knob kind refuses, modules and tracing BPF refused).
Results: `docs/vm/results/02-*`, `03-*`.

STIG release gate: `tests/oscap/stig-gate.sh` (39 checks in `tests/oscap/`) compares an
OpenSCAP result rule by rule with `tests/oscap/ubuntu2404-stig.expect`. The
VM release run reached 206 pass / 11 fail / 0 error after two remediation
passes; every remaining rule is classified in
[OSCAP_BUGS.md §5](OSCAP_BUGS.md#5-release-run-in-a-vm-v12-2026-10-26), and
the fixes it led to are in this release. The final VM rescan with those
fixes has not run yet, so the gate has **not** yet passed on a VM result.
The run also found that the scanner cannot evaluate `encrypt_partitions` on
Ubuntu 24.04 (false pass, OSB-19); the gate now uses an independent check
for it and refuses a release result without one.

Missing:

* Not yet in the kernel tests: chroot and mount-namespace edge cases,
  TimeVault, BinaryVault, RadioGuard, cooldown, home-write, the NodeJS
  guard, RAM-spike handling, TPM and firmware sysfs paths.
* The `no-audit`/`no-bpf`/`no-modules` variants are built, not booted.
* Add-on monitor/enforce modes (`temporary/`) have build checks only.
* Not required in CI yet (P0-1).

### P0-3 Boot proof — partly

What has been booted, all under QEMU/TCG with SeaBIOS
(`docs/vm/results/`):

| Kernel | Guest | Result |
|---|---|---|
| v11 LSM, upstream 6.14 | initramfs | **panic** at boot (`Ran out of static slots`, SECURITY_REVIEW #35); fixed in v12, guarded by `ci/check-lsm-hooks.sh` |
| v12 LSM, upstream 6.14 | initramfs, PID 1 test program | 118/118, and 118/118 with AppArmor stacked |
| v12, `install.sh build-kernel` package, upstream 6.14 | Ubuntu 24.04 cloud image (systemd, GRUB, AppArmor, virtio disk) | install/recovery/removal 51/51; active LSMs `lockdown,capability,landlock,yama,apparmor,secure_sudo,ima,evm`; services start; the configuration loads; the previous kernel stays bootable and is fallen back to |
| same | Ubuntu 24.04, STIG remediation | boots again after full STIG hardening with secure_sudo and AppArmor active; scan results above |

Known platform exclusions, recorded rather than claimed:

* Lockdown is `none` in these guests: no Secure Boot under SeaBIOS, so the
  "expected lockdown state" could only be checked as "not enforced".
* `fwupd-refresh` fails in the guest (no network firmware service), so
  systemd reports `degraded`; unrelated to secure_sudo.
* The VM kernel was built with `SS_LOCALMOD` from a fresh guest's module
  list. That dropped the netfilter modules, so ufw could not start (OSB-21);
  `install.sh` now keeps them. Not yet rebuilt and booted.

Missing for *Done*:

* **6.12 LTS, the installer's default, has never been booted** (only
  compiled against its headers; kernel.org was unreachable).
* No UEFI, Secure Boot, MOK enrollment or TPM test (no OVMF/KVM here).
* No VM of Fedora, openSUSE or Arch; no real hardware.
  [HARDWARE_SMOKE_TEST.md](HARDWARE_SMOKE_TEST.md) is the plan for that.
* The VM STIG run has not yet ended on a scan with no unexplained failures
  (above).

### P0-5 Transactional install, upgrade and recovery — done (Ubuntu 24.04)

`install/install.sh` was rewritten (SECURITY_REVIEW #43):

* `preflight` (also `--dry-run`) reports distro support, disk space, boot
  method, bootloader, Secure Boot and MOK state, the trial-boot plan, missing
  tools and every change, and changes nothing (tested).
* Every installed file is recorded with its hash; files that existed are
  backed up first; configuration files that exist are never touched.
* The new kernel is installed next to the running one, which stays the
  default; the new one boots **once** (`grub-reboot`) and becomes the
  default only after `install.sh verify --commit`, which refuses when verify
  finds a problem. A panicking trial kernel reboots into the previous one
  after 10 s (`CONFIG_PANIC_TIMEOUT`).
* `verify` checks files, shared libraries, the installed kernel config
  (secure_sudo in `CONFIG_LSM`, `MODULE_SIG_FORCE`), initramfs, module
  signatures, boot entries for both kernels, the image signature
  (`sbverify`), and on the running kernel the LSM list, signature
  enforcement, lockdown (optional expectation), the daemon and `lint`.
* Bootloader regeneration failures stop the install.
* `rollback [--default]`, and `uninstall` that removes only unchanged
  recorded files, restores backups, purges the kernel packages, clears the
  GRUB state it set, and refuses while PAM uses the modules
  (`--remove-pam-lines` takes them out with a backup).
* [RECOVERY.md](RECOVERY.md) covers an unbootable kernel, failed MOK
  enrollment, an interrupted package install and policy lockout.

Evidence: `tests/install/test-install.sh` (106 checks, including a
byte-identical root after install + uninstall and an interrupted install),
and the distro VM run: `06-distro-install-final/` on the packaged tree, **51/51**: install-kernel and
userspace on a fresh Ubuntu 24.04 cloud image, the trial boot with
secure_sudo and AppArmor active, `verify --commit`, a deliberately broken
trial that falls back to the previous kernel by itself, rollback, uninstall
refusing while PAM uses the modules, and a removal after which every file
under the directories `install.sh` touches is byte-identical to the fresh
image (apart from the runtime packages `libqrencode4 zip unzip`) and
`grub.cfg` is byte-identical to what GRUB generated before the install.

Missing: Fedora, openSUSE and Arch paths are exercised only by the host
suite's simulated roots, not in a VM of those distros. The MOK path is not
VM-tested (no UEFI).

### P0-6 Policy validation and administrator recovery — done

* `secure-sudo lint` checks syntax, unknown keys, bounds, list files
  (paths, ownership, permissions), admin groups (exist, have members, cover
  the admin running it), dependent settings, PAM order across includes,
  OTP readiness, installed modules, kernel support for each knob, and the
  lock state (`docs/COMMANDS.md`).
* `secure-sudo load` runs lint first and changes nothing on an error
  (`--force` overrides), then reports every setting as accepted, rejected
  or skipped and ends with `load INCOMPLETE` on a partial policy.
* Recovery drills, run on the real kernel in the distro VM
  (`tests/vm/distro/recovery-exercises.sh`): wrong `admin_gid` with
  `block_setid_exec`, an allowlist without `passwd`, an OTP PAM line before
  OTP is set up, and an accidental `lock`, each with its recovery from a root
  session (and a reboot for the lock). In the same VM run all four drills passed (35 checks, plus 4 after the lock
reboot): each mistake was caught by `lint` and refused by `load` before it
reached the kernel, forcing it through showed the lockout it would cause, and
each recovery restored sudo and `passwd` for the right users.

---

## P1 — not started

Groundwork already in this release, so the P1 work does not start from zero:

* P1-1: the ring now drops whole events and exposes `events_dropped`
  (SECURITY_REVIEW #44); no schema version, boot id or sequence numbers yet.
* P1-4: `install.sh verify` checks the running kernel, daemon and lint;
  `load` reports rejected settings. No unified health command yet.
* P1-6: `lint` is the non-mutating preview; there is no snapshot or change
  history.
* P1-7: [RECOVERY.md](RECOVERY.md) covers administrator lockout, not incident
  response.
* P1-8: network modes are tested with real `nft` in namespaces for IPv4 and
  IPv6; multiple interfaces, VPNs, DHCP changes, pre-existing rulesets and
  daemon restarts are not.
* P1-2: remote syslog is still UDP only.

## P2 — not started

P2-5 groundwork: the management GUI's access-token hole was fixed in v11
(SECURITY_REVIEW #29); it has no automated tests.

## P3

* P3-1 compatibility matrix: not started. What is known is in the P0-3
  table above.
* P3-2: this file, [RECOVERY.md](RECOVERY.md), the security review (#35–#47)
  and `docs/vm/results/` were brought up to date with the code in this
  release; making that part of a release checklist is not done.
* P3-3 maintenance and disclosure process: not started.
