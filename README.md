# secure_sudo — merged kernel security patch + userspace + installers

A defensive Linux hardening stack built around one in-kernel LSM. It is the
reconciled merge of the project's split-up v1 module and v2 LSM designs; see
`docs/FEATURE_MAP.md` for how every feature maps from the originals, and
`kernel/security/secure_sudo/INTEGRATION.md` for the kernel wiring and the full
runtime interface.

Target kernel: **6.12 LTS**. Everything here is local; nothing is pushed.

## Layout

```
kernel/security/secure_sudo/   The LSM (built into the kernel)
userspace/
  cli/        secure-sudo         control CLI (loads policy, status, knobs)
  pam/        pam_secure_sudo.so  feeds sudo/su auth results to the kernel
              pam_secure_otp.so   verifies the rotating OTP password
  daemon/     secure-sudod        logs, cooldown kill, nft, TimeVault, health heartbeat
  otp/        secure-sudo-otp     TOTP setup/verify, local QR, encrypted secret
  config/     templates for /etc/secure_sudo/
scripts/
  timevault-whitelist.sh          bash TimeVault allowlist tool (scan/add/remove/list/wipe)
  detect-admin-gids.sh            finds every admin group GID (used by install.sh)
  verify-kernel-source.sh         kernel.org signature check before extraction (fail closed)
  gen-sbom.sh                     SPDX SBOM of the release
  stig-harden.sh, oscap-results.py  STIG/CIS scan, remediation, result parsing
docs/
  COMMANDS.md                     every CLI command, explained
  CONFIGURATION.md                every config file and option
  SCRIPTS.md                      every script, with flags and usage
  RECOVERY.md                     getting a machine back: boot, Secure Boot, install, policy
  HARDWARE_SMOKE_TEST.md          the per-machine test plan VMs cannot replace
  ROADMAP_STATUS.md               where each Strategic TODO item stands, with evidence
  SECURITY_REVIEW.md              NIST-framed review: findings + fixes
  STIG.md                         STIG/CIS tooling, control map, results
  OSCAP_BUGS.md                   every oscap bug, root cause, patch, before/after
  FEATURE_MAP.md                  how each feature maps from the v1/v2 originals
  vm/results/                     recorded boot and VM test runs
install/
  install.sh                      preflight, build, trial-boot install, verify, rollback, uninstall
  keys/                           kernel.org signing key and pinned fingerprints
  ansible/secure_sudo.yml         YAML scaffold wrapping the installer
  encrypted/install-encrypted.sh  encrypted-source + Secure Boot (MOK) variant
  encrypted/deploy-encrypted.yml  Ansible wrapper for the encrypted variant
ci/
  build-gate.sh                   the release gate: lint, -Werror builds, header and in-tree
                                  kernel builds, every test suite, reproducible package
  make-release.sh                 byte-reproducible release tarball + SBOM
tests/
  run-all.sh                      every host test suite (TAP)
  install/ userspace/ provenance/ oscap/   host suites (root-only parts say so)
  vm/                             in-kernel tests in QEMU (initramfs)
  vm/distro/                      full Ubuntu VM: install, trial boot, recovery, removal, STIG
.github/workflows/build-gate.yml  CI for the gate and the VM jobs (written, not yet run on GitHub)
temporary/                        opt-in add-ons (below)
```

## What secure_sudo enforces

**K** = in the kernel LSM, **U** = userspace (CLI, PAM, daemon, tools).

| # | Where | Protection |
|---|-------|------------|
| 1 | K | Block non-sudo UID/GID switching (setuid/setgid/setgroups) and unprivileged user namespaces. **1b:** deny non-sudo exec of setuid/file-cap binaries unless allowlisted. |
| 2 | K | Command blacklist, matched by device + inode and path (not basename). |
| 3 | K | Block non-sudo firmware/flash access: `/dev/mem`, `/dev/port`, `/dev/mtd*`, `/dev/mei*`, and `/sys/firmware` writes. |
| 4 | K | Confine non-sudo writes to home + scratch/device trees + an allowlist. Opt-in (aggressive). Built on `file_open` + the `path_*` hooks; both source versions used a `path_permission` hook that does not exist. |
| 5 | K | Block TPM clear (`ppi/request`) for everyone unless booted with `secure_sudo.tpm_maint=1`. |
| 6 | K | Driver blacklist / anti-BYOVD: SHA-256 + name checked at module load. |
| 7 | K | RAM-spike detection drops caches (`si_mem_available`, kernel worker). |
| 8 | K + U | Sudo brute-force cooldown: PAM feeds failures, the kernel blocks, the daemon kills the offender. |
| 9 | K + U | Versioned JSON security events with per-boot sequence/clock/actor metadata and visible ring/audit loss counters; the daemon writes dated, rotated logs. `secure-sudo health` reports loss and component status; `evidence-export` creates hash-chained, optionally externally signed bundles. |
| 10 | K + U | Network host mode denies raw/`AF_PACKET` sockets; nft rules for LAN/public modes. |
| 11 | K | NodeJS child-process guard (LSM task blob + allowlist). |
| 12 | K | Restrict exec and `PROT_EXEC` mmap from `/tmp`, `/var/tmp`, `/dev/shm`. |
| 13 | K + U | **TimeVault:** hash-based exec gate with allowlist (+ auto-update entries), size cap, package-manager deny, and quarantine of blocked binaries. |
| 14 | U | **Rotating OTP sudo password:** prefix + 6-digit TOTP, verified by `pam_secure_otp`; QR rendered locally (`userspace/otp`). |
| 15 | U | **Encrypted OTP secret:** AES-256-GCM under a root-only key file (not TPM-sealed), `mlock`ed at runtime, prefix stored as a yescrypt hash, each code accepted once (RFC 6238 §5.2). |
| 16 | K | One-way config lock until reboot (TimeVault latches it); blocks module loads, kexec and kernel-memory patching while locked. |
| 17 | K | **BinaryVault:** freeze every executable + shared library (write/truncate/unlink/rename/hardlink/chmod/xattr) for all UIDs incl. root. Updates via a `secure_sudo.binvault_maint=1` maintenance reboot. See [docs/BINARYVAULT.md](docs/BINARYVAULT.md). |
| 18 | U | **STIG / OpenSCAP:** `scripts/stig-harden.sh` scan + two-pass remediate + known-issue patches; real results: DISA Ubuntu 24.04 STIG 61 pass / 1 fail in a container and 206 pass / 11 fail / 0 error in a VM after two passes (each remaining rule classified; final VM rescan pending), CIS L2 Server 190 / 17. See [docs/STIG.md](docs/STIG.md) and [docs/OSCAP_BUGS.md](docs/OSCAP_BUGS.md). |
| 19 | K | **RadioGuard:** Wi-Fi / Bluetooth lockdown + `ethernet_only` master switch (refuses wireless/BT core modules, `AF_BLUETOOTH` sockets, `/dev/rfkill` writes). `secure-sudo radio ...` |
| 20 | K | **Process Runtime Guard:** denies cross-process ptrace / `process_vm_writev` / `/proc/pid/mem` tampering and W^X mappings, with a CLI-managed exemption list; optional `prguard_observe` memory-access feed. `secure-sudo prguard ...` |
| 21 | U | **PheonixBox:** snapshot tamper protection + auto-repair for chosen files/dirs (SHA-256 manifest detects, compressed snapshot restores, permissions snapshot). See [docs/PHEONIXBOX.md](docs/PHEONIXBOX.md). |
| 22 | K | **BPF & perf guard:** `bpf_guard` / `perf_guard` deny bpf(2) and perf_event_open to non-sudo users; `bpf_lock_tracing` (default on) refuses tracing-class BPF programs (kprobe, tracepoint, fentry, BPF-LSM, freplace) for everyone once the lock latches. |
| 23 | K | **SysctlGuard:** freezes the security-critical sysctls (`core_pattern`, `modprobe`, `kptr_restrict`, `ptrace_scope`, `randomize_va_space`, `fs.protected_*`, ...) and binfmt_misc registration for every user, root included. Plus: `audit_events` feeds every kernel event to auditd, and `lock_confidentiality` extends the lock to kernel-memory reads. |

### Opt-in add-ons — `temporary/` (v10)

A separate, **opt-in** suite lives under `temporary/` (not built or installed by
the core `install.sh`; add it with `sudo bash temporary/install-temporary.sh`,
which enables nothing by default). It shares one logging mechanism (local +
optional off-box syslog + `notify_cmd`) and a compressed storage format whose
location rotates hourly or, per the `rotate` toggle, stays fixed:

* **ProcGuard** — kill non-allowlisted processes; quarantine (compressed,
  rotated) and remove respawning infections; optional off-box sync.
* **DriverGuard** — driver-file integrity + repair from rotated compressed
  backups.
* **BiosGuard** — firmware tamper **detection only** (logs + notifies; never
  writes firmware — a live reflash can brick the board).
* **BootGuard** — boot-partition tamper detection + restore **at next boot**
  (never a live rewrite of `/boot`).
* **Locus** — LAN request-only allocator for the rotating locations, with a
  read-only status GUI and configurable root dirs.
* **tamperwatch** — real-time attribution of *which process* tampered a
  protected file (fanotify), with optional kill + quarantine.
* **Management GUI** — one local (loopback, token-protected) web console to view
  status/logs/the memory-access feed and configure everything, including the
  rotating↔fixed quarantine toggle and per-PID quarantine.

The kernel LSM also gains an opt-in **`prguard_observe`** knob that logs every
cross-process memory read/write (source → target) for the GUI's memory feed.

Full write-up, honesty notes, commands, and settings: [docs/ADDONS.md](docs/ADDONS.md).

## Install (quick)

Keep a second root session open the whole time (`docs/RECOVERY.md`).

```sh
sudo ./install/install.sh preflight     # what will happen; changes nothing
sudo ./install/install.sh               # build 6.12 LTS (signature-verified), install it
                                        # next to the running kernel, install userspace
sudo ./install/install.sh verify        # check what was installed
sudo reboot                             # the new kernel boots ONCE; the old one stays default
sudo ./install/install.sh verify --commit   # happy with it: make it the default
sudo secure-sudo lint && sudo secure-sudo load   # check, then apply /etc/secure_sudo/*
```

If the new kernel does not come up, the next boot is the previous kernel by
itself. `install.sh rollback` boots the previous kernel again later;
`install.sh uninstall` removes exactly what was installed (and refuses while
PAM still uses the modules). Every command and variable is in
[docs/SCRIPTS.md](docs/SCRIPTS.md).

Plus DISA **STIG** tooling (#18): `scripts/stig-harden.sh` scans and optionally
remediates to the STIG baseline, and the installer honours `STIG=scan` /
`STIG=remediate`. The kernel→STIG control mapping and real before/after scan
results are in [docs/STIG.md](docs/STIG.md).

Full documentation is under [`docs/`](docs/): [commands](docs/COMMANDS.md),
[configuration](docs/CONFIGURATION.md), [scripts](docs/SCRIPTS.md), the
[security review](docs/SECURITY_REVIEW.md) and the [STIG mapping](docs/STIG.md).

Admin groups are detected automatically at install: every GID of `sudo`,
`wheel`, `admin` and any `%group` / `%#gid` rule in sudoers goes into
`admin_gid` (up to 16), so all sudo-group users count as sudo from the first
boot. After creating a new admin group, run `sudo secure-sudo detect-admins`
(`-n` previews without saving).

## TimeVault allowlist

Built into the CLI (root only), and mirrored by `scripts/timevault-whitelist.sh`
for systems without the CLI:

```sh
sudo secure-sudo vault-allow scan /usr/bin /usr/sbin /opt/app   # every ELF / #! script, hashed
sudo secure-sudo vault-allow scan -n /usr/local/bin              # dry run
sudo secure-sudo vault-allow add /usr/local/bin/mytool           # single file
sudo secure-sudo vault-allow remove /usr/local/bin/mytool
sudo secure-sudo vault-allow list
sudo secure-sudo vault-allow wipe                                # asks; -y to skip
```

Entries are stored as `<resolved path> <sha256>` in
`/etc/secure_sudo/timevault_allow.conf` and pushed to the kernel immediately.
Paths are canonicalised (symlinks become their targets, since that is what the
kernel matches); paths containing whitespace can't be represented and are
skipped. Re-running a scan re-hashes changed files. Limits: 16384 entries /
4 MiB. `wipe` refuses while TimeVault is engaged unless `--force`, and nothing
can change once the config is locked (reboot to edit).

PAM wiring (cooldown + OTP) is deliberately left as a reviewed manual step —
`install.sh` prints the exact lines — so a typo can't lock you out.

## Status

Release 0.12.0 works through the project's Strategic TODO; where every item
stands, with the evidence, is in [docs/ROADMAP_STATUS.md](docs/ROADMAP_STATUS.md).
In short:

* **Booted, not just compiled.** v11 compiled cleanly and still panicked at
  boot; v12 fixes that and is boot-tested on upstream **6.14** in QEMU: 118
  in-kernel checks pass (also with AppArmor stacked), and in a full Ubuntu
  24.04 guest the installer's package boots with GRUB, systemd and AppArmor,
  falls back to the old kernel when not committed, passes the four recovery
  drills, rolls back and uninstalls cleanly. Recorded runs:
  [docs/vm/results/](docs/vm/results/).
* **6.12 LTS, the installer's default, in CI** (GitHub Actions, KVM): 135
  in-kernel checks pass; the same install/fallback/commit/drills/removal run
  passes on Ubuntu 24.04; and after DISA STIG hardening the guest reboots
  into secure_sudo with AppArmor and the STIG release gate passes (only the
  allowed fails: unencrypted test disk, FIPS, sssd).
* **Not yet booted:** UEFI / Secure Boot, other distros, and real hardware.
  Run [docs/HARDWARE_SMOKE_TEST.md](docs/HARDWARE_SMOKE_TEST.md) on each
  machine model before relying on it there.
* **Build and tests:** `ci/build-gate.sh` (lint, `-Werror` builds, header and
  in-tree kernel builds, every test suite, reproducible package) runs on
  GitHub for every push and pull request; the VM jobs run weekly and on
  demand.
* Security review: [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md)
  (findings #35–#47 came from v12's tests and boots, #48–#51 since).
