<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `install/install.sh`

Run as root. Part of the [script reference](../SCRIPTS.md).

Build, install, verify, roll back and remove the secure_sudo kernel and
userspace on Debian/Ubuntu, Fedora/RHEL, Arch and openSUSE (family from
`/etc/os-release` `ID`/`ID_LIKE`). Run as root; review it first — it compiles
and installs a kernel. Recovery from every failure: [RECOVERY.md](../RECOVERY.md).

```sh
sudo ./install/install.sh --dry-run          # what would happen; changes nothing
sudo ./install/install.sh                    # everything below, in order
# reboot: the new kernel boots ONCE; if it fails, the next boot is the old one
sudo ./install/install.sh verify --commit    # make it the default
```

| Command | What it does |
|---|---|
| `all` (default) | preflight → build deps → fetch + verify source → build the kernel package → `install-kernel` → `userspace` → `verify` → `tpm-lockout` (skipped with no TPM, no tpm2-tools, or `SS_TPM_LOCKOUT=0`) |
| `preflight [all\|build-kernel\|install-kernel\|userspace [--prebuilt DIR]]` (`--dry-run`) | distro support, boot method, bootloader, Secure Boot state and keys, trial-boot availability, `/boot` and build space, DKMS modules, missing tools, PAM files that use the modules, the runtime packages it would install, and the list of changes. Changes nothing; non-zero exit on a blocking problem. `install-kernel` and `userspace` run their own preflight first |
| `build-kernel` | verified source → graft the LSM → configure from the running kernel's config → `bindeb-pkg`/`binrpm-pkg` into `$BUILD_ROOT/out/<release>/` with `build-info.txt`, `kernel.config`, `kernel-source.txt`, an SPDX SBOM and `SHA256SUMS` |
| `install-kernel [DIR\|PKG…]` | checks `SHA256SUMS`, installs the package next to the running kernel, signs the image when a MOK is given, regenerates the boot menu (failure stops the run), checks the menu has both kernels, arms the trial boot |
| `userspace [--prebuilt DIR]` | preflight, then installs the CLI, daemon, PAM modules, OTP helper, PheonixBox and `scripts/` tools, recording each file with its hash; backs up anything it replaces; creates missing `/etc/secure_sudo/*.conf` (never overwrites them); installs runtime packages (libqrencode, nftables, zip, unzip; on Debian/Ubuntu it refreshes the package lists first when a package has no candidate, as on a fresh cloud image); checks every program finds its libraries; enables `secure-sudod` |
| `stage-userspace DIR` | builds userspace into DIR, for `userspace --prebuilt` on other machines of the same distro release |
| `verify [--commit]` | installed files unchanged; libraries resolve; per kernel: image, `CONFIG_SECURITY_SECURE_SUDO`, `CONFIG_LSM`, `MODULE_SIG_FORCE`, initramfs, signed modules, boot entry, image signature; the known-good kernel still in the menu; on the running secure_sudo kernel: active LSMs, `sig_enforce`, lockdown (`SS_EXPECT_LOCKDOWN`), `secure-sudod` and `secure-sudo lint` (when userspace is installed); the trial-boot state. `--commit` makes a trial-booted kernel the default when everything passed |
| `tpm-lockout` | gap G4: sets a random TPM lockout password (printed **once**, never stored; keep it offline) and `disableClear`, so `TPM2_Clear` from the OS fails even for root. Leaves a TPM that already has a lockout password alone (warns if `disableClear` is off). Needs tpm2-tools |
| `rollback [--default]` | boot the kernel that ran before secure_sudo: next boot only, or as the default |
| `uninstall [--remove-pam-lines] [--keep-kernel] [--purge]` | refuses while PAM uses the modules or while the secure_sudo kernel is running; removes only recorded, unchanged files; restores what it replaced; clears the GRUB drop-in and entries; purges the kernel packages. `--purge` also deletes `/etc/secure_sudo` and `/var/log/secure_sudo`; TimeVault quarantine is always kept |

The install record is `/var/lib/secure_sudo/install/manifest` (kind, path,
value per line; rewritten atomically after every change).

| Variable | Default | Effect |
|----------|---------|--------|
| `KVER` | `6.12.114` | kernel.org 6.12 LTS point release to fetch and build. |
| `JOBS` | `nproc` | Parallel build jobs. |
| `BUILD_ROOT` | `/usr/src/secure_sudo-build` | Where the kernel is fetched and built (root-owned, never world-writable `/tmp`). |
| `KERNEL_TARBALL`, `KERNEL_SIGNATURE` | download | Local copies for offline builds; verified the same way. |
| `SS_KERNEL_TREE` + `SS_KERNEL_TREE_PROVENANCE` | — | Build a tree verified some other way; the record (with a `verified_by=` line) is required and kept as the build's `kernel-source.txt`. |
| `SS_BASE_CONFIG` | running kernel's | Config to start from. |
| `SS_LOCALMOD` | — | `lsmod` output for `localmodconfig` (smaller, faster builds; only those modules). |
| `SS_TRIAL_BOOT` | `1` | `0` lets the new kernel become the default at once. |
| `SS_PANIC_TIMEOUT` | `10` | Seconds before a panicking secure_sudo kernel reboots (so a trial falls back). |
| `SS_SB_KEY`, `SS_SB_CERT` | — | MOK key + PEM certificate: the image is signed with them; required when Secure Boot is on. |
| `SS_EXPECT_LOCKDOWN` | — | `verify` fails unless the running lockdown mode matches (`none`, `integrity`, `confidentiality`). |
| `SS_TPM_LOCKOUT` | `1` | `0` skips `tpm-lockout` in `all`. |
| `SS_TPM_DEV` | `/dev/tpmrm0` | TPM device `tpm-lockout` uses. |
| `STIG` | *(unset)* | `scan` / `remediate` after install ([STIG.md](../STIG.md)). |

What changed from 0.11: module signatures are enforced by the new kernel's
own config (`CONFIG_MODULE_SIG_FORCE`) instead of `module.sig_enforce=1` on
the shared GRUB command line, which also applied to the previous kernel and
its unsigned DKMS modules (uninstall removes that old edit); `update-grub`
failures stop the run instead of being ignored; RPM installs no longer use
`--force` or install `kernel-headers` over the distro's; an upgrade no longer
rewrites a hand-set `admin_gid`.

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
