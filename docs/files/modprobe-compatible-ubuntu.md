<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `install/ubuntu-modprobe.sh` and the Ubuntu modprobe-compatible install

Method 7 of the install guide (docs/INSTALL.md) is the Ubuntu
modprobe-compatible install: a guided wrapper around `install/install.sh`
that leaves signature-enforced module loading exactly as the kernel itself
does, so `modprobe` loads the new kernel's modules unchanged.

## Why it is a wrapper, not a new installer

secure_sudo is built into the kernel, not as a loadable module
(kernel/security/secure_sudo/INTEGRATION.md), so the enforcement point is
the kernel build and the boot command line, never a file in
`/etc/modprobe.d`. The playbook's "options module.sig_enforce=1" in
`/etc/modprobe.d` did nothing (ss_driver.c:31-33, the playbook's modprobe.d
option is inert), so the method:

- builds the kernel with `CONFIG_MODULE_SIG_FORCE=y` as a kernel config
  option, which makes the kernel refuse unsigned modules at load;
- passes `module.sig_enforce=1` as a kernel parameter on the boot
  command line (install.sh verify checks it at run time); and
- freezes `/proc/sys/kernel/modprobe` with the KernelGuard feature (the
  modprobe sysctl is feature #23) so root cannot re-point modprobe at
  boot.

The wrapper therefore only verifies, preflights and runs the same
`install.sh` subcommands that any other method runs. It never compiles a
kernel itself, and it does not write `/etc/modprobe.d` or any other
distro configuration file.

## What the file lists

- The wrapper script itself, with its options and how each is checked
  before anything is changed.
- Ubuntu-specific conventions the install relies on (the staged userspace
  directory, the add-on runner, the kernel-out directory layout).
- Which entries are Ubuntu-specific, who requested them and when they
  were added.
- How to change or approve changes to this method.

## The wrapper script

**Location:** `install/ubuntu-modprobe.sh` (SPDX header on lines 1-4).

**What it does, in order:**

1. Root check (CWE-250) — refuses to run as non-root.
2. Option parsing; every value is allow-listed, nothing is passed through
   eval or a shell string (CWE-78, CWE-20).
3. `--archive` handling (or the checkout it sits in): copies the archive
   and its `.sha256` into a private 0700 work directory; checks the
   SHA-256 (NIST SI-7); verifies the detached OpenPGP signature of the
   checksum file against a pinned fingerprint (SI-7(15), SR-4); refuses
   unsafe archive members (absolute paths, `..`, links out of the
   archive, device files, more than one top directory) (CWE-22, CWE-59);
   unpacks the verified copy.
4. Runs `install.sh preflight` with `SS_TPM_LOCKOUT` and `STIG` (where
   set) — changes nothing.
5. Hashes the command line: asks the operator to type `y` once (or
   `--yes`). Nothing is written until the answer is yes.
6. `--with-modprobe-check` (read-only proof): builds two tiny loadable
   modules with the kernel build's `make`, leaves one unsigned on purpose,
   signs the other with the kernel build's `scripts/sign-file`, then
   `modprobe --test` shows the unsigned module refused and the signed one
   loads. This is only a runtime check of the installed kernel's
   signature enforcement — it never installs anything and removes its
   temporary files. Needs the kernel headers, a compiler and a few MB in
   `/lib/modules`.
7. Runs `install.sh install-kernel` (trial-boot install), then
   `install.sh userspace`, then `install.sh verify`.
8. `--with-addons` runs the add-on runner (from the verified tree) with or
   without the BootGuard initramfs stage.
9. Prints the next steps: reboot once, then `install.sh verify --commit`.

**Exit codes:** `0` done or a dry run passed; `1` a step failed (the
message names it; nothing after it ran); `2` usage error or a refused
option value.

## Ubuntu-specific conventions

The method assumes the guest is Ubuntu 24.04 (verified in the VM tests,
`tests/vm/distro/run-install-test.sh` line 66). Transactions on the guest
follow this layout:

| Path | Purpose |
|---|---|
| `/root/ss/KernelPatch-merged` | The verified source checkout, copied from the archive or the local worktree. |
| `/root/ss/KernelPatch-merged/install/install.sh` | The installer; aliased as `$I` in the VM test. |
| `/root/release.tar.gz` | The built release (kernel packages + SBOM + `SHA256SUMS`). |
| `/root/stage.tgz` | The staged userspace (from `install.sh stage-userspace`). |
| `/root/kout` | What `install.sh build-kernel` wrote: `$BUILD_ROOT/out/<release>`. |
| `/root/before.sha` / `after.sha` | Guest file hashes taken with `guest-snapshot.sh` before and after the install, for the clean-removal check. |
| `/root/pkgs-before` | Package list before install; compared with the recovery exercises. |
| `/root/grub.cfg.image` | The boot menu before install; compared after removal for byte-identical restoration. |
| `/root/grub.cfg.regen` | `grub-mkconfig` output; compared with the real menu. |
| `/root/needs-reboot` | Left by the lock recovery exercise; the guest reboots into the secure_sudo kernel after it. |

## Entries

- Installer wrapper: `install/ubuntu-modprobe.sh` — root-only, verified
  archive, single confirmation; added 2026-11-27.
- Ubuntu-specific VM test: `tests/vm/distro/run-install-test.sh` —
  full install, trial boot, commit, rollback and removal on a clean cloud
  image; added 2026-11-27.
- VM test skeleton: `tests/vm/distro/guest-snapshot.sh` and
  `recovery-exercises.sh` — used by every distro test as well as Ubuntu;
  check-in date per file.

## Changing this method safely

- Changing the wrapper changes the install path an operator takes. The
  command pages in `docs/commands/` and the install guide describe the
  exact same flow, so every edit is a documentation change too.
- The options table in this file and `docs/commands/ubuntu-modprobe.md`
  must stay in step (checked by
  `ci/check-command-docs.py`); an option added here, with a behaviour,
  but not to the command page, fails the gate.
- The Ubuntu-specific entries in the tables above are for the VM test
  and the wrapper; distro-independent behaviour is in
  `docs/INSTALL.md` method 7 and the `install.sh` command page.
- The wrapper does not change `/etc/modprobe.d` and never will: signature
  enforcement is a kernel parameter, not a modprobe.d file (see
  `[features/driver-blacklist.md](../features/driver-blacklist.md)`).
