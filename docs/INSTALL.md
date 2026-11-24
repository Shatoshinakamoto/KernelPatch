<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# Installing the SatoshiNakamoto Kernel Patch (secure_sudo)

The SatoshiNakamoto Kernel Patch is secure_sudo: a Linux Security Module
built into a kernel, plus userspace tools. Installing it means **installing a new kernel**: every method below
puts the secure_sudo kernel *next to* your running kernel, boots it **once**
(a trial boot), and makes it the default only after you checked it. If the new
kernel does not come up, the machine boots the previous kernel by itself.

All methods run the same installer, `install/install.sh`, so they share its
safety rules: verified kernel source, a removable distro package, a file
manifest, a trial boot, rollback and a clean uninstall
([SCRIPTS.md](SCRIPTS.md#installinstallsh) lists every subcommand and variable).

## Contents

1. [Before you start](#before-you-start)
2. [Choose a method](#choose-a-method)
3. [Verify a release](#verify-a-release)
4. [Method 1: quick install](#method-1-quick-install)
5. [Method 2: step by step](#method-2-step-by-step)
6. [Method 3: build once, install on many machines](#method-3-build-once-install-on-many-machines)
7. [Method 4: Ansible (fleets)](#method-4-ansible-fleets)
8. [Method 5: Secure Boot and an encrypted source bundle](#method-5-secure-boot-and-an-encrypted-source-bundle)
9. [Method 6: offline or air-gapped](#method-6-offline-or-air-gapped)
10. [Try it in a throwaway VM first](#try-it-in-a-throwaway-vm-first)
11. [After the install](#after-the-install)
12. [Optional: add-ons, STIG and CIS hardening](#optional-add-ons-stig-and-cis-hardening)
13. [Roll back or remove](#roll-back-or-remove)
14. [Troubleshooting](#troubleshooting)
15. [How the install is secured](#how-the-install-is-secured)
16. [Tested](#tested)

## Before you start

| Requirement | Why |
|---|---|
| x86_64, a supported distribution ([SUPPORT.md](SUPPORT.md)); Ubuntu 24.04 LTS is the tested one | The installer refuses other architectures. Debian, Fedora/RHEL, Arch and openSUSE have installer branches but no recorded run yet. |
| Root (sudo) and a **second root session** kept open the whole time | So a mistake in PAM or policy cannot lock you out ([RECOVERY.md](RECOVERY.md)). |
| ~20 GB free in `/usr/src` (only when building the kernel on this machine) | The kernel build tree. Not needed with prebuilt packages (method 3). |
| Network access to `cdn.kernel.org` and your distro's mirrors (or method 6) | Kernel source download and build/runtime packages. |
| GRUB as the bootloader (tested: BIOS and UEFI) | The trial boot uses `grub-reboot`. systemd-boot is not tested yet. |
| **Out-of-tree modules signed**, or not needed | The secure_sudo kernel refuses unsigned modules (`CONFIG_MODULE_SIG_FORCE`): NVIDIA, ZFS, VirtualBox and other DKMS modules must be signed with the kernel's key. Check `dkms status` first. |
| Secure Boot on? Then read method 5 first | An unsigned or wrongly signed kernel does not boot with Secure Boot on. |

On a real machine (not a VM), also go through
[HARDWARE_SMOKE_TEST.md](HARDWARE_SMOKE_TEST.md) once per machine model.

Packages the installer needs (it installs missing ones itself and leaves them
installed on uninstall): on Debian/Ubuntu `build-essential bc bison flex
libelf-dev libssl-dev libpam0g-dev libqrencode-dev zlib1g-dev libcrypt-dev
debhelper rsync kmod cpio zstd gnupg xz-utils curl`, and for the TPM features
`libtss2-dev tpm2-tools`. `install.sh preflight` lists exactly what it would add.

## Choose a method

| Method | For | What it needs on the target | Time |
|---|---|---|---|
| [1. Quick install](#method-1-quick-install) | one machine, guided | compiler, kernel build space | one command, then a reboot |
| [2. Step by step](#method-2-step-by-step) | one machine, full control | compiler, kernel build space | a few commands |
| [3. Build once, install many](#method-3-build-once-install-on-many-machines) | several machines of one distro release | nothing extra (prebuilt packages) | build once, minutes per machine |
| [4. Ansible](#method-4-ansible-fleets) | fleets, repeatable rollouts | SSH, Python 3 | one playbook run, one host at a time |
| [5. Secure Boot / encrypted source](#method-5-secure-boot-and-an-encrypted-source-bundle) | Secure Boot on; source must not be on disk in clear | `age`, `mokutil`, `sbsigntool` | two runs around one MOK enrollment reboot |
| [6. Offline](#method-6-offline-or-air-gapped) | no internet on the target | a kernel tree verified elsewhere | as method 2 or 3 |

## Verify a release

Releases are published as GitHub Releases with the archive
`secure_sudo-X.Y.Z.tar.gz`, its `secure_sudo-X.Y.Z.tar.gz.sha256`, an SPDX
SBOM (`secure_sudo-X.Y.Z.spdx.json`) and, when the release is signed, a
detached signature `secure_sudo-X.Y.Z.tar.gz.sha256.asc`
([MAINTENANCE.md](MAINTENANCE.md#2-security-fix-release-process)).

```sh
# download (gh, or the release page in a browser); never pipe a download into a shell
gh release download vX.Y.Z -R Shatoshinakamoto/KernelPatch -D ~/secure_sudo-release
cd ~/secure_sudo-release
sha256sum -c secure_sudo-X.Y.Z.tar.gz.sha256        # must print: OK
# signed releases: check the signature with the maintainer's key, fingerprint
# confirmed through a second channel, before trusting the .sha256 file
gpg --verify secure_sudo-X.Y.Z.tar.gz.sha256.asc secure_sudo-X.Y.Z.tar.gz.sha256
```

`install/quick-install.sh --archive` does these checks itself (method 1).
Installing from a git checkout instead: check out a tag or commit you
reviewed. Either way the **kernel** source is verified separately: `install.sh`
checks the kernel.org signature against the pinned keys in `install/keys/`
before it unpacks anything, and there is no bypass.

## Method 1: quick install

`install/quick-install.sh` is a guided wrapper around `install.sh`: it verifies
the archive (when given one), runs the preflight, asks you, installs, and tells
you the next steps. Command reference: [commands/quick-install.md](commands/quick-install.md).

From a release archive (recommended):

```sh
tar -xzf secure_sudo-X.Y.Z.tar.gz KernelPatch-merged/install/quick-install.sh   # just the script, to read it
less KernelPatch-merged/install/quick-install.sh
sudo bash KernelPatch-merged/install/quick-install.sh \
    --archive ~/secure_sudo-release/secure_sudo-X.Y.Z.tar.gz --dry-run   # verify + preflight, changes nothing
sudo bash KernelPatch-merged/install/quick-install.sh \
    --archive ~/secure_sudo-release/secure_sudo-X.Y.Z.tar.gz             # asks, then installs
```

With a signed release, add the signature and pin the signer:

```sh
sudo bash quick-install.sh --archive secure_sudo-X.Y.Z.tar.gz \
    --signature secure_sudo-X.Y.Z.tar.gz.sha256.asc \
    --signer-key maintainer.asc --signer-fpr <40-hex fingerprint>
```

From a git checkout you reviewed:

```sh
git clone https://github.com/Shatoshinakamoto/KernelPatch.git && cd KernelPatch
git checkout vX.Y.Z                               # a tag or commit you reviewed
sudo bash install/quick-install.sh --dry-run      # preflight only
sudo bash install/quick-install.sh                # asks, then installs
```

Useful options: `--yes` (do not ask; for scripts, after you read a dry run),
`--no-tpm-lockout` (skip setting the TPM lockout password), `--stig scan`,
`--with-addons [--initramfs]`. Then [reboot and commit](#after-the-install).

## Method 2: step by step

The same as method 1, one installer step at a time:

```sh
sudo bash install/install.sh preflight         # what would happen; changes nothing
sudo bash install/install.sh build-kernel      # download + verify kernel.org source, build the package
sudo bash install/install.sh install-kernel    # install next to the running kernel, arm the trial boot
sudo bash install/install.sh userspace         # CLI, daemon, PAM modules, OTP helper, PheonixBox
sudo bash install/install.sh tpm-lockout       # optional: TPM lockout password (shown ONCE) + disableClear
sudo bash install/install.sh verify            # check what was installed
sudo reboot                                    # boots the new kernel ONCE
sudo bash install/install.sh verify --commit   # it came up and passes: make it the default
```

`sudo bash install/install.sh` with no subcommand runs preflight, build,
install-kernel, userspace, tpm-lockout (unless `SS_TPM_LOCKOUT=0`) and verify
in one go. Variables such as `KVER`, `JOBS`, `BUILD_ROOT`, `SS_TRIAL_BOOT`,
`SS_PANIC_TIMEOUT` and `STIG` are in [SCRIPTS.md](SCRIPTS.md).

The TPM lockout password is printed once and not stored on the machine. Write
it down offline: you need it to clear the TPM later.

## Method 3: build once, install on many machines

Build on one machine (a build host of the **same distro release** as the
targets), install on the others without a compiler or kernel source:

```sh
# on the build host
sudo bash install/install.sh build-kernel                 # -> /usr/src/secure_sudo-build/out/<release>/
sudo bash install/install.sh stage-userspace /tmp/ss-stage
# copy to each target (scp/rsync over SSH): the out/<release>/ directory, /tmp/ss-stage,
# and the same source tree or release archive

# on each target
sudo bash install/install.sh preflight install-kernel
sudo bash install/install.sh install-kernel /path/to/<release>/   # checks its SHA256SUMS first
sudo bash install/install.sh userspace --prebuilt /path/to/ss-stage
sudo bash install/install.sh verify && sudo reboot
sudo bash install/install.sh verify --commit
```

`out/<release>/` holds the kernel packages, `SHA256SUMS`, `build-info.txt`
(compiler, verified source hash, config hash) and an SPDX SBOM, so every
target can tell which build it got.

## Method 4: Ansible (fleets)

`install/ansible/secure_sudo.yml` with the role `install/ansible/roles/secure_sudo/`
runs methods 2 and 3 across a fleet, **one host at a time**, and stops at the
first host that fails. Per host: check variables, ship the code (the target
checks its SHA-256), preflight, install the kernel and userspace, verify,
reboot into the trial boot, check the host came back on the secure_sudo kernel,
`verify --commit`, set `net_mode`, start `secure-sudod`, `secure-sudo lint` and
`load`. A host that is already committed is left alone (the run is idempotent).

```sh
cd install/ansible
cp inventory.ini.example inventory.ini                        # list your hosts under [secure_sudo]
cp group_vars/secure_sudo.yml.example group_vars/secure_sudo.yml   # optional settings
ansible-playbook -i inventory.ini secure_sudo.yml --syntax-check
ansible-playbook -i inventory.ini secure_sudo.yml --limit canary1  # first one host
ansible-playbook -i inventory.ini secure_sudo.yml                  # then the rest
```

Common settings (all of them: [configuration/ansible-vars.md](configuration/ansible-vars.md)):

```yaml
# group_vars/secure_sudo.yml: build once (method 3), install everywhere
secure_sudo_kernel: prebuilt
secure_sudo_kernel_dir: /srv/secure_sudo/6.12.114-secure-sudo   # the build host's out/<release>/
secure_sudo_userspace_dir: /srv/secure_sudo/stage               # install.sh stage-userspace output
secure_sudo_net_mode: monitor
```

Needs ansible-core 2.14 or later on the controller, SSH and sudo to the
targets, Python 3 on the targets. The role never handles the TPM lockout
password (it would end up in Ansible's output and logs); set it on each host
at the console with `install.sh tpm-lockout` if you want it. PAM wiring and
the add-ons are off unless you turn them on. Run tags on their own:
`--tags config` (network mode and policy only), `--tags addons`.
`inventory.ini` and your `group_vars`/`host_vars` stay out of git and out of
any release archive.

The older single-play file is replaced by this role; the encrypted variant
(method 5) has its own playbook, `install/encrypted/deploy-encrypted.yml`.

## Method 5: Secure Boot and an encrypted source bundle

With Secure Boot on, the kernel must be signed with a Machine Owner Key (MOK)
that the firmware's shim trusts. `install/encrypted/install-encrypted.sh` does
that, and can also keep the source encrypted at rest (age) and build in RAM:

```sh
# workstation, once: the encrypted bundle
tar -C /path/to -c KernelPatch-merged | age -r <age-recipient> > secure_sudo-src.tar.age

# target, run 1: creates the MOK and asks mokutil to enroll it, then stops
sudo SRC_AGE=./secure_sudo-src.tar.age AGE_IDENTITY=./age.key bash install/encrypted/install-encrypted.sh
sudo reboot                     # MokManager appears: enroll the key with the password you chose
# target, run 2: builds in tmpfs, signs kernel and modules, installs (trial boot as usual)
sudo SRC_AGE=./secure_sudo-src.tar.age AGE_IDENTITY=./age.key bash install/encrypted/install-encrypted.sh
```

Variables (`MOK_KEY`, `MOK_CRT`, `MAKE_UKI`, `ESP`, `ENC_TMPFS_SIZE`, `KVER`) are
in [SCRIPTS.md](SCRIPTS.md). With your own existing MOK and the plain method 2,
set `SS_SB_KEY` and `SS_SB_CERT` instead. For several machines:
`ansible-playbook -i inventory.ini install/encrypted/deploy-encrypted.yml`
(keep the age identity in ansible-vault). MOK enrollment needs someone at
each machine's console once. Recovery: [RECOVERY.md section 2](RECOVERY.md#2-secure-boot-rejects-the-kernel-or-the-mok-enrollment-failed).

## Method 6: offline or air-gapped

On a machine with internet, fetch and verify the kernel source and the
packages, then carry them over:

- **Kernel source:** download `linux-6.12.114.tar.xz` and `.tar.sign` from
  kernel.org and verify them with `scripts/verify-kernel-source.sh` (the same
  check `install.sh` runs). On the target, point the build at the verified
  tree: `SS_KERNEL_TREE=/path/to/linux-6.12.114` and
  `SS_KERNEL_TREE_PROVENANCE=/path/to/record` (a file with a `verified_by=`
  line saying how it was checked; it is kept as the build's `kernel-source.txt`).
- **Or skip the build on the target entirely:** method 3 (prebuilt packages and
  staged userspace) needs no kernel source on the target at all.
- **Distro packages:** install the packages listed in
  [Before you start](#before-you-start) from your local mirror first;
  `install.sh preflight` then reports nothing to add.

## Try it in a throwaway VM first

The project's own VM tests build a fresh Ubuntu 24.04 guest from the
signature-checked cloud image and run the full install, trial boot, fallback,
commit, rollback and removal in it, without touching your machine. Needs Linux
with QEMU (KVM optional):

```sh
sudo bash install/install.sh build-kernel     # or reuse a build
sudo VM_TPM=1 bash tests/vm/distro/run-install-test.sh <cloud-image.img> <kernel-out-dir> /tmp/res-install
```

Details and the other VM tests: [tests/vm/distro/README.md](../tests/vm/distro/README.md).

## After the install

```sh
sudo reboot                                   # the secure_sudo kernel boots once
uname -r                                      # ends in -secure-sudo
cat /sys/kernel/security/lsm                  # lists secure_sudo (and AppArmor/SELinux)
sudo bash install/install.sh verify --commit  # make it the default
sudo secure-sudo lint && sudo secure-sudo load   # check, then apply /etc/secure_sudo/*
sudo secure-sudo status
```

Admin groups (`sudo`, `wheel`, `admin` and `%group` rules in sudoers) are
detected at install and go into `admin_gid`; after you add an admin group,
run `sudo secure-sudo detect-admins`. Then set the policy you want
([CONFIGURATION.md](CONFIGURATION.md), [configuration/secure-sudo-conf.md](configuration/secure-sudo-conf.md)).

## Optional: add-ons, STIG and CIS hardening

- **Add-ons** (ProcGuard, DriverGuard, BiosGuard, BootGuard, Locus,
  tamperwatch, the management console): `sudo bash temporary/install-temporary.sh`
  (`--initramfs` for the BootGuard initramfs stage). It enables nothing; turn
  each on as [ADDONS.md](ADDONS.md) says.
- **DISA STIG:** `sudo bash scripts/stig-harden.sh --scan`, read the report,
  then `--remediate` in a maintenance window ([STIG.md](STIG.md)). The
  installer also honours `STIG=scan` / `STIG=remediate`.
- **CIS Level 2 with its own firewall table next to secure_sudo's:**
  `sudo bash scripts/stig-harden.sh --remediate --profile xccdf_org.ssgproject.content_profile_cis_level2_server --cis-firewall`
  ([STIG.md](STIG.md); recorded run in `docs/vm/results/13-pc-cis-l2-2026-11-23/`).

## Roll back or remove

```sh
sudo bash install/install.sh rollback              # boot the previous kernel next time
sudo bash install/install.sh rollback --default    # ... and from now on
sudo bash install/install.sh uninstall --remove-pam-lines   # remove only what was installed
```

Uninstall refuses while PAM still uses the modules (`--remove-pam-lines`
removes those lines), restores every file it replaced, and keeps evidence it
must not destroy: the TimeVault quarantine, the policy history and snapshots,
an OTP that is still set up. It says what it kept. Full recovery paths:
[RECOVERY.md](RECOVERY.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `preflight: N blocking problem(s)` | a line marked `BLOCKED:` | Read the line; nothing was changed. |
| `kernel source signature` failure | the download is not signed by a pinned key | Do not work around it; download again from kernel.org. |
| the machine came back on the old kernel | the trial boot did not stay up | Expected fallback. Check the console log, `journalctl -b -1 -k`; `install.sh verify` says so too. |
| a module does not load (`module verification failed`) | it is not signed with the kernel's key | Sign it (DKMS: configure the signing key) or do without it. |
| Secure Boot refuses the kernel | MOK not enrolled or not used for signing | [RECOVERY.md section 2](RECOVERY.md#2-secure-boot-rejects-the-kernel-or-the-mok-enrollment-failed). |
| `sudo` stops working after a policy change | wrong `admin_gid`, allowlist or PAM line | Use the root session you kept open; [RECOVERY.md section 4](RECOVERY.md#4-policy-lockout). |
| quick-install: `SHA-256 MISMATCH` | the archive is damaged or not the one released | Download again; never skip the check. |
| Ansible: `came back on ... not the secure_sudo kernel` | the trial boot fell back on that host | The rollout stopped there; the host runs its old kernel. Fix, then rerun. |

## How the install is secured

| Threat | Control | Reference |
|---|---|---|
| tampered secure_sudo release | SHA-256 (and optional signature with a pinned fingerprint) checked before unpacking; no download-and-execute | NIST SI-7, SI-7(15), SR-4 |
| tampered kernel source | kernel.org signature checked against pinned keys before extraction, no bypass | SI-7, SR-4; TODO P0-4 |
| path traversal or link tricks in an archive | members with absolute paths, `..`, outside links or special files refused before extraction | CWE-22, CWE-59 |
| swapped file between check and use | quick-install hashes and unpacks a private copy; Ansible unpacks into a root-owned directory | CWE-367 |
| unbootable kernel | installed next to the running kernel, trial boot, commit only after it passed `verify`; panic reboots into the previous kernel | NIST CM-3, CP-10 |
| a bad build reaching every machine | Ansible rolls out one host at a time and stops at the first failure | CM-3 |
| a partial or wrong policy | `secure-sudo lint` before `load`; an incomplete load fails | CM-6 |
| leaking host names or secrets | inventories and vars kept out of git and releases; the TPM lockout password never passes through Ansible | CWE-200, IA-5 |
| command injection through settings | every option and variable allow-listed; no shell strings built from them | CWE-78, CWE-20 |

Installing does not by itself make a system STIG- or CIS-compliant; that needs
the hardening step and an assessment.

## Tested

| What | Result | Where |
|---|---|---|
| `install.sh` full run in an Ubuntu 24.04 VM (install, trial boot, fallback, commit, drills, rollback, removal) | 71/71 | PC, 2026-11-23, main 4885cdc |
| `tests/install/test-quick-install.sh` (verification, unsafe archives, signatures, options) | 37/37 | PC, 2026-11-24 |
| `tests/install/test-ansible.sh` (order, rollout safety, validation, syntax with ansible-core 2.16) | 25/25 | PC, 2026-11-24 |
| Ansible role (prebuilt kernel and userspace) against a fresh Ubuntu 24.04 VM: install, trial reboot, commit, `verify: OK`, secure_sudo active, `secure-sudod` active; a second run skipped install and reboot (idempotent); quick-install `--dry-run` passed on the guest and refused a tampered archive | 13/14, the one `not ok` a fault in the driver's own check (HistoryTest record has the evidence) | PC, 2026-11-24, `HistoryTest/runs/` (`vm-ansible`) |
| real hardware | not run yet | [HARDWARE_SMOKE_TEST.md](HARDWARE_SMOKE_TEST.md) |
