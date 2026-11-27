<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `install/ubuntu-modprobe.sh`: Ubuntu modprobe-compatible install

Guided Ubuntu 24.04 install of secure_sudo that is compatible with the
`modprobe` interface: signature-enforced module loading is a kernel build
option (`CONFIG_MODULE_SIG_FORCE`), not a file in `/etc/modprobe.d`, and the
modprobe sysctl is frozen by the KernelGuard feature for root as well as for
every user. It verifies a release archive, runs `install.sh preflight`, asks
once, then runs the installer.

Guide: [INSTALL.md, method 7](../INSTALL.md#method-7-ubuntu-modprobe-compatible-install).

```
ubuntu-modprobe.sh [--archive FILE [--sha256 FILE]
                    [--signature FILE --signer-key FILE --signer-fpr FPR]]
                   [--dest DIR] [--yes] [--dry-run] [--no-tpm-lockout]
                   [--stig scan|remediate] [--with-addons] [--initramfs]
                   [--with-modprobe-check]
```

**Privileges:** root (it installs a kernel). Refuses to run otherwise.

## Options

| Option | Argument | Default | What it does | Security note |
|---|---|---|---|---|
| `--archive` | path to `secure_sudo-X.Y.Z.tar.gz` | none: use the checkout it sits in | Install from a release archive. Copied into a private 0700 work directory, checked, and unpacked there. | Without it you trust the checkout; check out a tag or commit you reviewed. |
| `--sha256` | path | `<archive>.sha256` | Checksum file for `--archive`. Only the first field, the hash, is used. | A mismatch stops everything before anything is unpacked (NIST SI-7). |
| `--signature` | path to `<archive>.sha256.asc` | none | Detached OpenPGP signature over the checksum file. Needs `--signer-key` and `--signer-fpr`. | Checked in a throwaway keyring holding only `--signer-key` (SI-7(15)). |
| `--signer-key` | path to an armored public key | none | Key used to check `--signature`. | Get it and its fingerprint through a channel other than the download. |
| `--signer-fpr` | 40 hex digits | none | Fingerprint that must have made the signature (primary key or subkey). | Pins the signer; a valid signature by any other key is refused. |
| `--dest` | absolute path, no `..` | `/opt/secure_sudo` | Where the verified archive is kept (`<dest>/<archive name>/`), after you confirmed. Later `install.sh verify --commit`, `rollback` and `uninstall` run from there. | Root-owned 0755; an existing directory is refused, never overwritten. |
| `--yes` | – | ask | Do not ask before installing. | Use only after you read a `--dry-run` of the same archive. |
| `--dry-run` | – | off | Verify, run the preflight only; change nothing (nothing is written to `--dest`). | |
| `--no-tpm-lockout` | – | lockout on | Passes `SS_TPM_LOCKOUT=0`: do not set a TPM lockout password. | Without the lockout, root can clear the TPM. With it, write the password (shown once) down offline. |
| `--stig` | `scan` or `remediate` | none | Passes `STIG=` to `install.sh` (a STIG scan, or remediation after the install). | `remediate` changes PAM, SSH, audit and the firewall: run `scan` first (STIG.md). |
| `--with-addons` | – | off | Afterwards run `temporary/install-temporary.sh` (installs the add-ons, enables nothing). | Each add-on's enforcing mode stays off until you turn it on (ADDONS.md). |
| `--initramfs` | – | off | With `--with-addons`: also install the BootGuard initramfs stage. | See BOOT_ASSURANCE.md. |
| `--with-modprobe-check` | – | off | After the install, one read-only exercise: build an unsigned and a signed test module, then `modprobe --test` shows the unsigned one refused and the signed one loaded (signature enforcement active). Never installs anything; removes its temporary files. | Demonstrates `CONFIG_MODULE_SIG_FORCE` at run time; needs the kernel headers and a compiler. |

Every option value is allow-listed. Values are never passed through a shell
string (CWE-78, CWE-20).

## What is checked before anything is changed

1. The archive's SHA-256 against the checksum file (with `--archive` anyway).
2. The signature over the checksum file, by the pinned fingerprint (with
   `--signature`).
3. The archive's members: refused if any has an absolute path or `..`, is a
   link pointing outside the archive, is a device or other special file, or if
   there is more than one top directory (CWE-22, CWE-59).
4. `install.sh preflight`: a blocker stops the run.

## Environment, output and exit codes

- **Reads:** nothing from the environment. It sets `SS_TPM_LOCKOUT` and
  `STIG` for `install.sh` from its options.
- **Output:** `ubuntu-modprobe: ...` progress lines, the preflight and
  `install.sh`'s own output, then the next steps (reboot once, `install.sh
  verify --commit`).
- **Exit codes:** `0` done, a dry run passed, or you answered no; `1` a check
  or step failed (the message says which; nothing after it ran); `2` usage
  error or a refused option value.

## Examples

```sh
# basic: review a checkout first
sudo bash install/ubuntu-modprobe.sh --dry-run
sudo bash install/ubuntu-modprobe.sh

# common: installed from a downloaded release, verify first
sudo bash ubuntu-modprobe.sh --archive ~/dl/secure_sudo-0.12.0.tar.gz --dry-run
sudo bash ubuntu-modprobe.sh --archive ~/dl/secure_sudo-0.12.0.tar.gz

# signed release, unattended, with the add-ons and a STIG scan
sudo bash ubuntu-modprobe.sh --archive secure_sudo-0.12.0.tar.gz \
    --signature secure_sudo-0.12.0.tar.gz.sha256.asc \
    --signer-key maintainer.asc --signer-fpr 0123456789ABCDEF0123456789ABCDEF01234567 \
    --yes --with-addons --stig scan

# read-only proof that the installed kernel refuses unsigned modules
sudo bash ubuntu-modprobe.sh --archive ~/dl/secure_sudo-0.12.0.tar.gz \
    --sha256 ~/dl/secure_sudo-0.12.0.tar.gz.sha256 --with-modprobe-check
```

## Related

- [INSTALL.md, method 7](../INSTALL.md#method-7-ubuntu-modprobe-compatible-install)
- [install/install.sh](install-sh.md)
- [quick-install.sh](quick-install.md)
- [driver_blacklist.conf](files/driver_blacklist.md) and
  [features/driver-blacklist.md](../features/driver-blacklist.md) — why signature
  enforcement is a kernel parameter, not modprobe.d
- [features/sysctlguard.md](../features/sysctlguard.md) — the modprobe sysctl is
  frozen for root as well

## Tests

`tests/install/test-ubuntu-modprobe.sh` (root-only; the stub `install.sh`
records the calls, so nothing is installed). The full install scenario is run
in the Ubuntu 24.04 VM test (`tests/vm/distro/run-install-test.sh`): install,
trial reboot, commit, `module.sig_enforce=Y`, the modprobe control and rollback
are archived under `HistoryTest/runs/`.
