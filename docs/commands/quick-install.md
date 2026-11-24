<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `install/quick-install.sh`: guided one-machine install

Verifies a release archive (or uses the checkout it sits in), runs the
installer's preflight, asks, then runs `install/install.sh` to build and
install the secure_sudo kernel and userspace. It adds verification and a
confirmation step; all install logic stays in `install.sh`. Guide:
[INSTALL.md, method 1](../INSTALL.md#method-1-quick-install).

```
quick-install.sh [--archive FILE [--sha256 FILE]
                  [--signature FILE --signer-key FILE --signer-fpr FPR]]
                 [--dest DIR] [--yes] [--dry-run] [--no-tpm-lockout]
                 [--stig scan|remediate] [--with-addons] [--initramfs]
```

**Privileges:** root (it installs a kernel). It refuses to run otherwise.

## Options

| Option | Argument | Default | What it does | Security note |
|---|---|---|---|---|
| `--archive` | path to `secure_sudo-X.Y.Z.tar.gz` | none: use the checkout the script is in | Install from a release archive. The archive is copied into a private work directory, checked, and unpacked there for the preflight. | Without it you trust the checkout; check out a tag or commit you reviewed. |
| `--sha256` | path | `<archive>.sha256` | The checksum file to check the archive against. Only its first field, the hash, is used. | A mismatch stops everything before anything is unpacked (NIST SI-7). |
| `--signature` | path to `<archive>.sha256.asc` | none | Detached OpenPGP signature over the checksum file. Needs `--signer-key` and `--signer-fpr`. | Checked in a throwaway keyring holding only `--signer-key` (SI-7(15)). |
| `--signer-key` | path to an armored public key | none | The key to check `--signature` with. | Get it and its fingerprint through a channel other than the download. |
| `--signer-fpr` | 40 hex digits | none | The fingerprint that must have made the signature (primary key or subkey). | Pins the signer: a valid signature by any other key is refused. |
| `--dest` | absolute path, no `..` | `/opt/secure_sudo` | Where the verified archive is kept (`<dest>/<archive name>/`), only after you confirmed. Later `verify --commit`, `rollback` and `uninstall` run from there. | Root-owned 0755; an existing directory is refused, never overwritten. |
| `--yes` | – | ask | Do not ask before installing. | Use it only after you read a `--dry-run` of the same archive. |
| `--dry-run` | – | off | Verify and run the preflight only; change nothing (nothing is written to `--dest`). | |
| `--no-tpm-lockout` | – | lockout on | Passes `SS_TPM_LOCKOUT=0`: do not set a TPM lockout password. | Without the lockout, root can clear the TPM. With it, write the password (shown once) down offline. |
| `--stig` | `scan` or `remediate` | none | Passes `STIG=` to `install.sh` (a STIG scan, or remediation, after the install). | `remediate` changes PAM, SSH, audit and the firewall: run `scan` first ([STIG.md](../STIG.md)). |
| `--with-addons` | – | off | Afterwards run `temporary/install-temporary.sh` (installs the add-ons, enables nothing). | Each add-on's enforcing mode stays off until you turn it on ([ADDONS.md](../ADDONS.md)). |
| `--initramfs` | – | off | With `--with-addons`: also install the BootGuard initramfs stage. | See [BOOT_ASSURANCE.md](../BOOT_ASSURANCE.md). |
| `-h`, `--help` | – | – | Print the header (what it does, controls, usage). | |

Every option value is allow-listed. Values are never passed through a shell
string (CWE-78, CWE-20).

## What is checked before anything is changed

1. The archive's SHA-256 against the checksum file (always with `--archive`).
2. The signature over the checksum file, by the pinned fingerprint (with `--signature`).
3. The archive's members: refused if any has an absolute path or `..`, is a
   link pointing outside the archive, is a device or other special file, or if
   there is more than one top directory (CWE-22, CWE-59).
4. `install.sh preflight`: a blocker stops the run.
5. Your answer (unless `--yes`). Without a terminal and without `--yes` it
   stops and changes nothing.

It never downloads anything. You download the release, it verifies it
(INSTALL.md, "Verify a release").

## Environment, output and exit codes

- **Reads:** nothing from the environment. It sets `SS_TPM_LOCKOUT` and
  `STIG` for `install.sh` from its options.
- **Output:** `quick-install: ...` progress lines, the preflight and the
  installer's own output, then the next steps (reboot once, `install.sh verify --commit`).
- **Exit codes:** `0` done, a dry run passed, or you answered no; `1` a check
  or step failed (the message says which; nothing after it ran); `2` usage error
  or a refused option value.

## Examples

```sh
# basic: from a checkout you reviewed
sudo bash install/quick-install.sh --dry-run
sudo bash install/quick-install.sh

# common: a downloaded release, verify first, then install
sudo bash quick-install.sh --archive ~/dl/secure_sudo-0.12.0.tar.gz --dry-run
sudo bash quick-install.sh --archive ~/dl/secure_sudo-0.12.0.tar.gz

# advanced: signed release, unattended, with the add-ons and a STIG scan
sudo bash quick-install.sh --archive secure_sudo-0.12.0.tar.gz \
    --signature secure_sudo-0.12.0.tar.gz.sha256.asc \
    --signer-key maintainer.asc --signer-fpr 0123456789ABCDEF0123456789ABCDEF01234567 \
    --yes --with-addons --stig scan
```

Tests: `tests/install/test-quick-install.sh` (root-only; a stub `install.sh`
records the calls, so nothing is installed).
