<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Rotating OTP sudo password and encrypted secret

## Overview

**Rotating OTP sudo password:** prefix + 6-digit TOTP, verified by `pam_secure_otp`; QR rendered locally (`userspace/otp`). (feature #14/#15)

## How it works

`pam_secure_otp` checks `prefix$code`. The CLI covers `otp setup / show-qr / show-key / verify / reset / disable`. `show-qr` writes a root-only PNG and prints its `file://` URL.

**Code:** [`userspace/otp/`](../../userspace/otp/), [`userspace/pam/`](../../userspace/pam/).

## How it is secure

**Threat:** a stolen or guessed account password alone is enough for sudo; an observed code is replayed.

**Standards:** NIST IA-2(1), IA-2(6), IA-5, SC-28, SC-12; STIG SRG-OS-000105 / CCI-000765; CWE-308, CWE-312.

Runs as root from root-owned files; it is not a boundary against an attacker who already has root on an unlocked host. The general model: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `pam_secure_otp` in sudo's PAM stack, set up before it is wired in (recovery exercise E3); a correct clock.

**Commands:** [secure-sudo-otp](../commands/secure-sudo-otp.md).

```sh
sudo secure-sudo otp setup
sudo secure-sudo otp show-qr      # root-only PNG, rendered locally
sudo secure-sudo otp verify
# then add after the password include in /etc/pam.d/sudo:
auth  required  pam_secure_otp.so
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| libqrencode | distro package | local QR rendering | not checked for this page |
| OpenSSL libcrypto | distro package (3.x) | AES-256-GCM | not checked for this page |
| libcrypt (yescrypt) | distro package | prefix hash | not checked for this page |
| systemd-creds | distro package | TPM sealing of the master key | not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

A real-time phishing relay still works. The secret is AES-256-GCM under a master key that is sealed to the TPM when the machine has a working one (gap G3, built): a copy of the disk or of `/var/lib/secure_sudo/otp` is then useless elsewhere. No PCRs are bound, so root on the running machine can still have the TPM unseal it, and a TPM replaced or cleared means `otp reset`. Without a TPM the key is a root-only file, and anyone who reads an unencrypted disk can decrypt the seed (`secure-sudo otp key-store` says which). Codes are valid for their time step (each accepted once). It protects only the PAM services it is added to.

## Troubleshooting

- **Codes are refused.** Check the clock (TOTP needs it in sync) and that the code was not already used; a code is accepted once.
- **Locked out of sudo.** Root on the local console keeps the normal password path ([RECOVERY.md](../../RECOVERY.md)).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `tests/userspace/test-otp.sh` (with two software TPMs in CI: sealed key verifies, another TPM cannot unseal it, seal/unseal keep the seed, clean fallback without a TPM), the Ubuntu VM run with a software TPM on the secure_sudo kernel (G3 steps), `test-pam.sh` (real `pam_unix` stacks as root), recovery exercise E3.
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
