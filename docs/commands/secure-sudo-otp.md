<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo otp <subcommand>`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Rotating one-time-password sudo helper (#14/#15). Delegated to
`/usr/bin/secure-sudo-otp`; each subcommand does its own root check.

| Subcommand | What it does |
|------------|--------------|
| `otp setup [--prefix]` | generate a new TOTP seed; `--prefix` also sets a secret prefix word |
| `otp show-key` | print the manual-entry key and `otpauth://` URI |
| `otp show-qr` | render a scannable QR to a root-only PNG and print its `file://` path |
| `otp verify [--pam]` | verify a password; `--pam` reads it from stdin (used by the PAM module) |
| `otp reset [--prefix]` | regenerate the seed (keeps the prefix unless `--prefix`) |
| `otp disable` | shred and remove all OTP secret material (the sealed key too) |
| `otp key-store` | say where the master key is: `tpm2` (sealed to this machine's TPM) or `file` |
| `otp seal` | move the current master key into the TPM; the seed and the authenticator stay as they are |
| `otp unseal` | move it back to the root-only key file (before replacing or clearing the TPM) |

`otp setup` and `otp reset` take `--key-store=auto|tpm2|file`. `auto` (the
default) seals the master key with `systemd-creds` when the TPM works and
uses the root-only key file otherwise, and says which; `tpm2` fails, changing
nothing, if it cannot seal. No PCRs are bound, so firmware and Secure Boot
updates do not lock the admin out; a sealed copy only unseals on this
machine's TPM. If the TPM is replaced or cleared, `otp reset
--key-store=file` (as root, at the console) sets up a new seed.

```sh
sudo secure-sudo otp setup --prefix
sudo secure-sudo otp show-qr
```

See [CONFIGURATION.md](../CONFIGURATION.md#otp) for how the secret is stored and
how to wire OTP into PAM.

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
