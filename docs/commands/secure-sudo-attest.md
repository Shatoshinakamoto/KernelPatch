<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo attest <quote|ak|digest>`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Remote attestation (TODO P2-1). Full guide: [ATTESTATION.md](../ATTESTATION.md).

| Form | What it does |
|---|---|
| `attest quote --nonce HEX [--pcrs 0,1,...]` | Prints a bundle (JSON) for `secure-sudo-attest-verify` on another machine. It holds a host report (kernel, boot id, command line, whether the secure_sudo LSM is active, live policy digest and lock state, Secure Boot, the firmware TPM event log and its digest) and a TPM quote of the boot PCRs (default `0,1,2,3,4,5,7,8,9`; plus 6 and 10 when IMA is measuring) that signs `sha256(nonce \|\| report)`. The IMA log, when there is one, is read after the quote and added to the bundle. The nonce must be at least 16 bytes of hex from the verifier. |
| `attest ak` | Prints the attestation key's public part and name. |
| `attest quote ... --ek` / `attest ek` | Adds (or prints alone) the TPM's endorsement keys: RSA 2048, plus ECC P-256 and P-384 when the TPM has certificates for them. Each comes with the manufacturer's EK certificate from NV, for `enroll --ek-ca`. |
| `attest activate CHALLENGE` | Answers the verifier's credential-activation challenge (`TPM2_ActivateCredential`). The TPM recovers the secret only if the challenge was made for this TPM's EK and AK. Prints the response for `secure-sudo-attest-verify activate`. |
| `attest digest` | Prints `policy_sha256=<hex> locked=<0\|1>`, the digest of the policy that is currently loaded in the kernel (settings and every list). Use it with `--allow-policy` when you enroll. |

Needs root and a TPM. The key is a restricted primary key derived from the
TPM's owner seed, so nothing is stored. While locked, the tool may still
open the TPM because it is in the default `tpm_openers` list. The quote
proves the boot chain. On a kernel with policy measurement, the bundle also
carries the kernel's `policy_log` and quotes its PCR (13 by default), so the
verifier proves the policy too (`"policy_source": "measured"`). That needs
a locked policy whose `tpm_openers` holds nothing that can extend any PCR;
the defaults qualify (ATTESTATION.md, "What this proves").

The verifier replays the firmware event log against PCRs 0-9 (naming the
event that changed when the boot chain differs) and the IMA log against
PCR 10. `secure-sudo-attest-verify eventlog FILE` and `secure-sudo-attest-verify
ima BUNDLE [--ima-reference SHA256SUMS] [--list]` show them; `verify` takes
`--ima-reference FILE` and `--ima-unknown report|fail`, and `enroll` takes
`--ignore-eventlog` and `--ignore-ima` (ATTESTATION.md). `enroll --ek-ca
ROOT.pem [--ek-intermediate ICA.pem] [--ek-cert FILE] [--ek-template T] [--no-aia]`
checks the EK certificate (fetching missing intermediates from its AIA URL) and writes a
challenge; `secure-sudo-attest-verify activate HOST.json --response FILE`
finishes the binding (ATTESTATION.md, "Endorsement key and credential
activation").

```sh
N=$(secure-sudo-attest-verify nonce)                         # verifier
sudo secure-sudo attest quote --nonce "$N" > bundle.json     # host
secure-sudo-attest-verify verify bundle.json --host hosts/web1.json --nonce "$N" --max-age 300
```

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
