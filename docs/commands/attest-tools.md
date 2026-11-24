<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `userspace/attest/` (remote attestation, P2-1)

Run as root. Part of the [script reference](../SCRIPTS.md).

Installed as `/usr/libexec/secure-sudo/secure-sudo-attest`,
`/usr/libexec/secure-sudo/attest-report.sh` and
`/usr/bin/secure-sudo-attest-verify`. See [ATTESTATION.md](../ATTESTATION.md).

| Program | Runs on | What it does |
|---|---|---|
| `secure-sudo-attest ak` / `quote --nonce HEX --report FILE [--pcrs L]` | host (root) | tpm2-tss ESYS. Creates the AK primary from its fixed template, reads the PCRs, quotes them with `extraData = sha256(nonce \|\| report)`, and re-reads them (it retries up to 5 times if they changed in between). Prints JSON. It never extends, clears, or writes NV. Environment: `SS_ATTEST_TCTI` (TCTI string, default device), `SS_ATTEST_OWNER_AUTH_FILE`. |
| `attest-report.sh quote --nonce HEX [--pcrs L]` / `ak` | host (root) | Builds the report, calls the tool, and prints the bundle. Called by `secure-sudo attest`. |
| `secure-sudo-attest-verify nonce` / `enroll` / `verify` | verifier | python3 stdlib + `openssl`. Parses TPM2B_PUBLIC and TPMS_ATTEST, checks the ECDSA signature, the qualified signer name, the nonce binding, the PCR digest, the golden PCRs and the policy. `enroll --previous` keeps the same AK. Exit status 0 = every check passed; `--json` gives machine output. |

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
