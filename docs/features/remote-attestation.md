<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Remote attestation and measured policy

## Overview

Prove to a separate, trusted machine that a host booted the firmware, boot loader, kernel and policy it should have, using a TPM quote.

## How it works

`secure-sudo attest quote` returns a TPM quote of the boot PCRs that signs the verifier's nonce together with a host report. `secure-sudo-attest-verify` on a trusted machine checks it against a host record enrolled on a trusted boot ([ATTESTATION.md](../ATTESTATION.md)).

the LSM measures every policy change it accepts (knobs, lists, the lock) into PCR 13 with a securityfs log, and marks any extend it did not make. The verifier replays the log, so the policy and lock state are measured, not reported (SECURITY_REVIEW #68). The verifier also replays the firmware event log (it names the boot event that changed, and checks the measured Secure Boot state and command line) and the IMA log against PCR 10 (optionally against a reference list of file hashes).

**Code:** [`userspace/attest/`](../../userspace/attest/), [`kernel/security/secure_sudo/ss_measure.c`](../../kernel/security/secure_sudo/ss_measure.c).

Full write-up: [ATTESTATION.md](../ATTESTATION.md).

## How it is secure

**Threat:** a host that booted a different firmware, boot loader, kernel, initramfs or command line (an evil-maid or bootkit change, or a kernel without secure_sudo) still looks normal to its operator.

**Standards:** NIST SI-7, SI-7(9) (verify boot process), SC-34, AU-10; CWE-345.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** a TPM 2.0. Enrollment is trust on first use unless the verifier checks the TPM's EK certificate against the manufacturer CA and runs credential activation (`--ek-ca`), which binds the attestation key to a certified TPM (an RSA 2048, ECC P-256 or ECC P-384 EK).

**Commands:** [secure-sudo-attest](../commands/secure-sudo-attest.md), [attest-tools](../commands/attest-tools.md).

```sh
secure-sudo-attest-verify nonce                       # on the trusted verifier
sudo secure-sudo attest quote --nonce NONCE > bundle.json # on the host
secure-sudo-attest-verify enroll bundle.json --nonce NONCE --out host.json
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| tpm2-tss (ESYS) | distro package | TPM quotes | not checked for this page |
| OpenSSL | distro package (3.x) | signature checks on the verifier | not checked for this page |
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

The boot chain is proven, because root cannot forge a quote or set a PCR. The measured policy is proven only once locked, and only if nothing on `tpm_openers` can extend arbitrary PCR values (the defaults leave out systemd-pcrextend and tpm2-abrmd for this; a host that adds them back needs `--accept-pcr-extenders`). A process that opened the TPM before the lock could append events after the kernel's last one. A firmware-menu TPM clear changes the key, and the verifier reports it.

## Troubleshooting

- **verify fails after a firmware update.** PCRs changed; re-enroll from a trusted boot (`enroll --previous`), see [ATTESTATION.md](../../ATTESTATION.md).
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `tests/userspace/test-attest.sh` (software TPMs: enroll, verify, wrong and replayed nonces, edited reports and PCR values, another TPM, a PCR change, re-enrollment with `--previous`, the CLI digest, every way to falsify the measured log, real OVMF/GRUB/IMA logs, and an EK-certified software TPM for credential activation), and the in-kernel `ss-functest` P2-1 checks against a software TPM in the guest.
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
