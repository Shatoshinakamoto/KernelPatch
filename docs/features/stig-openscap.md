<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# STIG and OpenSCAP tooling

## Overview

**STIG / OpenSCAP:** `scripts/stig-harden.sh` scan + two-pass remediate + known-issue patches; real results: DISA Ubuntu 24.04 STIG 61 pass / 1 fail in a container and 206 pass / 11 fail / 0 error in a VM after two passes (each remaining rule classified; final VM rescan pending), CIS L2 Server 190 / 17. See [docs/STIG.md](../STIG.md) and [docs/OSCAP_BUGS.md](../OSCAP_BUGS.md). (feature #18)

## How it works

`install-encrypted.sh` + `deploy-encrypted.yml`. The source bundle is encrypted (age) and decrypted into tmpfs for the build. The kernel and module are signed with an enrolled MOK for Secure Boot, and the install is optionally a signed UKI.

**Code:** [`scripts/stig-harden.sh`](../../scripts/stig-harden.sh), [`scripts/oscap-results.py`](../../scripts/oscap-results.py), [`scripts/cis-nftables.sh`](../../scripts/cis-nftables.sh).

Full write-up: [STIG.md](../STIG.md).

## How it is secure

**Threat:** configuration drift from a hardened baseline.

**Standards:** NIST CM-6, RA-5, CA-7; DISA STIG Ubuntu 24.04; CIS Ubuntu 24.04 L2.

Runs as root from root-owned files; it is not a boundary against an attacker who already has root on an unlocked host. The general model: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** OpenSCAP and the SCAP Security Guide; the Ubuntu 24.04 profile.

**Commands:** [stig-harden](../commands/stig-harden.md), [oscap-results](../commands/oscap-results.md), [cis-nftables](../commands/cis-nftables.md).

```sh
sudo /usr/libexec/secure-sudo/stig-harden.sh --scan
sudo /usr/libexec/secure-sudo/stig-harden.sh --remediate     # scan, fix, rescan
sudo STIG=scan ./install/install.sh
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| OpenSCAP (oscap) | distro package | scanner | not checked for this page |
| SCAP Security Guide content | distro package or pinned datastream | STIG/CIS rules | not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

A passing scan shows the configuration matches the rules. It does not show that secure_sudo stops any attack. Accepted exceptions: FIPS mode (`is_fips_mode_enabled`, a self-built kernel cannot be FIPS-certified) and `service_sssd_enabled`. CIS's default-deny nftables rules are left out (OSB-16). Only the Ubuntu 24.04 STIG profile is tested.

## Troubleshooting

- **A rule fails in a container.** Container scans are diagnostics only; see [OSCAP_BUGS.md](../../OSCAP_BUGS.md) for each known result.

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** the CI STIG release gate on 6.12.114 (16/16), `tests/oscap/stig-gate.sh`, `test-oscap-results.sh`.
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
