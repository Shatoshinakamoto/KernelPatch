# secure_sudo documentation index

Every page in `docs/`, with one line on what it covers. New pages are linked
here (CLAUDE.MD section 5).

## Records kept with every change

| Page | What it is |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | Every addition, change, fix and removal, newest first (Keep a Changelog) |
| [SECURITY-LOG.md](SECURITY-LOG.md) | Every security patch, hardening change, CVE remediation and accepted risk |
| [SECURITY_REVIEW.md](SECURITY_REVIEW.md) | The full security review: each finding (#1 onward), its cause, fix and NIST controls |
| [ROADMAP_STATUS.md](ROADMAP_STATUS.md) | Where each Strategic TODO item stands, with evidence |
| [../HistoryTest/README.md](../HistoryTest/README.md) | The test-run archive: rules, layout and the index of every archived run |

## Overview and design

| Page | What it is |
|---|---|
| [FEATURE_MAP.md](FEATURE_MAP.md) | The merged feature map: every protection and where it lives |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat model and the supported deployment profile |
| [SUPPORT.md](SUPPORT.md) | Supported kernels, distributions and architectures, and the end-of-support policy |
| [MAINTENANCE.md](MAINTENANCE.md) | Vulnerability triage, security-fix releases, kernel/LTS tracking, dependencies, deprecation |

## Reference

| Page | What it is |
|---|---|
| [COMMANDS.md](COMMANDS.md) | The `secure-sudo` CLI and the other installed commands |
| [SCRIPTS.md](SCRIPTS.md) | Every script in `scripts/`, `ci/`, `install/` and `tests/`, with its flags |
| [commands/history-test.md](commands/history-test.md) | `scripts/history_test.py`, the HistoryTest recorder |
| [CONFIGURATION.md](CONFIGURATION.md) | Every configuration file and key |
| [EVENTS.md](EVENTS.md) | Event and log record formats, severities, integrations |

## Features in depth

| Page | What it is |
|---|---|
| [ADDONS.md](ADDONS.md) | The temporary/ add-ons (ProcGuard, DriverGuard, BiosGuard, BootGuard, Locus, console) |
| [BINARYVAULT.md](BINARYVAULT.md) | BinaryVault (#17) |
| [PHEONIXBOX.md](PHEONIXBOX.md) | PheonixBox (#21) |
| [ATTESTATION.md](ATTESTATION.md) | Remote attestation and measured boot (P2-1) |
| [BOOT_ASSURANCE.md](BOOT_ASSURANCE.md) | Boot and firmware assurance (P2-4) |

## Operations

| Page | What it is |
|---|---|
| [RECOVERY.md](RECOVERY.md) | Recovery from a bad install, lockout or failed boot |
| [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) | Incident response runbook and `secure-sudo contain` |
| [HARDWARE_SMOKE_TEST.md](HARDWARE_SMOKE_TEST.md) | The hardware smoke test a VM cannot cover |

## Compliance

| Page | What it is |
|---|---|
| [STIG.md](STIG.md) | DISA STIG / OpenSCAP and CIS hardening with `stig-harden.sh` |
| [OSCAP_BUGS.md](OSCAP_BUGS.md) | Every OpenSCAP issue (OSB-01 onward), its patch and results |
| [stig/results/](stig/results/) | Recorded STIG and CIS scan reports |
| [vm/results/](vm/results/) | Recorded VM test results |
