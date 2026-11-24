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
| [commands/quick-install.md](commands/quick-install.md) | `install/quick-install.sh`: the guided one-machine install, every option |
| [commands/history-test.md](commands/history-test.md) | `scripts/history_test.py`, the HistoryTest recorder |
| [CONFIGURATION.md](CONFIGURATION.md) | Every configuration file and key |
| [configuration/secure-sudo-conf.md](configuration/secure-sudo-conf.md) | `secure-sudo.conf`: every key's type, range, defaults, security impact and NIST reference |
| [configuration/net-conf.md](configuration/net-conf.md) | `net.conf`: what the network modes treat as the LAN, and the stop behaviour |
| [configuration/ansible-vars.md](configuration/ansible-vars.md) | The Ansible role's variables: allowed values, defaults, security impact |
| [configuration/pheonixbox-conf.md](configuration/pheonixbox-conf.md) | `pheonixbox.conf`: the protected paths and the snapshot trust mode |
| [files/blacklist.md](files/blacklist.md) | `blacklist.conf`: commands non-sudo users may not run (#2) |
| [files/setid_exec_allow.md](files/setid_exec_allow.md) | `setid_exec_allow.conf`: setuid/setgid programs non-sudo users may still run (#1b) |
| [files/tmp_exec_allow.md](files/tmp_exec_allow.md) | `tmp_exec_allow.conf`: exec exemptions in /tmp, /var/tmp, /dev/shm (#12) |
| [files/node_allowed_children.md](files/node_allowed_children.md) | `node_allowed_children.conf`: what a Node.js process may start (#11) |
| [files/node_sea_binaries.md](files/node_sea_binaries.md) | `node_sea_binaries.conf`: self-contained Node binaries to guard (#11) |
| [files/driver_blacklist.md](files/driver_blacklist.md) | `driver_blacklist.conf`: kernel modules refused at load (#6) |
| [files/timevault_allow.md](files/timevault_allow.md) | `timevault_allow.conf`: the hash-pinned programs allowed while TimeVault is engaged (#13) |
| [files/home_map.md](files/home_map.md) | `home_map.conf`: each user's writable home (#4) |
| [files/home_write_allow.md](files/home_write_allow.md) | `home_write_allow.conf`: extra writable prefixes for all non-sudo users (#4) |
| [files/binvault_allow.md](files/binvault_allow.md) | `binvault_allow.conf`: directories exempt from BinaryVault (#17) |
| [files/prguard_allow.md](files/prguard_allow.md) | `prguard_allow.conf`: programs exempt from the runtime memory guard (#20) |
| [files/tpm_openers.md](files/tpm_openers.md) | `tpm_openers.conf`: programs that may use the TPM once locked (#5, G4) |
| [configuration/driverguard-conf.md](configuration/driverguard-conf.md) | Add-on `driverguard.conf`: module tree, backups, mode, baseline trust |
| [configuration/bootguard-conf.md](configuration/bootguard-conf.md) | Add-on `bootguard.conf`: boot directory, staged restore, baseline trust |
| [configuration/biosguard-conf.md](configuration/biosguard-conf.md) | Add-on `biosguard.conf`: what the detection-only firmware fingerprint covers |
| [configuration/procguard-conf.md](configuration/procguard-conf.md) | Add-on `procguard.conf`: process allowlist enforcement and quarantine |
| [files/procguard_allow.md](files/procguard_allow.md) | Add-on `procguard_allow.conf`: executables ProcGuard allows |
| [configuration/tamperwatch-conf.md](configuration/tamperwatch-conf.md) | Add-on `tamperwatch.conf`: tamper attribution and quarantine |
| [configuration/logging-conf.md](configuration/logging-conf.md) | Add-on `logging.conf`: local logs, off-box shipping, notifications |
| [configuration/locus-conf.md](configuration/locus-conf.md) | Add-on `locus.conf`: the rotating-location allocator |
| [configuration/locus-client-conf.md](configuration/locus-client-conf.md) | Add-on `locus-client.conf`: where guards ask for a location |
| [configuration/gui-conf.md](configuration/gui-conf.md) | Add-on `gui.conf`: the local console's address and read-only/admin mode |
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
| [INSTALL.md](INSTALL.md) | Every way to install: quick install, step by step, build once, Ansible, Secure Boot, offline; verify a release |
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
