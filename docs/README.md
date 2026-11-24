# SatoshiNakamoto Kernel Patch: documentation index

The documentation for secure_sudo, the SatoshiNakamoto Kernel Patch
(formerly KernelPatch; see the [README](../README.md#history-and-name)).

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

## Commands and scripts

One page per command or script, with every option (CLAUDE.MD section 5).
`ci/check-command-docs.py` keeps them in step with the code.

| Page | What it is |
|---|---|
| [`userspace/daemon/helpers/apply-net.sh`](commands/apply-net.md) | The daemon's helper that applies the `lan-only` / `public-only` nft table. |
| [`userspace/attest/`](commands/attest-tools.md) | The attestation programs: the host-side TPM quote tool and report builder, and the verifier. |
| [`ci/build-gate.sh`](commands/build-gate.md) | The release gate: lint, -Werror builds, kernel header and in-tree builds, every test suite and a reproducible package. |
| [`ci/check-addon-maturity.py`](commands/check-addon-maturity.md) | Check temporary/maturity.json against the add-on promotion rules. |
| [`ci/check-command-docs.py`](commands/check-command-docs.md) | Fail if a command, script, add-on binary or feature has no page, a copied header drifted, or a page is not indexed. |
| [`ci/check-config-docs.py`](commands/check-config-docs.md) | Fail if docs/configuration/ or docs/files/ drift from the code and templates. |
| [`ci/check-lsm-hooks.sh`](commands/check-lsm-hooks.md) | Fail if any LSM hook is registered twice (the v11 boot panic). |
| [`ci/check-process-docs.py`](commands/check-process-docs.md) | Check that SECURITY.md and docs/MAINTENANCE.md keep their required sections. |
| [`ci/check-support-matrix.py`](commands/check-support-matrix.md) | Check docs/SUPPORT.md's matrix against the code and recorded evidence. |
| [`scripts/cis-nftables.sh`](commands/cis-nftables.md) | Install or check CIS's own firewall table, `inet filter`, next to secure_sudo's `inet secure_sudo`. |
| [`userspace/daemon/helpers/contain.sh`](commands/contain-sh.md) | The helper behind `secure-sudo contain`: isolate the network, freeze or kill a process tree, preserve evidence. |
| [`scripts/detect-admin-gids.sh`](commands/detect-admin-gids.md) | Print every admin-group GID on the box as a comma list (used by the installer and `secure-sudo detect-admins`). |
| [`userspace/daemon/helpers/evidence-export.sh`](commands/evidence-export-sh.md) | The helper behind `secure-sudo evidence-export`. |
| [`userspace/daemon/helpers/evidence-verify.py`](commands/evidence-verify-py.md) | The helper behind `secure-sudo evidence-verify`. |
| [`scripts/gen-sbom.sh`](commands/gen-sbom.md) | Write the SPDX SBOM of a release, or print the source tree hash. |
| [`ci/graft-lsm.sh`](commands/graft-lsm.md) | Copy the secure_sudo LSM into a kernel source tree and register it (Kconfig, Makefile, LSM count). |
| [`scripts/history_test.py`: the HistoryTest recorder](commands/history-test.md) | `scripts/history_test.py`, the HistoryTest recorder. |
| [`install/encrypted/install-encrypted.sh`](commands/install-encrypted.md) | The encrypted-source + Secure Boot (MOK-signed) install variant. |
| [`install/install.sh`](commands/install-sh.md) | Build, install, verify, roll back and remove the kernel and userspace on every supported distro family. |
| [`temporary/install-temporary.sh`](commands/install-temporary.md) | Opt-in installer for the temporary/ add-ons; installs everything, enables nothing. |
| [`ci/lsm-compile-check.sh`](commands/lsm-compile-check.md) | Compile every LSM source file against a kernel header tree. |
| [`ci/make-release.sh`](commands/make-release.md) | Build the byte-reproducible release tarball with its SHA-256 file and SPDX SBOM. |
| [`scripts/oscap-results.py`](commands/oscap-results.md) | Count and compare OpenSCAP results; used by `stig-harden.sh` and the STIG gate. |
| [`ci/publish-release.sh`](commands/publish-release.md) | Build a release locally and upload it as a GitHub Release with `gh` (a draft unless `--publish`). |
| [`userspace/daemon/helpers/quarantine.sh`](commands/quarantine-sh.md) | The daemon's helper that moves a blocked or changed file into quarantine. |
| [`tests/run-all.sh`](commands/run-all.md) | Run every host-side test suite (TAP). |
| [`secure-sudo-addon-failure`](commands/secure-sudo-addon-failure.md) | Report a failed add-on unit through the shared add-on logging (systemd OnFailure= handler). |
| [`secure-sudo attest <quote\|ak\|digest>`](commands/secure-sudo-attest.md) | Remote attestation (TODO P2-1). |
| [`secure-sudo-biosguard`](commands/secure-sudo-biosguard.md) | BiosGuard: fingerprint the firmware and report any change. |
| [`secure-sudo-bootguard`](commands/secure-sudo-bootguard.md) | BootGuard: detect boot-partition tampering and restore the last good copy at the next boot. |
| [`secure-sudo contain ...`](commands/secure-sudo-contain.md) | Incident containment: isolate the network, lock an account, freeze a process (TODO P1-7). |
| [`secure-sudo detect-admins [-n]`](commands/secure-sudo-detect-admins.md) | Re-detect every admin group on the box (the GIDs of `sudo`, `wheel`, `admin` and any `%group`/`%#gid` rule in sudoers) and set `admin_gid` to that list, in... |
| [`secure-sudo diff` (also `load --dry-run`)](commands/secure-sudo-diff.md) | Preview what `load` would change, after lint (TODO P1-6). |
| [`secure-sudo-driverguard`](commands/secure-sudo-driverguard.md) | DriverGuard: check kernel module files against a baseline and repair them from compressed backups. |
| [`secure-sudo evidence-export OUTPUT.tar.gz [--signing-key EXTERNAL.pem]`](commands/secure-sudo-evidence-export.md) | Create a root-only, hash-manifested incident evidence bundle, optionally signed with an external key. |
| [`secure-sudo evidence-verify FILE [--trusted-key PUBLIC.pem] [--checkpoints COLLECTOR.log] [--timevault COLLECTOR.log]`](commands/secure-sudo-evidence-verify.md) | Check an evidence bundle's manifest, log chains, signature and off-box checkpoints. |
| [`secure-sudo get [<knob>]`](commands/secure-sudo-get.md) | Show the **live kernel value** of one scalar knob, or of all of them when no name is given. |
| [`secure-sudo-gui`](commands/secure-sudo-gui.md) | The local, token-protected management web console for the add-ons. |
| [`secure-sudo health [--json]`](commands/secure-sudo-health.md) | Report whether secure_sudo, its audit feed, daemon, logging and forwarding are working, and the last load's outcome. |
| [`secure-sudo history [-n N] [--json] [--verify]`](commands/secure-sudo-history.md) | Who changed policy and what happened (TODO P1-6). |
| [`secure-sudo lint [options]`](commands/secure-sudo-lint.md) | Check the configuration before it is enforced (TODO P0-6). |
| [`secure-sudo list <name>`](commands/secure-sudo-list.md) | Show a policy list's **current kernel contents** (not the on-disk file). |
| [`secure-sudo load [--force]`](commands/secure-sudo-load.md) | Read every file under `/etc/secure_sudo/` and push it into the kernel. |
| [`secure-sudo lock [-y]`](commands/secure-sudo-lock.md) | Engage the one-way configuration lock (#16). |
| [`secure-sudo-locus`](commands/secure-sudo-locus.md) | Locus: the LAN request-only allocator for the add-ons' rotating storage locations, with a read-only status page. |
| [`secure-sudo net <monitor\|host\|lan-only\|public-only>`](commands/secure-sudo-net.md) | Shortcut for `set net_mode <mode>`; also persisted. |
| [`secure-sudo node-scan [--dry-run] [--quiet] [DIR\|FILE...]`](commands/secure-sudo-node-scan.md) | Find Node.js runtimes that are not at a standard path and register them for the Node child guard (#11), so their children must be on `node_allowed_children`. |
| [`secure-sudo otp <subcommand>`](commands/secure-sudo-otp.md) | Rotating one-time-password sudo helper (#14/#15). |
| [`secure-sudo pheonixbox <on\|off\|snapshot\|scan\|status\|add\|remove\|list> [path]`](commands/secure-sudo-pheonixbox.md) | PheonixBox (#21): snapshot-based tamper protection with automatic repair for a chosen set of files and directories. |
| [`secure-sudo prguard <on\|off\|status\|list\|add\|remove> [path]`](commands/secure-sudo-prguard.md) | Drive the Process Runtime Guard (#20), which protects the runtime memory of every process except whitelisted ones (denies cross-process ptrace/memory... |
| [`secure-sudo-procguard`](commands/secure-sudo-procguard.md) | ProcGuard: kill processes that are not on the allowlist, and quarantine one that keeps coming back. |
| [`secure-sudo radio <wifi\|bluetooth\|ethernet-only> <on\|off>`](commands/secure-sudo-radio.md) | RadioGuard (#19): toggle the wireless radios. |
| [`secure-sudo restore ID [--no-load] [-y]`](commands/secure-sudo-restore.md) | Return to a known-good policy snapshot without editing files by hand (TODO P1-6). |
| [`secure-sudo set <knob> <value>`](commands/secure-sudo-set.md) | Change one scalar knob. |
| [`secure-sudo settings`](commands/secure-sudo-settings.md) | List every configurable kernel setting: the scalar knobs and the policy lists. |
| [`secure-sudo snapshot`](commands/secure-sudo-snapshot.md) | Save the current policy files and live kernel values as a restorable snapshot (TODO P1-6). |
| [`secure-sudo status`](commands/secure-sudo-status.md) | Print the current kernel state: every scalar knob's live value, the TimeVault engage flag and denied-exec counter, and the lock state. |
| [`secure-sudo-tamperwatch`](commands/secure-sudo-tamperwatch.md) | tamperwatch: name the process that tampered with a protected file (fanotify), and optionally quarantine it. |
| [`secure-sudo timevault <on\|off>`](commands/secure-sudo-timevault.md) | Engage or disengage TimeVault (#13). |
| [`secure-sudo vault-allow <subcommand>`](commands/secure-sudo-vault-allow.md) | Manage the TimeVault exec allowlist. |
| [`secure-sudod`](commands/secure-sudod.md) | The userspace companion to the secure_sudo LSM. |
| [`scripts/stig-harden.sh`](commands/stig-harden.md) | Run a DISA STIG (or closest baseline) OpenSCAP scan, and optionally remediate. |
| [`scripts/timevault-whitelist.sh`](commands/timevault-whitelist.md) | Manage the TimeVault exec allowlist with nothing but bash, coreutils and findutils. |
| [`scripts/verify-kernel-source.sh`](commands/verify-kernel-source.md) | Verify a kernel.org tarball's signature against pinned signer keys before extraction; fail closed. |

## Features

One page per feature (CLAUDE.MD section 5): overview, how it works, how it is secure, how to use it, dependencies, limits, troubleshooting and test evidence.

| Page | What it is |
|---|---|
| [UID/GID switch block and user-namespace gate](features/uid-gid-switch-block.md) | Block non-sudo UID/GID switching (setuid/setgid/setgroups) and unprivileged user namespaces. |
| [Setuid and file-capability exec gate](features/setid-exec-gate.md) | Deny non-sudo users exec of setuid and file-capability programs, except an allowlist, so a bug in one of those programs (the PwnKit, Baron... |
| [Command blacklist](features/command-blacklist.md) | Command blacklist, matched by device + inode, path, and content (SHA-256 of each entry, so a renamed copy is refused too). |
| [Firmware, flash and raw-memory block](features/firmware-block.md) | Block non-sudo firmware/flash access: `/dev/mem`, `/dev/port`, `/dev/mtd*`, `/dev/mei*`, and `/sys/firmware` writes. |
| [Home-write confinement](features/home-write-confinement.md) | Confine non-sudo writes to home + scratch/device trees + an allowlist. |
| [TPM clear block](features/tpm-clear-block.md) | Block TPM clear: `ppi/request` for everyone unless booted with `secure_sudo.tpm_maint=1`; once locked, only `tpm_openers` programs may open... |
| [Driver blacklist (anti-BYOVD)](features/driver-blacklist.md) | Driver blacklist / anti-BYOVD: file SHA-256 + file name checked at load, and the module's own name checked before its init runs (catches renamed... |
| [RAM-spike cache drop](features/ram-spike-cache-drop.md) | RAM-spike detection drops caches (`si_mem_available`, kernel worker). |
| [Sudo brute-force cooldown](features/sudo-cooldown.md) | Sudo brute-force cooldown: PAM feeds failures, the kernel blocks, the daemon kills the offender. |
| [Events, logging, forwarding and evidence](features/events-logging-evidence.md) | Versioned JSON security events with per-boot sequence/clock/actor metadata and visible ring/audit loss counters; the daemon writes dated, rotated... |
| [Network modes](features/network-modes.md) | Network host mode denies raw/`AF_PACKET` sockets; nft rules for LAN/public modes. |
| [Node.js child-process guard](features/node-child-guard.md) | NodeJS child-process guard (LSM task blob + allowlist); `secure-sudo node-scan` registers single-executable apps, pkg builds and renamed node... |
| [Scratch-tree exec block](features/scratch-exec-block.md) | Restrict exec and `PROT_EXEC` mmap from `/tmp`, `/var/tmp`, `/dev/shm`. |
| [TimeVault](features/timevault.md) | TimeVault: hash-based exec gate with allowlist (+ auto-update entries), size cap, package-manager deny, and quarantine of blocked binaries. |
| [Rotating OTP sudo password and encrypted secret](features/otp-sudo-password.md) | Rotating OTP sudo password: prefix + 6-digit TOTP, verified by `pam_secure_otp`; QR rendered locally (`userspace/otp`). |
| [One-way configuration lock](features/config-lock.md) | One-way config lock until reboot (TimeVault latches it); blocks module loads, kexec and kernel-memory patching while locked. |
| [BinaryVault](features/binaryvault.md) | BinaryVault: freeze every executable + shared library (write/truncate/unlink/rename/hardlink/chmod/xattr) for all UIDs incl. |
| [STIG and OpenSCAP tooling](features/stig-openscap.md) | STIG / OpenSCAP: `scripts/stig-harden.sh` scan + two-pass remediate + known-issue patches; real results: DISA Ubuntu 24.04 STIG 61 pass / 1 fail... |
| [RadioGuard](features/radioguard.md) | RadioGuard: Wi-Fi / Bluetooth lockdown + `ethernet_only` master switch (refuses wireless/BT modules by file and module name, `AF_BLUETOOTH`... |
| [Process Runtime Guard](features/process-runtime-guard.md) | Process Runtime Guard: denies cross-process ptrace / `process_vm_writev` / `/proc/pid/mem` tampering and W^X mappings, with a CLI-managed... |
| [PheonixBox](features/pheonixbox.md) | PheonixBox: snapshot tamper protection + auto-repair for chosen files/dirs (SHA-256 manifest detects, compressed snapshot restores, permissions... |
| [BPF and perf guard](features/bpf-perf-guard.md) | BPF & perf guard: `bpf_guard` / `perf_guard` deny bpf(2) and perf_event_open to non-sudo users; `bpf_lock_tracing` (default on) refuses... |
| [SysctlGuard](features/sysctlguard.md) | SysctlGuard: freezes the security-critical sysctls (`core_pattern`, `modprobe`, `kptr_restrict`, `ptrace_scope`, `randomize_va_space`,... |
| [Remote attestation and measured policy](features/remote-attestation.md) | Prove to a separate, trusted machine that a host booted the firmware, boot loader, kernel and policy it should have, using a TPM quote. |
| [ProcGuard (add-on)](features/addon-procguard.md) | Kill processes whose executable is not on an allowlist; quarantine one that keeps respawning. |
| [DriverGuard (add-on)](features/addon-driverguard.md) | Check kernel module files against a baseline and repair them from compressed backups. |
| [BiosGuard (add-on)](features/addon-biosguard.md) | Fingerprint the firmware and report any change; detection only, it never writes firmware. |
| [BootGuard (add-on)](features/addon-bootguard.md) | Detect boot-partition tampering and restore the last good copy at the next boot. |
| [Locus (add-on)](features/addon-locus.md) | LAN request-only allocator for the add-ons' hourly-rotating storage locations. |
| [tamperwatch (add-on)](features/addon-tamperwatch.md) | Name, in real time, the process that tampered with a protected file; optionally quarantine it. |
| [Management GUI (add-on)](features/addon-gui.md) | One local, token-protected web console to view and configure the stack. |

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
