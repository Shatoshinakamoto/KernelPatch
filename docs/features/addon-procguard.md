<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# ProcGuard (add-on)

## Overview

Kill processes whose executable is not on an allowlist; quarantine one that keeps respawning. Details: [ADDONS.md](../ADDONS.md#1-procguard--process-allowlist-enforcer).

Part of the opt-in `temporary/` add-ons: experimental, outside the supported profile, installed by [`install-temporary.sh`](../commands/install-temporary.md), and nothing is enabled by default.

## How it works

The full description, with every mode and setting, is in [ADDONS.md](../ADDONS.md#1-procguard--process-allowlist-enforcer). Configuration: [procguard-conf.md](../configuration/procguard-conf.md), [procguard_allow.conf](../files/procguard_allow.md). Logging is shared ([logging-conf.md](../configuration/logging-conf.md)).

## How it is secure

**Defends:** a non-allowlisted program running at all; an implant that keeps respawning (removed after a compressed sample is quarantined).

**Evidence:** before an executable is removed, its hash, owner, mode, times and the quarantined copy are recorded (`evidence/procguard.jsonl`); if the record cannot be written, it is not removed.

**Races:** the binary is opened through `/proc/PID/exe` before the kill, so the quarantined copy is the program that ran; the path is removed only while it is still that file (same device and inode, not a symlink). Turned to enforce, it reports until armed ([Enforce arming](#enforce-arming)).

Every config is parsed strictly and an acting command refuses to run while it has an error (CWE-20, NIST CM-6); acting modes are opt-in and must be armed (NIST CM-3); units are sandboxed and report failures (NIST SI-4, AU-5). Shared threat model: [ADDONS.md](../ADDONS.md#threat-model).

## How to use it

```sh
sudo bash temporary/install-temporary.sh
sudo /usr/libexec/secure-sudo/secure-sudo-procguard check-config
sudo /usr/libexec/secure-sudo/secure-sudo-procguard status
```

Every command: [secure-sudo-procguard](../commands/secure-sudo-procguard.md).

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| OpenSSL (libssl, libcrypto) | distro package (3.x) | hashes, signatures, TLS log shipping | not checked for this page |
| zlib | distro package | compressed backups and quarantine | not checked for this page |

The release SBOM lists exact versions.

## Limitations and known risks

**Does not defend:** code inside an allowlisted executable (an interpreter on the list runs any script), anything faster than one scan interval, or an attacker who edits the allowlist (root).

**Harm if wrong:** killing a legitimate service missing from the allowlist, or removing its file. Mitigations: monitor is the default; an empty list refuses to run; PID 1, kernel threads, its own ancestors and the installed secure_sudo programs are never killed; nothing is removed from a system directory (now enforced by the unit's read-only system dirs too).

A root attacker who can rewrite the add-on, its config or its unit defeats it: these are tripwires and responders, not a boundary against root.

## Troubleshooting

- **A command exits 78.** The config has an error: run `secure-sudo-procguard check-config`, which names the file and line.
- **Enforce mode only reports.** It acts only after a clean pass or `arm` ([Enforce arming](../ADDONS.md#enforce-arming)), where the add-on has one.
- **Nothing in the off-box log.** Check [logging-conf.md](../configuration/logging-conf.md); the local log says `remote log shipping FAILED` with the reason.

## Test evidence

- `tests/userspace/test-addons.sh`, 163/0: [`HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/`](../../HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/)
- Shared logging over TLS: [`HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/`](../../HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/)
- Full build gate: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
