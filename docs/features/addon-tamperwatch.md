<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# tamperwatch (add-on)

## Overview

Name, in real time, the process that tampered with a protected file; optionally quarantine it. Details: [ADDONS.md](../ADDONS.md#6-tamperwatch--real-time-tamper-attribution).

Part of the opt-in `temporary/` add-ons: experimental, outside the supported profile, installed by [`install-temporary.sh`](../commands/install-temporary.md), and nothing is enabled by default.

## How it works

The full description, with every mode and setting, is in [ADDONS.md](../ADDONS.md#6-tamperwatch--real-time-tamper-attribution). Configuration: [tamperwatch-conf.md](../configuration/tamperwatch-conf.md). Logging is shared ([logging-conf.md](../configuration/logging-conf.md)).

## How it is secure

**Defends:** names, in real time, the process that wrote a protected file, and in quarantine mode stops it after compressing its executable.

Every config is parsed strictly and an acting command refuses to run while it has an error (CWE-20, NIST CM-6); acting modes are opt-in and must be armed (NIST CM-3); units are sandboxed and report failures (NIST SI-4, AU-5). Shared threat model: [ADDONS.md](../ADDONS.md#threat-model).

## How to use it

```sh
sudo bash temporary/install-temporary.sh
sudo /usr/libexec/secure-sudo/secure-sudo-tamperwatch check-config
sudo /usr/libexec/secure-sudo/secure-sudo-tamperwatch status
```

Every command: [secure-sudo-tamperwatch](../commands/secure-sudo-tamperwatch.md).

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| OpenSSL (libssl, libcrypto) | distro package (3.x) | hashes, signatures, TLS log shipping | not checked for this page |
| zlib | distro package | compressed backups and quarantine | not checked for this page |

The release SBOM lists exact versions.

## Limitations and known risks

**Does not defend:** writes through paths it does not watch (a bind mount, a new hard link), a writer that exits before the event is read, or a root attacker who stops it first (the stop is reported by failure reporting only if the unit fails, not if it is stopped cleanly).

**Harm if wrong:** killing a legitimate writer. Mitigations: log mode by default; quarantine mode reports until the operator arms it; never kills PID 1, itself, a secure_sudo program, or anything while a package manager is running.

A root attacker who can rewrite the add-on, its config or its unit defeats it: these are tripwires and responders, not a boundary against root.

## Troubleshooting

- **A command exits 78.** The config has an error: run `secure-sudo-tamperwatch check-config`, which names the file and line.
- **Enforce mode only reports.** It acts only after a clean pass or `arm` ([Enforce arming](../ADDONS.md#enforce-arming)), where the add-on has one.
- **Nothing in the off-box log.** Check [logging-conf.md](../configuration/logging-conf.md); the local log says `remote log shipping FAILED` with the reason.

## Test evidence

- `tests/userspace/test-addons.sh`, 163/0: [`HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/`](../../HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/)
- Shared logging over TLS: [`HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/`](../../HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/)
- Full build gate: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
