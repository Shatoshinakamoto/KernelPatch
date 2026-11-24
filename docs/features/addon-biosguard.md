<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# BiosGuard (add-on)

## Overview

Fingerprint the firmware and report any change; detection only, it never writes firmware. Details: [ADDONS.md](../ADDONS.md#3-biosguard--firmware-tamper-detection-only).

Part of the opt-in `temporary/` add-ons: experimental, outside the supported profile, installed by [`install-temporary.sh`](../commands/install-temporary.md), and nothing is enabled by default.

## How it works

The full description, with every mode and setting, is in [ADDONS.md](../ADDONS.md#3-biosguard--firmware-tamper-detection-only). Configuration: [biosguard-conf.md](../configuration/biosguard-conf.md). Logging is shared ([logging-conf.md](../configuration/logging-conf.md)).

## How it is secure

**Defends:** detects a change in the DMI identity or ACPI tables and reports it CRITICAL; it never writes firmware.

Every config is parsed strictly and an acting command refuses to run while it has an error (CWE-20, NIST CM-6); acting modes are opt-in and must be armed (NIST CM-3); units are sandboxed and report failures (NIST SI-4, AU-5). Shared threat model: [ADDONS.md](../ADDONS.md#threat-model).

## How to use it

```sh
sudo bash temporary/install-temporary.sh
sudo /usr/libexec/secure-sudo/secure-sudo-biosguard check-config
sudo /usr/libexec/secure-sudo/secure-sudo-biosguard status
```

Every command: [secure-sudo-biosguard](../commands/secure-sudo-biosguard.md).

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| OpenSSL (libssl, libcrypto) | distro package (3.x) | hashes, signatures, TLS log shipping | not checked for this page |
| zlib | distro package | compressed backups and quarantine | not checked for this page |

The release SBOM lists exact versions.

## Limitations and known risks

**Does not defend:** firmware changes that leave DMI and ACPI unchanged (measured boot, P2-1, is the stronger check), or a fingerprint rewritten while `baseline_trust = local` (with `signed`, an unsigned or edited fingerprint fails the scan with a CRITICAL notification).

**Harm if wrong:** a false alarm after a legitimate firmware update; nothing is changed. A table that appeared after the baseline is reported as well as one that changed or vanished; a table name with whitespace or control characters is reported, not fingerprinted.

A root attacker who can rewrite the add-on, its config or its unit defeats it: these are tripwires and responders, not a boundary against root.

## Troubleshooting

- **A command exits 78.** The config has an error: run `secure-sudo-biosguard check-config`, which names the file and line.
- **Enforce mode only reports.** It acts only after a clean pass or `arm` ([Enforce arming](../ADDONS.md#enforce-arming)), where the add-on has one.
- **Nothing in the off-box log.** Check [logging-conf.md](../configuration/logging-conf.md); the local log says `remote log shipping FAILED` with the reason.

## Test evidence

- `tests/userspace/test-addons.sh`, 163/0: [`HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/`](../../HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/)
- Shared logging over TLS: [`HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/`](../../HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/)
- Full build gate: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
