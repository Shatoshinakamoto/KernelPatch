<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Locus (add-on)

## Overview

LAN request-only allocator for the add-ons' hourly-rotating storage locations. Details: [ADDONS.md](../ADDONS.md#5-locus--the-rotating-location-allocator).

Part of the opt-in `temporary/` add-ons: experimental, outside the supported profile, installed by [`install-temporary.sh`](../commands/install-temporary.md), and nothing is enabled by default.

## How it works

The full description, with every mode and setting, is in [ADDONS.md](../ADDONS.md#5-locus--the-rotating-location-allocator). Configuration: [locus-conf.md](../configuration/locus-conf.md), [locus-client-conf.md](../configuration/locus-client-conf.md). Logging is shared ([logging-conf.md](../configuration/logging-conf.md)).

## How it is secure

**Defends:** spreads quarantine and backup locations across hourly buckets so a fixed path cannot be targeted.

Every config is parsed strictly and an acting command refuses to run while it has an error (CWE-20, NIST CM-6); acting modes are opt-in and must be armed (NIST CM-3); units are sandboxed and report failures (NIST SI-4, AU-5). Shared threat model: [ADDONS.md](../ADDONS.md#threat-model).

## How to use it

```sh
sudo bash temporary/install-temporary.sh
sudo /usr/libexec/secure-sudo/secure-sudo-locus check-config
sudo /usr/libexec/secure-sudo/secure-sudo-locus status
```

Every command: [secure-sudo-locus](../commands/secure-sudo-locus.md).

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| OpenSSL (libssl, libcrypto) | distro package (3.x) | hashes, signatures, TLS log shipping | not checked for this page |
| zlib | distro package | compressed backups and quarantine | not checked for this page |

The release SBOM lists exact versions.

## Limitations and known risks

**Does not defend:** anything on its own; a rogue allocator can only name a location, which the guards check (absolute, no `..`, no control characters).

**Harm if wrong:** a guard writing to a different directory than expected. It listens on 127.0.0.1 by default; the allocator protocol has no authentication, so do not widen `alloc_bind` beyond a trusted LAN. It serves one client at a time, and drops one that sends nothing within 2 seconds.

A root attacker who can rewrite the add-on, its config or its unit defeats it: these are tripwires and responders, not a boundary against root.

## Troubleshooting

- **A command exits 78.** The config has an error: run `secure-sudo-locus check-config`, which names the file and line.
- **Enforce mode only reports.** It acts only after a clean pass or `arm` ([Enforce arming](../ADDONS.md#enforce-arming)), where the add-on has one.
- **Nothing in the off-box log.** Check [logging-conf.md](../configuration/logging-conf.md); the local log says `remote log shipping FAILED` with the reason.

## Test evidence

- `tests/userspace/test-addons.sh`, 163/0: [`HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/`](../../HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/)
- Shared logging over TLS: [`HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/`](../../HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/)
- Full build gate: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
