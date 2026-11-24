<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Management GUI (add-on)

## Overview

One local, token-protected web console to view and configure the stack. Details: [ADDONS.md](../ADDONS.md#management-gui-local-web-console).

Part of the opt-in `temporary/` add-ons: experimental, outside the supported profile, installed by [`install-temporary.sh`](../commands/install-temporary.md), and nothing is enabled by default.

## How it works

The full description, with every mode and setting, is in [ADDONS.md](../ADDONS.md#management-gui-local-web-console). Configuration: [gui-conf.md](../configuration/gui-conf.md). Logging is shared ([logging-conf.md](../configuration/logging-conf.md)).

## How it is secure

**Defends:** nothing itself; it is the operator's console.

Every config is parsed strictly and an acting command refuses to run while it has an error (CWE-20, NIST CM-6); acting modes are opt-in and must be armed (NIST CM-3); units are sandboxed and report failures (NIST SI-4, AU-5). Shared threat model: [ADDONS.md](../ADDONS.md#threat-model).

## How to use it

```sh
sudo bash temporary/install-temporary.sh
sudo /usr/share/secure-sudo-gui/secure-sudo-gui check-config
sudo systemctl start secure-sudo-gui     # serves on loopback; the token file is printed
```

Details: [secure-sudo-gui](../commands/secure-sudo-gui.md), [gui-conf.md](../configuration/gui-conf.md).

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Python 3 | distro package (3.10+) | standard library only | not checked for this page |

The release SBOM lists exact versions.

## Limitations and known risks

A root attacker who can rewrite the add-on, its config or its unit defeats it: these are tripwires and responders, not a boundary against root.

## Troubleshooting

- **A command exits 78.** The config has an error: run `secure-sudo-gui check-config`, which names the file and line.
- **Enforce mode only reports.** It acts only after a clean pass or `arm` ([Enforce arming](../ADDONS.md#enforce-arming)), where the add-on has one.
- **Nothing in the off-box log.** Check [logging-conf.md](../configuration/logging-conf.md); the local log says `remote log shipping FAILED` with the reason.

## Test evidence

- `tests/userspace/test-addons.sh`, 163/0: [`HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/`](../../HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/)
- Shared logging over TLS: [`HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/`](../../HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/)
- Full build gate: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
