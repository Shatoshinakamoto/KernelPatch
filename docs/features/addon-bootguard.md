<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# BootGuard (add-on)

## Overview

Detect boot-partition tampering and restore the last good copy at the next boot. Details: [ADDONS.md](../ADDONS.md#4-bootguard--boot-partition-tamper-detection-restore-at-next-boot).

Part of the opt-in `temporary/` add-ons: experimental, outside the supported profile, installed by [`install-temporary.sh`](../commands/install-temporary.md), and nothing is enabled by default.

## How it works

The full description, with every mode and setting, is in [ADDONS.md](../ADDONS.md#4-bootguard--boot-partition-tamper-detection-restore-at-next-boot). Configuration: [bootguard-conf.md](../configuration/bootguard-conf.md). Logging is shared ([logging-conf.md](../configuration/logging-conf.md)).

## How it is secure

**Defends:** a changed kernel, initrd or boot loader config in /boot, put back from its backup at the next boot.

Every config is parsed strictly and an acting command refuses to run while it has an error (CWE-20, NIST CM-6); acting modes are opt-in and must be armed (NIST CM-3); units are sandboxed and report failures (NIST SI-4, AU-5). Shared threat model: [ADDONS.md](../ADDONS.md#threat-model).

## How to use it

```sh
sudo bash temporary/install-temporary.sh
sudo /usr/libexec/secure-sudo/secure-sudo-bootguard check-config
sudo /usr/libexec/secure-sudo/secure-sudo-bootguard status
```

Every command: [secure-sudo-bootguard](../commands/secure-sudo-bootguard.md).

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| OpenSSL (libssl, libcrypto) | distro package (3.x) | hashes, signatures, TLS log shipping | not checked for this page |
| zlib | distro package | compressed backups and quarantine | not checked for this page |

The release SBOM lists exact versions.

## Limitations and known risks

**Does not defend:** firmware or the ESP outside `boot_dir`, a change that never touches the files (a different boot entry in NVRAM), or a rewritten baseline while `baseline_trust = local`. The staged restore re-checks the baseline's trust at boot, and writes back only backups that match it.

**Harm if wrong:** booting an older kernel or initrd after a legitimate update. Mitigations: restores are staged, never live (`apply-now` needs `--i-understand-the-risk`); scans defer during a package transaction; the hooks re-baseline and drop a staged restore that predates an update.

A root attacker who can rewrite the add-on, its config or its unit defeats it: these are tripwires and responders, not a boundary against root.

## Troubleshooting

- **A command exits 78.** The config has an error: run `secure-sudo-bootguard check-config`, which names the file and line.
- **Enforce mode only reports.** It acts only after a clean pass or `arm` ([Enforce arming](../ADDONS.md#enforce-arming)), where the add-on has one.
- **Nothing in the off-box log.** Check [logging-conf.md](../configuration/logging-conf.md); the local log says `remote log shipping FAILED` with the reason.

## Test evidence

- `tests/userspace/test-addons.sh`, 163/0: [`HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/`](../../HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/)
- Shared logging over TLS: [`HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/`](../../HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/)
- Full build gate: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
