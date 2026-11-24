<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo-biosguard`

BiosGuard: fingerprint the firmware and report any change. Detection only; it never writes firmware. Part of the opt-in `temporary/` add-ons, installed by
[`install-temporary.sh`](install-temporary.md); experimental (see the maturity table in
[ADDONS.md](../ADDONS.md)).

- **Source:** [`temporary/biosguard/`](../../temporary/biosguard/)
- **Installed as:** `/usr/libexec/secure-sudo/secure-sudo-biosguard`
- **Run as:** root. Every acting command refuses to run while `check-config` reports a problem (exit 78).

## Usage and options

The program's own usage text, printed by `--help` (`ci/check-command-docs.py`
fails if it differs):

```text
usage: secure-sudo-biosguard <command>
  baseline   fingerprint the firmware (DMI, ACPI, SMBIOS, Secure Boot variables,
             ESRT, TPM PCRs: see status for what this host exposes)
  scan       check for firmware tamper; log + notify on any change (no repair)
  refresh [REASON]  after a legitimate firmware/Secure Boot update: log what
             changed (CRITICAL) and take a new baseline
  status     show state and what this host exposes
  check-config  check every config file strictly; 1 if any problem

Detection only by design: BiosGuard never writes firmware. Config: /etc/secure_sudo/addons/biosguard.conf
```

Every command and setting is explained in [ADDONS.md](../ADDONS.md#3-biosguard--firmware-tamper-detection-only).

## Related

- [biosguard-conf.md](../configuration/biosguard-conf.md)
- [logging-conf.md](../configuration/logging-conf.md) (shared logging)
