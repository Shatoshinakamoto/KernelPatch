<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo-driverguard`

DriverGuard: check kernel module files against a baseline and repair them from compressed backups. Part of the opt-in `temporary/` add-ons, installed by
[`install-temporary.sh`](install-temporary.md); experimental (see the maturity table in
[ADDONS.md](../ADDONS.md)).

- **Source:** [`temporary/driverguard/`](../../temporary/driverguard/)
- **Installed as:** `/usr/libexec/secure-sudo/secure-sudo-driverguard`
- **Run as:** root. Every acting command refuses to run while `check-config` reports a problem (exit 78).

## Usage and options

The program's own usage text, printed by `--help` (`ci/check-command-docs.py`
fails if it differs):

```text
usage: secure-sudo-driverguard <command>
  baseline   hash all modules + store compressed failsafe backups (hourly bucket)
  backup     refresh the hourly compressed backups only
  scan       check modules vs baseline; repair from backup in enforce mode
  refresh [REASON]  re-baseline after a legitimate update (logged)
  arm        let enforce mode act (it reports only until a clean pass or this)
  status     show configuration and baseline size
  check-config  check every config file strictly; 1 if any problem

Config: /etc/secure_sudo/addons/driverguard.conf
```

Every command and setting is explained in [ADDONS.md](../ADDONS.md#2-driverguard--driver-integrity--repair).

## Related

- [driverguard-conf.md](../configuration/driverguard-conf.md)
- [logging-conf.md](../configuration/logging-conf.md) (shared logging)
