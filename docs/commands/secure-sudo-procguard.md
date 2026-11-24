<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo-procguard`

ProcGuard: kill processes that are not on the allowlist, and quarantine one that keeps coming back. Part of the opt-in `temporary/` add-ons, installed by
[`install-temporary.sh`](install-temporary.md); experimental (see the maturity table in
[ADDONS.md](../ADDONS.md)).

- **Source:** [`temporary/procguard/`](../../temporary/procguard/)
- **Installed as:** `/usr/libexec/secure-sudo/secure-sudo-procguard`
- **Run as:** root. Every acting command refuses to run while `check-config` reports a problem (exit 78).

## Usage and options

The program's own usage text, printed by `--help` (`ci/check-command-docs.py`
fails if it differs):

```text
usage: secure-sudo-procguard <command>
  daemon        run the watch loop (monitor or enforce per config)
  scan          one pass now (detect in monitor, act in enforce)
  arm           let enforce mode act (it reports only until a clean pass or this)
  status        show the current configuration
  check-config  check every config file strictly; 1 if any problem

Config: /etc/secure_sudo/addons/procguard.conf
Allowlist: /etc/secure_sudo/addons/procguard_allow.conf
```

Every command and setting is explained in [ADDONS.md](../ADDONS.md#1-procguard--process-allowlist-enforcer).

## Related

- [procguard-conf.md](../configuration/procguard-conf.md)
- [procguard_allow.md](../files/procguard_allow.md)
- [logging-conf.md](../configuration/logging-conf.md) (shared logging)
