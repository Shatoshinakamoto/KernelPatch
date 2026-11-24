<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo-tamperwatch`

tamperwatch: name the process that tampered with a protected file (fanotify), and optionally quarantine it. Part of the opt-in `temporary/` add-ons, installed by
[`install-temporary.sh`](install-temporary.md); experimental (see the maturity table in
[ADDONS.md](../ADDONS.md)).

- **Source:** [`temporary/tamperwatch/`](../../temporary/tamperwatch/)
- **Installed as:** `/usr/libexec/secure-sudo/secure-sudo-tamperwatch`
- **Run as:** root. Every acting command refuses to run while `check-config` reports a problem (exit 78).

## Usage and options

The program's own usage text, printed by `--help` (`ci/check-command-docs.py`
fails if it differs):

```text
usage: secure-sudo-tamperwatch <daemon|arm|status|check-config>
  daemon   watch the protected set and attribute (and optionally quarantine) tampering
  arm      let quarantine mode act (until then it reports only)
  status   show configuration
  check-config  check every config file strictly; 1 if any problem

Needs root + CONFIG_FANOTIFY. Config: /etc/secure_sudo/addons/tamperwatch.conf
```

Every command and setting is explained in [ADDONS.md](../ADDONS.md#6-tamperwatch--real-time-tamper-attribution).

## Related

- [tamperwatch-conf.md](../configuration/tamperwatch-conf.md)
- [logging-conf.md](../configuration/logging-conf.md) (shared logging)
