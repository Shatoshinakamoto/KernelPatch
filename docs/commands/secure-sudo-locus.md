<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo-locus`

Locus: the LAN request-only allocator for the add-ons' rotating storage locations, with a read-only status page. Part of the opt-in `temporary/` add-ons, installed by
[`install-temporary.sh`](install-temporary.md); experimental (see the maturity table in
[ADDONS.md](../ADDONS.md)).

- **Source:** [`temporary/locus/`](../../temporary/locus/)
- **Installed as:** `/usr/libexec/secure-sudo/secure-sudo-locus`
- **Run as:** root. Every acting command refuses to run while `check-config` reports a problem (exit 78).

## Usage and options

The program's own usage text, printed by `--help` (`ci/check-command-docs.py`
fails if it differs):

```text
usage: secure-sudo-locus <serve|status|check-config>
  serve    run the allocator + read-only GUI listeners
  status   show the configured binds and roots
  check-config  check every config file strictly; 1 if any problem

Config: /etc/secure_sudo/addons/locus.conf
```

Every command and setting is explained in [ADDONS.md](../ADDONS.md#5-locus--the-rotating-location-allocator).

## Related

- [locus-conf.md](../configuration/locus-conf.md)
- [locus-client-conf.md](../configuration/locus-client-conf.md)
- [logging-conf.md](../configuration/logging-conf.md) (shared logging)
