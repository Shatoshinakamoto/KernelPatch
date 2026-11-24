<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo-bootguard`

BootGuard: detect boot-partition tampering and restore the last good copy at the next boot. Part of the opt-in `temporary/` add-ons, installed by
[`install-temporary.sh`](install-temporary.md); experimental (see the maturity table in
[ADDONS.md](../ADDONS.md)).

- **Source:** [`temporary/bootguard/`](../../temporary/bootguard/)
- **Installed as:** `/usr/libexec/secure-sudo/secure-sudo-bootguard`
- **Run as:** root. Every acting command refuses to run while `check-config` reports a problem (exit 78).

## Usage and options

The program's own usage text, printed by `--help` (`ci/check-command-docs.py`
fails if it differs):

```text
usage: secure-sudo-bootguard <command>
  baseline         hash all boot files + store compressed backups (hourly)
  scan             check vs baseline; stage a restore for NEXT BOOT on tamper
  restore-staged   apply a staged restore if PENDING (run early at boot)
  apply-now --i-understand-the-risk   operator-only LIVE restore
  refresh [REASON] re-baseline after a legitimate change, logging what changed
  status           show state
  check-config     check every config file strictly; 1 if any problem

Stage-and-apply-at-boot by design: the live boot partition is not rewritten
mid-run. Config: /etc/secure_sudo/addons/bootguard.conf
```

Every command and setting is explained in [ADDONS.md](../ADDONS.md#4-bootguard--boot-partition-tamper-detection-restore-at-next-boot).

## Related

- [bootguard-conf.md](../configuration/bootguard-conf.md)
- [logging-conf.md](../configuration/logging-conf.md) (shared logging)
