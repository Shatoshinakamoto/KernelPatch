<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo-addon-failure`

Report a failed add-on unit through the shared add-on logging (systemd OnFailure= handler).

- **Source:** [`temporary/failure/failure.c`](../../temporary/failure/failure.c)
- **Run by:** systemd (OnFailure=), not run by hand

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
secure-sudo-addon-failure - failure reporting for the temporary/ add-ons
(TODO P2-2).

Every add-on unit has OnFailure=secure-sudo-addon-failure@%n.service. When
a guard dies, is killed, hits its memory cap, or refuses to start because
its configuration is invalid, systemd starts that template, which runs

    secure-sudo-addon-failure <unit>

with the failed unit's result in MONITOR_SERVICE_RESULT, MONITOR_EXIT_CODE
and MONITOR_EXIT_STATUS (systemd >= 249; older systemd leaves them unset).
The failure goes through ssl_notify(): a CRITICAL line in the local add-on
log, the off-box syslog collector when one is configured, and the
operator's notify_cmd. A guard that silently stops guarding is the failure
this exists for: without it, a crashed ProcGuard looks the same as a quiet
host.

define _GNU_SOURCE
include <stdio.h>
include <stdlib.h>
include <string.h>
include <ctype.h>
include <unistd.h>
```

## Related

- [Script reference](../SCRIPTS.md)
- [ADDONS.md](../ADDONS.md)
- [logging-conf.md](../configuration/logging-conf.md)
