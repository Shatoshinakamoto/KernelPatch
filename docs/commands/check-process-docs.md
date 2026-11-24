<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `ci/check-process-docs.py`

Check that SECURITY.md and docs/MAINTENANCE.md keep their required sections.

- **Source:** [`ci/check-process-docs.py`](../../ci/check-process-docs.py)
- **Run by:** the gate's lint stage

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
check-process-docs.py - the disclosure and maintenance process (SECURITY.md,
docs/MAINTENANCE.md, TODO P3-3) must keep its parts: the reporting channel,
the response targets, triage, the security-fix release steps, kernel/LTS
tracking, dependency updates and the deprecation policy, and every file it
points to must exist. Usage: check-process-docs.py ROOT
```

## Related

- [Script reference](../SCRIPTS.md)
- [MAINTENANCE.md](../MAINTENANCE.md)
