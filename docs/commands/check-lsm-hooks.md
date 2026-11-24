<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `ci/check-lsm-hooks.sh`

Fail if any LSM hook is registered twice (the v11 boot panic).

- **Source:** [`ci/check-lsm-hooks.sh`](../../ci/check-lsm-hooks.sh)
- **Run by:** the gate's lint stage

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
check-lsm-hooks.sh - fail if any LSM hook is registered more than once by
secure_sudo. Since 6.9 each LSM has one static-call slot per hook, so a
second registration of the same hook panics the kernel at boot. Hooks used
by several protections belong in kernel/security/secure_sudo/ss_hooks.c.
```

## Related

- [Script reference](../SCRIPTS.md)
- [build-gate.md](build-gate.md)
