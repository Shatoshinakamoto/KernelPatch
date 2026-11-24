<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `ci/graft-lsm.sh`

Copy the secure_sudo LSM into a kernel source tree and register it (Kconfig, Makefile, LSM count).

- **Source:** [`ci/graft-lsm.sh`](../../ci/graft-lsm.sh)
- **Run by:** the build (install.sh, the gate) or a developer building their own kernel

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
graft-lsm.sh - copy the secure_sudo LSM into a kernel source tree and
register it with Kconfig and the security Makefile. Idempotent. Used by
install/install.sh, ci/build-gate.sh and tests/vm/build-test-kernel.sh so
every build wires the LSM in the same way.

Usage: ci/graft-lsm.sh <kernel-source-tree>
```

## Related

- [Script reference](../SCRIPTS.md)
- [INSTALL.md](../INSTALL.md)
- [install-sh.md](install-sh.md)
