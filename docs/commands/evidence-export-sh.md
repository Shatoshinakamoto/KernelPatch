<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `userspace/daemon/helpers/evidence-export.sh`

Run as root. Part of the [script reference](../SCRIPTS.md).

Invoked by `sudo secure-sudo evidence-export OUTPUT.tar.gz` to create a
root-only incident bundle. It copies local event logs, snapshots non-secret
policy files and live kernel state, includes service status and quarantine
metadata/hashes without copying quarantined contents, and creates a checksum
manifest plus per-log hash chains. An optional external Ed25519 PEM key signs
the chain checkpoint and the checksum manifest. The key must be root-owned and
not group/world-readable. See [COMMANDS.md](../COMMANDS.md) for verification and
key-custody limitations.

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
