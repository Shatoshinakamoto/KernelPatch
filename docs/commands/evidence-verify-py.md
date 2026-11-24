<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `userspace/daemon/helpers/evidence-verify.py`

Run as root. Part of the [script reference](../SCRIPTS.md).

Invoked by `secure-sudo evidence-verify ARCHIVE.tar.gz [--trusted-key PUBLIC.pem]
[--checkpoints COLLECTOR.log]`. `--checkpoints` matches the bundle's logs
against the `log_checkpoint` records the remote collector received.
It rejects unsafe archive members, verifies that the checksum manifest covers
the payload, recomputes each exported log chain, and validates detached
signatures against an independently supplied trusted public key. It never
extracts files outside a private temporary directory.

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
