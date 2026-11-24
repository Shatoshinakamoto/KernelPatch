<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `temporary/install-temporary.sh`

Opt-in installer for the temporary/ add-ons; installs everything, enables nothing.

- **Source:** [`temporary/install-temporary.sh`](../../temporary/install-temporary.sh)
- **Run by:** root, after the core install

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
install-temporary.sh - OPT-IN installer for the secure_sudo temporary/ add-ons
(ProcGuard, DriverGuard, BiosGuard, BootGuard, Locus, tamperwatch, management
GUI) plus the shared logging.

These add-ons are NOT installed by the core install.sh. Run this only when you
want them. It builds and installs the binaries, drops config TEMPLATES (never
overwriting your edited configs), installs the systemd units, and creates the
state/log directories - but it ENABLES NOTHING and KILLS NOTHING. Every
enforcing behaviour is opt-in and starts in a safe mode. The next-steps notice
at the end tells you exactly what to turn on and in what order.

NOTE: run with `bash install-temporary.sh` (the project tree may be mounted
noexec).
```

## Related

- [Script reference](../SCRIPTS.md)
- [ADDONS.md](../ADDONS.md)
- [INSTALL.md](../INSTALL.md)
