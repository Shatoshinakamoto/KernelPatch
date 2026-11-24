<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `tests/run-all.sh`

Run every host-side test suite (TAP).

- **Source:** [`tests/run-all.sh`](../../tests/run-all.sh)
- **Run by:** the gate's tests stage, or a developer

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
run-all.sh - run every host-side test suite (TODO P0-2). The build gate's
"tests" stage runs exactly this.

Suites print TAP. None needs the secure_sudo kernel, the network, or changes
to the host: they build what they test into scratch directories. Parts that
need root (real pam_unix in a private mount namespace, real nft in
throwaway network namespaces, ownership checks) are marked ROOT-ONLY in the
suites and skipped when not root. The in-kernel tests run in a VM instead:
tests/vm/build-test-kernel.sh + tests/vm/boot-test.sh.

Usage: tests/run-all.sh [suite-name-substring]
Exit: 0 every suite passed; 1 otherwise.
```

## Related

- [Script reference](../SCRIPTS.md)
- [build-gate.md](build-gate.md)
