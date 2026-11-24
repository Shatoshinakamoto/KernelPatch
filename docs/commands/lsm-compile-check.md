<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `ci/lsm-compile-check.sh`

Compile every LSM source file against a kernel header tree.

- **Source:** [`ci/lsm-compile-check.sh`](../../ci/lsm-compile-check.sh)
- **Run by:** the gate's lsm-headers stage, or a developer

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
lsm-compile-check.sh - compile every secure_sudo LSM source file against one
or more kernel header trees, with warnings as errors. This is a fast
compile check, NOT a substitute for the in-tree build (ci/build-gate.sh
--kernel-tree) or a boot test (tests/vm/boot-test.sh).

Modes:
  kbuild  (default) out-of-tree Kbuild run: make -C <tree> M=<copy>. This
          executes the tree's own host tools (fixdep, modpost, objtool), so
          use it only for header trees installed by your package manager.
  direct  calls the system compiler on each file with the x86_64 kernel
          flags and the tree's include paths. Nothing from the tree is
          executed, so it is safe for header trees you downloaded and only
          verified (e.g. Ubuntu mainline builds of a 6.12.y release).

A built-in LSM is compiled here as a module, so modpost's MODULE_LICENSE /
undefined-symbol complaints are expected and ignored; success means every
object compiled.

Usage: ci/lsm-compile-check.sh [--mode kbuild|direct] [--cc gcc]
                               [--record FILE] TREE...
```

## Related

- [Script reference](../SCRIPTS.md)
- [build-gate.md](build-gate.md)
