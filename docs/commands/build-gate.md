<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `ci/build-gate.sh`

The release gate: lint, -Werror builds, kernel header and in-tree builds, every test suite and a reproducible package.

- **Source:** [`ci/build-gate.sh`](../../ci/build-gate.sh)
- **Run by:** the maintainer, as root, before every merge and release

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
build-gate.sh - the release build gate (TODO P0-1). CI runs exactly this;
so can you, from a clean checkout. Each stage works in a scratch copy, so
the checkout is never modified, and the whole run is recorded in one file.

Stages (default: all that can run here):
  lint        bash -n + shellcheck on every shell script, py_compile on the
              GUI, and the duplicate-LSM-hook check
  userspace   CLI, daemon, PAM modules, OTP helper, PheonixBox: -Werror
  addons      every temporary/ add-on: -Werror
  lsm-headers LSM compile check against installed kernel header trees
              (or --headers DIR, repeatable), plus --headers-direct DIR
              trees (downloaded headers, compiled without their kbuild)
  lsm-tree    in-tree build of the LSM for every ci/kconfig/*.config variant
              (needs --kernel-tree DIR, a verified kernel source tree)
  tests       tests/run-all.sh (no root, no network, no kernel needed)
  package     reproducible release tarball, built twice and compared

Usage: ci/build-gate.sh [--stages a,b,...] [--kernel-tree DIR]
                        [--headers DIR]... [--headers-direct DIR]...
                        [--record FILE]
Exit: 0 every requested stage passed; 1 otherwise.
```

## Related

- [Script reference](../SCRIPTS.md)
- [SCRIPTS.md](../SCRIPTS.md)
- [README.md](../../HistoryTest/README.md)
