<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `scripts/gen-sbom.sh`

Write the SPDX SBOM of a release, or print the source tree hash.

- **Source:** [`scripts/gen-sbom.sh`](../../scripts/gen-sbom.sh)
- **Run by:** make-release.sh and the gate

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
gen-sbom.sh - SPDX 2.3 JSON software bill of materials for a secure_sudo
build (TODO P0-4): every secure_sudo source file with its SHA-256, the
verified kernel source archive, the toolchain, and the libraries the
userspace links against, with versions from the package manager.

Usage:
  scripts/gen-sbom.sh --tree-hash
      print one SHA-256 over every tracked secure_sudo source file
  scripts/gen-sbom.sh --list
      print the source file list itself (what a release contains)
  scripts/gen-sbom.sh [--build-info FILE] [--out FILE]
      write the SBOM (default: stdout). FILE is install.sh's
      build-metadata/build-info.txt; without it the kernel package is
      described as "not built".
```

## Related

- [Script reference](../SCRIPTS.md)
- [make-release.md](make-release.md)
