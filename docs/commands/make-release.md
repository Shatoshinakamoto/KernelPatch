<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `ci/make-release.sh`

Build the byte-reproducible release tarball with its SHA-256 file and SPDX SBOM.

- **Source:** [`ci/make-release.sh`](../../ci/make-release.sh)
- **Run by:** the maintainer

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
make-release.sh - build the release tarball reproducibly (TODO P0-1/P0-4).

Same inputs give a byte-identical archive: files are listed in a fixed
order, owners/timestamps are normalised to ci/release-epoch, gzip stores no
name or time, and file modes are set explicitly (0755 for anything with a
shebang, 0644 otherwise) so the archive never depends on whether the
checkout - or a network share it sits on - kept executable bits. Earlier
packages were built from such a share and shipped every script as 0644.

Writes <out>/<name>.tar.gz, <name>.tar.gz.sha256 and <name>.spdx.json.

Usage: ci/make-release.sh [--out DIR] [--name NAME] [--prefix DIR]
```

## Related

- [Script reference](../SCRIPTS.md)
- [publish-release.md](publish-release.md)
- [gen-sbom.md](gen-sbom.md)
