<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `ci/publish-release.sh`

Build a release locally and upload it as a GitHub Release with `gh` (a draft unless `--publish`).

- **Source:** [`ci/publish-release.sh`](../../ci/publish-release.sh)
- **Run by:** the owner, from their own machine

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
publish-release.sh - publish a release as a GitHub Release with gh.

Builds locally (ci/make-release.sh), optionally signs the SHA-256 file with
gpg, then uploads the archive, checksum, SBOM and signature with
`gh release create`. The release is created as a DRAFT unless --publish is
given, so the tag and notes can be reviewed on GitHub first. Nothing is
published without --publish.

Usage: ci/publish-release.sh --notes FILE [--tag vX.Y.Z] [--target BRANCH]
                             [--sign KEYID] [--publish] [--dry-run]
  --tag     default: v$(cat VERSION)
  --target  default: main (the tag is created there by GitHub)
  --sign    gpg key id; writes <name>.tar.gz.sha256.asc (detached, armored)
  --dry-run build and print the gh command; call gh for nothing
```

## Related

- [Script reference](../SCRIPTS.md)
- [make-release.md](make-release.md)
- [MAINTENANCE.md](../MAINTENANCE.md)
