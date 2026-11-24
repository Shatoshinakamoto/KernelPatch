<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `scripts/verify-kernel-source.sh`

Verify a kernel.org tarball's signature against the pinned signer keys before it is extracted; fail closed.

- **Source:** [`scripts/verify-kernel-source.sh`](../../scripts/verify-kernel-source.sh)
- **Run by:** install.sh and the gate, before any kernel build

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
verify-kernel-source.sh - check a kernel.org release archive against its
detached OpenPGP signature BEFORE anything extracts it (TODO P0-4).

kernel.org signs the uncompressed .tar, so the archive is decompressed into
gpgv as a stream; nothing is written to disk. Fails closed: a missing or
unreadable signature, a bad signature, a signer whose primary fingerprint is
not pinned in install/keys/release-signers.txt, a revoked/expired key, or a
corrupt archive all exit non-zero. There is no override.

Usage:
  scripts/verify-kernel-source.sh [--keys DIR] [--fetch-missing]
                                  [--metadata FILE] ARCHIVE SIGNATURE

  --keys DIR       pinned keyring dir (default: install/keys)
  --fetch-missing  if the signer's key is not shipped, fetch it via WKD
                   (gpg --locate-keys); it is still only accepted when its
                   fingerprint is pinned
  --metadata FILE  write verified provenance (key=value) to FILE

Exit: 0 verified; 1 verification failed; 2 usage/tooling error.
```

## Related

- [Script reference](../SCRIPTS.md)
- [install-sh.md](install-sh.md)
- [README.md](../../install/keys/README.md)
