# Kernel release signing keys

`install/install.sh` refuses to extract or build a kernel archive unless
`scripts/verify-kernel-source.sh` has checked its kernel.org signature against
these pinned keys. There is no bypass switch: an unsigned, badly signed, or
unknown-signer archive stops the install before `tar` runs.

| File | Purpose |
|------|---------|
| `release-signers.txt` | the pinned primary-key fingerprints that may sign a release |
| `*.asc` | public keys shipped so verification works offline |

## What is shipped

| Signer | Fingerprint | Key shipped? |
|--------|-------------|--------------|
| Greg Kroah-Hartman (stable/LTS releases, all 6.12.y) | `647F 2865 4894 E3BD 4571 99BE 38DB BDC8 6092 693E` | yes, `gregkh-647F…693E.asc` |
| Linus Torvalds (mainline x.y releases) | `ABAF 11C6 5A29 70B1 30AB E3C4 79BE 3E43 0041 1886` | no, fingerprint pinned only |

Greg's key was fetched by full fingerprint from keyserver.ubuntu.com on
2026-10-26, minimised (`--export-options export-minimal`), and its user IDs
checked (`gregkh@kernel.org`, "Linux kernel stable release signing key"). The
keyserver did **not** return Linus's key for its fingerprint, and a search by
his e-mail address returned two unrelated keys created in 2024 that merely
claim his address. That is exactly why trust here comes from the pinned
fingerprint and never from a keyserver search. If you build a mainline
(`x.y.0`) release, run the verifier with `--fetch-missing`: it retrieves the
key through kernel.org's WKD and still only accepts it when the fingerprint is
pinned.

## Independent check before first use

Compare the fingerprints above with at least one channel that does not depend
on this repository:

```sh
gpg --locate-keys torvalds@kernel.org gregkh@kernel.org   # kernel.org WKD
gpg --fingerprint gregkh@kernel.org torvalds@kernel.org
```

and https://www.kernel.org/signature.html . If they differ, stop.

## Adding or rotating a signer

1. Confirm the new fingerprint through two independent channels.
2. Add the 40-hex fingerprint to `release-signers.txt` with a comment.
3. Optionally add the minimised public key as `<name>-<FPR>.asc`.
4. Re-run `tests/provenance/test-verify-kernel-source.sh`.

Removing a fingerprint revokes trust in it for future builds immediately.
