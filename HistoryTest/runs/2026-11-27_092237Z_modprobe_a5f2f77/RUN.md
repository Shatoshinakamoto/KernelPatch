# modprobe test suite

- **Run id:** `2026-11-27_092237Z_modprobe_a5f2f77`
- **Area:** modprobe
- **Commit:** `a5f2f77`
- **Date (UTC):** 2026-11-27T00:00:00
- **Where:** owner PC (Docker container, root)
- **Verdict:** **pass**

## What was tested and why
tests/install/test-ubuntu-modprobe.sh - Ubuntu modprobe-compatible install (Method 7)

## How
See command.txt.

## Results
ok 1 - a verified archive installs (exit 0)
ok 2 - SHA-256 is reported as checked
ok 3 - preflight runs first
ok 4 - the numbered steps run in order
ok 5 - it is unpacked under --dest/<archive name>
ok 6 - the next steps name verify --commit
ok 7 - --with-modprobe-check runs (exit 0)
ok 8 - --with-modprobe-check ran
ok 9 - --dry-run passes (exit 0)
ok 10 - --dry-run only runs preflight
ok 11 - --dry-run leaves --dest alone
ok 12 - a tampered archive is refused
ok 13 - ... and its install.sh never runs
ok 14 - ... and nothing is unpacked
ok 15 - an archive with a '..' member is refused
ok 16 - ... and nothing ran
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
ok 17 - a good signature from the pinned fingerprint passes
ok 18 - a signature by any other fingerprint is refused
ok 19 - a checksum file changed after signing is refused
ok 20 - --stig with another value is a usage error
ok 21 - a relative --dest is a usage error
ok 22 - a --dest with '..' is a usage error
ok 23 - --initramfs without --with-addons is a usage error
ok 24 - an unknown option is a usage error
1..24

## Failures
None.

## Reproduce
From the repository root at commit a5f2f77: bash tests/install/test-ubuntu-modprobe.sh
