# quick-install.sh suite (root)

- **Run id:** `2026-11-24_101724Z_unit-quick-install_0968b2c`
- **Area:** unit-quick-install
- **Commit:** `0968b2c`
- **Date (UTC):** 2026-11-24T10:47:00+00:00
- **Where:** owner PC (Docker container, root)
- **Verdict:** **pass**

## What was tested and why
install/quick-install.sh: archive verification, unsafe archives, signatures by a pinned fingerprint, preflight blocker, options, no-terminal stop.

## How
See command.txt.

## Results
ok 1 - a verified archive installs (exit 0)
ok 2 - the SHA-256 is reported as checked
ok 3 - preflight runs first, then the full install
ok 4 - it is unpacked under --dest/<archive name>
ok 5 - the next steps name verify --commit
ok 6 - an existing unpack directory is refused, not overwritten
ok 7 - --dry-run passes (exit 0)
ok 8 - --dry-run only runs the preflight
ok 9 - --dry-run leaves --dest alone
ok 10 - a tampered archive is refused (SHA-256 mismatch)
ok 11 - ... and its install.sh never runs
ok 12 - ... and nothing is unpacked
ok 13 - an archive without its .sha256 file is refused
ok 14 - a checksum file without a SHA-256 is refused
ok 15 - an archive with a '..' member is refused
ok 16 - an archive with a link pointing outside is refused
ok 17 - an archive with two top directories is refused
ok 18 - ... none of them ran anything
ok 19 - ... and none was unpacked
ok 20 - a good signature from the pinned fingerprint passes
ok 21 - a signature by any other fingerprint is refused
ok 22 - a checksum file changed after signing is refused
ok 23 - --signature without --signer-key/--signer-fpr is a usage error
ok 24 - a preflight blocker stops it
ok 25 - ... before the install step
ok 26 - --no-tpm-lockout and --stig reach install.sh as SS_TPM_LOCKOUT=0 STIG=scan
ok 27 - --with-addons --initramfs runs install-temporary.sh --initramfs
ok 28 - without --yes and without a terminal it stops before installing
ok 29 - ... after the preflight only
ok 30 - ... and --dest is not written (nothing was changed)
ok 31 - --stig with another value is a usage error
ok 32 - a relative --dest is a usage error
ok 33 - a --dest with '..' is a usage error
ok 34 - --initramfs without --with-addons is a usage error
ok 35 - an unknown option is a usage error
ok 36 - an option missing its value is a usage error
ok 37 - it never downloads anything (no curl or wget)
1..37

## Failures
None.

## Reproduce
See command.txt.
