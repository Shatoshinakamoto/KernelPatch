<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `/etc/secure_sudo/pheonixbox.conf`

The set of files PheonixBox (#21) snapshots, locks read-only and restores
when they are changed or deleted, plus the snapshot trust mode. Feature
detail: [PHEONIXBOX.md](../PHEONIXBOX.md).

## Location, format and reload

- **Path:** `/etc/secure_sudo/pheonixbox.conf`, root-owned, not group- or
  world-writable. Whoever can edit it can drop a file from protection or
  lower the trust mode (NIST CM-5).
- **Read by:** the `secure-sudo-pheonixbox` helper (`secure-sudo pheonixbox
  ...`) and its daemon timer scan (about every 30 s).
- **Format:** two kinds of line.
  - A **path line** starts with `/` (after optional spaces): an absolute
    file, or a directory protected recursively. Paths with spaces, tabs or
    control characters, and paths with `.`, `..` or empty components, are
    skipped with a warning, because the manifest is line-based.
  - A **setting line**: `trust = local` or `trust = signed`.
  - Anything else (comments starting with `#`, blank lines, relative paths)
    is ignored.
- **Editing:** `secure-sudo pheonixbox add PATH` and `remove PATH`, or by
  hand. Path changes take effect on the next `secure-sudo pheonixbox snapshot`
  (run while PheonixBox is disabled). A `trust` change takes effect on the
  next scan.

## Key reference

<!-- config-keys:begin -->
| Key | Type | Allowed | Default | Shipped |
|-----|------|---------|---------|---------|
| `trust` | enum | `local`, `signed` | `local` | (commented) |
<!-- config-keys:end -->

The path lines have no key; the shipped file has only commented examples, so
nothing is protected until you add paths.

## What each setting does, and its security impact

- **`trust`**: what PheonixBox trusts as the good copy.
  - `local` trusts the host's own manifest. Simple, but root on a compromised
    host can rewrite the snapshot store and the manifest together, and
    PheonixBox would then "restore" the attacker's version.
  - `signed` repairs only while `manifest.sig` is a valid Ed25519 signature
    over the manifest by the operator's key, whose public half is
    `/etc/secure_sudo/addons/baseline-signing.pub` (root-owned, not group- or
    world-writable, or it is refused). The private key never needs to be on
    the host. While the manifest is not trusted, a scan still detects
    tampering, keeps the evidence and logs it CRITICAL, but writes nothing
    back.
  - **Fail-secure:** an unreadable config, or a `trust` line with an unknown
    value, counts as `signed`, so a typo never quietly trusts the host's own
    copy. Each new snapshot's SHA-256 and the key fingerprint are logged
    CRITICAL, and a scan that sees the mode lowered from `signed` to `local`
    says so CRITICAL, so both are on record off-box.
  - *Recommended:* `signed` on any host where root compromise is in scope.
    NIST SI-7, SI-7(6) (cryptographic protection), AU-9.
- **Path lines**: each listed file is snapshotted (SHA-256 manifest and a
  compressed copy, root-only `0700` store), its owner, mode and ACLs are
  recorded, and it is made read-only. *Security impact:* keep the list to
  files whose changes are always unwanted (for example `/etc/ssh/sshd_config`);
  protecting a file that legitimate software rewrites makes PheonixBox fight
  it. NIST SI-7, CM-5, CP-10 (restore).

## Tests

`tests/userspace/test-pheonixbox.sh` covers the path rules, snapshot, repair
and the trust modes.
