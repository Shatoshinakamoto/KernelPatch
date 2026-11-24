<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# PheonixBox

## Overview

**PheonixBox:** snapshot tamper protection + auto-repair for chosen files/dirs (SHA-256 manifest detects, compressed snapshot restores, permissions snapshot). See [docs/PHEONIXBOX.md](../PHEONIXBOX.md). (feature #21)

## How it works

**Code:** [`userspace/pheonixbox/`](../../userspace/pheonixbox/).

Full write-up: [PHEONIXBOX.md](../PHEONIXBOX.md).

## How it is secure

**Threat:** tampering with or deleting chosen files (for example configuration), repaired after the fact.

**Standards:** NIST SI-7, SI-7(6), CM-5, CP-10, AU-9; CWE-345.

Runs as root from root-owned files; it is not a boundary against an attacker who already has root on an unlocked host. The general model: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `secure-sudod`'s timer (about every 30 s); the store (`/var/lib/secure_sudo/pheonixbox`) on protected storage.

**Configuration:** [pheonixbox-conf.md](../configuration/pheonixbox-conf.md).

**Commands:** [secure-sudo-pheonixbox](../commands/secure-sudo-pheonixbox.md).

```sh
sudo secure-sudo pheonixbox add /etc/ssh/sshd_config
sudo secure-sudo pheonixbox snapshot
sudo secure-sudo pheonixbox on
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| OpenSSL | distro package (3.x) | SHA-256, Ed25519 manifest signatures | not checked for this page |
| zlib | distro package | snapshot compression | not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

It repairs within one interval, it does not block; whatever a tampered file did meanwhile has happened. Root can turn it off (the lock does not cover userspace). Root can rewrite the store too, unless `trust = signed`: then only an operator-signed snapshot is repaired from, and switching back to `local` is logged CRITICAL. Pair it with #17/#13 for programs.

## Troubleshooting

- **A legitimate edit keeps being reverted.** PheonixBox restores protected files. Disable it, edit, take a new snapshot, enable.

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `tests/userspace/test-pheonixbox.sh` (ROOT-ONLY, in a private mount namespace: snapshot, tamper, detect, restore, permissions, signed snapshots, edited manifests and ACL files).
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
