<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo evidence-export OUTPUT.tar.gz [--signing-key EXTERNAL.pem]`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Create a root-only incident bundle containing local secure_sudo logs,
non-secret policy/configuration files, live kernel knobs and loss counters,
boot/kernel/LSM identity, service state, quarantine metadata and a SHA-256
manifest. The exporter never copies quarantined file contents and excludes
configuration files whose names indicate secrets, keys, tokens or passwords.
Original logs and quarantined files are not changed.

The bundle includes a per-log hash chain. Optionally sign its final checkpoint
and checksum manifest with an Ed25519 PEM key held outside the monitored host
(for example on a controlled removable device); the public key is included
for verification. Verify `SHA256SUMS` first, then verify both detached
signatures with `openssl pkeyutl -verify -rawin -pubin`. Trust the public key
through a separate channel; the bundled key alone does not establish identity.
A locally stored signing key does not provide protection from a compromised
root account. Protect and transport the bundle as sensitive incident evidence.

```sh
sudo secure-sudo evidence-export /root/incident-2026-10-26.tar.gz
sudo secure-sudo evidence-export /root/incident.tar.gz --signing-key /mnt/key/incident-ed25519.pem
secure-sudo evidence-verify /root/incident-2026-10-26.tar.gz
secure-sudo evidence-verify /root/incident.tar.gz --trusted-key /mnt/trusted/incident-ed25519.pub
secure-sudo evidence-verify /root/incident.tar.gz --checkpoints collector-secure_sudo.log
secure-sudo evidence-verify /root/incident.tar.gz --timevault collector-secure_sudo.log
secure-sudo evidence-verify --timevault-root /var/lib/secure_sudo/manifest
```

`evidence-verify` safely inspects the archive without extracting untrusted
paths, validates the checksum manifest and recomputes every per-log chain.

`--checkpoints FILE` also checks the bundle against the `log_checkpoint`
records the remote collector received. `secure-sudod` logs and forwards one
every 5 minutes, holding the log name, line count and chain value. Each
record must match the chain after that many lines. A log edited or
truncated on the host afterwards fails, even if the attacker was root there:
the collector's copy was never on the host. The verifier reports, per log,
how many lines are anchored that way and how many came after the last
checkpoint. The file can be the collector's raw syslog output; the JSON
record is taken from the first `{` on each line.

`--timevault FILE` checks the TimeVault manifest (gap G2) against the same
collector file. While TimeVault is engaged the manifest never changes, so
every `timevault_merkle` root the daemon forwarded must equal the
engagement's `timevault_baseline` root; a different root means the
manifest was rewritten, and a second baseline with no `timevault_disengaged`
in between means it was deleted and retaken. The bundle's copy
(`live/timevault-manifest`) must hash to the last root. Outside changes the
daemon caught and undid (`timevault_manifest_modified`) are reported as
warnings. `--timevault-root MANIFEST` prints a manifest's root, to compare
by hand.
For signed bundles, pass the independently trusted public key; the verifier
checks both signatures and rejects a signed bundle if no trusted key is
provided. Unsigned bundles receive integrity checks but no authenticity proof.
For preservation, custody, and key-handling steps, see
[`INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md).

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
