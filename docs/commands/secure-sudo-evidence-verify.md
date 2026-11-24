<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo evidence-verify FILE [--trusted-key PUBLIC.pem] [--checkpoints COLLECTOR.log] [--timevault COLLECTOR.log]`

Check an evidence bundle made by [`secure-sudo evidence-export`](secure-sudo-evidence-export.md)
before you rely on it: every member is safe to read, the SHA-256 manifest
covers the whole payload, each exported log's hash chain recomputes, a
detached signature verifies against a public key you supply, and (with
`--checkpoints` / `--timevault`) the logs and TimeVault Merkle roots match what
the off-box collector received. Read-only; it does **not** need root, so run
it on the analyst's machine, not the suspect host. Members are only ever
unpacked into a private temporary directory.

```sh
secure-sudo evidence-verify /root/incident.tar.gz
secure-sudo evidence-verify incident.tar.gz --trusted-key /mnt/trusted/incident-ed25519.pub
secure-sudo evidence-verify incident.tar.gz --checkpoints collector.log --timevault collector.log
secure-sudo evidence-verify --timevault-root manifest.txt     # print a manifest's Merkle root
```

## Options

The helper's own option help (`userspace/daemon/helpers/evidence-verify.py --help`):

```text
usage: evidence-verify.py [-h] [--trusted-key TRUSTED_KEY]
                          [--checkpoints CHECKPOINTS] [--timevault TIMEVAULT]
                          [--timevault-root MANIFEST]
                          [archive]

verify checksums, event chains, and signatures in an evidence bundle

positional arguments:
  archive               evidence .tar.gz created by secure-sudo evidence-
                        export

options:
  -h, --help            show this help message and exit
  --trusted-key TRUSTED_KEY
                        trusted PEM public key for signed bundles
  --checkpoints CHECKPOINTS
                        log_checkpoint records as received by the remote
                        collector; each must match the bundle's logs
  --timevault TIMEVAULT
                        the collector's records (as for --checkpoints): every
                        TimeVault Merkle root must agree, and the bundle's
                        TimeVault manifest must hash to the last one
  --timevault-root MANIFEST
                        print the Merkle root of a TimeVault manifest file and
                        exit
```

Exit status 0 means every check passed; anything else names the check that failed.

## Security notes

- Unsafe archive members (absolute paths, `..`, links, devices) are refused
  (CWE-22). NIST AU-9, AU-10.
- A signature only means something if the public key came from somewhere
  the attacker could not reach; `--trusted-key` must be a copy you hold, not
  one from the bundle.
- `--checkpoints` and `--timevault` compare against the collector's copy, so a
  host that rewrote its own logs or TimeVault manifest is caught (AU-9(2)).

## Related

- [`secure-sudo evidence-export`](secure-sudo-evidence-export.md)
- [`evidence-verify.py`](evidence-verify-py.md)
- [INCIDENT_RESPONSE.md](../INCIDENT_RESPONSE.md)
