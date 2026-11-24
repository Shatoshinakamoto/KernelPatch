<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo history [-n N] [--json] [--verify]`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Who changed policy and what happened (TODO P1-6). The records are kept in
`/var/lib/secure_sudo/policy/history.jsonl` (root-only), one JSON object per
`load`, `restore`, `set`, `lock`, `timevault` and manual `snapshot`:

| Field | Meaning |
|---|---|
| `time`, `ts` | when (UTC; epoch seconds) |
| `action` | `load`, `restore`, `set`, `lock`, `timevault`, `snapshot` |
| `uid`, `loginuid`, `sudo_user` | who: the login uid survives `sudo`/`su` |
| `result` | `complete`, `partial` (the kernel rejected something), `refused` (lint errors, locked, no LSM, bad snapshot), `rejected` (a single `set`) |
| `lint_errors`, `changes` | lint errors, and how many settings/list entries differed from the kernel before the load |
| `accepted`, `rejected`, `skipped`, `rejected_keys` | the kernel's verdicts |
| `detail` | e.g. `sudo_max_fails = 9`, `--force despite lint errors` |
| `snapshot`, `snapshot_sums` | the snapshot taken before the change, and its `SHA256SUMS` hash |
| `restored_from` | the snapshot a restore put back |
| `prev` | SHA-256 of the previous line (64 zeros for the first) |

`history` prints the last 20 (`-n N`; `--json` prints the raw lines).
`--verify` walks the chain and fails on an edited, removed or reordered
line, or on a snapshot that no longer matches the hash recorded for it.
Every record is also sent to syslog (`authpriv.notice`, tag `secure-sudo`,
`policy_change {...}`), so a forwarding syslog keeps a copy off the box.
`evidence-export` includes the file as `live/policy-history.jsonl`.

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
