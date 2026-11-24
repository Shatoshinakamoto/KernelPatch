<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `userspace/daemon/helpers/contain.sh`

The helper behind `secure-sudo contain`: isolate the network, freeze or kill a process tree, preserve evidence.

- **Source:** [`userspace/daemon/helpers/contain.sh`](../../userspace/daemon/helpers/contain.sh)
- **Run by:** `secure-sudo contain` (not run by hand)

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
contain.sh - incident containment (TODO P1-7), run by `secure-sudo contain`.

  contain.sh status
  contain.sh network [--allow ADDR]... [--no-collector] [--dry-run] [-y]
  contain.sh account USER [--terminate] [--dry-run] [-y]
  contain.sh process PID [--kill] [--dry-run] [-y]
  contain.sh release network | account USER | process PID [-y]

Every action prefers the reversible step and keeps evidence first:

  network  one nftables table (inet secure_sudo_contain) dropping all
           traffic except loopback, the addresses given with --allow, the
           SSH client of the operator running this (so a remote responder
           is not cut off) and the configured remote_syslog collector (so
           evidence keeps flowing). Loaded in one transaction; `release
           network` deletes the table. It does not touch the net_mode
           table (inet secure_sudo).
  account  lock the password, expire the account (blocks SSH keys too),
           and STOP (SIGSTOP) every process of the user, after saving the
           process list. --terminate kills them instead. root, UID 0 and
           the operator's own account are refused. `release account`
           puts the lock and expiry back as they were and continues the
           stopped processes.
  process  save /proc evidence (cmdline, status, maps, open files,
           sockets, environment, a copy of the executable and its
           SHA-256), then STOP the process and its descendants. --kill
           kills them after the evidence is saved. PID 1, kernel threads
           and the operator's own shell chain are refused. `release
           process` continues them.

Without -y every action shows its plan and asks for "yes" (anything else
exits 3, nothing changed); --dry-run shows the plan and changes nothing. State and evidence go to
/var/lib/secure_sudo/contain (root-only). The CLI records each action in
the policy history (`secure-sudo history`).

Tests only: SS_CONTAIN_STATE (state dir), SS_CONTAIN_CONF (config file),
SS_CONTAIN_NFT_DRYRUN=<file> (write the ruleset there instead of loading
it), SS_CONTAIN_OPERATOR (the operator's login name), SS_CONTAIN_SSH_ADDR.
```

## Related

- [Script reference](../SCRIPTS.md)
- [secure-sudo-contain.md](secure-sudo-contain.md)
- [INCIDENT_RESPONSE.md](../INCIDENT_RESPONSE.md)
