<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `scripts/timevault-whitelist.sh`

Run as root. Part of the [script reference](../SCRIPTS.md).

Manage the TimeVault exec allowlist with nothing but bash, coreutils and
findutils. Functionally identical to `secure-sudo vault-allow`. Saves to
`/etc/secure_sudo/timevault_allow.conf` (as `<path> <sha256>` lines) and pushes
the whole list to `/sys/kernel/security/secure_sudo/timevault_allow`. Holds a
`flock` on `/run/secure_sudo-vault-allow.lock` so two editors never race.

```
timevault-whitelist.sh <subcommand> [options]
```

| Subcommand | Options | What it does |
|------------|---------|--------------|
| `scan <dir>…` | `-n`, `-x` | Walk each `<dir>`, and for every executable binary (ELF) or `#!` script, hash it (SHA-256) and add/refresh its entry. |
| `add <file>…` | — | Hash and add single files (warns, but still adds, if a file is not executable). |
| `remove <file>…` | — | Drop entries by path. |
| `list` | — | Print the saved allowlist. |
| `wipe` | `-y`, `--force` | Empty the allowlist. |

Flags:

* `-n`, `--dry-run` *(scan)* — print what would be added; change nothing.
* `-x`, `--one-file-system` *(scan)* — do not cross mount points.
* `-y`, `--yes` *(wipe)* — skip the confirmation prompt.
* `--force` *(wipe)* — wipe even while TimeVault is engaged (normally refused,
  since an empty allowlist would block nearly every exec).

Behaviour notes:

* Paths are canonicalised with `realpath`; a symlink is stored as its target,
  because that is the path the kernel sees at exec time.
* Paths containing whitespace cannot be represented in the kernel list and are
  skipped with a warning.
* Re-running `scan` re-hashes changed files and leaves unchanged ones alone.
* Limits match the kernel: 16384 entries / 4 MiB. Over that, nothing is saved.
* If the LSM is not loaded yet, it still writes the `.conf` and tells you the
  kernel will pick it up at next boot.
* This bash twin manages hash entries only. Auto-update entries (`add-auto`,
  `add-autodir`) and `remove-dir` are features of the compiled `secure-sudo
  vault-allow` CLI.

```sh
sudo /usr/libexec/secure-sudo/timevault-whitelist.sh scan -n /usr/local/bin
sudo /usr/libexec/secure-sudo/timevault-whitelist.sh scan /usr/bin /usr/sbin
sudo /usr/libexec/secure-sudo/timevault-whitelist.sh add /opt/app/bin/app
sudo /usr/libexec/secure-sudo/timevault-whitelist.sh wipe        # prompts
```

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
