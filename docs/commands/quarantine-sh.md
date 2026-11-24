<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `userspace/daemon/helpers/quarantine.sh`

Run as root. Part of the [script reference](../SCRIPTS.md).

Called by `secure-sudod` in two cases, both when `vault_action=quarantine`
(the default): when TimeVault is engaged and a new or changed file appears in a
watched tree, and when the kernel **blocks an exec** because a listed binary's
hash no longer matches or an unlisted binary tried to run. Not run by hand.

```
quarantine.sh <file>
```

It records the file's origin path, timestamp and SHA-256 in a `.meta` sidecar
(newlines in names escaped), packages file + metadata into a uniquely named
zip under `/var/lib/secure_sudo/quarantine/` (`tar.gz` if `zip` is absent),
**verifies the archive** (`unzip -l` / `tar -tzf`), and only then removes the
original. If archiving fails the original stays where it was and the daemon
logs it and retries later; two files with the same name never overwrite each
other's evidence. All filename handling uses `--` so an attacker-chosen name
cannot be read as an option.

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
