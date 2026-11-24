<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `scripts/detect-admin-gids.sh`

Run as root. Part of the [script reference](../SCRIPTS.md).

Print every admin-group GID on the box as a comma list (e.g. `27,10`), for
`admin_gid`. Sources: the groups `sudo`, `wheel`, `admin` that exist, plus
every `%group` / `%#gid` rule in `/etc/sudoers` and `/etc/sudoers.d/`
(skipping the files sudo itself ignores). The compiled CLI has the same logic
as `secure-sudo detect-admins`. `install.sh` calls this at install time.

```
detect-admin-gids.sh [--apply]
```

* *(no option)* — print the detected list to stdout and exit.
* `--apply` — also write it to `admin_gid` in `secure-sudo.conf` and to the
  live kernel knob (root only). Warns if no admin groups are found (only root
  would then count as sudo).

```sh
/usr/libexec/secure-sudo/detect-admin-gids.sh            # just print
sudo /usr/libexec/secure-sudo/detect-admin-gids.sh --apply
```

Caps at 16 GIDs (the kernel limit); extras are reported and ignored.

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
