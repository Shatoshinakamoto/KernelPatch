<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `scripts/cis-nftables.sh`

Run as root. Part of the [script reference](../SCRIPTS.md).

CIS's own firewall table, `inet filter`, next to secure_sudo's `inet secure_sudo`
(owner's choice 2026-11-23: coexist). Installed to
`/usr/libexec/secure-sudo/cis-nftables.sh`; `stig-harden.sh --cis-firewall`
runs it with `--apply`. Needs root only for `--apply`.

```
cis-nftables.sh [--allow-tcp PORT]... [--forward drop|established]
                [--print | --out FILE | --apply | --print-dropin]
```

| Flag | Default | What it does | Security note |
|------|---------|--------------|---------------|
| `--allow-tcp PORT` | none | Extra inbound TCP port, 1 to 65535 (repeatable). The ports `sshd -T` reports, or 22, are always added. | Every port added is reachable from anywhere that secure_sudo's mode allows; add only services you run. |
| `--forward drop\|established` | `established` | `established` passes replies to routed flows and drops new routed flows; `drop` routes nothing. | Both keep the CIS default-deny forward policy. |
| `--print` | yes | Write the ruleset to stdout. | Read-only. |
| `--out FILE` | | Write the ruleset to FILE. | Read-only for the firewall. |
| `--apply` | | Check with `nft -c`, back up `/etc/nftables.conf` as `.pre-cis`, install and load it (restoring the backup if the load fails), install the `nftables.service` drop-in (OSB-24), `systemctl daemon-reload` and `enable nftables.service`. | Changes the live firewall: run it from a console or with SSH on an allowed port. It never touches `inet secure_sudo`. |
| `--print-dropin` | | Write the drop-in to stdout. | Read-only. |

The ruleset never uses `flush ruleset` (OSB-23) and resets only `inet filter`.
The drop-in `/etc/systemd/system/nftables.service.d/secure-sudo-keep-tables.conf`
replaces the vendor `ExecStop=nft flush ruleset` with `nft delete table inet
filter` (OSB-24). Environment, for tests only: `SS_CIS_NFT_CONF`,
`SS_CIS_UNIT_DIR`, `SS_CIS_SSH_PORTS`, `SS_CIS_NO_SYSTEMCTL=1`. Exit codes: 0 ok,
1 the check or load failed (nothing changed, or the previous file restored), 2
usage. Tests: `tests/userspace/test-cis-firewall.sh`.

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
