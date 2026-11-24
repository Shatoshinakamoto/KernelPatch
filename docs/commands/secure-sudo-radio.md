<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo radio <wifi|bluetooth|ethernet-only> <on|off>`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

RadioGuard (#19): toggle the wireless radios. The sense is **radio off = radio
disabled**: `radio wifi off` turns Wi-Fi off (sets `block_wifi=1`), `radio wifi
on` re-allows it. `ethernet-only` is the master switch that turns both off at
once. Each change is written to the kernel and persisted, and is refused once
the config is locked. `radio status` prints the three live values. `bt` is an
alias for `bluetooth`.

```sh
sudo secure-sudo radio wifi off            # disable Wi-Fi
sudo secure-sudo radio bluetooth off       # disable Bluetooth
sudo secure-sudo radio ethernet-only on    # disable BOTH (wired only)
sudo secure-sudo radio status              # show current state
```

Equivalent generic form: `sudo secure-sudo set block_wifi 1`,
`set block_bluetooth 1`, `set ethernet_only 1`. What each knob enforces in the
kernel is in [CONFIGURATION.md](../CONFIGURATION.md#radioguard--wi-fi--bluetooth--ethernet-only-19).

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
