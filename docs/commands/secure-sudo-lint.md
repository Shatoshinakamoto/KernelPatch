<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo lint [options]`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Check the configuration before it is enforced (TODO P0-6). Nothing is
written; `lint` is the one command that also runs without root (the checks
that need root are then skipped and say so). It reports every problem with
the file and line it comes from, as `error`, `warning` or `note`, and exits
non-zero when there is at least one error.

What it checks:

* **syntax and bounds** — every line of `secure-sudo.conf` parses, every key
  is known (a typo is an error, not silently ignored), every value is in the
  range the kernel accepts (`max_ram_percent` 1–100, `sudo_max_fails`
  1–1000, …), booleans are `0`/`1`, `net_mode` is one of its four values;
* **list files** — absolute paths where paths are expected, names where
  names are, `uid /home/…` pairs in `home_map.conf`; files and the directory
  are root-owned and not group/world-writable;
* **admin groups** — every `admin_gid` exists and has members, and covers the
  admin running `lint` (via `SUDO_UID`); `unset` with `block_setid_exec = 1`
  is an error (only root could run setuid programs);
* **combinations** — settings that only work together (e.g.
  `block_home_write` with an empty `home_map.conf`), and what engaging the
  lock would freeze;
* **PAM** — the `sudo`/`su` stacks, following `@include`/`include`/`substack`:
  `pam_secure_sudo.so` placed before the password check, no
  `[default=die]` on a verifier, no old `authfail`/`authsucc` lines, OTP
  wired only once an OTP secret exists, `use_first_pass` not before a
  verifier, every referenced module installed;
* **the running kernel** — the LSM is active, every knob exists in this
  kernel, and the config is not locked (a locked kernel refuses every write
  until reboot).

```sh
secure-sudo lint                    # the installed configuration
secure-sudo lint -q                 # problems and the summary only
secure-sudo lint --source-tree --config-dir userspace/config --no-kernel   # a checkout
```

Options: `--config-dir DIR`, `--pam-dir DIR`, `--otp-dir DIR`, `--no-kernel`,
`--no-pam`, `--source-tree` (no ownership/machine/kernel/PAM checks), `-q`.

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
