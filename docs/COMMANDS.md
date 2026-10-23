# secure_sudo — command reference

Everything in secure_sudo is driven by one root-only CLI, `secure-sudo`
(installed to `/usr/bin/secure-sudo`). It reads the files under
`/etc/secure_sudo/` and pushes them into the kernel through
`/sys/kernel/secure_sudo/` (scalar knobs) and
`/sys/kernel/security/secure_sudo/` (policy list files). The OTP password
helper `secure-sudo-otp` is a second binary that `secure-sudo otp …` hands off
to.

Two rules apply to every command below:

* **Root only.** Each command checks `geteuid() == 0` and the kernel files are
  root-only as well, so a non-root invocation fails with a clear message.
* **Refused once locked.** After the one-way config lock engages (see `lock`),
  every write — knobs, policy lists, the allowlist — is refused by the kernel
  with `EPERM` until the machine reboots. Reads (`status`, `get`, `list`) keep
  working.

Run `secure-sudo` with no arguments for the built-in usage summary.

---

## `secure-sudo load`

Read every file under `/etc/secure_sudo/` and push it into the kernel. This is
what makes the on-disk configuration take effect: scalar keys from
`secure-sudo.conf` are written to their `/sys/kernel/secure_sudo/` knobs, and
each policy `*.conf` is written to its securityfs file.

`load` runs automatically at every boot (the systemd unit calls it with
`ExecStartPre`), so the kernel starts in `root-only` safe defaults and then
picks up your saved policy. Run it by hand after editing a `.conf` by hand.

A key the kernel does not recognise (the daemon-only keys such as
`retain_days`) is skipped, not an error.

```sh
sudo secure-sudo load
```

## `secure-sudo status`

Print the current kernel state: every scalar knob's live value, the TimeVault
engage flag and denied-exec counter, and the lock state. Read-only; works even
when locked. If the LSM is not active (wrong kernel booted) it says so.

```sh
sudo secure-sudo status
```

## `secure-sudo settings`

List every configurable kernel setting by name — all the scalar knobs and all
the policy lists — plus a pointer to the `vault-allow` and `lock` commands.
Use it to discover exactly what `get`/`set`/`list` accept. Read-only.

```sh
sudo secure-sudo settings
```

## `secure-sudo get [<knob>]`

Show the **live kernel value** of one scalar knob, or of all of them when no
name is given. Read-only.

```sh
sudo secure-sudo get                 # all knobs and their current values
sudo secure-sudo get block_setid     # just one
```

## `secure-sudo set <knob> <value>`

Change one scalar knob. The value is written to the kernel first; **only if the
kernel accepts it** is it also written back to `/etc/secure_sudo/secure-sudo.conf`,
so the saved configuration can never drift from live policy and the change
survives a reboot. Refused while locked, or if the kernel rejects the value
(for example a number outside its allowed range).

```sh
sudo secure-sudo set block_userns 1
sudo secure-sudo set max_ram_percent 85
sudo secure-sudo set block_setid_exec 1
sudo secure-sudo set binaryvault 1       # freeze all binaries (see CONFIGURATION.md #17)
```

Knob names are exactly the keys listed by `settings` (and documented in
[CONFIGURATION.md](CONFIGURATION.md)).

## `secure-sudo list <name>`

Show a policy list's **current kernel contents** (not the on-disk file).
`<name>` is the securityfs name or the `.conf` file name, e.g. `blacklist`,
`timevault_allow`, `setid_exec_allow`. Read-only.

```sh
sudo secure-sudo list blacklist
sudo secure-sudo list setid_exec_allow
sudo secure-sudo list binvault_allow
```

To change a policy list, edit its file under `/etc/secure_sudo/` and run
`load` (or, for the TimeVault allowlist, use `vault-allow`, which edits and
pushes in one step).

## `secure-sudo net <monitor|host|lan-only|public-only>`

Shortcut for `set net_mode <mode>`; also persisted. See
[CONFIGURATION.md](CONFIGURATION.md#net_mode) for what each mode does. The LAN
and public modes are enforced by the daemon's nftables helper; `host` mode's
raw/packet-socket block is in the kernel.

```sh
sudo secure-sudo net host
```

## `secure-sudo radio <wifi|bluetooth|ethernet-only> <on|off>`

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
kernel is in [CONFIGURATION.md](CONFIGURATION.md#radioguard--wi-fi--bluetooth--ethernet-only-19).

## `secure-sudo timevault <on|off>`

Engage or disengage TimeVault (#13). **Engaging latches the config lock** and
is refused if the allowlist is empty (that would leave nothing runnable).
Because engaging locks the configuration, an engaged vault cannot be
disengaged until the next reboot. The state is persisted.

```sh
sudo secure-sudo vault-allow scan /usr/bin /usr/sbin   # populate first
sudo secure-sudo timevault on
```

## `secure-sudo lock [-y]`

Engage the one-way configuration lock (#16). After this, **no** secure_sudo
setting can change until the machine reboots — the command cannot be re-run to
unlock, and the kernel refuses every write (and blocks module loads, kexec,
hibernation and kernel-memory patching while locked). You are asked to confirm
unless you pass `-y`.

```sh
sudo secure-sudo lock          # prompts "type yes"
sudo secure-sudo lock -y       # no prompt (for scripts)
```

## `secure-sudo vault-allow <subcommand>`

Manage the TimeVault exec allowlist. Entries are stored as `<path> <sha256>`
in `/etc/secure_sudo/timevault_allow.conf` and pushed to the kernel
immediately. Full details — including the standalone script equivalent — are
in [SCRIPTS.md](SCRIPTS.md#timevault-whitelist).

| Subcommand | What it does |
|------------|--------------|
| `vault-allow scan [-n] [-x] <dir>…` | hash every executable binary/script under each `<dir>` and add it. `-n` dry run; `-x` stay on one filesystem |
| `vault-allow add <file>…` | hash and add single files |
| `vault-allow remove <file>…` | drop entries |
| `vault-allow list` | print the saved allowlist |
| `vault-allow wipe [-y] [--force]` | empty the allowlist (asks unless `-y`; refuses while engaged unless `--force`) |

```sh
sudo secure-sudo vault-allow scan /usr/bin /usr/sbin /opt/app
sudo secure-sudo vault-allow add /usr/local/bin/mytool
sudo secure-sudo vault-allow list
```

## `secure-sudo detect-admins [-n]`

Re-detect every admin group on the box (the GIDs of `sudo`, `wheel`, `admin`
and any `%group`/`%#gid` rule in sudoers) and set `admin_gid` to that list, in
both the kernel and `secure-sudo.conf`. Run it after creating a new admin
group. `-n` prints what it found without saving. The installer runs the same
logic once at install time.

```sh
sudo secure-sudo detect-admins -n     # preview
sudo secure-sudo detect-admins        # apply
```

## `secure-sudo otp <subcommand>`

Rotating one-time-password sudo helper (#14/#15). Delegated to
`/usr/bin/secure-sudo-otp`; each subcommand does its own root check.

| Subcommand | What it does |
|------------|--------------|
| `otp setup [--prefix]` | generate a new TOTP seed; `--prefix` also sets a secret prefix word |
| `otp show-key` | print the manual-entry key and `otpauth://` URI |
| `otp show-qr` | render a scannable QR to a root-only PNG and print its `file://` path |
| `otp verify [--pam]` | verify a password; `--pam` reads it from stdin (used by the PAM module) |
| `otp reset [--prefix]` | regenerate the seed (keeps the prefix unless `--prefix`) |
| `otp disable` | shred and remove all OTP secret material |

```sh
sudo secure-sudo otp setup --prefix
sudo secure-sudo otp show-qr
```

See [CONFIGURATION.md](CONFIGURATION.md#otp) for how the secret is stored and
how to wire OTP into PAM.

---

## Quick recipes

```sh
# See everything at a glance
sudo secure-sudo status

# Turn on the setuid-exec gate after allowlisting the few tools users need
sudoedit /etc/secure_sudo/setid_exec_allow.conf
sudo secure-sudo load
sudo secure-sudo set block_setid_exec 1

# Lock a finished appliance down hard
sudo secure-sudo vault-allow scan /usr/bin /usr/sbin /usr/lib /usr/lib64
sudo secure-sudo timevault on      # engages + latches the lock
# (equivalently: sudo secure-sudo lock)

# Freeze every binary against tampering (anti-persistence); update via a
# maintenance reboot with secure_sudo.binvault_maint=1 (see CONFIGURATION.md #17)
sudo secure-sudo set binaryvault 1

# Lock the box to wired Ethernet only (disables Wi-Fi + Bluetooth)
sudo secure-sudo radio ethernet-only on

# Scan / harden to the DISA STIG baseline (reports in /var/log/secure_sudo/stig)
sudo /usr/libexec/secure-sudo/stig-harden.sh --scan
```

STIG scanning and remediation are driven by `stig-harden.sh`, documented in
[SCRIPTS.md](SCRIPTS.md#stig-harden) with the control mapping and real results
in [STIG.md](STIG.md).
