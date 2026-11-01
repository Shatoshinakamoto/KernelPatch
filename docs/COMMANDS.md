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

## `secure-sudo lint [options]`

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

## `secure-sudo load [--force]`

Read every file under `/etc/secure_sudo/` and push it into the kernel. This is
what makes the on-disk configuration take effect: scalar keys from
`secure-sudo.conf` are written to their `/sys/kernel/secure_sudo/` knobs, and
each policy `*.conf` is written to its securityfs file.

`load` runs automatically at every boot (the systemd unit calls it with
`ExecStartPre`), so the kernel starts in `root-only` safe defaults and then
picks up your saved policy. Run it by hand after editing a `.conf`.

It runs `lint` first (PAM problems count as warnings there) and **refuses to
change anything** if lint finds an error, so a typo cannot leave the kernel
running half a policy; `--force` loads anyway. Then it reports every setting:

```
  accepted  block_setid = 1
  rejected  sudo_max_fails = 7: Operation not permitted
  skipped   retain_days (read by secure-sudod, not the kernel)
load: 41 accepted, 1 rejected, 6 skipped
secure-sudo: load INCOMPLETE: the kernel is running a partial policy; ...
```

Exit status is non-zero on a refusal or when any setting was rejected.
Daemon-only keys (`retain_days`, `remote_syslog`, …) and `timevault_enabled`
are reported as skipped, never as errors.

Remote forwarding uses the daemon-only settings in
[`CONFIGURATION.md`](CONFIGURATION.md#logging--retention-9). Configure
`remote_syslog_transport = tls` with a collector `host:port` to enable
certificate-verified RFC 5425 syslog and a bounded persistent retry queue.
`secure-sudo health --json` reports transport state, queue backlog and drops;
neither UDP datagram sends nor TLS stream writes claim collector persistence.

```sh
sudo secure-sudo lint && sudo secure-sudo load
```

Recovery from a policy that locks you out: [RECOVERY.md](RECOVERY.md).

## `secure-sudo status`

Print the current kernel state: every scalar knob's live value, the TimeVault
engage flag and denied-exec counter, and the lock state. Read-only; works even
when locked. If the LSM is not active (wrong kernel booted) it says so.

```sh
sudo secure-sudo status
```

## `secure-sudo health [--json]`

report whether secure_sudo is active, whether the configured kernel audit feed
and root-owned mode-0600 daemon heartbeat/metrics are active and fresh, whether
configured kernel settings match their live values, whether local log writes
failed, whether event or forwarding queues have reported loss, and whether
log retention is active or held for an investigation. It also
reports the last `load` outcome
and its accepted, rejected and skipped counts. Refused or partial loads degrade
health; the root-owned mode-0600 result is atomically updated after each load
and bound to the current boot ID, so a result from a previous boot is stale.
The result includes rejected setting names (up to eight, with an omitted count)
without persisting their configured values or error text.
Missing or untrusted load status is reported as unknown and degrades health.
Exit status is zero only when all available checks are healthy. `--json` emits
a machine-readable object for monitoring; unavailable loss counters are
`null`, never treated as zero.
An active `/var/lib/secure_sudo/retention.hold` marker suspends age- and
size-based log deletion; health reports `held`, while an invalid marker
reports `hold_error` and degrades health. See
[`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) for the preservation procedure.

```sh
sudo secure-sudo health
sudo secure-sudo health --json
```

This is an initial health view, not a complete fleet-health or collector
delivery guarantee. It reports UDP send errors and labels successful
`sendto` calls `udp_unconfirmed`; configured UDP forwarding remains degraded.
TLS queue state and loss are reported, but successful TLS writes are also
unconfirmed at the collector-application level. The JSON includes
`addon_health` plus the load, active and enabled states of optional add-on
services and timers installed by `temporary/`. Disabled optional units do not
degrade health; enabled units that failed to start do. If systemd status cannot
be queried, add-on health is `unavailable` and the overall result is degraded.
Timer entries include their last trigger time and the associated scan service's
last exit time, result, and exit status; a failed scan or enabled timer with no
successful scan in the preceding 26 hours degrades health. DriverGuard,
BootGuard and BiosGuard timer
entries also report baseline age. An enabled scan timer with no root-owned
regular baseline, a baseline older than 30 days, or a future timestamp
degrades health.

## `secure-sudo evidence-export OUTPUT.tar.gz [--signing-key EXTERNAL.pem]`

Create a root-only incident bundle containing local secure_sudo logs,
non-secret policy/configuration files, live kernel knobs and loss counters,
boot/kernel/LSM identity, service state, quarantine metadata and a SHA-256
manifest. The exporter never copies quarantined file contents and excludes
configuration files whose names indicate secrets, keys, tokens or passwords.
Original logs and quarantined files are not changed.

The bundle includes a per-log hash chain. Optionally sign its final checkpoint
and checksum manifest with an Ed25519 PEM key held outside the monitored host
(for example on a controlled removable device); the public key is included
for verification. Verify `SHA256SUMS` first, then verify both detached
signatures with `openssl pkeyutl -verify -rawin -pubin`. Trust the public key
through a separate channel; the bundled key alone does not establish identity.
A locally stored signing key does not provide protection from a compromised
root account. Protect and transport the bundle as sensitive incident evidence.

```sh
sudo secure-sudo evidence-export /root/incident-2026-10-26.tar.gz
sudo secure-sudo evidence-export /root/incident.tar.gz --signing-key /mnt/key/incident-ed25519.pem
secure-sudo evidence-verify /root/incident-2026-10-26.tar.gz
secure-sudo evidence-verify /root/incident.tar.gz --trusted-key /mnt/trusted/incident-ed25519.pub
secure-sudo evidence-verify /root/incident.tar.gz --checkpoints collector-secure_sudo.log
secure-sudo evidence-verify /root/incident.tar.gz --timevault collector-secure_sudo.log
secure-sudo evidence-verify --timevault-root /var/lib/secure_sudo/manifest
```

`evidence-verify` safely inspects the archive without extracting untrusted
paths, validates the checksum manifest and recomputes every per-log chain.

`--checkpoints FILE` also checks the bundle against the `log_checkpoint`
records the remote collector received. `secure-sudod` logs and forwards one
every 5 minutes, holding the log name, line count and chain value. Each
record must match the chain after that many lines. A log edited or
truncated on the host afterwards fails, even if the attacker was root there:
the collector's copy was never on the host. The verifier reports, per log,
how many lines are anchored that way and how many came after the last
checkpoint. The file can be the collector's raw syslog output; the JSON
record is taken from the first `{` on each line.

`--timevault FILE` checks the TimeVault manifest (gap G2) against the same
collector file. While TimeVault is engaged the manifest never changes, so
every `timevault_merkle` root the daemon forwarded must equal the
engagement's `timevault_baseline` root; a different root means the
manifest was rewritten, and a second baseline with no `timevault_disengaged`
in between means it was deleted and retaken. The bundle's copy
(`live/timevault-manifest`) must hash to the last root. Outside changes the
daemon caught and undid (`timevault_manifest_modified`) are reported as
warnings. `--timevault-root MANIFEST` prints a manifest's root, to compare
by hand.
For signed bundles, pass the independently trusted public key; the verifier
checks both signatures and rejects a signed bundle if no trusted key is
provided. Unsigned bundles receive integrity checks but no authenticity proof.
For preservation, custody, and key-handling steps, see
[`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md).

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
| `vault-allow add-auto <file>…` | add a self-updating **file** as an auto-update entry (exec allowed without a hash check) |
| `vault-allow add-autodir <dir>…` | add a self-updating **directory**: any binary under it execs without a hash check |
| `vault-allow remove <file>…` | drop entries by path |
| `vault-allow remove-dir <dir>…` | walk a directory and remove every executable binary / script found under it from the allowlist (plus an `autodir` entry for the dir itself) |
| `vault-allow list` | print the saved allowlist |
| `vault-allow wipe [-y] [--force]` | empty the allowlist (asks unless `-y`; refuses while engaged unless `--force`) |

Auto-update entries are only honoured while `timevault_allow_autoupdate = 1`
(see [CONFIGURATION.md](CONFIGURATION.md)); set that to `0` to refuse every
auto-update entry at once. The allowlist size is capped by
`timevault_max_entries`.

```sh
sudo secure-sudo vault-allow scan /usr/bin /usr/sbin /opt/app
sudo secure-sudo vault-allow add /usr/local/bin/mytool
sudo secure-sudo vault-allow add-autodir /opt/self-updating-app
sudo secure-sudo vault-allow remove-dir /opt/old-app
sudo secure-sudo vault-allow list
```

## `secure-sudo prguard <on|off|status|list|add|remove> [path]`

Drive the Process Runtime Guard (#20), which protects the runtime memory of
every process except whitelisted ones (denies cross-process ptrace/memory
tampering and writable+executable mappings).

| Form | What it does |
|------|--------------|
| `prguard on` / `prguard off` | enable/disable the guard (kernel + persisted) |
| `prguard status` | print the live `prguard_enabled` value |
| `prguard list` | print the live kernel exemption list |
| `prguard add <path>` | add an absolute **executable path** to the exemption list and push it |
| `prguard remove <path>` | remove an exemption |

The exemption list is `/etc/secure_sudo/prguard_allow.conf` (securityfs
`prguard_allow`); list a program here only if it genuinely needs to debug other
processes or map W+X memory (gdb, strace, perf, some JITs). Refused once the
config is locked.

```sh
sudo secure-sudo prguard add /usr/bin/gdb     # let gdb debug (exempt it)
sudo secure-sudo prguard on                    # guard everything else
sudo secure-sudo prguard status
sudo secure-sudo prguard list
```

See [BINARYVAULT.md](BINARYVAULT.md) for the companion anti-tamper feature, and
[CONFIGURATION.md](CONFIGURATION.md) for every setting these commands touch.

## `secure-sudo pheonixbox <on|off|snapshot|scan|status|add|remove|list> [path]`

PheonixBox (#21): snapshot-based tamper protection with automatic repair for a
chosen set of files and directories. Delegated to the
`/usr/bin/secure-sudo-pheonixbox` helper; each form is root-only. Full detail is
in [PHEONIXBOX.md](PHEONIXBOX.md).

**Important:** this does *not* reverse a hash — a SHA-256 hash is one-way and
cannot be turned back into a file. PheonixBox uses a SHA-256 manifest to
**detect** tampering and a root-only, zlib-compressed **snapshot store of the
original bytes** to **restore** it (reversible, no password). The hash finds the
damage; the snapshot store does the repair.

| Form | What it does |
|------|--------------|
| `pheonixbox on` / `enable` | snapshot the protected files (hashes + compressed originals + owner/mode/ACLs), lock them read-only, and start periodic scanning |
| `pheonixbox off` / `disable` | restore every file's original permissions (and ACLs) from the PermissionsSnapshot and stop protecting |
| `pheonixbox snapshot` | (while off) re-capture current contents, hashes and permissions as the new known-good baseline |
| `pheonixbox scan [--quiet]` | check every protected file now and repair any tampering (the daemon runs this on a ~30 s timer) |
| `pheonixbox status` | show whether protection is on, how many files are covered, and the last scan |
| `pheonixbox add <path>` | add a file or directory (recursive) to the protected set |
| `pheonixbox remove <path>` | remove a path from the protected set |
| `pheonixbox list` | list the protected paths |

The protected set lives in `/etc/secure_sudo/pheonixbox.conf` (one absolute path
per line). A real update to a protected file is a deliberate `off` → edit →
`on` (or `off` → edit → `snapshot` → `on`).

```sh
sudo secure-sudo pheonixbox add /etc/ssh/sshd_config
sudo secure-sudo pheonixbox add /usr/local/bin        # whole dir, recursive
sudo secure-sudo pheonixbox on                         # lock + begin repairing
sudo secure-sudo pheonixbox status
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

## `secure-sudo node-scan [--dry-run] [--quiet] [DIR|FILE...]`

Find Node.js runtimes that are not at a standard path and register them for
the Node child guard (#11), so their children must be on
`node_allowed_children`. A runtime is an executable ELF file holding Node's
SEA fuse (a single-executable app, or a renamed `node`) or pkg's markers.
Electron apps embed Node too but are reported, not registered; list one in
`node_sea_binaries.conf` to confine it.

With no DIR it searches `node_sea_scan_dirs`. With DIRs it searches only
those and keeps what earlier scans found elsewhere. Results go to
`/var/lib/secure_sudo/node_sea_auto.list`; the kernel gets the hand-written
`node_sea_binaries.conf` entries first, then these, up to 256 entries (the
command exits 1 and says how many did not fit). Unchanged files are not
read again. The daemon runs it at start and every `node_sea_scan_interval`
minutes; run it yourself right after deploying an app. `--dry-run` prints
`PATH<TAB>KIND` lines (`sea`, `node`, `pkg`) and changes nothing.

```sh
sudo secure-sudo node-scan --dry-run /opt/myapp   # what would be registered
sudo secure-sudo node-scan                         # scan and register
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
