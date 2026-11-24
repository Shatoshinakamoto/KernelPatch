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

Each command has its own page under [commands/](commands/), with every
option, examples and its security notes.

| Command | What it does |
|---|---|
| [`secure-sudo lint [options]`](commands/secure-sudo-lint.md) | Check the configuration before it is enforced (TODO P0-6). |
| [`secure-sudo load [--force]`](commands/secure-sudo-load.md) | Read every file under `/etc/secure_sudo/` and push it into the kernel. |
| [`secure-sudo diff` (also `load --dry-run`)](commands/secure-sudo-diff.md) | Preview a change (TODO P1-6). |
| [`secure-sudo snapshot`](commands/secure-sudo-snapshot.md) | Save the current policy files and live kernel values as a restorable snapshot (TODO P1-6). |
| [`secure-sudo history [-n N] [--json] [--verify]`](commands/secure-sudo-history.md) | Who changed policy and what happened (TODO P1-6). |
| [`secure-sudo restore ID [--no-load] [-y]`](commands/secure-sudo-restore.md) | Return to a known-good policy (TODO P1-6) without editing files by hand. |
| [`secure-sudo contain ...`](commands/secure-sudo-contain.md) | Incident containment (TODO P1-7); the runbook is [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) section 4. |
| [`secure-sudo status`](commands/secure-sudo-status.md) | Print the current kernel state. |
| [`secure-sudo health [--json]`](commands/secure-sudo-health.md) | Report whether secure_sudo, its audit feed, daemon, logging and forwarding are working, and the last load's outcome. |
| [`secure-sudo attest <quote\|ak\|digest>`](commands/secure-sudo-attest.md) | Remote attestation (TODO P2-1). |
| [`secure-sudo evidence-export OUTPUT.tar.gz [--signing-key EXTERNAL.pem]`](commands/secure-sudo-evidence-export.md) | Create a root-only, hash-manifested incident evidence bundle, optionally signed with an external key. |
| [`secure-sudo settings`](commands/secure-sudo-settings.md) | List every configurable kernel setting: the scalar knobs and the policy lists. |
| [`secure-sudo get [<knob>]`](commands/secure-sudo-get.md) | Show the **live kernel value** of one scalar knob, or of all of them when no name is given. |
| [`secure-sudo set <knob> <value>`](commands/secure-sudo-set.md) | Change one scalar knob. |
| [`secure-sudo list <name>`](commands/secure-sudo-list.md) | Show a policy list's **current kernel contents** (not the on-disk file). |
| [`secure-sudo net <monitor\|host\|lan-only\|public-only>`](commands/secure-sudo-net.md) | Shortcut for `set net_mode <mode>`; also persisted. |
| [`secure-sudo radio <wifi\|bluetooth\|ethernet-only> <on\|off>`](commands/secure-sudo-radio.md) | RadioGuard (#19). |
| [`secure-sudo timevault <on\|off>`](commands/secure-sudo-timevault.md) | Engage or disengage TimeVault (#13). |
| [`secure-sudo lock [-y]`](commands/secure-sudo-lock.md) | Engage the one-way configuration lock (#16). |
| [`secure-sudo vault-allow <subcommand>`](commands/secure-sudo-vault-allow.md) | Manage the TimeVault exec allowlist. |
| [`secure-sudo prguard <on\|off\|status\|list\|add\|remove> [path]`](commands/secure-sudo-prguard.md) | Drive the Process Runtime Guard (#20), which protects the runtime memory of every process except whitelisted ones (denies cross-process ptrace/memory tampering and writable+executable mappings). |
| [`secure-sudo pheonixbox <on\|off\|snapshot\|scan\|status\|add\|remove\|list> [path]`](commands/secure-sudo-pheonixbox.md) | PheonixBox (#21). |
| [`secure-sudo detect-admins [-n]`](commands/secure-sudo-detect-admins.md) | Re-detect every admin group on the box (the GIDs of `sudo`, `wheel`, `admin` and any `%group`/`%#gid` rule in sudoers) and set `admin_gid` to that list, in both the kernel and `secure-sudo.conf`. |
| [`secure-sudo node-scan [--dry-run] [--quiet] [DIR\|FILE...]`](commands/secure-sudo-node-scan.md) | Find Node.js runtimes that are not at a standard path and register them for the Node child guard (#11), so their children must be on `node_allowed_children`. |
| [`secure-sudo otp <subcommand>`](commands/secure-sudo-otp.md) | Rotating one-time-password sudo helper (#14/#15). |

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
[stig-harden](commands/stig-harden.md) with the control mapping and real results
in [STIG.md](STIG.md).
