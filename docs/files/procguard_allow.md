<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `/etc/secure_sudo/addons/procguard_allow.conf`

The executables ProcGuard (v8 add-on, [procguard.conf](../configuration/procguard-conf.md))
allows to run. In `enforce` mode any other process is killed, and one that
keeps coming back is quarantined as an infection.

## Facts

- **Location:** `/etc/secure_sudo/addons/procguard_allow.conf` (template
  `temporary/config/procguard_allow.conf`). Root-owned, not group- or
  world-writable; `secure-sudo-procguard check-config` checks the owner, mode
  and every line (NIST CM-5).
- **Read by:** `secure-sudo-procguard` (`temporary/procguard/procguard.c`)
  when the daemon starts. Restart it after a change.
- **Limit:** none in code (the list grows as needed).
- **Always exempt, whatever the list says:** PID 1, kernel threads, the
  shell process tree ProcGuard was started from, and the secure_sudo binaries.
- **Empty list:** ProcGuard refuses to run, because an empty list would mean
  "kill everything".
- **Security reference:** NIST SP 800-53 CM-7(5) (allow-by-exception), SI-4.

## Format

One absolute executable path per line, matched exactly against the running
process's executable. `#` starts a comment line; blank lines are ignored. A
relative path is an error in `check-config`.

```
/usr/sbin/sshd
/usr/bin/bash
```

## Changing it safely

- Populate it in `mode = monitor` first: watch the log for "would kill" lines
  and add the paths you actually need, then switch to `enforce`.
- Run `sudo secure-sudo-procguard check-config` before restarting the daemon;
  the daemon refuses to start on a config error.
- **Approval:** the host owner approves additions; record the reason next to
  the entry (see below).

## Security impact

Every entry is a program that may run on the host; a shell in the list lets
anything a shell can start run too, because ProcGuard checks only the
executable, not its arguments or scripts. Keep the list to what the host's
role needs.

## Entries

Entries shipped in the template, with why each is there, who asked for it and
when it was added. `ci/check-config-docs.py` fails when the template and this
table disagree.

<!-- list-entries:begin -->
| Entry | Why it is there | Requested by | Added |
|---|---|---|---|
<!-- list-entries:end -->

The template ships with no entries (only commented examples: systemd, sshd,
bash, dash, login), so ProcGuard will not start until you add your own.

## Register convention for site entries

Put one comment line directly above each entry you add:

```
# 2026-11-23 requested by: ops; approved by: host owner; why: SSH access
/usr/sbin/sshd
```
