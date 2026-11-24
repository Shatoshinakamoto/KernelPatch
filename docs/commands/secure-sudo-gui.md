<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo-gui`

The local, token-protected management web console for the add-ons.

- **Source:** [`temporary/gui/secure-sudo-gui`](../../temporary/gui/secure-sudo-gui)
- **Run by:** root, through its systemd unit

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
secure-sudo-gui - local web management console for the secure_sudo stack.

One dependency-free (Python stdlib) HTTP service that lets an operator view
and configure the whole stack from a browser:
  - status of every guard (ProcGuard/DriverGuard/BiosGuard/BootGuard/Locus/
    tamperwatch) and PheonixBox, plus the live kernel knobs;
  - the logs coming specifically from this kernel patch (the daemon's dated
    event logs) and from each guard;
  - the process memory-access feed (read/write + source process) from the
    Process Runtime Guard's observe events;
  - PheonixBox status, its tamper/repair events, and the attributed tampering
    process from tamperwatch, with a one-click quarantine;
  - editing each guard's config, including toggling the rotating quarantine
    zones on/off (fixed) and enabling/disabling guards;
  - auto-detect helpers (driver tree, seed the ProcGuard allowlist).

READ-ONLY BY DEFAULT (P2-5). gui.conf `mode = read_only` (the default) lets
the console show everything (status, health, event loss, the merged event
timeline, policy changes, evidence, logs) and refuses every POST; destructive
actions (config edits, knob changes, quarantine, scans that stage restores)
need `mode = admin`. The views are plain semantic HTML.

SECURITY / ATTACK SURFACE. Root-only. Binds 127.0.0.1 by default (configure
in gui.conf). EVERY /api request (read or write) needs the per-install token
in the X-SS-Token header. The token lives only in a root-only 0600 file and is
never embedded in the page, so reaching the port is not enough: any local
user can connect to loopback, but only someone who can read the token file
(i.e. root) can use the console. The operator pastes the token into the
login screen once per browser session. Tokens are compared in constant time,
and the Host header is checked on every API call (DNS-rebinding defense).
Keep the bind on loopback unless you front it with your own authenticated
proxy - this console can change config and quarantine processes.
```

## Commands

| Invocation | What it does |
|---|---|
| `secure-sudo-gui` | Serve the console on `bind`:`port` from [gui.conf](../configuration/gui-conf.md) (loopback by default), printing where the access token is. Exits 78 on a config error. |
| `secure-sudo-gui check-config` | Print every config problem; exit 1 if there is one, 0 if the config is OK. |

It must run as root. Installed as `/usr/share/secure-sudo-gui/secure-sudo-gui` and started by `secure-sudo-gui.service`.

## Related

- [Script reference](../SCRIPTS.md)
- [ADDONS.md](../ADDONS.md)
- [gui-conf.md](../configuration/gui-conf.md)
