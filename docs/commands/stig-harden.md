<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `scripts/stig-harden.sh`

Run as root. Part of the [script reference](../SCRIPTS.md).

Run a DISA STIG (or the closest hardening baseline the distro actually ships)
OpenSCAP evaluation on the host, and optionally apply the generated
remediation. Installed to `/usr/libexec/secure-sudo/stig-harden.sh`. Auto-
detects the distro, installs `oscap` + SCAP Security Guide content if missing,
picks the right datastream + profile, and writes timestamped HTML + XML reports
to `/var/log/secure_sudo/stig/`. Full context, the kernel→STIG control mapping,
and the real before/after results are in [STIG.md](../STIG.md).

```
stig-harden.sh [--scan] [--remediate] [--profile <id>] [--datastream <f>]
               [--tailoring <f>] [--list-profiles] [--outdir <dir>] [--yes]
               [--passes <n>] [--skip-rules <regex>] [--post-patch-only]
               [--cis-firewall] [--allow-tcp <port>]...
```

| Flag | What it does |
|------|--------------|
| `--scan` *(default)* | Scan only; produce reports. Read-only, safe anytime. |
| `--remediate` | Scan, apply the generated bash fixes, then re-scan. Asks for confirmation unless `--yes`. Rewrites PAM/password/banner/audit/permission policy — do it in a maintenance window with a root shell open. |
| `--profile <id>` | Force a specific XCCDF profile (see `--list-profiles`). |
| `--datastream <f>` | Force a specific SSG datastream file. |
| `--cis-firewall` | With `--remediate`: before the baseline scan, load CIS's own nftables table `inet filter` with `scripts/cis-nftables.sh --apply` (persistent in `/etc/nftables.conf`, default-deny input/forward/output, loopback rules, established traffic, essential ICMP/ICMPv6, DHCP replies, inbound SSH on the ports `sshd -T` reports). It coexists with secure_sudo's `inet secure_sudo` table. |
| `--allow-tcp <port>` | Extra inbound TCP port for `--cis-firewall` (repeatable). |
| `--tailoring <f>` | XCCDF tailoring file with your site's values (time servers, ...); scans and fixes use its profile. Example: `tests/vm/distro/stig-vm-tailoring.xml`. |
| `--list-profiles` | List the profiles in the chosen datastream and exit. |
| `--outdir <dir>` | Report directory (default `/var/log/secure_sudo/stig`). |
| `--yes`, `-y` | Do not prompt before remediating. |
| `--passes <n>` | Remediation passes before the final scan (default 2). |
| `--skip-rules <regex>` | Leave matching rules unremediated (listed in `*.skipped`, still in the report). |
| `--post-patch-only` | Apply only the known-issue patches (OSB-03..07, OSB-20), then rescan. |

Every scan also writes `<result>.crosscheck`: independent checks of the rules
the platform's scanner cannot evaluate (OSB-19, `encrypt_partitions` and
`dir_perms_world_writable_sticky_bits` on Ubuntu 24.04), which the STIG gate
uses instead of the scanner's answer.

Profile selection prefers the DISA STIG profile and falls back, in order, to
CIS Level 2 → ANSSI high → the standard profile, announcing which it chose.
STIG profiles exist (SSG 0.1.78) for RHEL 8/9/10, Oracle Linux 9, SLE 15 and
Ubuntu 20.04/22.04/24.04; other distros use the fallback.

```sh
sudo /usr/libexec/secure-sudo/stig-harden.sh --scan          # read-only scan
sudo /usr/libexec/secure-sudo/stig-harden.sh --list-profiles # what's available
sudo /usr/libexec/secure-sudo/stig-harden.sh --remediate     # scan+fix+rescan
```

The installer can run it automatically: `sudo STIG=scan ./install/install.sh`
or `STIG=remediate` (opt-in; off by default).

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
