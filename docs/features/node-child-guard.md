<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Node.js child-process guard

## Overview

NodeJS child-process guard (LSM task blob + allowlist); `secure-sudo node-scan` registers single-executable apps, pkg builds and renamed node binaries. (feature #11)

## How it works

A task blob marks processes whose exe is `node`/`nodejs` or a registered SEA/pkg binary. Their children's exec has to be on `node_allowed_children`. The daemon finds SEA binaries by their fuse marker and registers them (`secure-sudo node-scan`, built for THREAT_MODEL.md gap G1; also pkg builds and renamed node, not Electron apps).

**Code:** [`kernel/security/secure_sudo/ss_node.c`](../../kernel/security/secure_sudo/ss_node.c), [`userspace/cli/node_scan.c`](../../userspace/cli/node_scan.c).

## How it is secure

**Threat:** remote code execution in a Node.js application pivots to a shell or other programs (`child_process.exec`).

**Standards:** NIST CM-7(5), SI-3; CWE-78 (blocks the shell-out step of injected commands).

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** the application runs as a program named `node`/`nodejs`, at a standard path, or registered in `node_sea_binaries`; `node_allowed_children` lists exactly the programs it needs to start. `secure-sudo node-scan` (run by the daemon at start and hourly) registers single-executable apps, pkg builds and renamed node binaries it finds under `node_sea_scan_dirs`.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `node_sea_scan_dirs`, `node_sea_scan_interval`.

**Policy files:** [node_allowed_children.conf](../files/node_allowed_children.md), [node_sea_binaries.conf](../files/node_sea_binaries.md).

**Commands:** [secure-sudo-node-scan](../commands/secure-sudo-node-scan.md), [secure-sudo-load](../commands/secure-sudo-load.md).

```sh
sudo secure-sudo node-scan --dry-run /opt
sudo secure-sudo node-scan /opt
sudoedit /etc/secure_sudo/node_allowed_children.conf
sudo secure-sudo lint && sudo secure-sudo load
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

It guards exec only. The attacker still runs any JavaScript or native addon code inside the Node process, with its UID's rights (files, network). A child on the allowlist runs unguarded: allowlisting a shell, an interpreter, `git`, `npm` or anything else that starts programs reopens the pivot. A Node build under another name is guarded only once it is registered: `node-scan` finds it by Node's SEA fuse or pkg's markers, but only under the scanned directories and only up to an hour after it appears (run `node-scan` after deploying one). A build with the markers stripped is not found. Electron apps are reported, not registered (they would confine a whole desktop UI). Registering a file only adds restriction, so a planted marker gains an attacker nothing; root-owned files are listed ahead of others so planted ones cannot crowd them out of the kernel's 256 entries. A bare name entry matches that name in any directory. It applies to root too.

## Troubleshooting

- **A Node app can no longer start `git` or another helper.** Add the helper's absolute path to `node_allowed_children.conf` and reload.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_node` (unlisted child refused, event, root, allowed child, registered single-executable app); `tests/userspace/test-node-scan.sh` (finding SEA/pkg/renamed node by marker, real Node with a flipped fuse, Electron skipped, merge order and limits, cache, partial scans); the Ubuntu VM run (a found app's child refused by the real kernel, G1 steps).
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
