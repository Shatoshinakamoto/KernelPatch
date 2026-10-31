# secure_sudo — OpenSCAP bugs, patches and results

This is the complete record of every problem met while running OpenSCAP
(`oscap`) on this project's build host: what caused each one, the patch that was
applied, and the scan numbers before and after. It complements
[STIG.md](STIG.md), which covers the control mapping and how to run scans.

Everything here was run for real, inside the Ubuntu 24.04.5 LTS build
container, with OpenSCAP 1.3.9 and SCAP Security Guide (SSG) 0.1.78. The raw
reports are in [`docs/stig/results/`](stig/results/).

Each issue has an ID (`OSB-nn`). The patches that can be automated are built
into [`scripts/stig-harden.sh`](../scripts/stig-harden.sh) and run
automatically after remediation, or on their own with `--post-patch-only`. Each
one first checks that its problem is actually present, so it does nothing on a
host that is already clean.

---

## 1. DISA STIG (Ubuntu 24.04 STIG V1R1): score history

Profile `xccdf_org.ssgproject.content_profile_stig`, 230 rules evaluated.

| Step | When | Pass | Fail | Error | Not applicable | Not checked |
|------|------|-----:|-----:|------:|---------------:|------------:|
| Baseline (fresh container) | v4, 2026-10-23 | 25 | 24 | 0 | 178 | 3 |
| Remediation pass 1 | v4 | 47 | 16 | 1 | 163 | 3 |
| Pass 2 + OSB-04 + OSB-06 | v4 | 58 | 4 | 1 | 164 | 3 |
| + OSB-03 (banner repair) + OSB-07 (log perms) | v4 | 60 | 2 | 1 | 164 | 3 |
| Fresh rescan: OSB-07 drift back, SSSD still failing | v5, 2026-10-23 | 59 | 3 | 1 | 164 | 3 |
| + OSB-05 (SSSD cert mapping), OSB-07 re-fixed | v5 | **61** | **1** | 1 | 164 | 3 |
| Fresh rescan | v11, 2026-10-26 | **61** | **1** | 1 | 164 | 3 |
| Bugs re-created for the regression test (§3) | v11 | — | 5 | 1 | — | 3 |
| `stig-harden.sh --post-patch-only` | v11 | **61** | **1** | 1 | 164 | 3 |

The one remaining **fail** is *Encrypt Partitions* (OSB-12), which no container
can pass. The **error** is AppArmor (OSB-13). The three **not checked** are
manual-review controls (OSB-14).

---

## 2. Every issue, its cause, and its patch

### Content and environment

| ID | Symptom | Root cause | Patch | Status |
|----|---------|-----------|-------|--------|
| **OSB-01** | The distro's SSG package has no Ubuntu 24.04 datastream (only up to 22.04, which has no STIG profile). | Ubuntu 24.04 ships SSG 0.1.71; the 24.04 STIG content arrived in later upstream releases. | Use upstream SSG **0.1.78** (`ssg-ubuntu2404-ds.xml`). `stig-harden.sh --datastream` accepts any datastream. | Fixed (workaround) |
| **OSB-02** | `Failed to connect to bus: Host is down` during remediation. | The container has no systemd D-Bus, so `systemctl` calls in the fixes fail; their file changes still apply. | None needed on a real host. Not fatal: the script continues and keeps a log per pass. | Environment only |
| **OSB-11** | After one remediation pass every pwquality rule (`dcredit`, `lcredit`, `minlen`, `difok`, `dictcheck`, `enforcing`, ...) was still **fail**. | Pass 1 installs `libpam-pwquality` and creates its config; the value-setting rules only take effect on the next pass. | `stig-harden.sh` now runs **two passes by default** (`--passes n`), regenerating the fix from the latest result each time. | Fixed in script |

### Bugs in the generated remediation (SSG 0.1.78)

| ID | Rule | Symptom | Root cause | Patch | Verified |
|----|------|---------|-----------|-------|----------|
| **OSB-03** | `banner_etc_profiled_ssh_confirm`, `banner_etc_issue_net` | Still **fail** after its own fix; `/etc/profile.d/ssh_confirm.sh` became one broken line, and in the VM `/etc/issue.net` got the same token. | **Upstream SSG bug:** the fixes write the OVAL regex token `(?:[n]+\|(?:n)+)` literally where newlines belong. Reproduced again in v11, so it is still in 0.1.78. | Replace each token with a newline (`ssh_confirm.sh`, `/etc/issue.net`, `/etc/issue`); for the script, check with `bash -n` and restore the original if the check fails. Backup kept as `.pre-patch`. | Reproduced and fixed (§3); `issue.net` part not yet VM-verified |
| **OSB-05** | `sssd_enable_user_cert` | Still **fail** after its own fix. | The fix sets `pam_cert_auth = True`, but the OVAL check looks for `ldap_user_certificate` in the `[domain/...]` section, which the fix never writes. | Add `ldap_user_certificate = userCertificate;binary` to each existing `[domain/...]` section (only if one exists); keep mode 0600; backup kept. | Reproduced and fixed (§3) |
| **OSB-06** | `file_groupowner_var_log` | Still **fail** after its own fix. | The fix only `chgrp`s to `syslog` if that group exists and silently does nothing otherwise; a minimal install has no rsyslog, so no `syslog` group. | Install rsyslog when the group is missing (STIG requires it anyway), then `chgrp syslog /var/log`. | Reproduced and fixed (§3) |

### Drift and consistency

| ID | Rule | Symptom | Root cause | Patch | Verified |
|----|------|---------|-----------|-------|----------|
| **OSB-07** | `file_permissions_var_log_stig` | Passes after remediation, then **fails again later**. Happened for real twice: in v5 after package installs, and in v11 after installing kernel headers for the compile check. | Package installs create new log files with wider modes, and remediation itself installs packages, so it can undo its own fix. | Tighten `/var/log` files (`u-x,g-wx,o-rwx`) **last**, after every install, just before the final scan. Re-run `--post-patch-only` after big package changes. | Reproduced and fixed (§3) |
| **OSB-04** | (consistency) | `/etc/security/pwquality.conf` keeps `# retry = 3` commented out after remediation. | The rule `accounts_password_pam_retry` checks the `pam_pwquality` line in PAM, which remediation does set, so the scan passes either way. | Uncomment / add `retry = 3` so the config file agrees with PAM. **Correction to the v4 write-up:** the v11 regression test showed this is not what made a rule pass; it is kept as consistency hardening only. | Tested (§3) |

### Bugs in our own script (`stig-harden.sh`)

| ID | Symptom | Root cause | Patch |
|----|---------|-----------|-------|
| **OSB-08** | `/usr/bin/env: bad interpreter: Permission denied` | The project tree is on a `noexec` mount. | Run as `bash stig-harden.sh`; the installer and docs do. |
| **OSB-09** | Scan tally empty or wrong under `set -o pipefail`. | `scan()` passed its result through a pipe and re-ran `oscap` a second time just to count. | `scan()` sets a global `SCAN_RESULT` and counts from the XML it just wrote: no second scan, no pipe. |
| **OSB-10** | The post-remediation tally never printed. | The final `scan after` was redirected to `/dev/null`. | Redirect removed; every pass prints its tally and a Markdown summary is written (`summary-<ts>.md`). |
| **OSB-22** | `file_permissions_var_log_stig` fails on the first scan after `--remediate` although the OSB-07 step tightened `/var/log` just before remediation's last scan (CI VM run, 6.12.114, 2026-10-31: the only failure the expectation file does not explain). | Our reports. The default `--outdir` is under `/var/log`, and the "after" scan's result, report and cross-check and the summary are written after the OSB-07 step, with mode 0644. The rule wants every file under `/var/log` at 0640 or stricter. | Everything `stig-harden.sh` writes to its outdir is 0600 (umask 077 for its own writes, not for the remediation it runs). The VM run prints every `/var/log` file the rule would flag after the final scan. |

### Cannot pass inside a container (documented, not patchable here)

| ID | Rule | Result | Why | What makes it pass on a real host |
|----|------|--------|-----|-----------------------------------|
| **OSB-12** | `encrypt_partitions` | fail | A container has no partitions to encrypt. | Install with LUKS full-disk encryption; pair with the `install/encrypted/` variant. |
| **OSB-13** | `apparmor_configured` | error | No init and no AppArmor to query in the container. | AppArmor is active by default on Ubuntu; `aa-status` confirms. |
| **OSB-14** | `account_temp_expire_date`, `ensure_sudo_group_restricted`, `only_allow_dod_certs` | notchecked | Manual-review controls (site policy, DoD PKI). | Set temp-account expiry per policy; audit the sudo group (secure_sudo's `admin_gid` also limits who counts as sudo); install your DoD CA bundle. |

---

## 3. Regression test of the automated patches (v11)

Each automatable patch was tested by **re-creating the original bug on the
host**, confirming oscap fails the rule, running
`stig-harden.sh --post-patch-only`, and confirming the rule passes. Log:
[`04-v11-patch-regression.log`](stig/results/04-v11-patch-regression.log).

| Rule | Before | Bug re-created | After `--post-patch-only` |
|------|--------|----------------|---------------------------|
| `banner_etc_profiled_ssh_confirm` (OSB-03) | pass | **fail** (SSG's own fix re-run: 1 line, token present) | pass |
| `sssd_enable_user_cert` (OSB-05) | pass | **fail** (mapping removed) | pass |
| `file_groupowner_var_log` (OSB-06) | pass | **fail** (`/var/log` group reset to root) | pass |
| `file_permissions_var_log_stig` (OSB-07) | **fail** (real drift from the header install) | fail (plus a 0666 test log) | pass |
| `accounts_password_pam_retry` (OSB-04) | pass | pass (config line commented) | pass |

Full scan after the patch run: **61 pass / 1 fail / 1 error / 164 not
applicable / 3 not checked**, matching the best result.

---

## 4. CIS Benchmark: Ubuntu 24.04 Level 2 Server (v11)

Profile `xccdf_org.ssgproject.content_profile_cis_level2_server` (507 rules),
run on 2026-10-26 with:

```sh
bash scripts/stig-harden.sh --remediate --yes \
  --profile xccdf_org.ssgproject.content_profile_cis_level2_server \
  --skip-rules 'ufw|nftables|iptables|firewalld|firewall'
```

| Step | Pass | Fail | Unknown | Not applicable |
|------|-----:|-----:|--------:|---------------:|
| Baseline | 163 | 44 | 1 | 299 |
| Remediation pass 1 | 190 | 17 | 1 | 299 |
| Remediation pass 2 | 190 | 17 | 1 | 299 |
| Known-issue patches + final scan | **190** | **17** | 1 | 299 |

Reports and per-rule lists: [`stig/results/cis/`](stig/results/cis/)
(`01-cis-l2-baseline-*`, `02-cis-l2-after-remediation-*`, `summary.md`,
`skipped-rules.txt`).

**Fixed by remediation (27 rules, fail → pass):** password quality and
history (`maxrepeat`, `maxsequence`, `minclass`, `enforce_root`, `pwhistory_*`),
faillock unlock times (incl. root), hashing algorithm, default umask in
`/etc/bashrc` and `/etc/profile`, user core dumps disabled, `/var/log` owner and
group for every log class, user init-file permissions, world-writable files,
no login shell for system accounts, `su` restricted to an empty wheel group,
`apparmor-utils` installed, `openldap-clients` and the X server removed.

> Operator note: CIS restricts `su` to members of an (empty) `sugroup`
> (`use_pam_wheel_group_for_su`, `ensure_pam_wheel_group_empty`). After CIS
> remediation, use `sudo`; add accounts to that group only if you need `su`.

### What remains (17 fail + 1 unknown), and why

| Rules | Result | Cause | ID |
|-------|--------|-------|----|
| `partition_for_home`, `_tmp`, `_var`, `_var_log`, `_var_log_audit`, `_var_tmp` (6) | fail | A container has no partitions. CIS wants each of these on its own filesystem. | OSB-12 |
| `nftables_ensure_default_deny_policy`, `nftables_rules_permanent`, `set_nftables_base_chain`, `set_nftables_loopback_traffic`, `set_nftables_table` (5) | fail | **Left unremediated on purpose** with `--skip-rules`: CIS installs a default-deny nftables ruleset that would fight secure_sudo's own nft table (#10 network modes) and, in this container, could cut network access. | OSB-16 |
| `firewall_single_service_active` | unknown | oscap could not evaluate it here. It checks which firewall service is enabled, which most likely needs the running init the container lacks (not confirmed). | OSB-02 |
| `all_apparmor_profiles_enforced`, `all_apparmor_profiles_in_enforce_complain_mode`, `grub2_enable_apparmor` (3) | fail | No AppArmor kernel interface and no bootloader in the container (`update-grub: command not found`). Also hit OSB-15. | OSB-13, OSB-15 |
| `mount_option_dev_shm_nodev`, `_noexec`, `_nosuid` (3) | fail | The container has two tmpfs mounts stacked on `/dev/shm`. The fix wrote the right fstab entry and remounted the top one (now `nodev,noexec,nosuid`), but the lower one belongs to the container runtime and keeps its options, so the check still sees a weaker entry. | OSB-17 |

### New issues found by the CIS run

| ID | Symptom | Root cause | Patch | Status |
|----|---------|-----------|-------|--------|
| **OSB-15** | `aa-enforce` crashed 102 times during remediation: `ImportError: cannot import name '_LibAppArmor' from partially initialized module 'LibAppArmor'`. | `/usr/bin/python3` on this host is Python 3.13 (switched via alternatives), but Ubuntu's `python3-libapparmor` ships only a 3.12 binary (`_LibAppArmor.cpython-312-*.so`). Every AppArmor tool is a Python script, so all of them fail. Stock Ubuntu 24.04 uses 3.12 and is not affected. | `stig-harden.sh` detects the mismatch, finds a Python that can import the binding, and **prints** the exact command (`python3.12 /usr/sbin/aa-enforce /etc/apparmor.d/*`). It does not run it, because enforcing every profile can break applications. Verified here: the tools then load, and stop only because the container has no AppArmor. | Detect and advise |
| **OSB-16** | (design conflict) CIS nftables rules vs secure_sudo #10. | Both want to own the firewall. | New `--skip-rules <regex>` option strips matching rules' fix blocks from the generated remediation and lists them in `*.skipped`; they stay in the report as fail so nothing is hidden. On a host **not** using secure_sudo's network modes you can drop the option and let CIS apply its ruleset. | Script feature |
| **OSB-17** | `/dev/shm` mount options still fail after a correct fix. | Stacked tmpfs mounts in the container (upper mount ID 36 dates from container start, not from remediation). | None possible from inside the container. On a real host there is a single `/dev/shm` and the remount passes. secure_sudo #12 (`block_tmpfs_exec`) blocks exec from `/dev/shm` regardless, as a compensating control. | Environment only |
| **OSB-18** | The script said "no DISA STIG for this distro" when CIS was chosen on purpose. | The message was keyed only on the profile name. | Now reports "(chosen with --profile)" when the profile was forced. | Fixed in script |

---

## 5. Release run in a VM (v12, 2026-10-26)

`tests/vm/distro/run-stig-test.sh` on a fresh Ubuntu 24.04 cloud image with
the secure_sudo kernel installed and committed (systemd, AppArmor, GRUB,
real block devices), QEMU without KVM. Raw output:
[`docs/vm/results/07-distro-stig/`](vm/results/07-distro-stig/).

| Step | Pass | Fail | Error | Not applicable | Not checked |
|------|-----:|-----:|------:|---------------:|------------:|
| Baseline | 57 | 64 | 0 | 105 | 4 |
| Remediation pass 1 | 122 | 95 | 0 | 8 | 5 |
| Remediation pass 2 | **206** | **11** | **0** | 8 | 5 |

The VM evaluates the machine-level rules a container marks not applicable,
so far more of the same 230 rules apply (8 not applicable instead of 164). **Zero evaluation errors**: `apparmor_configured` (OSB-13) evaluates
and passes on a real host, as expected.

The run was stopped after pass 2: the post-remediation scan was cut off by
the build host's 2-hour job limit, and the final rescan after the fixes below
was skipped to ship v12. **The fixes below are therefore not yet confirmed by
a VM scan**; the next run of the workflow's nightly STIG job is that check.

Every rule not at pass after pass 2, by rule ID:

| Rule | Result | Cause | What v12 does | ID |
|------|--------|-------|---------------|----|
| `encrypt_partitions` | **pass (false)** | The disk is not encrypted. The scanner cannot check this rule here, see OSB-19. | Independent check; the gate uses it (it reports fail, as expected for the test VM) | OSB-19, OSB-12 |
| `is_fips_mode_enabled` | fail | No FIPS mode on a self-built kernel; it cannot be FIPS 140-validated. | **Accepted** by Pheonix; listed as an allowed fail | — |
| `service_sssd_enabled` | fail | The STIG fix writes a placeholder `[domain/example.com]` with no `id_provider`; sssd refuses to start ("No domain is enabled"). Needs the site's directory. | **Accepted** by Pheonix; listed as an allowed fail; STIG.md lists the settings | — |
| `banner_etc_issue_net` | fail | Same SSG bug as OSB-03, in `/etc/issue.net`: the regex token written instead of newlines. Applies only on a real host (the rule needs `linux-base`). | OSB-03 now repairs `/etc/issue.net` and `/etc/issue` too | OSB-03 |
| `banner_etc_profiled_ssh_confirm` | fail | OSB-03 (the post-patch ran after this scan) | existing patch | OSB-03 |
| `accounts_password_pam_retry` | fail | Unlike in the container, this fails on a real host after both passes. OSB-04's patch (`retry = 3` in `pwquality.conf`) ran after this scan; whether it is what this rule needs here is not yet confirmed | existing patch | OSB-04 |
| `sssd_enable_user_cert` | fail | OSB-05 (the post-patch ran after this scan) | existing patch | OSB-05 |
| `directory_permissions_var_log_audit` | fail | Passed after pass 1. Pass 2's fix for `file_group_ownership_var_log_audit_stig` sets `log_group = root`, which makes this rule want 0700 instead of 0750, and nothing re-runs its fix. | New post-patch | OSB-20 |
| `check_ufw_active`, `ufw_rate_limit` | fail | SSG has no fix for either ("FIX FOR THIS RULE ... IS MISSING"): turning on the firewall is the site's call. | Site step: `ufw limit 22/tcp`, `ufw --force enable`. **Doing this showed ufw cannot start on the test kernel**, see OSB-21 | OSB-21 |
| `auditd_offload_logs` | fail | No SSG fix; wants a weekly `/etc/cron.weekly/audit-offload`. | Site step installs one (local stand-in destination in the VM; a site sends to its log host) | — |
| `chronyd_specify_remote_server` | fail | Every `server` line must be in the approved list, which the STIG profile fixes to `0.us.pool.ntp.mil`; the VM's site server is 10.0.2.2. | New `stig-harden.sh --tailoring FILE`; the VM run passes `tests/vm/distro/stig-vm-tailoring.xml` | — |
| `account_temp_expire_date`, `ensure_sudo_group_restricted`, `only_allow_dod_certs` | notchecked | Manual review | listed | OSB-14 |
| `ufw_only_required_services`, `auditd_audispd_configure_sufficiently_large_partition` | notchecked | Manual review (new on the VM) | listed | OSB-14 |

### New issues found by the VM run

| ID | Symptom | Root cause | Patch | Status |
|----|---------|-----------|-------|--------|
| **OSB-19** | `encrypt_partitions` **passes on an unencrypted disk**. | Two bugs together. (1) Ubuntu builds OpenSCAP 1.3.9 with PCRE2; the partition probe counts only a return of 0 as a match, PCRE2 returns 1, so a `partition_object` selected by a mount-point pattern never has items and the rule's "no unencrypted partition" test is always true. (2) The cloud image's `/etc/crypttab` holds only a comment, and the rule's pattern `^\s*(\S+)` takes the `#` as an entry. The same probe bug empties `dir_perms_world_writable_sticky_bits`'s list of filesystems, so it passes without searching. Evidence: `07-distro-stig/oscap-partition-probe.txt`. | `stig-harden.sh` checks both rules itself after every scan (dm-crypt under every local filesystem outside `/boot`; `find -xdev` for world-writable directories without the sticky bit) and writes `<result>.crosscheck`. The gate uses those results instead of the scanner's for the rules marked `crosscheck` in the expectation file, says so in its output, and in release mode **fails** if they are missing. | Patched in our tooling; upstream not checked (GitHub unreachable) |
| **OSB-20** | `directory_permissions_var_log_audit` passes after pass 1, fails after pass 2. | Ordering between two rules' fixes (see table). | Post-patch: when `auditd.conf` has `log_group = root`, set the audit log directory to 0700. | Fixed in script; passes in the CI VM run (2026-10-31) |
| **OSB-21** | `ufw --force enable` fails on the secure_sudo test kernel: `Extension conntrack ... not supported`, `RULE_APPEND failed`; ufw is left half-applied and new SSH connections hang. | The VM kernel was built with `SS_LOCALMOD` (localmodconfig from a fresh guest's `lsmod`), which drops every module not loaded at that moment. ufw was not on yet, so `NF_CONNTRACK`, `NFT_COMPAT`, the xt matches and `ip_tables` were not built. Log: `07-distro-stig/site-ufw-enable.log`. | `install.sh build-kernel` now always keeps the netfilter stack ufw and secure_sudo's network modes need when `SS_LOCALMOD` is used, and stops if it does not stick. Checked with Kconfig (`make olddefconfig`) against the VM kernel's config. The default build (no `SS_LOCALMOD`) starts from the distro config and was not affected. **Rebuilt and booted in CI (6.12.114, 2026-10-31): the site step still failed** and the hardened guest was unreachable after its reboot. ufw 0.36's IPv6 rules use the `hl` match (`-m hl`, 22 rules in `before6.rules`), which the keep-list lacked, so `ip6tables-restore` failed as a whole. `NETFILTER_XT_MATCH_HL` is now kept and checked; the VM STIG test now stops at a failed site step instead of hardening a half-firewalled guest and timing out. | Fixed in installer (second fix); ufw starts and the site steps pass in the CI VM run (2026-10-31) |

---

## 6. How to reproduce

```sh
# STIG: scan, two remediation passes, known-issue patches, final scan
sudo bash scripts/stig-harden.sh --remediate

# CIS Level 2 Server, leaving the firewall to secure_sudo's nft modes
sudo bash scripts/stig-harden.sh --remediate \
  --profile xccdf_org.ssgproject.content_profile_cis_level2_server \
  --skip-rules 'ufw|nftables|iptables|firewalld|firewall'

# After big package changes (log-permission drift, OSB-07), re-apply patches
sudo bash scripts/stig-harden.sh --post-patch-only
```

Each run writes its reports and a `summary-<timestamp>.md` to
`/var/log/secure_sudo/stig/`.
