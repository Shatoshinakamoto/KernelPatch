# Security log

Every security patch, hardening change, CVE remediation and accepted risk,
newest first (CLAUDE.MD section 5). Entries start on 2026-11-22. Earlier
findings, #1 to #75, are in [SECURITY_REVIEW.md](SECURITY_REVIEW.md), which
stays the detailed record. Each entry here points to it.

CVSS and EPSS scores are given only where a CVE exists. These are project
findings without CVE IDs, so none are given; no scores are invented.

## 2026-11-24 — HistoryTest chain accepts merged branches without rewriting sealed runs
- **Type:** hardening (process, evidence integrity)
- **CVE / CWE / advisory:** none; CWE-345 (insufficient verification of data authenticity) considered
- **Severity:** no CVSS (no CVE). Development record only; never shipped.
- **Affected:** `scripts/history_test.py verify`.
- **What changed:** `verify` required each run to link the run immediately before it, so merging two branches that both archived runs failed it, and the only "fix" would have been rewriting sealed manifests. Each run must now link an earlier sealed run whose manifest hash matches exactly; the first run has no link.
- **Why it is secure now:** any edit to a sealed manifest still breaks every run that links it, and a link to a missing or later run or a wrong hash is rejected (NIST AU-9, AU-10). Sealed runs are never rewritten.
- **Verification:** `tests/userspace/test-history-test.sh` 49/0 (new fork, missing-run and wrong-hash checks); `history_test.py verify` 38 runs, 0 problems on the merged tree.

## 2026-11-24 — disclosure policy confirmed for a public repository
- **Type:** hardening (process)
- **CVE / CWE / advisory:** none
- **Severity:** no CVSS (no CVE). Not a code change.
- **Affected:** `SECURITY.md`, `docs/MAINTENANCE.md`, `docs/SUPPORT.md`.
- **What changed:** the owner confirmed the response targets (acknowledge in 3 days, triage in 7, critical fixes in 14, high in 30, medium and low in 90, disclosure at release or 90 days) and the end-of-support policy. GitHub private vulnerability reporting is named as the only reporting channel, to be enabled when the repository is made public; no personal contact is published.
- **Why it is secure now:** reporters have one private channel with committed response times, so a vulnerability does not have to be disclosed in a public issue (NIST SI-5, IR-6, SA-11; CISA Secure by Design: vulnerability disclosure).
- **Accepted by the owner:** the repository's git history keeps the commit author emails and two removed early folders (`node-pkg-plugin/`, `pheonix-cli/`) with contact emails; making it public publishes them. History is not rewritten.
- **Verification:** `ci/check-process-docs.py` and `ci/check-support-matrix.py` pass in the build gate's lint stage (run recorded on the pull request).

## 2026-11-23 — add-on logs can be shipped over verified TLS, and reconnect
- **Type:** patch (hardening)
- **CVE / CWE / advisory:** none; CWE-319, CWE-295, CWE-297
- **Severity:** no CVSS (no CVE). Project rating: medium. Add-on log records (quarantined file names, host state) could only leave the host as plain UDP or TCP syslog, readable and changeable on the path, and the collector was not authenticated. A TCP collector restart silently ended shipping.
- **Affected:** `temporary/common/ssaddon_log.c`, new `temporary/common/ssaddon_tls.c`/`.h`, the seven add-on Makefiles (now `-lssl`), `temporary/config/logging.conf`.
- **What changed:** `remote_proto = tls` with `remote_ca_file`: TLS 1.2+, certificate chain and host name (or IP) checks, SNI, 3 s timeouts, SIGPIPE blocked. `tcp` and `tls` detect a closed connection before each write and reconnect; a collector that stays down is retried every 30 s and the outage and recovery are logged locally once each. `check-config` rejects a CA file that does not load.
- **Why it is secure now:** with `tls`, only the collector holding a certificate from the operator's CA receives the records, and they cannot be read or changed on the way (NIST SC-8, SC-8(1), SC-23, AU-9(2)). Shipping no longer stops silently.
- **Remaining:** `udp` stays the shipped default for compatibility; the docs recommend `tls`. Lines logged during an outage are not resent.
- **Verification:** `tests/userspace/test-addon-log-tls.sh` 20/0 (`HistoryTest/runs/2026-11-23_220553Z_unit-addon-log-tls_2894faf/`); mutation runs with verification, the host check or the peer-close check turned off each fail it. `test-addons.sh` 163/0 (`HistoryTest/runs/2026-11-23_220600Z_unit-addons_2894faf/`). Gate lint pass (`HistoryTest/runs/2026-11-23_220640Z_gate-lint_2894faf/`). Whole suite 1374 ok, 2 failing only from the sandbox rm wrapper (`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`, see its note). PC build gate overall pass, 1423 checks, 0 not ok (`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`). SECURITY_REVIEW #79.

## 2026-11-23 — kernel refuses over-long policy lists instead of dropping entries
- **Type:** patch
- **CVE / CWE / advisory:** none; CWE-1284
- **Severity:** no CVSS (no CVE). Project rating: medium (fail-open for deny lists; needs a root write, so not a privilege escalation).
- **Affected:** `kernel/security/secure_sudo/` `ss_exec.c`, `ss_tmpexec.c`, `ss_node.c`, `ss_driver.c`, `ss_home.c`, `ss_binvault.c`, `ss_prguard.c`, `ss_tpm.c`, `secure_sudo.h`.
- **What changed:** every policy-list write counts its entries and returns `E2BIG` when there are more than the kernel keeps; the list already loaded stays. `driver_blacklist` refuses a 257th hash or name instead of keeping a hash as a name.
- **Why it is secure now:** a policy list is applied in full or not at all, whoever writes it (NIST CM-6, SI-10).
- **Verification:** compiles with `-Werror` against 6.14 and 6.17 header trees (`ci/lsm-compile-check.sh`, 21/21 files each). `tests/vm/ss-functest.c` `t_list_limits` on a 6.12.114 VM: 32/32, whole suite 305/0, no kernel problems (`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`). PC build gate overall pass, 1403 checks (`HistoryTest/runs/2026-11-23_215528Z_gate_aaffc26/`). SECURITY_REVIEW #78.

## 2026-11-23 — policy lists could silently lose entries, or fail to load, after a clean lint
- **Type:** patch
- **CVE / CWE / advisory:** none; CWE-1284 (improper validation of specified quantity in input) and CWE-20
- **Severity:** no CVSS (no CVE). Project rating: medium. A `blacklist.conf` or `driver_blacklist.conf` over the kernel's limit (1024 paths, 256 hashes or names) loaded with no error and the extra entries were not enforced. A `timevault_allow.conf` with one bare path passed lint and then the kernel refused the whole allowlist. Exploiting it needs an administrator to write such a file; it is a fail-open for denylists, not a privilege escalation.
- **Affected:** `userspace/cli/policy.c` (`secure-sudo lint` and `load`), templates `timevault_allow.conf`, `node_allowed_children.conf`, `blacklist.conf`.
- **What changed:** lint knows each list's kernel limits (entries and bytes) and refuses a file over them; it checks the TimeVault grammar (`<path> <sha256|auto|autodir>`, no duplicates, `timevault_max_entries`), accepts absolute paths in `node_allowed_children.conf` (with a note that bare names are weaker), and checks `driver_blacklist.conf` hash and name counts separately. Because `load` runs lint first and refuses on an error, the normal load path can no longer drop entries.
- **Why it is secure now:** a policy either loads in full or not at all (NIST CM-6, SI-10).
- **Remaining:** the kernel itself stopped reading most lists at its limit without an error, so a direct securityfs write by root bypassed lint. Fixed in the kernel the same day (entry above, SECURITY_REVIEW #78).
- **Verification:** `tests/userspace/test-cli.sh` 180/0 (11 new lint checks) and `tests/userspace/test-config-docs.sh` 20/0: `HistoryTest/runs/2026-11-23_212209Z_unit-cli_cc21580/`, `HistoryTest/runs/2026-11-23_212216Z_unit-config-docs_cc21580/`. Whole suite `HistoryTest/runs/2026-11-23_212221Z_suite_cc21580/`: 1349 ok, 2 failing only because of a sandbox rm wrapper (see that run's note).

## 2026-11-23 — template example lines gave invalid values when uncommented
- **Type:** hardening (secure defaults)
- **CVE / CWE / advisory:** none; CWE-1188 (insecure default initialization of resource) is the nearest class
- **Severity:** not applicable (no CVE). Project rating: low. `secure-sudo lint` and `load` already refused the kernel keys, but the daemon read `remote_syslog_transport = tls # udp | tls` as an invalid transport and stopped forwarding (`config_error`), `alert_min_severity = high # ...` turned alerting off, and the alert limits kept their defaults. Both showed as `config_error` in `secure-sudo health`, so the failure was visible but easy to cause.
- **Affected:** `userspace/config/secure-sudo.conf` (template only).
- **What changed:** every example comment is on its own line, and the template says that a `#` after a value is part of the value. `pheonixbox.conf` now shows `trust = local|signed` and its fail-secure handling.
- **Why it is secure now:** uncommenting an example line gives the value it shows, so log forwarding over TLS and alerting work as configured (NIST CM-6, AU-4(1)).
- **Verification:** `tests/userspace/test-cli.sh` (the shipped config passes lint with 0 errors and 0 warnings) and `tests/userspace/test-config-docs.sh`. HistoryTest: `runs/2026-11-23_211054Z_unit-config-docs_6544e45` (14/0), `runs/2026-11-23_211056Z_unit-cli_6544e45` (169/0), `runs/2026-11-23_211103Z_unit-pheonixbox_6544e45` (61 ok, 2 skipped), `runs/2026-11-23_211112Z_gate-lint_6544e45` (pass).

## 2026-11-23 — nftables.service stop deleted secure_sudo's network-mode table
- **Type:** patch
- **CVE / CWE / advisory:** none; CWE-693 (protection mechanism failure)
- **Severity:** no CVSS (no CVE). Project rating: medium. `lan-only`/`public-only` were off for up to one daemon refresh (about 15 s) after every `systemctl restart nftables`. KEV: not applicable.
- **Affected:** hosts running Ubuntu 24.04's `nftables.service` (nftables 1.0.9-1ubuntu0.1) alongside secure_sudo network modes. Code: `scripts/cis-nftables.sh`, `scripts/stig-harden.sh`.
- **What changed:** a drop-in `nftables.service.d/secure-sudo-keep-tables.conf` replaces the vendor `ExecStop=nft flush ruleset` with a delete of only the CIS/conf tables (OSB-24).
- **Why it is secure now:** stopping or restarting the firewall service can no longer remove another component's boundary rules (NIST SC-7, CM-7).
- **Verification:** `tests/userspace/test-stig-patches.sh` (63 ok) and `tests/userspace/test-cis-firewall.sh` (29 ok). Both use real nft in network namespaces: the vendor stop deletes the table, the drop-in stop keeps it. Found by the CIS L2 VM run (`docs/vm/results/13-pc-cis-l2-2026-11-23/`). VM-verified 21/21 on main 8d432e8 (restart, stop+start and stopped states keep `inet secure_sudo`, before and after a reboot): `HistoryTest/runs/2026-11-23_134551Z_vm-osb24_8d432e8/`. SECURITY_REVIEW #77, PR #59.

## 2026-11-23 — CIS firewall coexists with secure_sudo's table
- **Type:** hardening
- **CVE / CWE / advisory:** none
- **Severity:** not applicable
- **Affected:** `scripts/cis-nftables.sh` (new), `scripts/stig-harden.sh --cis-firewall`
- **What changed:** CIS's default-deny `inet filter` table is loaded next to `inet secure_sudo`. A packet must pass both, so the stricter rule wins. This replaces the blanket firewall `--skip-rules` workaround (OSB-16).
- **Why it is secure now:** the CIS nftables controls are applied instead of skipped, without weakening secure_sudo's modes (CIS Ubuntu 24.04 L2 section 4, NIST SC-7).
- **Verification:** `test-cis-firewall.sh` (real TCP between namespaces). The CIS L2 VM run had 441 pass, 9 fail (site decisions) and 0 error, and no firewall rule failed. PR #58.

## 2026-11-23 — stock nftables.conf "flush ruleset" deleted secure_sudo's table
- **Type:** patch
- **CVE / CWE / advisory:** none; CWE-693
- **Severity:** no CVSS (no CVE). Project rating: medium (same window as above, on every load of the file).
- **Affected:** hosts that load Ubuntu's stock `/etc/nftables.conf`; `scripts/stig-harden.sh`.
- **What changed:** post_patch rewrites `flush ruleset` to reset only the file's own tables. It checks the result with `nft -c` and restores the original on failure (OSB-23).
- **Why it is secure now:** loading the firewall file no longer removes other tables (NIST SC-7).
- **Verification:** `test-stig-patches.sh`, with real nft load in a namespace. SECURITY_REVIEW #76, PR #57.

## 2026-11-23 — build-gate record named a build directory instead of the sources
- **Type:** hardening (supply chain)
- **CVE / CWE / advisory:** none
- **Severity:** not applicable
- **Affected:** `ci/build-gate.sh`
- **What changed:** `source_tree_sha256` and the release package come from a pristine copy, so the same commit always gives the same hashes.
- **Why it is secure now:** a release can be rebuilt and matched to its recorded inputs (SLSA provenance, NIST SSDF PS.3, TODO P0-1/P0-4).
- **Verification:** two full gate runs on the owner's PC (main 4885cdc) gave identical tree and package hashes, equal to the clean checkout. PR #54.

## 2026-11-22 — repository stays private; reporting channel
- **Type:** accepted risk
- **CVE / CWE / advisory:** none
- **Severity:** not applicable
- **Affected:** SECURITY.md
- **What changed:** the owner chose to keep the repository private. GitHub private vulnerability reporting is unavailable, so reports go to the owner directly.
- **Why it is acceptable:** there are no outside users yet. Revisit when the repository goes public (NIST SSDF RV.1).
- **Verification:** the gh API returned 404 for private vulnerability reporting on the private repository. PR #50.

## 2026-11-27 — Method 7: modprobe.d does not set module signature enforcement
- **Type:** hardening (design, documented)
- **CVE / CWE / advisory:** none; the project finding is the playbook's
  `options module.sig_enforce=1` in `/etc/modprobe.d`, which did nothing
  (ss_driver.c:31-33). CWE-1328 (incorrect permission assignment for a
  critical resource) is the nearest class; no CVE exists and no score is
  given.
- **Severity:** no CVSS (no CVE). Project rating: medium at the time the
  playbook option was added (a `modprobe.d` file cannot enforce module
  signature mode); now resolved by design and documented.
- **Affected:** the earlier install guide's 6th method, the Ubuntu playbook
  path with `modprobe.d`. The enforcement point is not a modprobe file.
- **What changed:** `docs/INSTALL.md` now carries Method 7, the
  Ubuntu modprobe-compatible install, and `install/ubuntu-modprobe.sh`
  wraps the same `install.sh` subcommands (preflight, install-kernel,
  userspace, verify) as every other method. The installer builds the kernel
  with `CONFIG_MODULE_SIG_FORCE=y` (a kernel config option), passes
  `module.sig_enforce=1` as a kernel parameter, verifies `module.sig_enforce=Y`
  at run time, and the KernelGuard feature (#23) freezes
  `/proc/sys/kernel/modprobe` so root cannot re-point modprobe at boot. The
  method never writes `/etc/modprobe.d` and documents out-of-tree module
  signing (DKMS / distro signing infrastructure) for signed modules. The
  wrapper's `--with-modprobe-check` builds an unsigned and a signed test
  module and shows `modprobe --test` refusing the unsigned one and loading
  the signed one.
- **Why it is secure now:** signature enforcement happens in the kernel
  build and on the boot command line, exactly where the upstream kernel
  applies it; there is no `modprobe.d` file to bypass or to leave broken.
  NIST SSDF PS.2/BUILD, NIST SP 800-53 SI-7, CM-6.
- **Verification:** `tests/install/test-ubuntu-modprobe.sh`
  12/0 (root-only; a stub `install.sh` records the calls, nothing is
  installed). VM-verified full flow: install, trial reboot, commit,
  `module.sig_enforce=Y` check, the modprobe control and rollback, on a
  clean Ubuntu 24.04 cloud image
  (`tests/vm/distro/run-install-test.sh`, results under
  `HistoryTest/runs/2026-11-27_*` and `tests/vm/distro/results/`).
