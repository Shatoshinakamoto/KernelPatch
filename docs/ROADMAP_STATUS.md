# secure_sudo — where the Strategic TODO stands

Status of every item in [TODO.md](../TODO.md) for release **0.12.0**
(2026-10-26), with the evidence behind each claim and what is still missing.
"Done" below means the item's own *Done when* is met by something that ran
and can be re-run; anything short of that is "partly" or "not started", with
the reason.

When release 0.12.0 was built (2026-10-26), kernel.org and GitHub were not
reachable and there was no KVM, so every boot test then ran on upstream
**6.14** under TCG with BIOS firmware. Since 2026-10-31 the project runs on
GitHub: `ci/build-gate.sh` runs for every push and pull request, and the VM
jobs (6.12.114 under KVM, the Ubuntu 24.04 install run, the STIG run) run
weekly and on demand (`.github/workflows/build-gate.yml`). Nothing has run
under UEFI or Secure Boot, or on real hardware.

| Item | Status | One line |
|---|---|---|
| P0-1 build + CI gate | partly | `ci/build-gate.sh` passes from a clean copy and on GitHub for every push/PR, 6.12.114 in-tree in six configs; not yet a required check (branch protection) |
| P0-2 tests | partly | 680 host checks pass in CI on every push; 233/233 in-kernel checks pass on 6.12.114 in CI (`kernel-boot`, run 41292806854); STIG gate compares rule IDs; not yet a required check |
| P0-3 boot proof | partly | 6.12.114 with secure_sudo, all in CI: 233/233 in-kernel checks (initramfs, KVM), the full Ubuntu 24.04 install/trial/fallback/commit/drills/removal run (52 checks), and the STIG run 16/16: the hardened guest reboots and the release gate passes; not UEFI, other distros or hardware |
| P0-4 source provenance | done | signature-verified before extraction, tamper test, SBOM, reproducible archive |
| P0-5 transactional install | done (Ubuntu 24.04) | trial boot, automatic fallback, commit, rollback and byte-clean removal proven in a VM, on 6.14 and again on 6.12.114 in CI; other distros simulated only |
| P0-6 policy validation + recovery | done | lint/load refuse bad policy before anything is applied; four recovery drills pass on the real kernel in a VM |
| P1-1 | done | schema-v1 JSON events; every target a typed PID/UID; paths whole in `object` up to 256 bytes, so no consumer reads the message; `actor.kernel_started` marks deferred work; sequence numbers in ring order and reads of whole records, so gaps are exact; `events_sequence`/`events_boot_id`; the daemon logs `event_stream`/`event_gap` records and keeps a restart cursor; health shows gaps; 20,000-event burst measured in CI (about 200,000 records/s, none lost) |
| P1-2 | done | authenticated RFC 5425 TLS, bounded persistent queue, batched flush with backoff, clean TLS close; 10-check integration suite (delivery, wrong host, untrusted CA, missing CA, CA rotation, outage, queue exhaustion, batching, backoff) passes in CI. A TLS write is reported as `tls_sent_unconfirmed`, never as collector persistence |
| P1-3 | partly (active) | root-only export with checksums and per-log chains, optional external Ed25519 signing, `log_checkpoint` records forwarded off-host every 5 min and checked by `evidence-verify --checkpoints`, `log_modified` on outside changes. Remaining: a completed tabletop (people) and a redaction review |
| P1-4 | done | `secure-sudo health [--json]`: LSM, daemon heartbeat (atomic), audit feed, configured vs live knobs, last load with rejected names, ring/audit loss and daemon-seen gaps, local log failures, remote queue/errors, add-on units, scan results/age and baselines. Collector-side receipt is outside the host's view; the forwarded checkpoints let the collector alert on silence |
| P1-5 | done | [THREAT_MODEL.md](THREAT_MODEL.md): trust assumptions, attackers in scope, the supported profile (roles, admin groups, LSM order, boot path, logging, distro tooling), and every control with its threat, preconditions, limits and test; §6 says what names and compliance mappings do not mean. Writing it found and fixed SECURITY_REVIEW #54–#57; of the four promises it listed (TODO "Doc promises to build"), G1 (`node-scan`, #59), G2 (TimeVault Merkle root, #60), G3 (TPM-sealed OTP key, #61) and G4 (TPM clear through `/dev/tpm*`, #63) are built |
| P1-6 | done | `secure-sudo diff` (= `load --dry-run`) previews a change against the running kernel; snapshots of the config files and the live kernel state (SHA256SUMS, chained to the previous one) before every load, set, lock and restore; a hash-chained change history (who, lint result, changes, accepted/rejected, snapshot) also sent to syslog; `restore ID` (verified, previewed, refused while locked unless `--no-load`). See "P1-6" below |
| P1-7 | code-complete (tabletop remains) | [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md): triage, evidence, containment, escalation, recovery, rebuild, and the inventory of automatic destructive actions (false positives, exclusions, audit trail, undo, test); `secure-sudo contain network/account/process` with dry run, confirmation, evidence first and release, recorded in the history; guardrail tests for every destructive add-on and package/kernel hooks that re-baseline BootGuard/DriverGuard after updates (SECURITY_REVIEW #64–#66). Remaining: a people-run tabletop |
| P1-8 | done | [CONFIGURATION.md](CONFIGURATION.md#net_mode): what counts as the LAN, failure modes, the fail-safe (keep) stop policy, and why no mode is host isolation (`contain network` is); every LAN interface, VPN exclusion, a forward chain for routed containers, refresh every 15 s, fail-closed pending rules, health state (SECURITY_REVIEW #67); `test-netpolicy.sh` |
| P2-1 | partly (parts 1 and 2) | [ATTESTATION.md](ATTESTATION.md): `secure-sudo attest quote` (TPM quote of the boot PCRs bound to a nonce and the host report) and `secure-sudo-attest-verify` (enroll, verify, re-enroll with the same key); enrollment, verifier trust, revocation, recovery, PCR meanings, IMA/EVM/fs-verity/dm-verity evaluation; `test-attest.sh`. Part 2: the LSM measures every accepted knob, list and lock into PCR 13 (`policy_log`, foreign-extend markers) and the verifier replays it (SECURITY_REVIEW #68). The verifier replays the firmware event log (names the changed event; measured Secure Boot state and command line) and the IMA log (PCR 10, boot_aggregate, reference lists), checked against a real OVMF/GRUB/Ubuntu boot. Remaining: EK certificate checks / credential activation |
| P2-2 … P2-5 | not started | |
| P3-1 … P3-3 | partly (P3-2) | evidence and docs updated with this release; no matrix or disclosure process yet |

---

## P0 — release blockers

### P0-4 Source provenance — done

* `scripts/verify-kernel-source.sh` checks the kernel.org detached signature
  of the *uncompressed* tarball **before** anything is extracted. Only
  signers whose primary fingerprint is pinned in
  `install/keys/release-signers.txt` (Greg Kroah-Hartman's and Linus
  Torvalds's) are accepted; Greg's key is shipped, others can be fetched by
  WKD and are still checked against the pin. A missing, empty or bad
  signature, an unpinned or revoked key, or a corrupt archive fails, with no
  override. `install.sh build-kernel` uses it for every download.
* The signer fingerprint, archive SHA-256 and release go into
  `kernel-source.txt`; `build-info.txt` adds the compiler, `make`, config
  hash and LSM list; `secure_sudo.spdx.json` is an SPDX SBOM; all are
  installed under `/usr/share/doc/secure-sudo/build/<release>/`.
* A tree that did not come from kernel.org (`SS_KERNEL_TREE`) is refused
  unless it has a provenance record with a `verified_by=` line, which becomes
  the build's `kernel-source.txt`. The VM kernel used this route: apt checked
  the Ubuntu archive's signed `InRelease` and the `Sources` hashes, and
  `fetch-kernel-source.sh` re-checked the `.orig` tarball against the `.dsc`
  (SHA-256 `a6dd4538…d911e`).
* Tests: `tests/provenance/` (19 checks): a tampered or truncated archive, a
  missing, empty or mismatched signature, and an unshipped or unpinned signer
  are each rejected, and `install.sh` does not extract a rejected archive.
* `ci/make-release.sh` builds a byte-identical archive from the same inputs
  (checked twice in the gate).

Gaps: toolchain versions are recorded, not pinned. A byte-identical rebuild
of the *kernel package* from its record has not been demonstrated (the
build takes its timestamp from the source's signature time and fixes the
build user and host, which removes the usual differences, but nobody has
compared two builds).

### P0-1 Build and CI gate — partly

Done:

* `ci/build-gate.sh` runs, from a clean copy of the tree: shell/Python lint,
  the userspace (5 components) and add-ons (6) with `-Werror`, the LSM
  against three header trees (6.11 and 6.14 through kbuild, **6.12.114**
  directly), the LSM inside a real kernel tree in six configurations
  (default, module signing, no audit, no BPF, no modules, AppArmor stacked),
  every host test suite, `ci/check-lsm-hooks.sh` (no hook registered twice),
  and the reproducible package. It writes a record (compiler, tree hash,
  config hashes, per-stage result).
* It found a real break: `ss_bpf.c` did not compile for 6.12
  (SECURITY_REVIEW #41).
* `.github/workflows/build-gate.yml` runs the same gate on every push and
  pull request against the installer's default kernel, fetched and verified
  from kernel.org, plus weekly/on-demand VM jobs: the installer builds the
  kernel package, then the install/recovery/removal scenario and the STIG
  release gate run on fresh Ubuntu 24.04 guests.

Missing:

* The workflow runs on GitHub on every push and pull request
  (Shatoshinakamoto/KernelPatch) and passes, lsm-tree included: the LSM's
  objects build with `-Werror` inside the signature-verified 6.12.114 tree
  in all six configurations. It is not yet a *required* check: that is a
  branch-protection setting on `main`, which only the repository owner can
  turn on.
* The gate's lsm-headers stage builds against the runner's own kernel
  headers, which GitHub moves forward (6.17, then 7.0 by 2026-10-31). Each
  move can break the gate with no change in this tree; the API shims for
  6.16 to 7.0 are in `secure_sudo.h`.
* A whole 6.12.114 kernel image is built only by the weekly/on-demand
  `kernel-boot` and `distro-vm` jobs, not on every push.
* The TODO names `6.12.48`; the installer default is now `6.12.114`, the
  newest 6.12 LTS point release available when this was done.

### P0-2 Automated tests — partly

Host suites (`tests/run-all.sh`, TAP; root-only parts marked and skipped
without root):

| Suite | Checks | Covers |
|---|---|---|
| `tests/userspace/test-pheonixbox.sh` | 26 | the real PheonixBox helper: refuses unprivileged; snapshot, lock, tamper, repair, re-lock, permission restore, hostile file names (root, private mount namespace with overlays) |
| `tests/userspace/test-node-scan.sh` | 48 | `node-scan` (#11, gap G1): SEA/pkg/renamed-node markers incl. across read boundaries, a real Node binary with its fuse flipped, Electron apps skipped, unlistable names, merge order and the kernel's limits, the cache, partial scans, ownership order |
| `tests/userspace/test-daemon-events.sh` | 79 | how the daemon acts on kernel events (typed fields, cooldown kill, quarantine), the ring reader, sequence gaps, the background node-scan, the TimeVault baseline and Merkle root (G2), and the net_mode apply/refresh/pending/stop loop (P1-8) |
| `tests/userspace/test-otp.sh` | 86 | RFC 4226/6238 vectors, secret at rest, prefix, replay refusal, the master key sealed to a software TPM and the key-file fallback (G3) |
| `tests/userspace/test-pam.sh` | 50 | both PAM modules through libpam, the documented stacks, real `pam_unix` + `pam_faillock` (root, private mount namespace) |
| `tests/userspace/test-netpolicy.sh` | 71 | net_mode against real traffic in namespaces: IPv4/IPv6, two LAN NICs, a VPN, DHCP subnet change, routed container, existing nftables + iptables-nft rules, restart (nft untouched), failed detection (kept / pending), bad config, on_stop keep/remove, forward = 0 |
| `tests/userspace/test-attest.sh` | 62 | P2-1 attestation against software TPMs: the AK is stable per TPM, enroll and verify, wrong/replayed nonce, edited report, edited PCR value, a bundle from another TPM, a PCR extended after enrollment, re-enrollment with `--previous` (same TPM only), `--require-lock`, `attest digest`; the measured policy log (edited, hidden/downgraded, pending, list after the lock, a tightening knob after it, tpm_openers text and PCR extenders, foreign extends); the firmware event log (a real OVMF/GRUB log replays to that TPM's PCRs and matches tpm2_eventlog; edited, truncated, hidden; reported Secure Boot and command line against the measured ones; the changed event named; `--ignore-eventlog`) and the IMA log (the real log replays to PCR 10; the quote meets the log mid-way; boot_aggregate; reference lists; edited, hidden) |
| `tests/userspace/test-helpers.sh` | 84 | `apply-net.sh` with real `nft` in network namespaces (all four modes, IPv4 + IPv6, DHCP/DNS), `quarantine.sh` (archive before delete) |
| `tests/userspace/test-cli.sh` | 163 | config parsing, `otp` hand-off to the helper, `lint`, `load` reporting (entry counts, node-scan merge), P1-6 `diff`/snapshots/history/restore (partial loads, forged snapshots, edited or removed history lines, restore while locked) and persisted boot-bound load-health status, health status/JSON, including audit-feed activity, log-retention hold, systemd add-on/timer state, scan outcomes/age and baseline freshness, against stand-in knob and list files |
| `tests/userspace/test-remote-forwarding.sh` | 11 | TLS CA/hostname validation and CA rotation, RFC 5425 delivery, queue persistence/exhaustion, outage retry |
| `tests/userspace/test-addons.sh` | 31 | ProcGuard (monitor kills nothing, empty allowlist refused, PID 1/ancestors/stack exempt, renamed `secure-sudo-*` not exempt, respawn → quarantine, system dirs never deleted), BootGuard/DriverGuard (tamper staged/restored, scan deferred under a held dpkg lock, `refresh` re-baselines and drops a staged restore, hook script), TamperWatch (attributes a writer, never kills the stack or during a package update) |
| `tests/userspace/test-contain.sh` | 32 | `secure-sudo contain`: dry runs change nothing, refusals (UID 0, own account, PID 1, kernel threads, own shell chain, bad addresses), real processes frozen with evidence and continued, descendants, `--kill`, account lock/expiry restored as it was, real nftables in a namespace |
| `tests/userspace/test-evidence-export.sh` | 24 | checksum, secret exclusion, independent verification, path traversal and tampering rejection, external-key signature validation, TimeVault manifest against the collector's roots, policy history in the bundle |
| `tests/oscap/` | 39 | result parsing and the STIG gate's rule-by-rule comparison, release vs diagnostic mode, independent checks (OSB-19) |
| `tests/provenance/` | 19 | P0-4 above |
| `tests/install/test-install.sh` | 141 | P0-5 below |

In-kernel tests (`tests/vm/ss-functest.c`, run as PID 1 of an initramfs by
`tests/vm/boot-test.sh`): the CI `kernel-boot` job passed **135/135** on
6.12.114 under KVM on 2026-11-01 against the current source, including the
typed targets, the schema checks, the P1-1 sequence checks and the
sustained burst (`docs/vm/results/11-ci-kernel-boot-6.12-p1-1/`; the first
CI run, 126/126 on 2026-10-31, is in `08-ci-kernel-boot-6.12/`). Earlier runs passed
118/118 on upstream 6.14, and 118/118 with AppArmor stacked; the stacked
configuration has not been re-run on 6.12.
They cover registration and stacking, knob defaults,
modes and bounds, setid/setgroups/userns, setuid-exec allowlist, command
blacklist (incl. hard links), `/tmp` and memfd exec, `/dev/mem`, packet
sockets, BPF and perf, SysctlGuard and binfmt_misc, Process Runtime Guard,
`finit_module` and `init_module` with name and hash blacklists, concurrent
list rewrites during exec, the event ring wrap and loss counter, and the
one-way lock (every knob kind refuses, modules and tracing BPF refused).
Results: `docs/vm/results/02-*`, `03-*`.

STIG release gate: `tests/oscap/stig-gate.sh` (39 checks in `tests/oscap/`) compares an
OpenSCAP result rule by rule with `tests/oscap/ubuntu2404-stig.expect`.
**It passes on a VM result** since 2026-10-31 (CI run 41243002797, 6.12.114,
`docs/vm/results/10-ci-distro-stig-6.12/`): final scan after the hardened
reboot 215 pass / 2 fail / 0 error, and with the independent checks the
three fails are the allowed ones (`encrypt_partitions` on the unencrypted
test disk, FIPS and sssd, accepted). The v12 VM run before it reached 206
pass / 11 fail / 0 error after two remediation passes; every rule left then
is classified in
[OSCAP_BUGS.md §5](OSCAP_BUGS.md#5-release-run-in-a-vm-v12-2026-10-26).
The run also found that the scanner cannot evaluate `encrypt_partitions` on
Ubuntu 24.04 (false pass, OSB-19); the gate now uses an independent check
for it and refuses a release result without one.

Missing:

* Not yet in the kernel tests: chroot and mount-namespace edge cases,
  TimeVault, BinaryVault, RadioGuard, cooldown, home-write, the NodeJS
  guard, RAM-spike handling, TPM and firmware sysfs paths.
* The `no-audit`/`no-bpf`/`no-modules` variants are built, not booted.
* Add-on monitor/enforce modes (`temporary/`) have build checks only.
* The host suites run as root in the gate on every push and pull request.
  The in-kernel tests run in the `kernel-boot` job (weekly and on demand)
  against 6.12.114 with secure_sudo built in.

### P0-3 Boot proof — partly

What has been booted, under QEMU with SeaBIOS (TCG here, KVM in CI;
`docs/vm/results/`):

| Kernel | Guest | Result |
|---|---|---|
| v11 LSM, upstream 6.14 | initramfs | **panic** at boot (`Ran out of static slots`, SECURITY_REVIEW #35); fixed in v12, guarded by `ci/check-lsm-hooks.sh` |
| v12 LSM, upstream 6.14 | initramfs, PID 1 test program | 118/118, and 118/118 with AppArmor stacked |
| current LSM, kernel.org 6.12.114 (CI `kernel-boot`, KVM) | initramfs, PID 1 test program | 135/135, no kernel splat (126/126 on 2026-10-31 before the P1-1 checks) |
| v12, `install.sh build-kernel` package, upstream 6.14 | Ubuntu 24.04 cloud image (systemd, GRUB, AppArmor, virtio disk) | install/recovery/removal 51/51; active LSMs `lockdown,capability,landlock,yama,apparmor,secure_sudo,ima,evm`; services start; the configuration loads; the previous kernel stays bootable and is fallen back to |
| same | Ubuntu 24.04, STIG remediation | remediation ran; the run was cut off before the post-hardening reboot (`07-distro-stig/run-stig-test.tap` ends at check 6), so a reboot of a hardened guest was **not** shown. An earlier version of this row said it was |
| `install.sh build-kernel` package, 6.12.114 (CI `distro-vm`) | Ubuntu 24.04, STIG remediation with ufw on | site steps, remediation and rescan complete; **after the reboot the hardened guest did not come back** (2026-10-31, twice). Cause: the GRUB password held the boot at Ubuntu's restricted "Advanced options" submenu, where the installer had put the default kernel (SECURITY_REVIEW #51). Fixed: in run 41237968131 the hardened guest reboots into the secure_sudo kernel with AppArmor active; the release gate then had one unexplained failure, `file_permissions_var_log_stig`, caused by the hardening script's own reports (OSB-22) |
| same, with both fixes (run 41243002797) | Ubuntu 24.04, STIG hardened, rebooted | **16/16**: reboots into secure_sudo with AppArmor; the STIG release gate passes (`10-ci-distro-stig-6.12/`) |

Known platform exclusions, recorded rather than claimed:

* Lockdown is `none` in these guests: no Secure Boot under SeaBIOS, so the
  "expected lockdown state" could only be checked as "not enforced".
* `fwupd-refresh` fails in the guest (no network firmware service), so
  systemd reports `degraded`; unrelated to secure_sudo.
* The VM kernel is built with `SS_LOCALMOD` from a fresh guest's module
  list. That dropped the netfilter modules, so ufw could not start (OSB-21);
  `install.sh` now keeps them, and ufw starts on the 6.12.114 CI build.

Missing for *Done*:

* No UEFI, Secure Boot, MOK enrollment or TPM test (no OVMF/KVM here).
* No VM of Fedora, openSUSE or Arch; no real hardware.
  [HARDWARE_SMOKE_TEST.md](HARDWARE_SMOKE_TEST.md) is the plan for that.

### P0-5 Transactional install, upgrade and recovery — done (Ubuntu 24.04)

`install/install.sh` was rewritten (SECURITY_REVIEW #43):

* `preflight` (also `--dry-run`) reports distro support, disk space, boot
  method, bootloader, Secure Boot and MOK state, the trial-boot plan, missing
  tools and every change, and changes nothing (tested).
* Every installed file is recorded with its hash; files that existed are
  backed up first; configuration files that exist are never touched.
* The new kernel is installed next to the running one, which stays the
  default; the new one boots **once** (`grub-reboot`) and becomes the
  default only after `install.sh verify --commit`, which refuses when verify
  finds a problem. A panicking trial kernel reboots into the previous one
  after 10 s (`CONFIG_PANIC_TIMEOUT`).
* `verify` checks files, shared libraries, the installed kernel config
  (secure_sudo in `CONFIG_LSM`, `MODULE_SIG_FORCE`), initramfs, module
  signatures, boot entries for both kernels, the image signature
  (`sbverify`), and on the running kernel the LSM list, signature
  enforcement, lockdown (optional expectation), the daemon and `lint`.
* Bootloader regeneration failures stop the install.
* `rollback [--default]`, and `uninstall` that removes only unchanged
  recorded files, restores backups, purges the kernel packages, clears the
  GRUB state it set, and refuses while PAM uses the modules
  (`--remove-pam-lines` takes them out with a backup).
* [RECOVERY.md](RECOVERY.md) covers an unbootable kernel, failed MOK
  enrollment, an interrupted package install and policy lockout.

Evidence: `tests/install/test-install.sh` (131 checks, including a
byte-identical root after install + uninstall with the daemon's runtime
state present, undelivered remote events kept, and an interrupted install),
and the distro VM run: `06-distro-install-final/` on the packaged tree, **51/51**: install-kernel and
userspace on a fresh Ubuntu 24.04 cloud image, the trial boot with
secure_sudo and AppArmor active, `verify --commit`, a deliberately broken
trial that falls back to the previous kernel by itself, rollback, uninstall
refusing while PAM uses the modules, and a removal after which every file
under the directories `install.sh` touches is byte-identical to the fresh
image (apart from the runtime packages `libqrencode4 zip unzip`) and
`grub.cfg` is byte-identical to what GRUB generated before the install.
The same 51 checks passed on 6.12.114 in the CI `distro-vm` job on
2026-10-31 (`09-ci-distro-install-6.12/`). That run's first attempt found
that uninstall left the daemon's heartbeat, cursor and load-result files
in `/var/lib/secure_sudo`; uninstall now removes them and keeps only a
non-empty remote queue.

Missing: Fedora, openSUSE and Arch paths are exercised only by the host
suite's simulated roots, not in a VM of those distros. The MOK path is not
VM-tested (no UEFI).

### P0-6 Policy validation and administrator recovery — done

* `secure-sudo lint` checks syntax, unknown keys, bounds, list files
  (paths, ownership, permissions), admin groups (exist, have members, cover
  the admin running it), dependent settings, PAM order across includes,
  OTP readiness, installed modules, kernel support for each knob, and the
  lock state (`docs/COMMANDS.md`).
* `secure-sudo load` runs lint first and changes nothing on an error
  (`--force` overrides), then reports every setting as accepted, rejected
  or skipped and ends with `load INCOMPLETE` on a partial policy.
* Recovery drills, run on the real kernel in the distro VM
  (`tests/vm/distro/recovery-exercises.sh`): wrong `admin_gid` with
  `block_setid_exec`, an allowlist without `passwd`, an OTP PAM line before
  OTP is set up, and an accidental `lock`, each with its recovery from a root
  session (and a reboot for the lock). In the same VM run all four drills passed (35 checks, plus 4 after the lock
reboot): each mistake was caught by `lint` and refused by `load` before it
reached the kernel, forcing it through showed the lockout it would cause, and
each recovery restored sudo and `passwd` for the right users.

---

## P1-1 through P1-4 — P1-1, P1-2 and P1-4 done; P1-3 partial

### P1-1 Event schema and loss — done

`ss_log.c` now writes one JSON record per event with schema version 1,
per-boot random ID, monotonically increasing sequence, realtime and monotonic
nanoseconds, event category, actor PID/UID, typed target/operation/object/
decision/reason fields, and the original message. Denial producers now supply
stable classification values rather than requiring consumers to parse the
message. Cross-process memory-access events also carry target PID and UID.
All string fields are JSON-escaped and bounded so untrusted path text
cannot forge records. The existing whole-record ring-drop counter remains,
and `audit_events_dropped` counts failures to obtain an audit buffer. Both are
readable under `/sys/kernel/secure_sudo/` and reported by `secure-sudo health`.
The message encoder escapes non-ASCII bytes as `\u00xx`, keeping records valid
JSON even when paths are not UTF-8. The daemon parses each record as JSON
and acts only on its typed fields:

* the cooldown kill takes its UID from `target_uid`, which the kernel now
  sets;
* the TimeVault quarantine takes its path from `object` and needs an
  untruncated record (until 2026-11-01 it matched the message against the
  kernel's exact format).

Before, it searched the message text, which let a crafted file name
trigger either action (SECURITY_REVIEW #48). Records that straddle two
ring reads are now reassembled (#49). Actor UIDs are logged in the initial
user namespace. A `truncated` boolean
reports when the event type, typed string, or message was shortened. The
64 KiB ring caps lines at 1024 bytes (640 before P1-1 was finished),
discards oldest whole records on saturation, and exposes a loss counter. The CLI/health, daemon-event,
TLS-forwarding (CA rotation included) and evidence export/verify suites
are built against the OpenSSL development headers and run as root in the
CI gate on every push and pull request.

Gap detection is now exact:

* The kernel numbers records under the ring lock, in ring order, so a
  jump in `sequence` is precisely the records a full ring dropped.
* It exposes `events_sequence` and `events_boot_id`.
* It counts events raised before securityfs was ready in
  `events_dropped`; they used to vanish without trace.
* `secure-sudod` writes `event_stream` records (a new boot, with the
  previous boot's id and last sequence) and `event_gap` records into the
  log and the forwarded stream.
* It keeps a cursor, so loss while it was stopped is also reported.
* Health shows `event_gaps`/`events_missing`.
* Host tests cover gaps, repeats, restarts and reboots.
* The in-kernel test now checks that surviving records are contiguous and
  that the gap equals `events_dropped`; it passed on 6.12.114 in CI.

So a consumer can detect gaps, correlate events across a reboot, and parse
records without the message text.

Target identity, paths and deferred work (finished 2026-11-01, PRs #11 and
#12):

* Every producer names its target with a typed `target_pid`/`target_uid`.
  A denial of the caller's own action names the caller; ptrace-style events
  name the other task; the cooldown block names the blocked UID. Only the
  boot-time `event_log` record has a null target.
* `object` holds up to 256 bytes, so a path is whole in a typed field and
  the daemon takes the TimeVault path from it instead of the message. Before,
  the 64-byte bound meant a longer path marked the record truncated, and the
  daemon then never quarantined it (SECURITY_REVIEW #52). Longer paths are
  cut, flagged `truncated`, and never acted on. Lines are capped at 1024
  bytes and built in a static buffer under the ring lock, not on the hook's
  stack.
* `actor.kernel_started` is true for kernel threads and for processes the
  kernel started itself (a `modprobe` for an autoload, a core-dump handler).
  The kernel does not keep the userspace task that caused such work, so the
  record says that its actor is a helper instead of passing the helper off
  as the initiator.
* A read now returns whole records only. A read that stopped mid-record
  could have its tail discarded by a producer making room, and the next
  record was then lost without being counted (SECURITY_REVIEW #53).
* What a record can reveal, and who can read each copy, is documented in
  `kernel/security/secure_sudo/INTEGRATION.md`.

In-kernel tests on 6.12.114 under KVM in CI, 135/135 (run 41278080075,
`docs/vm/results/11-ci-kernel-boot-6.12-p1-1/`): the record format (every
field, `truncated`, typed classification), a self-targeted denial's typed
target, a 220-byte path whole in `object`, the audit feed, a denial from a
kernel-started core-dump handler, ring saturation (surviving records are
contiguous and the sequence gap equals `events_dropped`), both loss
counters, and a sustained burst. In the burst one non-sudo process raised
20,000 denials while the test read the ring in 4 KiB chunks: every read
ended at a record boundary and every record was read or counted as
dropped. On the CI runner's 2-vCPU KVM guest that was 20,000 records in
0.10 s (about 200,000/s, 474 bytes on average), all read, none dropped. With
no reader the 64 KiB ring holds about 138 such records before it starts
dropping the oldest. These rates depend on the machine; the accounting is
what is checked.

Not part of P1-1: a kernel-side rate limit (there is none; saturation drops
the oldest records and counts them) and the initiating task of deferred
work, which the kernel does not record.

### P1-2 Remote forwarding — partial

`remote_syslog_transport=tls` selects RFC 5425 TLS syslog, verifies the
configured CA and collector hostname/IP, and sends octet-counted RFC 5424
messages. Unsent events are persisted as private, individually bounded queue
files and retried oldest first after reconnect, reload, or restart. The queue
cap is configurable from 1 to 1024 MiB (10 MiB default), with an additional
4096-file ceiling; exhaustion drops the newest event and increments a visible
counter. DNS, connection, TLS,
certificate, write, queue, and drop state is exposed in the daemon heartbeat
and health JSON. UDP remains available as a legacy explicitly selected
transport; its state is still `udp_unconfirmed`. Local logging happens before
forwarding and continues through collector outages.

Each event is written locally, acted on (cooldown, TimeVault), and only then
queued. The main loop sends the queue in batches of up to 512 over one TLS
connection. After a failure it retries after 5 s, then twice as long after
each further failure, up to 5 minutes. Before this, every event connected
and handshook inline, so a collector that dropped packets stalled the daemon
for 3 s or more per event (SECURITY_REVIEW #50). Connections now end with
`close_notify` and a bounded read: closing over unread session tickets
caused a TCP reset, and in the batch test that reset lost the last event.

Neither UDP send nor a successful TLS stream write is a collector
acknowledgment. The queue removes an event after the TLS write succeeds, so a
collector-side failure after receipt can still lose it; an ambiguous retry
can also duplicate it. The integration suite (10 checks, run as root in
CI) covers:

* trusted delivery;
* wrong-host and untrusted-CA rejection;
* outage retention and queue exhaustion;
* atomic server-CA bundle rotation;
* in-order batch delivery over one connection;
* the queue-only and backoff behaviour. Rotation instructions use an overlap of
old/new trust anchors; client certificates and private keys are not supported.
RFC 5425 offers no durable collector acknowledgment. Health deliberately says
`tls_sent_unconfirmed`; no custom receiver protocol is introduced, and
collector-side persistence is not claimed. The CA-rotation assertion and
the rest of the suite pass in the GitHub build gate.

### P1-3 Incident evidence — partial

`secure-sudo evidence-export OUTPUT.tar.gz` creates a root-only bundle with
logs, non-secret configuration snapshots, live knobs/counters, boot/kernel/LSM
identity, service state, quarantine metadata and a SHA-256 manifest. It also
builds per-log hash chains. With an operator-supplied Ed25519 key it signs
the last log's final chain value and the checksum manifest, which covers
every log and `event-chain.txt`; the corresponding public key is included.
The chain is now computed in one Python pass, falling back to the shell
loop, which took minutes for a 100k-line day; a test checks that both write
the same chain.

Off-host checkpoints (new):

* `secure-sudod` keeps the same chain over its local log as it writes.
* At start and every 5 minutes it logs and forwards a `log_checkpoint`
  record with the log name, line count and chain value.
* The collector's copies are the integrity anchor that is never stored on
  the monitored host. `evidence-verify --checkpoints COLLECTOR.log` fails a
  bundle whose log was edited or truncated after a checkpoint, and reports
  how much of each log is anchored.
* If the log changes underneath the daemon (appended, truncated or
  replaced by anyone else), it records `log_modified`.
* Daemon messages can no longer split into extra log lines.
* Tests:
  - the C chain is checked against an independent Python one;
  - edited, truncated and malformed-checkpoint cases fail as they should.
Quarantined file contents and key/token/password-named config files are not
exported. The exporter leaves source evidence untouched.

`docs/INCIDENT_RESPONSE.md` documents the root-only retention hold, external
key custody/rotation steps, chain-of-custody records, and a tabletop procedure.
The daemon preserves logs while the hold marker is valid and reports `held` or
`hold_error` through health. Still missing for *Done*:

* A stronger review of secret redaction.
* A completed chain-of-custody tabletop. People have to run it, with the
  steps in INCIDENT_RESPONSE.md, now including the checkpoint check.
* Checkpoints are anchored by the collector's copy, not signed. A host that
  never forwards has only its own word, plus signed exports. Independent verification is
implemented in `secure-sudo evidence-verify`; the test suite validates
unsigned and signed bundles and rejects tampering, untrusted keys and unsafe
archive paths.
An export signed with a key stored only on the monitored host is not
tamper-resistant against host root.

### P1-4 Unified health — partial

`secure-sudo health` (and `--json`) reports whether the LSM exists, whether
the configured kernel audit feed and daemon's root-owned heartbeat are active
and fresh, whether configured kernel knobs match live values, event/audit loss,
local log write failures, active log-retention holds, remote transport,
queue records/bytes and dropped remote events. It also reports the last policy
load state and accepted/rejected/skipped counts from an atomically written,
root-owned mode-0600 result file bound to the current boot ID; missing,
untrusted, refused, partial and previous-boot load results degrade health.
It preserves up to eight rejected setting names and an omitted count, but not
configured values or error text.
Heartbeats are accepted only
when fresh, regular, root-owned and mode 0600, and a missing metric field
degrades health. The JSON command exits nonzero on queue backlog/drop,
forwarding or local-log errors, event loss, or configured UDP forwarding
(which remains unconfirmed). TLS stream writes are explicitly named
`tls_sent_unconfirmed`; health does not claim collector persistence.

Still missing for *Done*: collector-side durable receipt, rejected-setting
error details, and
comprehensive machine-readable health coverage. Systemd service/timer unit
state, each scan service's exit result/status/time and 26-hour freshness, and DriverGuard, BootGuard
and BiosGuard baseline
presence/freshness are included; disabled optional units are informational,
while enabled inactive units or missing/stale baselines degrade health.

### Other P1 items still deferred

P1-7 is code-complete (a people-run tabletop remains); P1-8 is done. The earlier overview's
"groundwork" below is historical; it does not mean these requirements are
complete.

## P1-5 — done (2026-11-01)

[THREAT_MODEL.md](THREAT_MODEL.md) maps each control (#1–#23, the install
and boot path, and the `temporary/` add-ons) to the threat it answers, what
it needs, its known limits and bypasses, and the test that checks it. Where
a control had no test, one was written:

* `tests/vm/ss-functest.c` gained home-write confinement, the RAM guard,
  the sudo cooldown, the Node guard, BinaryVault, RadioGuard and TimeVault
  (prepare, engage, allowlist, hash mismatch, package manager, memfd,
  write-open, disengage refused), plus an event check for every denial
  that logs one. 233/233 pass on 6.14 locally under TCG.
* `tests/userspace/test-pheonixbox.sh` (new) runs the real PheonixBox
  helper in a private mount namespace: snapshot, lock, tamper, repair,
  re-lock, permission restore. 26/26 locally.

Writing it found four real faults, all fixed (SECURITY_REVIEW #54–#57):
five controls whose denials never reached the event log; a PheonixBox file
name that ran a root command; a blacklist that a renamed copy got past and
module checks that a renamed file got past; and committed binaries that
could be installed instead of a fresh build.

Four doc promises the code does not keep yet are tracked as features to
build in [TODO.md](../TODO.md) "Doc promises to build" (G1 Node SEA
auto-detection, G2 TimeVault Merkle tree, G3 TPM2-sealed OTP secret, G4
TPM clear through `/dev/tpm*`). Until each lands, its doc says "not built
yet". G1 is built: `secure-sudo node-scan` (SECURITY_REVIEW #59). G2 is built: the TimeVault manifest's Merkle root (SECURITY_REVIEW #60). G3 is built: the OTP master key sealed to the TPM (SECURITY_REVIEW #61). G4 is built: `tpm_openers` and `install.sh tpm-lockout` (SECURITY_REVIEW #63).

## P1-6 — done (2026-11-01)

* **Preview**: `secure-sudo diff` (also `load --dry-run`) runs lint and
  shows each setting and list entry where `/etc/secure_sudo` differs from
  the running kernel. It writes nothing. After a load, any difference left
  is exactly what the kernel did not take.
* **Snapshots**: `load`, `restore`, `set`/`net`, `lock` and `timevault on`
  first save the configuration files and the live kernel settings, lists
  and lock state under `/var/lib/secure_sudo/policy/snapshots/ID/`, with
  `meta` (who, why, kernel, boot id, lock state), `SHA256SUMS`, and the hash
  of the previous snapshot's sums. `snapshot verify` detects an edited,
  missing or extra file, and a predecessor whose sums were rewritten.
* **History**: one JSON line per change in `policy/history.jsonl`: action,
  uid, login uid, `SUDO_USER`, lint errors, the number of differences,
  accepted/rejected/skipped, the rejected settings, the snapshot before
  it. Each line carries the SHA-256 of the line before (`history
  --verify`), and each is sent to syslog for an off-box copy.
  `evidence-export` includes it.
* **Partial loads** name the rejected settings and the snapshot to restore.
  `lock` warns when the running policy differs from the files it would
  freeze.
* **Restore**: `restore ID` verifies the snapshot, shows each setting and
  entry it changes, asks, saves the current state, writes the files
  atomically and loads them. It is refused while locked, except
  `--no-load`, which only puts the files back for the next boot.
* Tests: `tests/userspace/test-cli.sh` 119 → 157 checks, with stand-in
  kernel files: a partial load and its diff, restore with and without
  confirmation, restore while locked, a forged snapshot with rewritten
  sums, and edited or removed history lines.
* Not covered: an attacker who is root before the lock can rewrite the
  local history and snapshots consistently. The syslog copy is the
  record they cannot rewrite once it is forwarded.

## P1-7 — code-complete (2026-11-01; tabletop remains)

* [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) is now the runbook: roles
  and the first five minutes, triage (read-only commands and what to look
  for), evidence (the P1-3 export), containment, escalation criteria (which
  also mean "rebuild"), recovery, rebuild, and an extended tabletop.
* `secure-sudo contain` (helper `contain.sh`): network isolation that keeps
  loopback, `--allow` addresses, the operator's SSH client and the log
  collector; account lock + expiry + freeze (or `--terminate`); process
  freeze + evidence (or `--kill` after it). Each has `--dry-run`, a `yes`
  prompt, a release that puts back what was there, and a history record.
  Writing its tests found that a refusal check inside a `set -o pipefail`
  pipeline never fired, so the helper froze its own caller; fixed before
  release.
* Section 8 lists every automatic destructive action with its false-positive
  cost, exclusions, audit trail, undo and test; every row now has a test.
* `tests/userspace/test-addons.sh` (31 checks) drives ProcGuard,
  BootGuard, DriverGuard and TamperWatch against temporary trees and real
  processes. It found three bugs, fixed: ProcGuard's exemption could be
  borrowed by naming a binary `secure-sudo-*` and it deleted system
  binaries (#64); TamperWatch killed PheonixBox repairs and package updates
  (#65); BootGuard and DriverGuard rolled kernel updates back (#66). New
  apt/dnf/kernel-install hooks run `addons-refresh` after an update.
* Remaining: the tabletop exercise in INCIDENT_RESPONSE.md 9 needs people;
  CI cannot run it.

## P1-8 — done (2026-11-01)

* `tests/userspace/test-netpolicy.sh` builds a small network from
  namespaces (internet, LAN router with DNS, a second LAN on another NIC, a
  VPN-named link, a container behind a bridge) and checks real ping and UDP
  traffic in every mode, IPv4 and IPv6, beside a pre-existing nftables table
  and an iptables-nft rule. It found four gaps, built: the second NIC leaked
  in public-only, forwarded container traffic ignored both modes, a DHCP
  subnet change left stale rules, and nothing was loaded before the first
  address (SECURITY_REVIEW #67).
* Fail-safe policy: one-transaction replace, failures keep the loaded rules,
  fail-closed pending rules when no LAN is found, `on_stop = keep` by
  default, uninstall removes the table. `secure-sudo health` shows
  `Network policy rules: off|applied|pending|failing`.
* Documented that `host`/raw-socket blocking and the LAN modes are not host
  isolation; the auditable isolation procedure is `secure-sudo contain
  network` (P1-7).
* Remaining by design: a namespace with its own uplink (macvlan) is not
  covered; real NIC/Wi-Fi/VPN hardware checks are in HARDWARE_SMOKE_TEST.md.

Earlier groundwork notes (historical):

* P1-1: the ring drops whole events and exposes `events_dropped`
  (SECURITY_REVIEW #44); expanded in the partial implementation above.
* P1-4: `install.sh verify` checks the running kernel, daemon and lint;
  `load` reports rejected settings; expanded in the partial implementation above.
* P1-2: TLS syslog and a bounded persistent queue now exist; collector
  acknowledgment remains unresolved.

## P2 — not started

P2-5 groundwork: the management GUI's access-token hole was fixed in v11
(SECURITY_REVIEW #29); it has no automated tests.

## P3

* P3-1 compatibility matrix: not started. What is known is in the P0-3
  table above.
* P3-2: this file, [RECOVERY.md](RECOVERY.md), the security review (#35–#47)
  and `docs/vm/results/` were brought up to date with the code in this
  release; making that part of a release checklist is not done.
* P3-3 maintenance and disclosure process: not started.
