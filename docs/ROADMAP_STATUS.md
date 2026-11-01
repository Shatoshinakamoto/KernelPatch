# secure_sudo — where the Strategic TODO stands

Status of every item in [TODO.md](../TODO.md) for release **0.12.0**
(2026-10-26), with the evidence behind each claim and what is still missing.
"Done" below means the item's own *Done when* is met by something that ran
and can be re-run; anything short of that is "partly" or "not started", with
the reason.

Two limits of the build environment shape this release and are named
wherever they matter:

* **kernel.org, GitHub and the Debian archive were not reachable.** The
  installer's default kernel (6.12.114) was therefore compiled only against
  its headers here, never built as a whole tree or booted. Every boot test
  used **upstream 6.14** (Ubuntu's unpatched `.orig` tarball, fetched through
  the signed Ubuntu archive).
* **No KVM.** All VMs ran under TCG emulation with BIOS firmware (SeaBIOS),
  so nothing was tested under UEFI or Secure Boot, and nothing ran on real
  hardware.

The GitHub workflow (`.github/workflows/build-gate.yml`) is written and
syntax-checked but has **never run on GitHub**: per the project rule,
nothing is pushed from here.

| Item | Status | One line |
|---|---|---|
| P0-1 build + CI gate | partly | `ci/build-gate.sh` passes from a clean copy and on GitHub for every push/PR, 6.12.114 in-tree in six configs; not yet a required check (branch protection) |
| P0-2 tests | partly | 556 host checks pass in CI on every push; 126/126 in-kernel checks pass on 6.12.114 in CI (`kernel-boot`); STIG gate compares rule IDs; not yet a required check |
| P0-3 boot proof | partly | 6.12.114 with secure_sudo, all in CI: 126/126 in-kernel checks (initramfs, KVM), the full Ubuntu 24.04 install/trial/fallback/commit/drills/removal run (52 checks), and the STIG run 16/16: the hardened guest reboots and the release gate passes; not UEFI, other distros or hardware |
| P0-4 source provenance | done | signature-verified before extraction, tamper test, SBOM, reproducible archive |
| P0-5 transactional install | done (Ubuntu 24.04) | trial boot, automatic fallback, commit, rollback and byte-clean removal proven in a VM, on 6.14 and again on 6.12.114 in CI; other distros simulated only |
| P0-6 policy validation + recovery | done | lint/load refuse bad policy before anything is applied; four recovery drills pass on the real kernel in a VM |
| P1-1 | partly (active) | schema-v1 JSON events with typed fields; sequence numbers given in ring order so gaps are exact; `events_sequence`/`events_boot_id`; the daemon logs `event_stream`/`event_gap` records and keeps a restart cursor; health shows gaps. Remaining: some targets are labels rather than typed PID/UID; long paths are only complete in `message`; deferred-work actor attribution |
| P1-2 | done | authenticated RFC 5425 TLS, bounded persistent queue, batched flush with backoff, clean TLS close; 10-check integration suite (delivery, wrong host, untrusted CA, missing CA, CA rotation, outage, queue exhaustion, batching, backoff) passes in CI. A TLS write is reported as `tls_sent_unconfirmed`, never as collector persistence |
| P1-3 | partly (active) | root-only export with checksums and per-log chains, optional external Ed25519 signing, `log_checkpoint` records forwarded off-host every 5 min and checked by `evidence-verify --checkpoints`, `log_modified` on outside changes. Remaining: a completed tabletop (people) and a redaction review |
| P1-4 | done | `secure-sudo health [--json]`: LSM, daemon heartbeat (atomic), audit feed, configured vs live knobs, last load with rejected names, ring/audit loss and daemon-seen gaps, local log failures, remote queue/errors, add-on units, scan results/age and baselines. Collector-side receipt is outside the host's view; the forwarded checkpoints let the collector alert on silence |
| P1-5 … P1-8 | not started | see remaining-work notes below |
| P2-1 … P2-5 | not started | |
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
| `tests/userspace/test-otp.sh` | 66 | RFC 4226/6238 vectors, secret at rest, prefix, replay refusal |
| `tests/userspace/test-pam.sh` | 50 | both PAM modules through libpam, the documented stacks, real `pam_unix` + `pam_faillock` (root, private mount namespace) |
| `tests/userspace/test-helpers.sh` | 74 | `apply-net.sh` with real `nft` in network namespaces (all four modes, IPv4 + IPv6, DHCP/DNS), `quarantine.sh` (archive before delete) |
| `tests/userspace/test-cli.sh` | 105 | config parsing, `lint`, `load` reporting and persisted boot-bound load-health status, health status/JSON, including audit-feed activity, log-retention hold, systemd add-on/timer state, scan outcomes/age and baseline freshness, against stand-in knob and list files |
| `tests/userspace/test-remote-forwarding.sh` | 9 | TLS CA/hostname validation and CA rotation, RFC 5425 delivery, queue persistence/exhaustion, outage retry |
| `tests/userspace/test-evidence-export.sh` | 13 | checksum, secret exclusion, independent verification, path traversal and tampering rejection, external-key signature validation |
| `tests/oscap/` | 39 | result parsing and the STIG gate's rule-by-rule comparison, release vs diagnostic mode, independent checks (OSB-19) |
| `tests/provenance/` | 19 | P0-4 above |
| `tests/install/test-install.sh` | 106 | P0-5 below |

In-kernel tests (`tests/vm/ss-functest.c`, run as PID 1 of an initramfs by
`tests/vm/boot-test.sh`): the CI `kernel-boot` job passed **126/126** on
6.12.114 under KVM on 2026-10-31 against the current source, including the
cross-process target identity, the schema checks and the P1-1 sequence
checks (`docs/vm/results/08-ci-kernel-boot-6.12/`). Earlier runs passed
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
| current LSM, kernel.org 6.12.114 (CI `kernel-boot`, KVM) | initramfs, PID 1 test program | 126/126, no kernel splat |
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

## P1-1 through P1-4 — active, partial

### P1-1 Event schema and loss

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
* the TimeVault quarantine needs an untruncated record whose message
  matches the kernel's format exactly.

Before, it searched the message text, which let a crafted file name
trigger either action (SECURITY_REVIEW #48). Records that straddle two
ring reads are now reassembled (#49). Actor UIDs are logged in the initial
user namespace. A `truncated` boolean
reports when the event type, typed string, or message was shortened. The
64 KiB ring caps lines at 640 bytes, discards oldest whole records on
saturation, and exposes a loss counter. The CLI/health, daemon-event,
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

The in-kernel tests for the record format (every field, `truncated`,
typed classification from a producer), ring saturation (the surviving
records are contiguous, the sequence gap equals `events_dropped`) and both
loss counters ran in CI on 6.12.114 under KVM: 126/126
(`docs/vm/results/08-ci-kernel-boot-6.12/`).

Still missing for *Done*: target values are not consistently typed PID/UID
identities and can be descriptive labels. Cross-process memory-access events
now include target PID and UID, but other target identities remain partial;
deferred work may record the kernel worker rather than the initiating userspace
actor. Sustained-throughput behavior is not measured.

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

P1-5 through P1-8 remain unstarted: threat model/support profile; policy
snapshots and change history; incident runbooks and containment guardrails;
and broader network-policy/failure-mode validation. The earlier overview's
"groundwork" below is historical; it does not mean these requirements are
complete.

## P1-5 through P1-8 — not started

Pre-existing groundwork (not completion):

* P1-1: the ring drops whole events and exposes `events_dropped`
  (SECURITY_REVIEW #44); expanded in the partial implementation above.
* P1-4: `install.sh verify` checks the running kernel, daemon and lint;
  `load` reports rejected settings; expanded in the partial implementation above.
* P1-6: `lint` is the non-mutating preview; there is no snapshot or change
  history.
* P1-7: [RECOVERY.md](RECOVERY.md) covers administrator lockout, not incident
  response.
* P1-8: network modes are tested with real `nft` in namespaces for IPv4 and
  IPv6; multiple interfaces, VPNs, DHCP changes, pre-existing rulesets and
  daemon restarts are not.
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
