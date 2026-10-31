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
| P0-1 build + CI gate | partly | `ci/build-gate.sh` passes from a clean copy; not yet required in CI, 6.12 not built as a tree |
| P0-2 tests | partly | 421 host checks and 118/118 in-kernel checks pass; STIG gate compares rule IDs; not yet required in CI |
| P0-3 boot proof | partly | boots and runs on upstream 6.14 in Ubuntu 24.04 VMs (install 51/51, STIG run classified); not 6.12, UEFI, other distros or hardware |
| P0-4 source provenance | done | signature-verified before extraction, tamper test, SBOM, reproducible archive |
| P0-5 transactional install | done (Ubuntu 24.04) | trial boot, automatic fallback, commit, rollback and byte-clean removal proven in a VM; other distros simulated only |
| P0-6 policy validation + recovery | done | lint/load refuse bad policy before anything is applied; four recovery drills pass on the real kernel in a VM |
| P1-1 | partly (active) | schema-v1 JSON events, boot/sequence/clock/actor fields, typed fields across denial producers, ring + audit loss counters; target identity and deferred actor attribution remain incomplete |
| P1-2 | partly (active) | opt-in authenticated RFC 5425 TLS, bounded persistent queue/retry, and queue/error health reporting; collector acknowledgment and integration proof remain |
| P1-3 | partly (active) | root-only evidence export with checksums, per-log hash chains and optional externally-held Ed25519 signing key; no periodic signed checkpoints or tabletop |
| P1-4 | partly (active) | `secure-sudo health [--json]` validates the configured audit feed, fresh root-owned heartbeat/metrics, configured/live knobs, boot-bound last load outcome/counts/rejected setting names, event loss, local log failures, remote queue/errors and optional add-on/timer state including scan results/age; collector receipt remains |
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
  from kernel.org, plus a nightly distro VM job: the installer builds the
  kernel package, then the install/recovery/removal scenario and the STIG
  release gate run on fresh Ubuntu 24.04 guests.

Missing:

* The workflow has not run on GitHub, so "required in CI" is not yet true.
  The first push will show whether it works as written.
* The in-tree builds used 6.14; 6.12.114 was compiled against headers only.
  The workflow builds 6.12.114 as a full tree, which is the first time that
  will happen.
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
`tests/vm/boot-test.sh`): historical runs passed **118/118** on upstream 6.14,
and again 118/118 with AppArmor stacked. The source now has an additional
cross-process target-identity assertion and updated schema checks, so those
recorded runs do not validate the current source; a new VM run is required.
They cover registration and stacking, knob defaults,
modes and bounds, setid/setgroups/userns, setuid-exec allowlist, command
blacklist (incl. hard links), `/tmp` and memfd exec, `/dev/mem`, packet
sockets, BPF and perf, SysctlGuard and binfmt_misc, Process Runtime Guard,
`finit_module` and `init_module` with name and hash blacklists, concurrent
list rewrites during exec, the event ring wrap and loss counter, and the
one-way lock (every knob kind refuses, modules and tracing BPF refused).
Results: `docs/vm/results/02-*`, `03-*`.

STIG release gate: `tests/oscap/stig-gate.sh` (39 checks in `tests/oscap/`) compares an
OpenSCAP result rule by rule with `tests/oscap/ubuntu2404-stig.expect`. The
VM release run reached 206 pass / 11 fail / 0 error after two remediation
passes; every remaining rule is classified in
[OSCAP_BUGS.md §5](OSCAP_BUGS.md#5-release-run-in-a-vm-v12-2026-10-26), and
the fixes it led to are in this release. The final VM rescan with those
fixes has not run yet, so the gate has **not** yet passed on a VM result.
The run also found that the scanner cannot evaluate `encrypt_partitions` on
Ubuntu 24.04 (false pass, OSB-19); the gate now uses an independent check
for it and refuses a release result without one.

Missing:

* Not yet in the kernel tests: chroot and mount-namespace edge cases,
  TimeVault, BinaryVault, RadioGuard, cooldown, home-write, the NodeJS
  guard, RAM-spike handling, TPM and firmware sysfs paths.
* The `no-audit`/`no-bpf`/`no-modules` variants are built, not booted.
* Add-on monitor/enforce modes (`temporary/`) have build checks only.
* Not required in CI yet (P0-1).

### P0-3 Boot proof — partly

What has been booted, all under QEMU/TCG with SeaBIOS
(`docs/vm/results/`):

| Kernel | Guest | Result |
|---|---|---|
| v11 LSM, upstream 6.14 | initramfs | **panic** at boot (`Ran out of static slots`, SECURITY_REVIEW #35); fixed in v12, guarded by `ci/check-lsm-hooks.sh` |
| v12 LSM, upstream 6.14 | initramfs, PID 1 test program | 118/118, and 118/118 with AppArmor stacked |
| v12, `install.sh build-kernel` package, upstream 6.14 | Ubuntu 24.04 cloud image (systemd, GRUB, AppArmor, virtio disk) | install/recovery/removal 51/51; active LSMs `lockdown,capability,landlock,yama,apparmor,secure_sudo,ima,evm`; services start; the configuration loads; the previous kernel stays bootable and is fallen back to |
| same | Ubuntu 24.04, STIG remediation | boots again after full STIG hardening with secure_sudo and AppArmor active; scan results above |

Known platform exclusions, recorded rather than claimed:

* Lockdown is `none` in these guests: no Secure Boot under SeaBIOS, so the
  "expected lockdown state" could only be checked as "not enforced".
* `fwupd-refresh` fails in the guest (no network firmware service), so
  systemd reports `degraded`; unrelated to secure_sudo.
* The VM kernel was built with `SS_LOCALMOD` from a fresh guest's module
  list. That dropped the netfilter modules, so ufw could not start (OSB-21);
  `install.sh` now keeps them. Not yet rebuilt and booted.

Missing for *Done*:

* **6.12 LTS, the installer's default, has never been booted** (only
  compiled against its headers; kernel.org was unreachable).
* No UEFI, Secure Boot, MOK enrollment or TPM test (no OVMF/KVM here).
* No VM of Fedora, openSUSE or Arch; no real hardware.
  [HARDWARE_SMOKE_TEST.md](HARDWARE_SMOKE_TEST.md) is the plan for that.
* The VM STIG run has not yet ended on a scan with no unexplained failures
  (above).

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

Evidence: `tests/install/test-install.sh` (106 checks, including a
byte-identical root after install + uninstall and an interrupted install),
and the distro VM run: `06-distro-install-final/` on the packaged tree, **51/51**: install-kernel and
userspace on a fresh Ubuntu 24.04 cloud image, the trial boot with
secure_sudo and AppArmor active, `verify --commit`, a deliberately broken
trial that falls back to the previous kernel by itself, rollback, uninstall
refusing while PAM uses the modules, and a removal after which every file
under the directories `install.sh` touches is byte-identical to the fresh
image (apart from the runtime packages `libqrencode4 zip unzip`) and
`grub.cfg` is byte-identical to what GRUB generated before the install.

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
saturation, and exposes a loss counter. The earlier CLI revision
passed 92/92 checks. The earlier 103-check suite's focused audit-feed,
scan-outcome and boot-bound load-health assertions passed. Two retention-state
health assertions have since been added, but the updated suite could not be
run here because its build needs missing OpenSSL development headers; the
ownership/load cases also require root. The evidence export/verification suite
previously passed 13/13 checks.
The daemon and TLS forwarding
harness compile and the original local forwarding suite passed 8/8 using
temporary OpenSSL API declarations against the installed runtime libraries.
The new CA-rotation assertion has not yet been rerun. A build against upstream
OpenSSL development headers remains unverified because those headers are
unavailable here.

Still missing for *Done*: target values are not consistently typed PID/UID
identities and can be descriptive labels. Cross-process memory-access events
now include target PID and UID, but other target identities remain partial;
deferred work may record the kernel worker rather than the initiating userspace
actor. A source-level VM assertion checks the truncation field and normal
short-event value, but it has not yet been run in a clean VM; saturation and
loss-counter behavior also need a fresh VM result. Sustained-throughput
behavior is not measured.

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
builds per-log hash chains and can sign each final chain checkpoint and the
checksum manifest with an operator-supplied Ed25519 key; the corresponding
public key is included.
Quarantined file contents and key/token/password-named config files are not
exported. The exporter leaves source evidence untouched.

`docs/INCIDENT_RESPONSE.md` documents the root-only retention hold, external
key custody/rotation steps, chain-of-custody records, and a tabletop procedure.
The daemon preserves logs while the hold marker is valid and reports `held` or
`hold_error` through health. Still missing for *Done*: periodic checkpoints
signed off-host, stronger secret redaction review, and a completed
chain-of-custody tabletop. Independent verification is
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
