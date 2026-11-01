# secure_sudo Strategic TODO

**Review snapshot:** 2026-10-26  
**Purpose:** prioritize the work needed to make this defensive Linux LSM and
its companion tools safer to build, deploy, operate, and trust during an
incident. This is a roadmap, not a claim that the existing protections are
absent or that the project is already production-certified.

Execution update: P1-1, P1-2 and P1-4 meet their **Done when** criteria.
P1-3 is still in progress; its remaining acceptance gaps are tracked in
[docs/ROADMAP_STATUS.md](docs/ROADMAP_STATUS.md). Keep its checkbox open
until its full **Done when** criteria is met.

## Scope and current baseline

The repository is a built-in Linux LSM plus userspace policy, PAM, logging,
installation, compliance, and optional monitoring components. The core already
implements privilege and exec controls, firmware/driver restrictions,
TimeVault, BinaryVault, Process Runtime Guard, BPF/perf and sysctl protections,
kernel event reporting, OTP, and STIG/CIS tooling. `temporary/` contains
additional opt-in monitors and a local management GUI. Keep these existing
features; focus the TODO on proving their behavior and closing operational,
assurance, and evidence gaps.

Review basis: repository documentation, kernel and userspace sources, config
templates, scripts, service definitions, installers, and the checked-in STIG /
CIS result artifacts. Generated OpenSCAP HTML reports and `.git/` internals
are historical or repository metadata, not implementation components.
No dedicated test suite or CI workflow was present in the repository at this
review snapshot; the roadmap treats repeatable validation as a release blocker.

### Priority guide

- **P0 — Release blockers:** complete before recommending production use.
- **P1 — Operational assurance:** complete before relying on the stack for
  incident response or fleet deployment.
- **P2 — Defense-in-depth:** valuable capabilities and maturity improvements
  after release gates are reliable.
- **P3 — Ongoing:** documentation, compatibility, and long-term maintenance.

## P0 — prove the kernel and installer are safe to release

- [ ] **P0-1: Establish a reproducible build and CI gate.**
  - Add automated builds for the exact installer default (`6.12.48`) and the
    explicitly supported kernel versions; exercise relevant config variants
    such as audit, BPF, perf, module signing, and LSM stacking.
  - Build the CLI, daemon, PAM modules, OTP helper, and all shipped add-ons
    with warnings treated as errors where practical.
  - Record compiler, kernel source revision, config, and build results for
    each release.
  - **Done when:** a clean checkout passes the same build gate in CI that is
    required for a release, with no unrecorded reliance on a local build tree.

- [ ] **P0-2: Add automated functional and regression tests.**
  - Create tests for kernel policy parsers and list replacement, config bounds,
    lock irreversibility, event-ring wrap/reader behavior, error paths, and
    credential/path decisions.
  - Add privileged integration tests in disposable VMs (for example QEMU):
    boot the built kernel; confirm LSM registration and stacking; exercise
    allowed and denied setid/userns, privileged exec, tmpfs/memfd exec,
    module loading, BPF/perf, sysctl, ptrace/memory access, and lock behavior.
  - Cover both `finit_module` and `init_module`, mount/chroot edge cases,
    concurrent policy reads/writes, and expected behavior when optional kernel
    features are disabled.
  - Add userspace tests for CLI/config parsing, PAM success/failure paths,
    RFC 6238 OTP vectors and secret handling, daemon/helper behavior, and
    add-on monitor/enforce modes. Tests that need root or kernel features must
    be isolated and clearly marked.
  - Add an OpenSCAP regression job for the Ubuntu 24.04 STIG profile using
    the pinned SSG content and scanner versions from
    [OSCAP_BUGS.md](docs/OSCAP_BUGS.md). Run the release gate in an Ubuntu
    VM with systemd and AppArmor so the final result has exactly one `fail`
    (`encrypt_partitions`, OSB-12), zero `error`, and zero other failed rules;
    compare rule IDs, not only totals.
  - Keep container scans as diagnostics, not as the release acceptance gate:
    their AppArmor error and other environment-dependent results must be
    resolved by running in a capable VM/host, not hidden or counted as a pass.
    Do not count `error`, `unknown`, or unexplained `notchecked` as passing
    results or as part of the one-failure exception.
  - **Done when:** tests assert both denials and legitimate workflows, run
    repeatably without touching the developer host, and are required in CI;
    the STIG VM regression gate meets the stated exception exactly.

- [ ] **P0-3: Boot-test the release kernel before declaring support.**
  - Boot the exact packaged kernel and representative supported distro
    configurations in disposable VMs, then run a hardware smoke-test plan for
    Secure Boot, TPM, Wi-Fi/Bluetooth, firmware interfaces, and common storage
    and network drivers.
  - Verify that secure_sudo appears in the active LSM list, the expected
    lockdown state is active, services start, configuration loads, and the
    previous kernel remains bootable.
  - On an Ubuntu VM with systemd, bootloader, AppArmor, and virtual disks,
    verify the STIG results that are misrepresented by container limitations:
    AppArmor rules must evaluate without errors, and all applicable rules must
    pass. If the VM cannot validate encrypted partitions, permit only the
    exact `encrypt_partitions` failure (OSB-12); do not infer encrypted-volume
    support from a container scan.
  - **Done when:** results and known platform exclusions are recorded per
    supported kernel/distro combination; documentation no longer treats
    compilation as a substitute for boot testing, and the VM STIG run has no
    unexplained failures or evaluation errors.

- [ ] **P0-4: Verify kernel source provenance before extraction/build.**
  - Verify the upstream kernel release signature against a documented,
    independently trusted keyring; fail closed on an invalid or unavailable
    signature. Record the verified source hash and release in build metadata.
  - Pin or record toolchain and dependency versions, and generate an SBOM for
    release artifacts.
  - **Done when:** a tampered archive is rejected before extraction and a
    release can be rebuilt from its recorded inputs.

- [ ] **P0-5: Make installation, upgrade, and recovery transactional.**
  - Add a preflight/dry-run that reports distro support, disk space, boot
    method, signing state, required tools, and changes before making them.
  - Verify the installed kernel configuration, active LSM list, module-signing
    enforcement, generated bootloader entry, and boot artifact signatures;
    report failures instead of treating failed update steps as success.
  - Preserve a known-good boot entry and document recovery from an unbootable
    kernel, failed MOK enrollment, interrupted package install, and policy
    lockout. Provide a supported uninstall/rollback path that restores only
    files owned by this package.
  - **Done when:** install/upgrade failure leaves the previous boot path
    usable, and a VM test proves both rollback and clean removal.

- [ ] **P0-6: Validate first-boot policy and administrator recovery.**
  - Add a policy preflight that checks syntax, kernel-supported settings,
    allowlist existence/ownership, dependency combinations, PAM ordering, and
    expected lock effects before enabling enforcement.
  - Make configuration loading report every accepted, skipped, or rejected
    setting and avoid silently starting with an unintended partial policy.
  - Document and test a recovery route for an incorrect admin GID, incomplete
    allowlist, failed PAM change, and accidental one-way lock. Keep a tested
    root recovery session open for PAM changes.
  - **Done when:** invalid or incomplete policy is clearly identified before
    the operator engages irreversible controls, and a recovery exercise
    succeeds in a VM.

## P1 — make security events dependable incident evidence

- [x] **P1-1: Give kernel events a stable, loss-aware schema.**
  - Include a schema version, boot identifier, monotonic and wall-clock time,
    event sequence, event type, actor/target identity, operation, object
    identity where available, decision, and reason.
  - Track ring-buffer overwrite and audit-backlog loss counters and expose
    them to status/health checks; never silently imply a complete event
    history after loss.
  - Bound and document event volume, truncation, sensitive fields, and
    backpressure behavior.
  - **Done when:** a consumer can detect gaps, correlate events across a
    reboot, and parse records without relying on free-form message text.

- [x] **P1-2: Harden core daemon log forwarding.**
  - The core daemon currently forwards remote syslog using UDP; add an
    explicitly configured reliable and authenticated transport (such as
    TLS syslog), bounded retry/queue behavior, and visible health/error
    reporting. Keep local logging functional when the network is unavailable.
  - Make delivery, queue limits, replay behavior, destination identity, and
    certificate/key rotation explicit. Do not silently discard forwarding
    failures or claim remote delivery when only local write succeeded.
  - **Done when:** an integration test proves delivery and detects loss,
    outage, invalid certificates, and queue exhaustion; documentation matches
    the core daemon's actual transport options.

- [ ] **P1-3: Protect and export evidence for incident response.**
  - Add tamper-evident log checkpoints (for example chained hashes with
    periodic signatures) whose signing material is not stored solely on the
    monitored host; document verification and key custody.
  - Add a root-only incident bundle/export containing kernel and daemon
    events, loss counters, policy/config snapshots, boot/kernel identifiers,
    relevant service state, and quarantine metadata. Preserve originals and
    hashes; redact secrets and unrelated personal data.
  - Define retention, access, clock synchronization, export, and chain-of-
    custody procedures; ensure retention does not silently delete records
    needed for an active incident.
  - **Done when:** an exported bundle can be independently integrity-checked
    on another machine and a documented tabletop exercise completes.

- [x] **P1-4: Provide a unified health and policy view.**
  - Distinguish configured values from live kernel values and show whether
    the LSM, daemon, audit feed, remote collector, timers, and add-ons are
    actually active or degraded.
  - Surface rejected settings, dropped events, stale baselines, last scan
    times, and service failures in the CLI and machine-readable output.
  - **Done when:** operators can detect an inactive enforcement component
    without consulting source code or assuming that an installed service is
    healthy.

## P1 — improve safe operation and response

- [x] **P1-5: Define a testable threat model and supported deployment profile.**
  - Done 2026-11-01: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). The
    promises it found the code did not keep are listed under "Doc promises
    to build" below.
  - State explicitly that the design trusts the install-time administrator
    and does not by itself defeat a compromised kernel, trusted root before
    lock, physical attacker, malicious/compromised firmware, or an attacker
    who can boot an untrusted kernel.
  - Define supported host/server/container roles, admin-group semantics,
    LSM ordering, lockdown/Secure Boot assumptions, and expected interactions
    with SELinux, AppArmor, Yama, Landlock, auditd, and distribution tooling.
  - **Done when:** each control is mapped to a threat, precondition, known
    bypass/limitation, and validation test; out-of-scope protections are not
    implied by feature names or compliance mappings.

- [x] **P1-6: Add policy preview, snapshot, and change history.**
  - Done 2026-11-01: `secure-sudo diff` / `load --dry-run`, `snapshot`,
    `history`, `restore` (docs/COMMANDS.md, RECOVERY.md 4g); every load,
    set, lock and restore snapshots first and is recorded;
    tests/userspace/test-cli.sh.
  - Provide a non-mutating policy lint/preview and a versioned, integrity-
    checked snapshot of both disk configuration and live kernel state before
    changes or lock engagement.
  - Record who changed policy, what changed, validation results, and whether
    the kernel accepted it. Make multi-file loads report partial application
    clearly and support deliberate restoration before locking.
  - **Done when:** operators can review a proposed change, identify partial
    application, and restore a known-good unlocked policy without editing
    files blindly.

- [ ] **P1-7: Create incident-response runbooks and safe containment modes.**
  - Partly done 2026-11-01: docs/INCIDENT_RESPONSE.md (triage, evidence,
    containment, escalation, recovery, rebuild, and an inventory of every
    automatic kill/wipe/restore/quarantine) and `secure-sudo contain`
    (dry run, confirmation, evidence first, release; tests/userspace/
    test-contain.sh).
  - Built 2026-11-01: guardrail tests for every destructive add-on
    (tests/userspace/test-addons.sh, 31 checks) and package/kernel hooks
    that re-baseline BootGuard/DriverGuard after an update. The tests found
    three real bugs, fixed (SECURITY_REVIEW #64-#66). Code-complete;
    remaining: a people-run tabletop exercise (INCIDENT_RESPONSE.md 9),
    which is the "done when" test and cannot be run by CI.
  - Document triage, evidence preservation, network isolation, account
    containment, process quarantine, policy lock, escalation, recovery, and
    post-incident rebuild steps.
  - Prefer monitor/dry-run and operator confirmation before destructive
    actions. For every automatic kill, wipe, restore, or quarantine action,
    document false-positive impact, exclusions, audit trail, and undo path.
  - **Done when:** an operator can complete a tabletop exercise without
    relying on undocumented developer knowledge, and every destructive
    automation has tested guardrails and a recovery procedure.

- [x] **P1-8: Verify network policy behavior and failure modes.**
  - Done 2026-11-01: tests/userspace/test-netpolicy.sh drives real traffic
    through network namespaces (IPv4/IPv6, two LAN NICs, a VPN, a DHCP
    subnet change, routed containers, existing nftables and iptables-nft
    rules, restart, failed detection, on_stop). It found four gaps, built
    (SECURITY_REVIEW #67): every LAN interface, a forward chain, refresh
    every 15 s, fail-closed pending rules. Fail-safe policy and "not host
    isolation" in docs/CONFIGURATION.md#net_mode; the isolation procedure is
    `secure-sudo contain network` (P1-7). Real NIC/Wi-Fi/VPN hardware
    checks stay in docs/HARDWARE_SMOKE_TEST.md.
  - Test IPv4 and IPv6, multiple interfaces, VPNs, changing DHCP/subnets,
    network namespaces, pre-existing nftables rules, daemon restarts, and
    failed subnet detection for each network mode.
  - Document that blocking raw/packet sockets is not equivalent to isolating
    a host or preventing all network exfiltration; define a separate,
    auditable host-isolation procedure.
  - **Done when:** tests prove rules are scoped to the intended traffic,
    coexist safely with existing firewall policy, and are removed or retained
    according to a documented fail-safe policy when the daemon stops.

## P2 — extend defense-in-depth and monitoring

- [ ] **P2-1: Add measured-boot and executable-integrity integration.**
  - Evaluate TPM-backed measured boot and remote attestation of Secure Boot,
    kernel, initramfs/UKI, and critical policy; document enrollment, verifier
    trust, revocation, and recovery.
  - Evaluate IMA appraisal/EVM, fs-verity, or dm-verity as complementary
    integrity controls rather than reimplementing filesystem integrity in
    every userspace monitor.
  - **Done when:** an operator can verify remotely that the expected boot
    chain and policy are active, or the feature is explicitly deferred with
    its blocker and threat-model rationale.
  - **Progress (2026-11-01):** part 1 is built. `secure-sudo attest quote`
    gives a TPM quote of the boot PCRs bound to a nonce and a host report,
    and `secure-sudo-attest-verify` enrolls hosts and verifies bundles.
    Enrollment, verifier trust, revocation, recovery, and the IMA/EVM,
    fs-verity and dm-verity evaluation are in
    [docs/ATTESTATION.md](docs/ATTESTATION.md). Tested by `test-attest.sh`.
    Part 2 is built too: the LSM logs every accepted knob, list and lock in
    `policy_log` and extends each into PCR 13, with `foreign` markers for
    extends it did not make. The verifier replays the log, so the policy is
    measured, not reported, once locked and with no PCR-extending program
    on `tpm_openers`. Tested by `test-attest.sh` and in-kernel
    `ss-functest` checks against a software TPM. The verifier also replays
    the firmware TPM event log (PCRs 0-9 and 14; names the changed event,
    checks the measured Secure Boot state and command line) and the IMA log
    (PCR 10, `boot_aggregate`, optional reference list), tested against
    logs from a real OVMF + GRUB + Ubuntu 24.04 boot on a software TPM.
    The EK certificate check and credential activation are built too
    (`enroll --ek-ca`, `attest activate`, `secure-sudo-attest-verify
    activate`), for RSA 2048 EKs, tested against a software TPM with a
    manufacturer-style EK certificate. Still to build: activation for
    ECC-only EKs, and fetching intermediate CAs from the certificate's AIA
    URL.

- [ ] **P2-2: Promote add-ons through an explicit maturity gate.**
  - Keep `temporary/` features opt-in until each has automated tests,
    least-privilege service settings, configuration validation, resource
    limits, failure reporting, and documented upgrade/rollback behavior.
  - For ProcGuard, DriverGuard, BootGuard, BiosGuard, PheonixBox, tamperwatch,
    Locus, and the GUI, test malicious inputs, concurrent file replacement,
    symlink/path races, stale or attacker-modified baselines, storage
    exhaustion, and monitor-to-enforce transitions.
  - Protect baseline manifests and recovery copies with an independently
    verified trust source; retain original evidence and hashes when
    quarantining or repairing.
  - **Done when:** each add-on has a published maturity status, threat model,
    test evidence, and operator-approved promotion criteria; none is
    presented as a kernel-guaranteed control while it remains a userspace
    best-effort monitor.

- [ ] **P2-3: Improve alerting and fleet integration.**
  - Define a documented event format and supported integrations for common
    audit/SIEM pipelines, with severity mapping, deduplication, rate limits,
    and alert tests.
  - Ensure notification-command failures are visible and arguments remain
    safely handled; avoid executing user-controlled event text as shell code.
  - **Done when:** a test event can be traced from the kernel through local
    storage to an external alert, with gaps and failures observable.

- [ ] **P2-4: Make boot and firmware assurance stronger.**
  - Evaluate an initramfs-stage BootGuard restore/verification path and test
    recovery with encrypted roots, separate ESPs, and supported bootloaders.
  - Document BiosGuard's actual measurement coverage and limits; investigate
    platform-supported authenticated firmware measurements and event logs.
    Do not attempt generic automatic firmware reflashing.
  - **Done when:** supported claims are backed by platform tests and baseline
    provenance, and the operator has an explicit, safe recovery path.

- [ ] **P2-5: Add maintainable operator-facing visibility.**
  - Keep the GUI loopback-only by default; test authentication, authorization,
    CSRF/DNS rebinding, request-size limits, session handling, and privileged
    actions. Define a supported TLS-proxy deployment only if remote access is
    required.
  - Add accessible, read-only views for timelines, policy changes, event
    loss, and evidence export; do not make destructive action the default UI
    path.
  - **Done when:** the GUI has automated security tests and its displayed
    status agrees with the CLI and kernel state.

## P3 — sustain support and trust

- [ ] **P3-1: Publish a compatibility and release-support matrix.**
  - Track supported kernel releases, distro versions, architectures, boot
    methods, compiler versions, and required kernel options; identify tested
    versus merely expected combinations.
  - **Done when:** every release has an updated matrix and end-of-support
    policy.

- [ ] **P3-2: Keep documentation and evidence synchronized.**
  - Re-run STIG/CIS scans on supported target systems (not only containers),
    label environment-specific results and dates, and retain failures and
    skipped rules transparently.
  - Reconcile feature maps, configuration references, systemd units,
    installer behavior, and claims about logging transports against the
    tested release.
  - Track every OpenSCAP item in [OSCAP_BUGS.md](docs/OSCAP_BUGS.md) through
    a rule-ID-based acceptance matrix:
    - **STIG release gate:** run in an Ubuntu VM/host capable of evaluating
      systemd, AppArmor, GRUB, and filesystem controls. The sole permitted
      failure is `encrypt_partitions` (OSB-12) only when the test environment
      cannot validate encryption; all other evaluated rules must pass and
      there must be zero errors or unknown results. Container AppArmor errors
      are not accepted as release results. The three OSB-14 manual-review
      controls must be explicitly reviewed before claiming site compliance;
      `notchecked` is never represented as `pass`.
    - **Encrypted-host follow-up:** validate `encrypt_partitions` on a
      genuinely encrypted target when available; do not turn the temporary
      test-environment exception into a product-wide waiver.
    - **CIS Level 2 gate:** remove the blanket firewall `--skip-rules`
      workaround (OSB-16) by defining and testing an explicit ownership and
      compatibility model for CIS nftables controls and secure_sudo network
      modes. Provision the VM with the filesystems and init needed to evaluate
      its partition, AppArmor, `/dev/shm`, and firewall rules. All evaluated
      rules must pass with zero errors/unknowns; no rule may be omitted from
      remediation merely to improve the score. Any approved exception needs
      a rule-specific security rationale, owner, and compensating-control
      test, and must not be presented as a passing result.
    - Resolve or classify CIS's remaining AppArmor/GRUB (OSB-13/15),
      stacked `/dev/shm` mount (OSB-17), partition, and firewall-service
      unknown (OSB-02) results on an appropriate VM/host. Container-only
      behavior must be labelled as such and must not mask target-host
      failures.
  - Keep OSB-03..07 and OSB-15..18 regression tests: deliberately recreate
    each reproducible bug, run the relevant patch/remediation, and assert the
    exact expected rule result. Add tests for package-install permission
    drift, profile selection, skip-rule matching/recording, and final summary
    parsing so the report cannot silently omit a failed or unknown rule.
  - Make remediation idempotent and conflict-aware: scan before and after,
    preserve backups, verify each modified setting, avoid fighting existing
    firewall/AppArmor policy, and clearly report skipped, unsupported, or
    conflicting fixes rather than counting them as successful remediation.
  - **Done when:** documentation changes are part of release review and
    published results are reproducible from documented commands and inputs;
    the STIG release gate has no failure except the single named
    `encrypt_partitions` environment exception, and the CIS gate has no
    unexplained conflict, failure, error, unknown, or skipped security
    control.

- [ ] **P3-3: Establish maintenance and disclosure processes.**
  - Document supported reporting channels, security-fix release process,
    kernel API/LTS tracking, dependency updates, vulnerability triage, and
    deprecation policy.
  - **Done when:** maintainers can respond to a kernel regression or
    vulnerability with a tracked, testable release process.

## Doc promises to build

Pheonix's rule (2026-11-01): when a doc promises more than the code does,
that is a missing feature to build, not a sentence to delete. Each doc says
"not built yet" until the feature lands. Found while writing
[docs/THREAT_MODEL.md §7](docs/THREAT_MODEL.md#7-promises-not-yet-kept-work-to-build).

- [x] **G1: Node SEA auto-detection** (FEATURE_MAP #11). Built 2026-11-01:
  `secure-sudo node-scan`, run by secure-sudod; tested by
  `tests/userspace/test-node-scan.sh` and the Ubuntu VM run. Find Node single-
  executable (and pkg) binaries by their fuse marker in configured
  directories, at `load` and on a timer, and register them in
  `node_sea_binaries`. **Done when:** a test SEA binary is found and
  registered and the Node guard applies to it without manual listing.
- [x] **G2: TimeVault Merkle tree** (FEATURE_MAP #13). Built 2026-11-01
  (SECURITY_REVIEW #60): RFC 6962 root over the baseline manifest, logged and
  forwarded; `evidence-verify --timevault`; tested by
  `tests/userspace/test-daemon-events.sh` and `test-evidence-export.sh`.
  Build a Merkle tree
  over the manifest; log and forward its root each scan. **Done when:** a
  collector can tell a rewritten manifest from a legitimate rescan, and a
  test proves a changed entry changes the root.
- [x] **G3: TPM2-sealed OTP secret** (FEATURE_MAP #15). Built 2026-11-01
  (SECURITY_REVIEW #61): `systemd-creds` seals the master key, key file
  without a TPM; tested by `tests/userspace/test-otp.sh` (two software TPMs,
  required in CI) and the Ubuntu VM run (VM_TPM=1). Seal the OTP key to
  the TPM when one is present, root-only key file as the fallback.
  **Done when:** the OTP verifies with a sealed key in a swtpm VM and falls
  back cleanly without a TPM.
- [x] **G4: TPM clear through `/dev/tpm*`** (README #5). Built 2026-11-01
  (SECURITY_REVIEW #63), both halves as Pheonix chose: the `tpm_openers`
  guard once locked (in-kernel tests) and `install.sh tpm-lockout`
  (test-install, Ubuntu VM with a software TPM). Only the PPI route
  is blocked; an LSM cannot read TPM command bytes. Needs Pheonix's call on
  the approach (lockout authorization at install, an opener allowlist for
  `/dev/tpm*`, or both).

Built during P1-5 because the docs already promised them: blacklist copies
(#2), module-name checks (#6, #19), and events for five silent controls
(SECURITY_REVIEW #54, #56).

## Suggested execution order

1. P0-4 (source provenance), P0-1 (build gate), and P0-2 (tests).
2. P0-3 (boot proof), P0-5 (safe installation/recovery), and P0-6 (policy
   validation).
3. P1-1 through P1-4 (complete, trustworthy event and evidence pipeline).
4. P1-5 through P1-8 (threat model, operational controls, and response).
5. P2 and P3 items as the validated release baseline grows.

Do not enable irreversible locks, broad allowlist enforcement, or automatic
quarantine/repair on production systems as a substitute for completing the
relevant tests and recovery work above.
