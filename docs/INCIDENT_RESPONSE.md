# secure_sudo incident response

This is the runbook for a suspected compromise of a host running secure_sudo
(TODO P1-7). It covers triage, evidence, containment, escalation, recovery
and rebuild, and lists every action secure_sudo can take on its own that
kills, deletes, restores or quarantines something (section 8). It assumes the
threat model in [THREAT_MODEL.md](THREAT_MODEL.md); in particular, root
before the lock and a compromised kernel are out of scope, so section 5 says
when to stop trusting the host.

Two rules run through all of it:

* **Evidence before action.** Export (section 3) before you contain, and
  contain with the reversible step (freeze, isolate) before the destructive
  one (kill, delete, rebuild). `secure-sudo contain` saves process evidence
  itself before it stops anything.
* **Look before you change.** Every containment command has `--dry-run`, and
  without `-y` it shows its plan and asks for `yes`. Every action that ran is
  in `secure-sudo history`.

The export can contain sensitive host and user metadata; restrict access to
it.

## 1. Roles and first five minutes

* **Incident owner** decides containment, escalation and release.
* **Responder** runs the commands (needs root through sudo, from a session
  that stays open: keep a second root session, RECOVERY.md).
* **Evidence custodian** receives and verifies exports on another machine.

First five minutes:

1. Open a case record: UTC time, host, boot id (`cat
   /proc/sys/kernel/random/boot_id`), who is acting, why.
2. Start the retention hold (section 3, step 1) so no log is aged out.
3. Do not reboot and do not run `secure-sudo load` yet: a reboot loses the
   live state and unlocks the config; a load changes it.

## 2. Triage

Read-only; none of these change anything.

| Question | Command | Look for |
|---|---|---|
| Is secure_sudo running and enforcing? | `sudo secure-sudo health --json` | `"overall":"ok"`, the LSM active, `last_load` complete, no `events_dropped`, `remote_state` |
| What does the kernel enforce right now? | `sudo secure-sudo status`, `sudo secure-sudo diff` | a policy that differs from `/etc/secure_sudo` (diff not 0), `lock` |
| Who changed policy, and when? | `sudo secure-sudo history -n 50` and `history --verify` | changes nobody on the team made; a broken chain |
| What did it deny? | `sudo grep -h '"decision":"deny"' /var/log/secure_sudo/*.log \| tail -50` | `setid`, `blacklist`, `timevault`, `tpm_guard`, `prguard`, `home_write` events, their `actor` |
| Has a protected file changed? | `sudo secure-sudo pheonixbox status`, the add-on logs in `/var/log/secure_sudo/addons/` | tamper, repair, `CRITICAL` lines |
| Is anything already contained? | `sudo secure-sudo contain status` | |
| Who is logged in, what runs? | `who`, `loginctl list-sessions`, `ps -eo pid,ppid,user,lstart,args --forest`, `ss -tunap` | unknown sessions, processes from `/tmp`, `/dev/shm`, deleted executables |

If the logs or the history chain fail their checks (`evidence-verify`,
`history --verify`), treat local records as untrusted and work from the
collector's copy (section 3, step 4).

## 3. Preserve evidence

1. Keep a root session open and create the retention-hold marker:

   ```sh
   sudo install -o root -g root -m 0600 /dev/null \
     /var/lib/secure_sudo/retention.hold
   sudo secure-sudo health --json
   ```

   After the daemon's next retention and heartbeat cycles (within ten
   seconds), health must report `"retention_state":"held"`. While held, the
   daemon does not delete old logs or trim logs to the configured size cap. A
   present but non-regular, incorrectly owned, or incorrectly permissioned
   marker (or an error inspecting it) is treated as a retention error; logs are
   preserved and health reports `hold_error`. If the marker is absent, normal
   retention is active.

2. Record the UTC time, host identity, boot ID, operator, incident/case ID,
   and clock-synchronization status. Do not adjust the system clock during
   collection; record any known offset separately.
3. Export to a new root-owned directory with mode `0700`. If signing, use the
   organization's controlled Ed25519 key on protected removable media, not a
   key copied into the evidence bundle:

   ```sh
   sudo install -d -o root -g root -m 0700 \
     /var/lib/secure_sudo/incidents/CASE-123
   sudo secure-sudo evidence-export \
     /var/lib/secure_sudo/incidents/CASE-123/evidence.tar.gz \
     --signing-key /mnt/controlled-key/incident-ed25519.pem
   ```

   The exporter requires a root-owned key that is not group/world-readable.
   The key is read on the monitored host while exporting; this is not an
   offline-signing workflow. Unmount protected media as soon as the export
   completes. Keep the public key and its fingerprint in a separate trusted
   system. For rotation, generate the next key on a controlled workstation,
   authenticate its fingerprint out of band, use it for new exports, and
   retain prior public keys until all bundles signed by them have passed the
   organization's evidence-retention period.
4. Transfer the archive and a separately authenticated public-key fingerprint
   to the evidence custodian. Verify on a separate trusted machine:

   ```sh
   secure-sudo evidence-verify evidence.tar.gz \
     --trusted-key incident-ed25519.pub
   sha256sum evidence.tar.gz
   ```

   If the host forwards to a remote collector, also check the bundle against
   the collector's copy of the `log_checkpoint` records. They are the
   tamper-evidence anchor that never lived on the monitored host:

   ```sh
   grep log_checkpoint /var/log/remote/HOST/secure_sudo.log > checkpoints.txt
   secure-sudo evidence-verify evidence.tar.gz --checkpoints checkpoints.txt
   ```

   Lines up to the last matching checkpoint are anchored. Lines after it
   (at most 5 minutes' worth, plus any collector outage) rest on the host's
   word alone. A host-side `log_modified` record means the daemon saw its
   log change underneath it.

   Record the archive SHA-256, transfer time, sender, recipient, storage
   location, verification result, and any custody transfer. Never rely on the
   public key embedded in the bundle as proof of signer identity.
5. Keep the hold active while the incident remains open. Monitor free space:
   retention holds intentionally bypass both age and size deletion limits.
   Make additional exports to separate, access-controlled destinations when
   required by the incident plan. After the custodian confirms a verified
   copy and the incident owner authorizes release, remove the marker and
   confirm health returns to `"retention_state":"active"`:

   ```sh
   sudo rm -- /var/lib/secure_sudo/retention.hold
   sudo secure-sudo health --json
   ```

The hold protects only files in `/var/log/secure_sudo` from the daemon's
retention deletion. It does not prevent disk failure, administrator deletion,
or other system cleanup. The export preserves its source evidence, but it does
not freeze the log files against new appends.

## 4. Contain

Pick the smallest step that stops the harm. Each one has `--dry-run`, asks
for `yes` without `-y`, is recorded in `secure-sudo history`, and has an
undo. `secure-sudo contain status` lists what is in effect.

| Step | Command | What it does | Undo |
|---|---|---|---|
| Network isolation | `sudo secure-sudo contain network [--allow ADDR]...` | one nftables table drops all traffic except loopback, `--allow` addresses, **your SSH client** (found from `SSH_CONNECTION` or `who -m`) and the `remote_syslog` collector (so evidence still leaves the box; `--no-collector` drops it too). Separate from `net_mode`'s table. | `contain release network` |
| Account | `sudo secure-sudo contain account USER [--terminate]` | locks the password, expires the account (blocks SSH keys and new logins) and **freezes** (SIGSTOP) every process of the user after saving the list; `--terminate` kills them instead. Refuses UID 0 and your own account. | `contain release account USER`: the expiry and lock go back to what they were; frozen processes continue |
| Process | `sudo secure-sudo contain process PID [--kill]` | freezes the process and its descendants, then saves `cmdline`, `environ`, `status`, `maps`, open files, sockets, a copy of the executable and its SHA-256 under `/var/lib/secure_sudo/contain/`; `--kill` kills them after that. Refuses PID 1, kernel threads and your own shell chain. | `contain release process PID` (not after `--kill`) |
| Freeze policy | `sudo secure-sudo lock` | the kernel refuses every policy change, module load, kexec and hibernation until reboot. `lock` warns first when the running policy differs from the files. | reboot only |
| Executable allowlist | `sudo secure-sudo timevault on` | only allowlisted, hash-matching programs run from the watched trees; also locks the config. Test the allowlist first (`vault-allow`), or the box may stop working. | reboot only |

Order of preference: network isolation for an active attacker with a
remote channel; account containment for a stolen or misused login; process
containment for one bad program; lock to stop policy tampering. Freeze
first, kill later: a frozen process keeps its memory and connections for
analysis and can still be killed.

Remote responders: check that the dry run says `keeping your SSH client ...
reachable`. If it warns that no SSH client was found, pass `--allow
YOUR_ADDRESS`, or you cut yourself off. Console or out-of-band access is
the fallback.

## 5. Escalate

Escalate to the incident owner and, by your organisation's plan, to the
security team when any of these hold. They also mean: stop trusting the
host and plan a rebuild (section 7).

* evidence of root or kernel compromise: an unexpected kernel module load
  (`lock_modules` off), `install.sh verify` reporting a changed kernel or
  LSM file, the secure_sudo LSM missing from `/sys/kernel/security/lsm`, a
  history or log chain that does not verify;
* BootGuard or BiosGuard tamper alerts (the boot chain is in doubt);
* containment actions that did not take (`contain status` disagrees, `diff`
  shows a policy nobody loaded);
* credential exposure: SSH keys, the OTP secret, the TPM lockout password,
  signing keys.

Give the owner the case record, the export's SHA-256 and verification
result, and `secure-sudo history -n 50`.

## 6. Recover (the host stays)

Only when the owner decides the host is trustworthy:

1. Export again (section 3), so the record covers the containment period.
2. Release containment in reverse order: `contain release process PID`,
   `contain release account USER`, `contain release network`. Check
   `contain status` says `nothing contained`.
3. Return policy to a known-good state: `secure-sudo history` shows the
   snapshot before the suspect change, `secure-sudo restore ID` puts it back
   (RECOVERY.md 4g). If the config was locked, reboot first.
4. Verify: `secure-sudo diff` reports 0 changes, `secure-sudo health` is
   `ok`, `install.sh verify` passes, the add-ons' `status` shows no tamper.
5. Rotate what the attacker could have seen: passwords and SSH keys of
   contained accounts, `secure-sudo otp reset` for OTP users, the TPM
   lockout password if it could have been seen (`tpm2_changeauth -c lockout
   -p OLD NEW`), and the remote syslog and signing keys if root was reached.
6. Remove the retention hold once the custodian has a verified copy.

## 7. Rebuild

Rebuild when section 5 applies. Do not try to clean a host where root or
the kernel was reached.

1. Export evidence and confirm the custodian verified it (section 3). Keep
   the disk image if your plan requires it.
2. Reinstall the OS from trusted media; do not reuse `/boot`, kernels or
   binaries from the old host.
3. Build and install secure_sudo from a verified checkout: `install.sh`
   checks the kernel source signature; `install.sh verify` checks the
   result.
4. Bring the configuration back from a reviewed snapshot: copy
   `snapshots/ID/disk/*` from the export, read them (an attacker may have
   edited them before the snapshot), `secure-sudo lint`, `secure-sudo load`.
5. New secrets: SSH host keys, OTP (`otp setup`), TPM lockout password
   (`install.sh tpm-lockout` on a cleared TPM), signing keys.
6. Re-baseline the add-ons on the clean system (`bootguard baseline`,
   `driverguard baseline`, PheonixBox `snapshot`), then `secure-sudo lock`.

## 8. What secure_sudo does on its own

Every automatic action that kills, deletes, restores, quarantines or locks,
with what a false positive costs, how to exclude something, where it is
recorded, how to undo it and what tests it. Defaults are in bold.
"Monitor" modes report what they would do without doing it: start there,
and only switch to enforcement after the exclusions are right (TODO caution:
enforcement is not a substitute for the tests and recovery work).

| Action | When | False positive costs | Exclude with | Recorded in | Undo | Tested by |
|---|---|---|---|---|---|---|
| TimeVault **quarantine** (or `wipe`) of a new or changed file, or a blocked binary | only while TimeVault is engaged (by hand), `vault_action` | a legitimate file is moved out of `vault_watch`; the program using it breaks | `timevault_allow.conf` (`vault-allow`), `vault_watch`, `timevault_allow_autoupdate` | daemon log (`timevault_*`), the quarantine sidecar (origin, hash) | quarantine: unzip from `/var/lib/secure_sudo/quarantine/` to the recorded origin. **wipe: none** | test-helpers (quarantine.sh), test-daemon-events (first scan is a baseline, #60), ss-functest TimeVault |
| RAM guard drops page/slab caches | `ram_spike_enabled`, use above `max_ram_percent` | a burst of slow I/O while caches refill; no data loss | the threshold, `drop_cooldown_ms` | `ram_guard` event | nothing to undo | ss-functest |
| sudo cooldown blocks sudo | `sudo_cooldown_enabled`, `sudo_max_fails` failures in `sudo_window_sec` | an admin who mistypes is locked out of sudo for `sudo_block_time_sec` | thresholds | `cooldown` event | wait out `sudo_block_time_sec`, or from an open root session `secure-sudo set sudo_cooldown_enabled 0` | ss-functest |
| Config lock / TimeVault engage | only by hand (`lock`, `timevault on`) | policy cannot be fixed until reboot | | history (`lock`, `timevault`) with a snapshot | reboot | test-cli (history), ss-functest |
| PheonixBox **repair** of a protected file | `pheonixbox on`, every scan | a legitimate edit is reverted to the snapshot | `pheonixbox snapshot` after a real update; `pheonixbox remove` | PheonixBox log | the reverted content is in the tamper log; `pheonixbox off`, edit, `snapshot` | test-pheonixbox |
| ProcGuard kills a process not on its allowlist; quarantines and (`remove_on_infection`) deletes its file after `respawn_threshold` kills | **`mode = monitor`**: nothing killed | a needed program is killed, its executable removed | `procguard_allow.conf`; never kills the secure_sudo stack; refuses to run with an empty allowlist | `addons/procguard.log` (shipped off-box if configured) | restore the executable from the compressed sample in the quarantine | **not yet** (P1-7 guardrail tests) |
| TamperWatch kills the writer of a protected file and quarantines its executable | **`mode = log`** | an updater or admin tool is killed | the PheonixBox set, `tamperwatch.conf` | `addons/tamperwatch.log` | restore from its quarantine | **not yet** |
| DriverGuard restores a changed module from backup | **`mode = monitor`** | a module updated by the distro is rolled back | `driverguard baseline` after a kernel update | `addons/driverguard.log` | `driverguard baseline` and reinstall the package | **not yet** |
| BootGuard stages a restore of changed `/boot` files, applied at next boot | **`mode = enforce`** | a kernel update's new initramfs or GRUB config is rolled back at the next boot: a kernel without its initramfs may not boot | `bootguard baseline` after every kernel update | `addons/bootguard.log` | boot the previous kernel (RECOVERY.md 1), `bootguard baseline` | **not yet** |
| `contain` (network, account, process) | only by hand | see section 4 | | history (`contain`, `release`), `/var/lib/secure_sudo/contain/` | `contain release ...` | test-contain, test-cli |

The rows marked "not yet" are the remaining P1-7 work: guardrail tests for
the add-ons, and BootGuard and DriverGuard re-baselining after a package
update so a kernel update is not treated as tampering.

## 9. Tabletop exercise

Run this with the incident responder, system owner, evidence custodian, and a
second machine available for verification. Use a disposable VM and a
non-production signing key.

1. Generate a test denial event and confirm it appears in the local log.
2. Enable the retention hold and verify health reports `held`.
3. Export and sign a bundle; verify it on the second machine using a public
   key whose fingerprint was communicated separately.
4. Confirm a modified copy fails verification, while the original still
   verifies. With a collector, edit one line of a local log that is older
   than the last checkpoint, export again, and confirm `--checkpoints`
   reports the change. Record timestamps, hashes, custody transfers, and any clock
   offset.
5. Containment: on the VM, start a `sleep` as a test user, then run
   `contain process PID --dry-run`, `contain process PID`, check its
   evidence directory and `contain release process PID`; `contain account
   USER` and its release; `contain network --dry-run` from an SSH session
   and confirm your client address is kept, then `contain network` and
   `contain release network` from the console. Check each action is in
   `secure-sudo history`.
6. Policy: make a change, `secure-sudo diff`, `load`, then `restore` the
   snapshot from before it and confirm `diff` reports 0 changes.
7. Remove the hold, verify health reports `active`, and confirm the daemon
   resumes normal retention on a disposable log set.

Record participants, observed results, gaps, and corrective actions in the
incident record. This procedure is not evidence that an exercise has already
been completed.
