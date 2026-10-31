# secure_sudo incident evidence

This procedure preserves secure_sudo logs during an active investigation,
exports an integrity-checkable bundle, and records its custody. The export can
contain sensitive host and user metadata; restrict access accordingly.

## Preserve and export

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

## Tabletop exercise

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
5. Remove the hold, verify health reports `active`, and confirm the daemon
   resumes normal retention on a disposable log set.

Record participants, observed results, gaps, and corrective actions in the
incident record. This procedure is not evidence that an exercise has already
been completed.
