# secure_sudo — PheonixBox (#21), in depth

PheonixBox protects a chosen set of files and directories against tampering
**at runtime** and repairs them automatically: if a protected file is
overwritten, truncated, or deleted, PheonixBox puts the exact original bytes
back and re-locks the file read-only. It is a toggle — turn it on to protect,
off to return the box to exactly its prior state.

---

## 1. The honest design — read this first

The feature was asked for as *"a SHA-based tamper check with a two-way digest
that compresses the original contents into a hash, so it's reversible without a
password."*

**A SHA-256 hash cannot be reversed.** It is a one-way, fixed-size (32-byte)
digest: the original file is not inside it and cannot be recovered from it, with
or without a password. That is the whole point of a cryptographic hash, and no
implementation can change it. Anything that claims to "decompress a hash back
into the file" is not a hash — it is ordinary compression wearing the word.

So PheonixBox delivers what was actually wanted — *detect tampering and restore
the original without a password* — with the two mechanisms that genuinely do
that job:

| Part | What it is | What it's for |
|------|-----------|---------------|
| **Integrity manifest** | the SHA-256 digest of each protected file | **detection** — cheap, tiny; says *"this file changed"* |
| **Snapshot store** | the real original bytes, zlib/DEFLATE-compressed, root-only | **restoration** — reversible, needs no key; says *"here is what it should be"* |

Compression (zlib) *is* reversible and needs no password — that is the
"reversible without a password" part, done correctly. Hashing is what makes
detection fast. **The hash never restores anything; the compressed snapshot
store does.** Keep that distinction in mind and the rest of this document is
straightforward.

## 2. What it does, step by step

### Enable — `secure-sudo pheonixbox on`

1. **Snapshot.** Every protected file is read and two things are stored: its
   SHA-256 in the manifest, and its original bytes (zlib-compressed) in the
   snapshot store.
2. **PermissionsSnapshot.** Each file's owner, group, and mode go into the
   manifest line, and its POSIX ACLs are captured alongside (via `getfacl`, if
   present). This is what lets disable put permissions back *exactly*.
3. **Read-only lock.** Every protected file has its write bits stripped
   (`chmod a-w`), so even root must deliberately re-add write to touch one.
4. **Scanning begins.** The daemon runs `pheonixbox scan` on a timer (every
   ~30 s). Each scan re-hashes every protected file; on any mismatch, missing
   file, or re-added write bit it repairs or re-locks immediately.

### Disable — `secure-sudo pheonixbox off`

Scanning stops and every file's **original owner, group, mode, and ACLs are
restored from the PermissionsSnapshot**, undoing the read-only lock. The box
returns to exactly the permission state it had before PheonixBox was enabled.

### Snapshot (while off) — `secure-sudo pheonixbox snapshot`

Re-captures current contents, hashes, and permissions as the new "known good"
baseline. Run this after you have *legitimately* changed a protected file (a
real update) so the new version becomes what repairs restore to. It is refused
while enabled — snapshotting the already-locked state would be meaningless.

## 3. What gets protected

Configured in `/etc/secure_sudo/pheonixbox.conf`, one absolute path per line.
A line may name a single **file** or a **directory**, and a directory is walked
recursively (depth ≤ 24) — every *regular file* beneath it is protected.
Symlinks, device nodes, FIFOs, and sockets are ignored. Paths containing a
space or tab are skipped with a warning, because the line-based manifest cannot
represent them unambiguously.

## 4. The store

Everything lives under `/var/lib/secure_sudo/pheonixbox`, mode `0700`, root-only
(so no non-root user can read the original contents or forge a replacement):

| Path | Contents |
|------|----------|
| `enabled` | present ⇒ protection is ON |
| `manifest` | one line per file: `<content-sha256> <mode-octal> <uid> <gid> <abspath>`, plus `acl <acl-file-sha256> <abspath>` for each captured ACL file |
| `manifest.sig` | Ed25519 signature over `manifest` by the operator's key (`trust = signed`) |
| `blobs/<path-sha256>.z` | the file's original bytes, zlib-compressed, with an 8-byte little-endian length header |
| `acls/<path-sha256>.acl` | the file's `getfacl` output, if ACL tools are present |
| `lastscan` | timestamp + tally of the last scan (checked, repaired, unrepaired) |
| `trust` | the trust mode the last scan ran with (to notice it being lowered) |
| `reported/<path-sha256>` | how an unrepaired file was last reported, so each change is reported once |

Blob and ACL filenames are the SHA-256 of the file's **absolute path**, which
gives a slash-free, collision-free name per file.

## 5. How repair works

On each scan, for every manifest entry:

* **missing** (lstat fails) → restore from the snapshot blob;
* **no longer a regular file** (a symlink, even to identical bytes) → restore;
* **content changed** (SHA-256 differs) → restore from the snapshot blob;
* **content fine but a write bit re-appeared** → re-strip write bits (re-lock);
* **unchanged** → nothing.

Before a restore, what is there now is kept as evidence: a compressed copy in
`/var/lib/secure_sudo/pheonixbox/evidence/` and a CRITICAL syslog line with
its SHA-256, size, owner, mode and mtime (for a symlink: where it pointed). If
that copy cannot be kept (a full disk), the file is **not** repaired and the
log says so.

A restore decompresses the blob and uses it only if its SHA-256 is the one in
the manifest (a swapped blob is refused). It writes a new file next to the
target with the captured owner and the read-only mode, `fsync`s it, and
renames it over the target, so a symlink planted at the path is replaced and
never written through. A file is never left writable after a repair.

The snapshot records, for each file, the hash of exactly the bytes it stored,
and refuses to replace the previous snapshot if any file could not be stored
in full. Manifest lines whose path is not a plain absolute path (whitespace,
control characters, `.` or `..` components) are ignored and logged.

### Snapshot trust (signed snapshots)

Every blob and every ACL file is used only if its SHA-256 is the one in the
manifest, so the manifest is the one thing that has to be trusted. By default
(`trust = local`) PheonixBox trusts the host's own manifest. Root on the host
could then rewrite a protected file, its blob and the manifest together, and
the next scan would "repair" to the attacker's version.

With this line in `/etc/secure_sudo/pheonixbox.conf`:

```
trust = signed
```

PheonixBox repairs only while `manifest.sig` is a valid Ed25519 signature
over the manifest by the operator's key. The public half lives at
`/etc/secure_sudo/addons/baseline-signing.pub`. It is the same key the
`temporary/` add-ons use for their baselines (docs/ADDONS.md "Baseline trust
and evidence"), so one key signs every baseline on the host. The key file must
be root-owned and writable only by root. The private key never has to be on
the host: copy the manifest off, or sign from removable media.

```sh
sudo secure-sudo pheonixbox on            # or `snapshot`: prints the manifest's sha256
# on the signing machine, after checking that sha256:
openssl pkeyutl -sign -rawin -inkey KEY.pem \
    -in /var/lib/secure_sudo/pheonixbox/manifest \
    -out /var/lib/secure_sudo/pheonixbox/manifest.sig
sudo secure-sudo pheonixbox status        # "snapshot trust: signed - signature valid"
```

While the snapshot is not trusted (it is unsigned, edited after signing, the
signature does not verify, or the key is missing or unsafe):

* each scan still finds tampering, keeps the evidence and logs it CRITICAL
  (`TAMPERED, NOT repaired`), but **writes nothing back**. Each change is
  reported and copied once, not every 30 seconds;
* `off` unlocks the files (gives back the owner write bit the lock took) but
  does **not** apply the manifest's owners, modes or ACLs, because an edited
  manifest could name setuid root;
* "snapshot NOT TRUSTED" is logged CRITICAL at most every 10 minutes.

Every new snapshot deletes the old signature and logs CRITICAL its file
count, the manifest's SHA-256 and the signing key's fingerprint. A scan that
finds `trust` lowered from `signed` to `local` logs that CRITICAL too. Both
are on record off-box, so neither can be done quietly. ACL files captured
before this release have no hash in the manifest and are not applied until
the next snapshot.

### Checking the configuration

`secure-sudo pheonixbox check-config` checks `/etc/secure_sudo/pheonixbox.conf`
strictly: root-owned and not group/world writable; each line blank, a `#`
comment, one `trust = local|signed` (`signed` needs a usable key), or one
absolute path without whitespace, control characters or
`.`/`..`, listed once (a path that does not exist yet is a note). `on` and
`snapshot` refuse to run (exit 78) while it has an error; `add`, `remove`,
`list`, `status` and `scan` still work.

## 6. Commands

All are root-only.

```sh
sudo secure-sudo pheonixbox add /etc/ssh/sshd_config   # protect a file
sudo secure-sudo pheonixbox add /usr/local/bin         # protect a dir (recursive)
sudo secure-sudo pheonixbox list                       # show protected paths
sudo secure-sudo pheonixbox on                         # snapshot + lock + scan
sudo secure-sudo pheonixbox status                     # on/off, entries, snapshot trust, last scan
sudo secure-sudo pheonixbox scan                       # scan+repair now (daemon does this on a timer)
sudo secure-sudo pheonixbox off                        # restore permissions, stop
sudo secure-sudo pheonixbox snapshot                   # (while off) re-baseline after a real update
sudo secure-sudo pheonixbox remove /usr/local/bin      # stop protecting a path
sudo secure-sudo pheonixbox check-config               # check the path list strictly
```

`secure-sudo pheonixbox …` simply hands off to the `secure-sudo-pheonixbox`
helper (installed at `/usr/bin/secure-sudo-pheonixbox`), exactly as
`secure-sudo otp …` hands off to its helper.

## 7. Updating a protected file legitimately

Because protected files are read-only and auto-repaired, a real update is a
deliberate three-step:

```sh
sudo secure-sudo pheonixbox off          # unlock + stop repairing
# ... apply your update (edit the config, upgrade the binary) ...
sudo secure-sudo pheonixbox on           # re-snapshot the new version + re-lock
```

(or `off`, edit, `snapshot`, `on` — equivalent). Until you re-snapshot, the old
version is what repairs restore to, by design.

## 8. Limitations (honest)

* **Not a hash reversal.** As section 1 says, restoration is from the stored
  compressed originals, not from the hashes. If the snapshot store is deleted,
  there is nothing to restore from — keep `/var/lib/secure_sudo` on protected
  storage, and consider putting the store itself under TimeVault/BinaryVault.
* **Snapshot size.** The store holds a compressed copy of every protected
  file, so do not point it at huge data trees; it is meant for configs,
  binaries, scripts, and keys. Files over 256 MB are skipped.
* **Userspace + periodic.** PheonixBox repairs on a timer (default ~30 s), so a
  tamper is corrected within one scan interval, not instantaneously. For
  *inline, kernel-enforced* immutability of executables use **BinaryVault
  (#17)**; for *exec-time hash allowlisting* use **TimeVault (#13)**. PheonixBox
  complements them by covering arbitrary files (configs, keys) and by actively
  *restoring* content rather than only blocking writes.
* **ACLs are best-effort.** Capture/restore uses `getfacl`/`setfacl`; on a
  system without them, the owner/group/mode from the manifest are still
  restored. A captured ACL file is applied only if its hash matches the
  manifest's.
* **Trust is only as strong as the mode.** With `trust = local` the snapshot is
  the host's own copy (see "Snapshot trust"). With `trust = signed`, root can
  still edit the config back to `local`, but not silently: that change is
  logged CRITICAL.

## 9. Relationship to the other anti-tamper layers

| Feature | Scope | Mechanism | When |
|---------|-------|-----------|------|
| **BinaryVault (#17)** | all executables + libraries | kernel *blocks* any write | inline, always |
| **TimeVault (#13)** | exec allowlist | kernel *refuses exec* unless hash matches | at exec |
| **PheonixBox (#21)** | any chosen files/dirs | userspace *restores* original from snapshot | on a timer |

They stack: BinaryVault/TimeVault stop tampering with code; PheonixBox watches
the files *you* nominate (including non-executable ones) and heals them.
