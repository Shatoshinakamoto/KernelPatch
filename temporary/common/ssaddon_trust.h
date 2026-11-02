/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ssaddon_trust - baseline trust and evidence for the temporary/ add-ons
 * (TODO P2-2 part 2).
 *
 * A guard that repairs from a baseline is only as trustworthy as that
 * baseline. Three things are added here:
 *
 *  1. An independent trust source for the baseline manifests. With
 *     `baseline_trust = signed` a guard acts on its manifest only when
 *     MANIFEST.sig is a valid Ed25519 signature over it by the operator's key,
 *     whose public half is SSADDON_SIGNING_KEY. The private key never has to
 *     be on the host: sign on another machine (or from removable media) with
 *         openssl pkeyutl -sign -rawin -inkey KEY.pem -in manifest -out manifest.sig
 *     A new baseline (`baseline`, a package-hook `refresh`) is unsigned until
 *     the operator signs it, and until then the guard reports but never
 *     repairs. `local` (the default) trusts the host's own copy, as before.
 *     Either way, every new baseline's SHA-256 (and the signing key's
 *     fingerprint) is logged CRITICAL, so it is on record off-box.
 *
 *  2. Recovery copies verified against the baseline: a restore is written to
 *     a temporary file next to the target, its SHA-256 must equal the
 *     manifest's, the target's owner and mode are kept, and only then is it
 *     renamed into place. A swapped or corrupted backup is refused.
 *
 *  3. Evidence: before a guard overwrites, removes or quarantines a file, the
 *     original bytes are kept compressed and a JSON record (path, SHA-256,
 *     expected SHA-256, size, mode, owner, times, sample) is appended to
 *     SSADDON_EVIDENCE_ROOT/<feature>.jsonl and logged CRITICAL.
 */
#ifndef SSADDON_TRUST_H
#define SSADDON_TRUST_H

#include <stddef.h>

#ifndef SSADDON_SIGNING_KEY
#define SSADDON_SIGNING_KEY	"/etc/secure_sudo/addons/baseline-signing.pub"
#endif
#ifndef SSADDON_EVIDENCE_ROOT
#define SSADDON_EVIDENCE_ROOT	"/var/lib/secure_sudo/addons/evidence"
#endif

enum sst_mode { SST_LOCAL = 0, SST_SIGNED = 1 };

/* The choices for a `baseline_trust` key (ssaddon_conf SSC_ENUM). */
extern const char *const sst_modes[];

/* SHA-256 of a file as 64 hex characters. 0 on success. */
int sst_sha256_file(const char *path, char out[65]);

/* May the guard act on @manifest? SST_LOCAL: yes if it exists. SST_SIGNED:
 * only with a valid signature in "<manifest>.sig" by SSADDON_SIGNING_KEY
 * (root-owned, not group/world writable). 1 = trusted; 0 = not, with the
 * reason in @why. */
int sst_manifest_trusted(const char *manifest, int mode, char *why, size_t n);

/* After writing a new baseline: remove its now stale signature and log the
 * manifest's SHA-256, file count and the key fingerprint, CRITICAL. */
void sst_announce(const char *feature, const char *manifest, const char *reason,
		  int mode);

/* Short description of the trust state for `status`. */
void sst_describe(const char *manifest, int mode, char *out, size_t n);

/* Restore @blob (ssaddon_store format) over @dst only if its bytes hash to
 * @expect_sha: via "<dst>.ss-restore" in the same directory, keeping dst's
 * owner and mode (0644 if dst is gone), fsync, rename. 0 on success, else -1
 * with the reason in @why. */
int sst_restore_verified(const char *blob, const char *dst, const char *expect_sha,
			 char *why, size_t n);

/* Restore @dst from the newest backup under @root (ssaddon_store, @label)
 * whose bytes match @expect_sha, walking back through older hourly buckets
 * and the fixed one past any that do not. The blob used goes to @used. */
int sst_restore_from_backups(const char *root, const char *label, const char *dst,
			     const char *expect_sha, char *used, size_t un,
			     char *why, size_t n);

/* Record evidence about @path before @action ("repair", "restore", "remove",
 * "quarantine") changes it. @expect_sha (may be NULL) is what the baseline
 * says it should be. @sample (may be NULL) is a copy the caller already
 * stored; otherwise the bytes are stored under SSADDON_EVIDENCE_ROOT. A
 * missing file is recorded as missing; a symlink is recorded as a link, with
 * its target, and never followed. 0 if the record and the copy were kept;
 * -1 if either could not be (e.g. the disk is full): then do not act. */
int sst_evidence(const char *feature, const char *path, const char *action,
		 const char *expect_sha, const char *sample);

/* Is @path strictly inside @root ("<root>/..."), with no "..", ".", empty
 * components or control characters? A baseline entry outside the tree the
 * guard owns is never repaired from or restored over (P2-2 part 3). */
int sst_path_within(const char *root, const char *path);

/*
 * Enforce arming (TODO P2-2 part 3, monitor -> enforce). Turning a guard to
 * `mode = enforce` does not make it act at once: until it is armed it only
 * reports what it would do. A scanner arms itself after one full pass that
 * finds nothing to act on; otherwise the operator runs `<tool> arm` after
 * reading the report. Going back to monitor mode disarms it. The state is
 * "<statedir>/enforce-armed" (root-owned, 0600).
 */
int sst_armed(const char *statedir);
int sst_arm(const char *feature, const char *statedir, const char *how);
void sst_disarm(const char *feature, const char *statedir);
void sst_describe_arming(const char *statedir, int enforce, char *out, size_t n);

#endif /* SSADDON_TRUST_H */
