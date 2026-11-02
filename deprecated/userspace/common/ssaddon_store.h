/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ssaddon_store - shared hourly-rotating compressed storage + Locus client for
 * the secure_sudo runtime guards.
 *
 * Several add-ons keep compressed copies of things in a location that ROTATES
 * EVERY HOUR: ProcGuard's infected-process quarantine (so a fixed path can't be
 * used to re-expand malware for reinfection) and DriverGuard's failsafe driver
 * backups. This helper centralises:
 *
 *   - picking the current hour's bucket directory under a root, creating it
 *     0700, where the root may be a fixed configured path OR one requested at
 *     runtime from the Locus location-allocator over the LAN; and
 *   - storing a file into that bucket as zlib-compressed bytes with the same
 *     8-byte little-endian length header PheonixBox uses, so the format is one
 *     thing across the whole project.
 */
#ifndef SSADDON_STORE_H
#define SSADDON_STORE_H

#include <stddef.h>

/* Cap on a single file stored compressed (256 MiB), matching PheonixBox. */
#define STORE_MAX_FILE (256UL * 1024UL * 1024UL)

/* Compute the current hourly bucket "<root>/<YYYYMMDDHH>" into @out and create
 * it (and @root) mode 0700. Returns 0 on success. Because the bucket name is
 * the hour, the active location changes every hour automatically. */
int store_current_bucket(const char *root, char *out, size_t n);

/* Compress @srcpath's current bytes into "<bucketdir>/<label>.<sha8>.z" (0600),
 * where <sha8> is the first 8 hex of the SHA-256 of @srcpath so two files with
 * the same label do not collide. Writes the final path to @outpath. Returns 0
 * on success, -1 on error (unreadable, too large, or compression failure). */
int store_put_compressed(const char *srcpath, const char *bucketdir,
			 const char *label, char *outpath, size_t n);

/* Decompress a stored blob (written by store_put_compressed, i.e. with the
 * 8-byte LE length header) at @blobpath and write the original bytes to
 * @dstpath (created/truncated, 0600, fsync'd). Returns 0 on success. */
int store_restore_compressed(const char *blobpath, const char *dstpath);

/* Find the NEWEST stored blob for @srcpath under @root's hourly buckets. The
 * blob name is "<label>.<sha8-of-srcpath>.z"; buckets are "<root>/<YYYYMMDDHH>"
 * so lexically-greatest bucket name == most recent. Writes the path to @out.
 * Returns 0 if found, -1 otherwise. */
int store_find_latest(const char *root, const char *label, const char *srcpath,
		      char *out, size_t n);

/* Ask the Locus allocator (if configured and reachable over the LAN) for a root
 * directory to use for @purpose (e.g. "procguard-quarantine"). On success
 * writes the allocated path to @out and returns 0; on any failure returns -1
 * and the caller should fall back to its configured default root. */
int locus_request_root(const char *purpose, char *out, size_t n);

#endif /* SSADDON_STORE_H */
