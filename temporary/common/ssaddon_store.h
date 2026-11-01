/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ssaddon_store - shared hourly-rotating compressed storage + Locus client for
 * the secure_sudo temporary/ add-ons.
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
#include <stdio.h>

/* Cap on a single file stored compressed (256 MiB), matching PheonixBox. */
#define STORE_MAX_FILE (256UL * 1024UL * 1024UL)

/* Compute the current hourly bucket "<root>/<YYYYMMDDHH>" into @out and create
 * it (and @root) mode 0700. Returns 0 on success. Because the bucket name is
 * the hour, the active location changes every hour automatically. */
int store_current_bucket(const char *root, char *out, size_t n);

/* Like store_current_bucket, but when @rotate == 0 the bucket is the fixed name
 * "<root>/fixed" (no hourly rotation) - used when the operator has turned the
 * rotating quarantine/backup zones OFF so the location stays put. @rotate != 0
 * gives the hourly bucket. Returns 0 on success. */
int store_bucket(const char *root, int rotate, char *out, size_t n);

/* Compress @srcpath's current bytes into "<bucketdir>/<label>.<sha8>.z" (0600),
 * where <sha8> is the first 8 hex of the SHA-256 of @srcpath so two files with
 * the same label do not collide. Writes the final path to @outpath. Returns 0
 * on success, -1 on error (unreadable, too large, or compression failure). */
int store_put_compressed(const char *srcpath, const char *bucketdir,
			 const char *label, char *outpath, size_t n);

/* The same, also giving the SHA-256 (64 hex) of exactly the bytes stored, so
 * a caller can record a hash that its own copy is guaranteed to match.
 * @srcpath is opened O_NOFOLLOW: a symlink is refused, not followed. A file
 * that changes size while being read, or a copy that cannot be written in
 * full (disk full), fails (-1) and leaves no partial copy behind. */
int store_put_compressed_sha(const char *srcpath, const char *bucketdir,
			     const char *label, char *outpath, size_t n, char sha_out[65]);

/* The same from an open file: @fd is read (pread, from offset 0), @name names
 * the blob (its sha8). Used for a running program's binary via /proc/PID/exe,
 * which stays the right file even if its path has been replaced. */
int store_put_fd(int fd, const char *name, const char *bucketdir,
		 const char *label, char *outpath, size_t n, char sha_out[65]);

/* Decompress a stored blob (written by store_put_compressed, i.e. with the
 * 8-byte LE length header) at @blobpath and write the original bytes to
 * @dstpath (created/truncated, 0600, fsync'd). Returns 0 on success. */
int store_restore_compressed(const char *blobpath, const char *dstpath);

/* Decompress a stored blob into memory: *out (malloc'd, free it) and *len.
 * 0 on success. */
int store_load_compressed(const char *blobpath, unsigned char **out, size_t *len);

/* Find the NEWEST stored blob for @srcpath under @root's hourly buckets. The
 * blob name is "<label>.<sha8-of-srcpath>.z"; buckets are "<root>/<YYYYMMDDHH>"
 * so lexically-greatest bucket name == most recent. Writes the path to @out.
 * Returns 0 if found, -1 otherwise. */
int store_find_latest(const char *root, const char *label, const char *srcpath,
		      char *out, size_t n);

/* Like store_find_latest, but only buckets whose name sorts before @below
 * (NULL = no bound), ending with the fixed bucket; the bucket used is
 * written to @bucket. Lets a caller walk back through older backups. */
int store_find_before(const char *root, const char *label, const char *srcpath,
		      const char *below, char *out, size_t n, char *bucket, size_t bn);

/* Ask the Locus allocator (if configured and reachable over the LAN) for a root
 * directory to use for @purpose (e.g. "procguard-quarantine"). On success
 * writes the allocated path to @out and returns 0; on any failure returns -1
 * and the caller should fall back to its configured default root. */
int locus_request_root(const char *purpose, char *out, size_t n);

/* Check locus-client.conf strictly (ssaddon_conf); each problem goes to
 * @report. Returns the number of errors. */
int locus_check_conf(FILE *report);

/*
 * Is a package manager in the middle of a transaction (dpkg, rpm, zypper
 * hold their lock)? Then /boot and the module tree are being rewritten on
 * purpose: BootGuard and DriverGuard defer their scan, and the package hook
 * re-baselines when it ends. Writes the lock file to @which. 1 or 0.
 */
int ssaddon_pkg_busy(char *which, size_t n);

/*
 * Is @path an installed secure_sudo program (/usr/bin/secure-sudo*,
 * /usr/sbin/secure-sudod, /usr/libexec/secure-sudo/), root-owned and not
 * group/world-writable? The guards never kill those. A name is not enough:
 * /tmp/secure-sudo-x is not one (SECURITY_REVIEW #64).
 */
int ssaddon_is_stack_exe(const char *path);

#endif /* SSADDON_STORE_H */
