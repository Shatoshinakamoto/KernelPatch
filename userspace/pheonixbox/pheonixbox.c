// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * secure-sudo-pheonixbox - PheonixBox (#21): snapshot-based runtime tamper
 * protection with automatic repair.
 *
 * ============================= THE HONEST DESIGN =========================
 * The request described "compressing the contents into a hash so it can be
 * reversible without a password". A cryptographic hash (SHA-256) is ONE-WAY
 * and lossy by design: you cannot turn a 32-byte digest back into the original
 * file. So PheonixBox is built as the two-part mechanism that actually
 * delivers what was asked:
 *
 *   1. a SHA-256 integrity MANIFEST - the one-way digest of each protected
 *      file, used only to DETECT tampering (cheap, tiny); and
 *   2. a root-only, compressed SNAPSHOT STORE of the real original bytes
 *      (zlib/DEFLATE, no password) - this is what REVERSIBLY restores a
 *      tampered file.
 *
 * Compression (zlib) is reversible and needs no key; hashing is not. The hash
 * says "this changed"; the compressed snapshot says "here is what it should be
 * again". Together they give fast detection plus exact repair.
 *
 * ============================== WHAT IT DOES =============================
 * Protects a configured set of files and directories (directories recursively,
 * every regular file inside). It is a toggle:
 *
 *   ENABLE  -> take a snapshot if needed (hashes + compressed originals),
 *              capture every file's owner/group/mode and POSIX ACLs (the
 *              PermissionsSnapshot), make each protected file READ-ONLY, and
 *              begin periodic scanning. On any detected tamper the file is
 *              immediately restored from the snapshot and re-locked read-only.
 *   DISABLE -> stop scanning and restore every file's ORIGINAL permissions
 *              (and ACLs) from the PermissionsSnapshot - undoing the read-only
 *              lock so the box returns exactly to its prior state.
 *   SNAPSHOT (while off) -> re-capture the current contents, hashes and
 *              permissions as the new "known good" baseline for repairs.
 *
 * The periodic scan is driven by secure-sudod (it runs `pheonixbox scan` on a
 * timer); `scan` is a no-op when protection is off.
 *
 * ============================== THE STORE ================================
 * Everything lives under /var/lib/secure_sudo/pheonixbox (mode 0700, root):
 *   enabled              present => protection is ON
 *   manifest             one line per file: <csha> <mode> <uid> <gid> <path>
 *   blobs/<psha>.z       zlib-compressed original bytes (8-byte LE size header)
 *   acls/<psha>.acl      getfacl output for the file (POSIX ACLs), if captured
 *   lastscan             text timestamp of the last scan
 * where <csha> = SHA-256 of the file's contents, <psha> = SHA-256 of its
 * absolute path (a slash-free, collision-free blob/acl filename).
 *
 * Protected paths are configured in /etc/secure_sudo/pheonixbox.conf (one
 * absolute path per line; '#' comments). Paths containing whitespace are
 * skipped with a warning, because the line-based manifest cannot represent
 * them unambiguously.
 *
 * Root-only. The snapshot store is 0700 so no non-root user can read the
 * original contents or forge a blob.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <zlib.h>

#define STORE     "/var/lib/secure_sudo/pheonixbox"
#define BLOBS     STORE "/blobs"
#define ACLS      STORE "/acls"
#define MANIFEST  STORE "/manifest"
#define ENABLED   STORE "/enabled"
#define LASTSCAN  STORE "/lastscan"
#define EVIDENCE  STORE "/evidence"
#define CONF      "/etc/secure_sudo/pheonixbox.conf"

/* Guard against snapshotting something enormous into RAM. */
#define MAX_FILE  (256UL * 1024 * 1024)

static int require_root(void)
{
	if (geteuid() != 0) {
		fprintf(stderr, "secure-sudo pheonixbox: must run as root\n");
		return -1;
	}
	return 0;
}

/* ----------------------------- hashing ---------------------------------- */

static int sha256_mem(const void *data, size_t len, char out[65])
{
	unsigned char d[EVP_MAX_MD_SIZE];
	unsigned int n = 0;
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	int ok = 0, i;

	if (c && EVP_DigestInit_ex(c, EVP_sha256(), NULL) &&
	    EVP_DigestUpdate(c, data, len) && EVP_DigestFinal_ex(c, d, &n))
		ok = 1;
	EVP_MD_CTX_free(c);
	if (!ok)
		return -1;
	for (i = 0; i < (int)n; i++)
		sprintf(out + 2 * i, "%02x", d[i]);
	out[2 * n] = '\0';
	return 0;
}

static int sha256_str(const char *s, char out[65])
{
	return sha256_mem(s, strlen(s), out);
}

/* Read a whole regular file into a malloc'd buffer (caller frees). The file
 * is opened O_NOFOLLOW: a protected file replaced by a symlink is never read
 * through it (it could point at anything). A file that changes size while it
 * is read is refused rather than stored half-old, half-new. */
static unsigned char *read_file(const char *path, size_t *out_len)
{
	struct stat st;
	unsigned char *buf;
	size_t got = 0;
	ssize_t r;
	int fd;

	fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		close(fd);
		return NULL;
	}
	if ((unsigned long)st.st_size > MAX_FILE) {
		fprintf(stderr, "secure-sudo pheonixbox: %s too large to snapshot\n", path);
		close(fd);
		return NULL;
	}
	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}
	while (got <= (size_t)st.st_size &&
	       (r = pread(fd, buf + got, (size_t)st.st_size + 1 - got, (off_t)got)) > 0)
		got += (size_t)r;
	close(fd);
	if (got != (size_t)st.st_size) {
		free(buf);
		return NULL;
	}
	*out_len = got;
	return buf;
}

static int sha256_file(const char *path, char out[65])
{
	size_t len = 0;
	unsigned char *buf = read_file(path, &len);
	int r;

	if (!buf)
		return -1;
	r = sha256_mem(buf, len, out);
	free(buf);
	return r;
}

/* --------------------------- blob (snapshot) ----------------------------- */

static void blob_path(const char *abspath, char *out, size_t n, const char *dir,
		      const char *ext)
{
	char psha[65];

	if (sha256_str(abspath, psha) != 0)
		psha[0] = '\0';
	snprintf(out, n, "%s/%s%s", dir, psha, ext);
}

/* Compress @abspath's current contents into @bp. The SHA-256 of exactly the
 * bytes stored goes to @sha_out, so a manifest built from it always matches
 * its own snapshot (a file rewritten mid-snapshot cannot split them). Returns
 * 0, -1 when the file cannot be read (a symlink, too large, changing), or -2
 * when the copy cannot be written in full (disk full): no partial blob stays. */
static int blob_store_to(const char *abspath, const char *bp, char sha_out[65])
{
	size_t len = 0;
	unsigned char *buf = read_file(abspath, &len);
	uLongf clen;
	unsigned char *cbuf;
	FILE *f;
	uint64_t hdr = len;
	int rc = -2, fd;

	if (!buf)
		return -1;
	if (sha_out && sha256_mem(buf, len, sha_out) != 0) {
		free(buf);
		return -1;
	}
	clen = compressBound(len);
	cbuf = malloc(clen ? clen : 1);
	if (!cbuf) {
		free(buf);
		return -2;
	}
	if (compress2(cbuf, &clen, buf, len, Z_BEST_COMPRESSION) != Z_OK)
		goto out;
	fd = open(bp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		goto out;
	f = fdopen(fd, "wb");
	if (!f) {
		close(fd);
		unlink(bp);
		goto out;
	}
	/* 8-byte little-endian original length, then the compressed bytes;
	 * a full disk can show up at any of these steps */
	if (fwrite(&hdr, 1, 8, f) == 8 && fwrite(cbuf, 1, clen, f) == clen &&
	    fflush(f) == 0 && fsync(fd) == 0)
		rc = 0;
	if (fclose(f) != 0)
		rc = -2;
	if (rc != 0)
		unlink(bp);
out:
	free(cbuf);
	free(buf);
	return rc;
}

static int blob_store(const char *abspath, char sha_out[65])
{
	char bp[PATH_MAX];

	blob_path(abspath, bp, sizeof(bp), BLOBS, ".z");
	return blob_store_to(abspath, bp, sha_out);
}

/* Load and decompress a blob into memory (caller frees). */
static unsigned char *blob_load(const char *bp, size_t *out_len)
{
	FILE *f;
	uint64_t orig = 0;
	long csz;
	unsigned char *cbuf, *obuf;
	uLongf olen;

	f = fopen(bp, "rbe");
	if (!f)
		return NULL;
	if (fread(&orig, 1, 8, f) != 8 || orig > MAX_FILE || fseek(f, 0, SEEK_END) != 0 ||
	    (csz = ftell(f) - 8) <= 0 || fseek(f, 8, SEEK_SET) != 0) {
		fclose(f);
		return NULL;
	}
	cbuf = malloc((size_t)csz);
	obuf = malloc(orig ? (size_t)orig : 1);
	if (!cbuf || !obuf || fread(cbuf, 1, (size_t)csz, f) != (size_t)csz) {
		fclose(f);
		free(cbuf);
		free(obuf);
		return NULL;
	}
	fclose(f);
	olen = orig;
	if (uncompress(obuf, &olen, cbuf, (uLong)csz) != Z_OK || olen != orig) {
		free(cbuf);
		free(obuf);
		return NULL;
	}
	free(cbuf);
	*out_len = (size_t)orig;
	return obuf;
}

/* Keep what is at @abspath now, before a repair overwrites it: a compressed
 * copy under evidence/ and a CRITICAL syslog line with its hash, owner and
 * mode (a symlink: where it pointed). 0 if kept, or nothing was there. */
static int keep_evidence(const char *abspath, const char *expect)
{
	char bp[PATH_MAX], psha[65], sha[65] = "", target[PATH_MAX] = "";
	struct stat st;
	ssize_t tl;

	if (lstat(abspath, &st) != 0) {
		syslog(LOG_CRIT, "EVIDENCE before repair: %s missing (expected %.64s)",
		       abspath, expect);
		return 0;
	}
	if (S_ISLNK(st.st_mode)) {
		tl = readlink(abspath, target, sizeof(target) - 1);
		target[tl > 0 ? tl : 0] = '\0';
		syslog(LOG_CRIT, "EVIDENCE before repair: %s was replaced by a symlink "
		       "to %s (expected %.64s)", abspath, target, expect);
		return 0;
	}
	if (!S_ISREG(st.st_mode)) {
		syslog(LOG_CRIT, "EVIDENCE before repair: %s is no longer a regular file "
		       "(mode %o)", abspath, (unsigned)st.st_mode);
		return 0;
	}
	if (sha256_str(abspath, psha) != 0)
		return -1;
	mkdir(EVIDENCE, 0700);
	snprintf(bp, sizeof(bp), "%s/%s.%ld.z", EVIDENCE, psha, (long)time(NULL));
	if (blob_store_to(abspath, bp, sha) != 0) {
		syslog(LOG_CRIT, "EVIDENCE could not be kept for %s (disk full?)", abspath);
		return -1;
	}
	syslog(LOG_CRIT, "EVIDENCE before repair: %s sha256=%s expected=%.64s size=%lld "
	       "mode=%04o uid=%u gid=%u mtime=%lld copy=%s", abspath, sha, expect,
	       (long long)st.st_size, (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid,
	       (unsigned)st.st_gid, (long long)st.st_mtime, bp);
	return 0;
}

/* Put the snapshot of @abspath back: only if its bytes hash to @csha (the
 * manifest's), written to a new file next to it with the captured owner and
 * a read-only mode, then renamed over whatever is there. A symlink planted
 * at @abspath is replaced, never written through. */
static int blob_restore(const char *abspath, const char *csha, mode_t mode,
			uid_t uid, gid_t gid)
{
	char bp[PATH_MAX], tmp[PATH_MAX], got[65];
	unsigned char *obuf;
	size_t len = 0;
	int fd, rc = -1;

	blob_path(abspath, bp, sizeof(bp), BLOBS, ".z");
	obuf = blob_load(bp, &len);
	if (!obuf)
		return -1;
	if (sha256_mem(obuf, len, got) != 0 || strcmp(got, csha) != 0) {
		syslog(LOG_CRIT, "snapshot of %s does not match the manifest: not used",
		       abspath);
		free(obuf);
		return -1;
	}
	if (snprintf(tmp, sizeof(tmp), "%s.pbx-restore", abspath) >= (int)sizeof(tmp)) {
		free(obuf);
		return -1;
	}
	unlink(tmp);
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		free(obuf);
		return -1;
	}
	if (write(fd, obuf, len) == (ssize_t)len && fchown(fd, uid, gid) == 0 &&
	    fchmod(fd, mode & ~(mode_t)(S_IWUSR | S_IWGRP | S_IWOTH)) == 0 && /* RO */
	    fsync(fd) == 0)
		rc = 0;
	close(fd);
	free(obuf);
	if (rc == 0 && rename(tmp, abspath) != 0)
		rc = -1;
	if (rc != 0)
		unlink(tmp);
	return rc;
}

/* A manifest path PheonixBox will act on: absolute, no whitespace or
 * control characters, no "." / ".." / empty components. */
static int manifest_path_ok(const char *p)
{
	const char *q;

	if (p[0] != '/' || !p[1])
		return 0;
	for (q = p; *q; q++) {
		if (*q == ' ' || (unsigned char)*q < 0x20 || *q == 0x7f)
			return 0;
		if (q[0] == '/' && (q[1] == '/' || !q[1] ||
		    (q[1] == '.' && (q[2] == '/' || !q[2] ||
				     (q[2] == '.' && (q[3] == '/' || !q[3]))))))
			return 0;
	}
	return 1;
}

/* Open @path for a permission change without following a symlink; -1 if it
 * is not a regular file any more. */
static int open_reg(const char *path)
{
	struct stat st;
	int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);

	if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))) {
		close(fd);
		fd = -1;
	}
	return fd;
}

/* ------------------------------ ACLs ------------------------------------- */
/*
 * Best-effort POSIX ACL capture/restore via getfacl/setfacl if present.
 *
 * The tools are run directly (fork + execvp), never through a shell: a
 * protected directory can hold files whose names its owner chose, and a
 * name such as  a';touch$IFS/x;'  used to be run as a root command when it
 * was pasted into a quoted shell line (SECURITY_REVIEW #55).
 *
 * Runs argv with stdout to @out (NULL: /dev/null) and stderr to /dev/null.
 * Returns the exit status, or -1 if the tool could not be started.
 */
static int run_tool(char *const argv[], const char *out)
{
	pid_t pid = fork();
	int st;

	if (pid < 0)
		return -1;
	if (pid == 0) {
		int null = open("/dev/null", O_RDWR | O_CLOEXEC);
		int o = out ? open(out, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW |
				   O_CLOEXEC, 0600) : null;

		if (null < 0 || o < 0)
			_exit(127);
		dup2(null, STDIN_FILENO);
		dup2(o, STDOUT_FILENO);
		dup2(null, STDERR_FILENO);
		execvp(argv[0], argv);
		_exit(127);
	}
	if (waitpid(pid, &st, 0) < 0 || !WIFEXITED(st))
		return -1;
	return WEXITSTATUS(st) == 127 ? -1 : WEXITSTATUS(st);
}

static void acl_capture(const char *abspath)
{
	char ap[PATH_MAX];
	/* -p keeps leading slash; --absolute-names avoids path rewriting. */
	char *argv[] = { "getfacl", "-p", "--absolute-names", "--",
			 (char *)abspath, NULL };

	blob_path(abspath, ap, sizeof(ap), ACLS, ".acl");
	if (run_tool(argv, ap) == 0)
		chmod(ap, 0600);
	else
		unlink(ap);		/* no getfacl, or it failed: keep no stub */
}

static void acl_restore(const char *abspath)
{
	char ap[PATH_MAX], opt[PATH_MAX + 16];
	char *argv[] = { "setfacl", opt, NULL };
	struct stat st;

	blob_path(abspath, ap, sizeof(ap), ACLS, ".acl");
	if (stat(ap, &st) != 0)
		return;
	snprintf(opt, sizeof(opt), "--restore=%s", ap);
	(void)run_tool(argv, NULL);	/* best-effort ACL restore */
}

/* --------------------------- config + walk ------------------------------- */

/*
 * The manifest is one line per file with the path last, so a path with
 * whitespace or any control character (a newline would start a forged
 * manifest line) cannot be stored safely and is skipped.
 */
static int path_has_ws(const char *p)
{
	for (; *p; p++)
		if (*p == ' ' || (unsigned char)*p < 0x20 || *p == 0x7f)
			return 1;
	return 0;
}

/* Callback type for walking every protected regular file. */
typedef void (*file_cb)(const char *abspath, void *ctx);

static void walk_path(const char *path, file_cb cb, void *ctx, int depth)
{
	struct stat st;
	DIR *d;
	struct dirent *de;

	if (depth > 24 || lstat(path, &st) != 0)
		return;
	if (S_ISREG(st.st_mode)) {
		if (path_has_ws(path))
			fprintf(stderr, "secure-sudo pheonixbox: skipping path with whitespace "
				"or a control character\n");
		else
			cb(path, ctx);
		return;
	}
	if (!S_ISDIR(st.st_mode))
		return;			/* ignore symlinks, devices, etc. */
	d = opendir(path);
	if (!d)
		return;
	while ((de = readdir(d))) {
		char child[PATH_MAX];

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (snprintf(child, sizeof(child), "%s/%s", path, de->d_name) >=
		    (int)sizeof(child))
			continue;
		walk_path(child, cb, ctx, depth + 1);
	}
	closedir(d);
}

/* Walk every configured protected path. Returns the number of roots read. */
static int for_each_protected(file_cb cb, void *ctx)
{
	FILE *f = fopen(CONF, "re");
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	int roots = 0;

	if (!f)
		return 0;
	while ((len = getline(&line, &cap, f)) >= 0) {
		char *p = line;

		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p != '/')
			continue;		/* comments/blanks/relative */
		walk_path(p, cb, ctx, 0);
		roots++;
	}
	free(line);
	fclose(f);
	return roots;
}

/* ------------------------- manifest building ----------------------------- */

struct snap_ctx {
	FILE *mf;
	size_t files, failed;
};

static void snap_one(const char *abspath, void *vctx)
{
	struct snap_ctx *c = vctx;
	struct stat st;
	char csha[65];

	if (lstat(abspath, &st) != 0 || !S_ISREG(st.st_mode))
		return;
	switch (blob_store(abspath, csha)) {
	case 0:
		break;
	case -2:
		fprintf(stderr, "secure-sudo pheonixbox: could not store a snapshot of %s "
			"(disk full?)\n", abspath);
		c->failed++;
		return;
	default:
		fprintf(stderr, "secure-sudo pheonixbox: could not snapshot %s\n", abspath);
		return;
	}
	acl_capture(abspath);
	/* manifest: <content-sha> <mode-octal> <uid> <gid> <abspath> */
	fprintf(c->mf, "%s %o %u %u %s\n", csha, (unsigned)(st.st_mode & 07777),
		(unsigned)st.st_uid, (unsigned)st.st_gid, abspath);
	c->files++;
}

static int do_snapshot(void)
{
	struct snap_ctx ctx = { 0 };
	char tmp[] = STORE "/.manifest.XXXXXX";
	int fd;

	/* The parent may not exist yet on a host where nothing else of
	 * secure_sudo has written state; mkdir(STORE) alone then failed. */
	mkdir("/var/lib/secure_sudo", 0755);
	mkdir(STORE, 0700);
	mkdir(BLOBS, 0700);
	mkdir(ACLS, 0700);
	chmod(STORE, 0700);

	fd = mkstemp(tmp);
	if (fd < 0) {
		fprintf(stderr, "secure-sudo pheonixbox: %s: %s\n", STORE, strerror(errno));
		return -1;
	}
	ctx.mf = fdopen(fd, "we");
	if (!ctx.mf) {
		close(fd);
		unlink(tmp);
		return -1;
	}
	for_each_protected(snap_one, &ctx);
	if (fflush(ctx.mf) != 0 || fsync(fileno(ctx.mf)) != 0 || ferror(ctx.mf))
		ctx.failed++;
	if (fclose(ctx.mf) != 0)
		ctx.failed++;
	if (ctx.failed) {
		/* a snapshot that cannot hold what it lists would make those
		 * repairs impossible: the previous one is kept */
		unlink(tmp);
		syslog(LOG_CRIT, "snapshot REFUSED: %zu file(s) could not be stored "
		       "(disk full?); the previous snapshot is kept", ctx.failed);
		fprintf(stderr, "secure-sudo pheonixbox: snapshot refused: %zu file(s) "
			"could not be stored; free space under " STORE "\n", ctx.failed);
		return -1;
	}
	if (rename(tmp, MANIFEST) != 0) {
		unlink(tmp);
		return -1;
	}
	chmod(MANIFEST, 0600);
	syslog(LOG_INFO, "snapshot captured %zu files", ctx.files);
	printf("secure-sudo pheonixbox: snapshot captured %zu files\n", ctx.files);
	return 0;
}

/* --------------------------- manifest reading ---------------------------- */

/* Parse one manifest line into its fields. Returns 0 on success; @path points
 * into @line (which is modified in place). */
static int manifest_parse(char *line, char **csha, mode_t *mode, uid_t *uid,
			  gid_t *gid, char **path)
{
	char *save, *tok;
	unsigned m, u, g;

	tok = strtok_r(line, " ", &save); if (!tok) return -1; *csha = tok;
	tok = strtok_r(NULL, " ", &save); if (!tok) return -1;
	if (sscanf(tok, "%o", &m) != 1) return -1;
	tok = strtok_r(NULL, " ", &save); if (!tok) return -1;
	if (sscanf(tok, "%u", &u) != 1) return -1;
	tok = strtok_r(NULL, " ", &save); if (!tok) return -1;
	if (sscanf(tok, "%u", &g) != 1) return -1;
	tok = strtok_r(NULL, "", &save);  if (!tok) return -1;	/* rest = path */
	while (*tok == ' ') tok++;
	*mode = (mode_t)m; *uid = (uid_t)u; *gid = (gid_t)g; *path = tok;
	return 0;
}

typedef void (*man_cb)(const char *csha, mode_t mode, uid_t uid, gid_t gid,
		       const char *path, void *ctx);

static int for_each_manifest(man_cb cb, void *ctx)
{
	FILE *f = fopen(MANIFEST, "re");
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	int n = 0;

	if (!f)
		return -1;
	while ((len = getline(&line, &cap, f)) >= 0) {
		char *csha, *path;
		mode_t mode; uid_t uid; gid_t gid;

		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		if (len == 0 || line[0] == '#')
			continue;
		if (manifest_parse(line, &csha, &mode, &uid, &gid, &path) != 0)
			continue;
		if (strlen(csha) != 64 || !manifest_path_ok(path)) {
			/* not written by a snapshot: never acted on */
			syslog(LOG_CRIT, "manifest entry IGNORED (not a safe absolute path "
			       "or hash): %.200s", path);
			continue;
		}
		cb(csha, mode, uid, gid, path, ctx);
		n++;
	}
	free(line);
	fclose(f);
	return n;
}

/* ------------------------- enable / disable ------------------------------ */

/* Make a protected file read-only (strip all write bits). */
static void lock_ro(const char *csha, mode_t mode, uid_t uid, gid_t gid,
		    const char *path, void *ctx)
{
	int fd = open_reg(path);

	(void)csha; (void)uid; (void)gid; (void)ctx;
	if (fd < 0)
		return;		/* not a regular file now: the scan repairs it */
	if (fchmod(fd, mode & ~(mode_t)(S_IWUSR | S_IWGRP | S_IWOTH)) != 0)
		syslog(LOG_ERR, "could not lock %s read-only", path);
	close(fd);
}

static int is_enabled(void)
{
	return access(ENABLED, F_OK) == 0;
}

static int cmd_enable(void)
{
	FILE *f;

	if (is_enabled()) {
		printf("secure-sudo pheonixbox: already enabled\n");
		return 0;
	}
	/* Capture contents + hashes + PermissionsSnapshot (mode/uid/gid in the
	 * manifest, ACLs alongside). */
	if (do_snapshot() != 0)
		return 1;
	/* Lock every protected file read-only. */
	for_each_manifest(lock_ro, NULL);
	f = fopen(ENABLED, "we");
	if (f) {
		fprintf(f, "enabled\n");
		fclose(f);
		chmod(ENABLED, 0600);
	}
	syslog(LOG_WARNING, "ENABLED - protected files locked read-only, scanning active");
	printf("secure-sudo pheonixbox: ENABLED - files locked read-only, scanning active\n");
	return 0;
}

static void restore_perms(const char *csha, mode_t mode, uid_t uid, gid_t gid,
			  const char *path, void *ctx)
{
	int fd = open_reg(path), rc;

	(void)csha; (void)ctx;
	if (fd < 0) {
		/* a symlink here could point at any file: its permissions are
		 * never changed through it */
		syslog(LOG_CRIT, "permissions NOT restored: %s is not a regular file "
		       "any more", path);
		return;
	}
	/* Put ownership and mode back exactly as captured, then ACLs. */
	rc = fchown(fd, uid, gid);
	(void)rc;			/* best-effort; mode/ACL restore follows */
	if (fchmod(fd, mode) != 0)
		syslog(LOG_ERR, "could not restore the mode of %s", path);
	close(fd);
	acl_restore(path);
}

static int cmd_disable(void)
{
	if (!is_enabled()) {
		printf("secure-sudo pheonixbox: not enabled\n");
		return 0;
	}
	/* Restore every file's original permissions from the PermissionsSnapshot
	 * (this undoes the read-only lock). */
	for_each_manifest(restore_perms, NULL);
	unlink(ENABLED);
	syslog(LOG_WARNING, "DISABLED - original permissions restored");
	printf("secure-sudo pheonixbox: DISABLED - original permissions restored\n");
	return 0;
}

/* ------------------------------ scan ------------------------------------- */

struct scan_ctx {
	size_t checked, repaired, missing;
	int quiet;
};

static void scan_one(const char *csha, mode_t mode, uid_t uid, gid_t gid,
		     const char *path, void *vctx)
{
	struct scan_ctx *c = vctx;
	char now[65];
	struct stat st;
	int tampered = 0;

	c->checked++;

	if (lstat(path, &st) != 0) {
		tampered = 1;			/* deleted/replaced */
		c->missing++;
	} else if (!S_ISREG(st.st_mode)) {
		tampered = 1;			/* a symlink (to anything) or other */
	} else if (sha256_file(path, now) != 0 || strcmp(now, csha) != 0) {
		tampered = 1;			/* contents changed */
	} else if ((st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH))) {
		/* contents fine but someone re-added a write bit: re-lock. */
		lock_ro(csha, mode, uid, gid, path, NULL);
	}

	if (!tampered)
		return;
	if (keep_evidence(path, csha) != 0) {
		/* what is there would be lost: it is left for the operator */
		syslog(LOG_CRIT, "NOT repaired: %s (its current bytes could not be kept)",
		       path);
		if (!c->quiet)
			fprintf(stderr, "secure-sudo pheonixbox: NOT repaired %s: the "
				"evidence copy could not be kept\n", path);
		return;
	}
	if (blob_restore(path, csha, mode, uid, gid) == 0) {
		c->repaired++;
		/* Log every repair (forwardable off-box via syslog/rsyslog) so a
		 * tamper event leaves a durable record even if quiet. */
		syslog(LOG_CRIT, "repaired tampered file %s", path);
		if (!c->quiet)
			printf("repaired %s\n", path);
	} else {
		syslog(LOG_ERR, "FAILED to repair %s", path);
		if (!c->quiet)
			fprintf(stderr, "secure-sudo pheonixbox: FAILED to repair %s\n", path);
	}
}

static int cmd_scan(int quiet)
{
	struct scan_ctx ctx = { 0 };
	FILE *f;

	if (!is_enabled())
		return 0;			/* no-op when off (daemon calls this) */
	ctx.quiet = quiet;
	if (for_each_manifest(scan_one, &ctx) < 0)
		return 0;			/* no manifest yet */

	f = fopen(LASTSCAN, "we");
	if (f) {
		fprintf(f, "%ld checked=%zu repaired=%zu\n", (long)time(NULL),
			ctx.checked, ctx.repaired);
		fclose(f);
		chmod(LASTSCAN, 0600);
	}
	if (!quiet)
		printf("secure-sudo pheonixbox: scanned %zu, repaired %zu\n",
		       ctx.checked, ctx.repaired);
	return 0;
}

/* ----------------------------- status/list ------------------------------- */

static void count_cb(const char *csha, mode_t mode, uid_t uid, gid_t gid,
		     const char *path, void *ctx)
{
	(void)csha; (void)mode; (void)uid; (void)gid; (void)path;
	(*(size_t *)ctx)++;
}

static int cmd_status(void)
{
	size_t n = 0;
	char buf[128] = "";
	FILE *f;

	printf("PheonixBox: %s\n", is_enabled() ? "ENABLED (read-only + scanning)" :
	       "disabled");
	for_each_manifest(count_cb, &n);
	printf("snapshot entries: %zu\n", n);
	f = fopen(LASTSCAN, "re");
	if (f) {
		if (fgets(buf, sizeof(buf), f))
			printf("last scan: %s", buf);
		fclose(f);
	}
	return 0;
}

/* ----------------------------- add/remove -------------------------------- */

static int conf_edit(const char *path, int add)
{
	char real[PATH_MAX];
	FILE *in, *out;
	char tmp[] = CONF ".XXXXXX";
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	int found = 0, fd;

	if (!realpath(path, real))
		snprintf(real, sizeof(real), "%s", path);
	if (real[0] != '/') {
		fprintf(stderr, "secure-sudo pheonixbox: path must be absolute\n");
		return 1;
	}
	/* the temporary file goes next to the config, so its directory must
	 * exist first (before any other part of secure_sudo has made it) */
	if (mkdir("/etc/secure_sudo", 0755) != 0 && errno != EEXIST) {
		fprintf(stderr, "secure-sudo pheonixbox: cannot create /etc/secure_sudo: %s\n",
			strerror(errno));
		return 1;
	}
	fd = mkstemp(tmp);
	if (fd < 0) {
		fprintf(stderr, "secure-sudo pheonixbox: cannot write %s: %s\n", CONF,
			strerror(errno));
		return 1;
	}
	out = fdopen(fd, "we");
	if (!out) { close(fd); unlink(tmp); return 1; }

	in = fopen(CONF, "re");
	if (in) {
		while ((len = getline(&line, &cap, in)) >= 0) {
			char *p = line;
			while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
				line[--len] = '\0';
			while (*p == ' ' || *p == '\t') p++;
			if (!strcmp(p, real)) {
				found = 1;
				if (!add)
					continue;	/* drop on remove */
			}
			fprintf(out, "%s\n", line);
		}
		free(line);
		fclose(in);
	} else {
		fprintf(out, "# PheonixBox (#21) protected paths - one absolute path per line.\n");
	}
	if (add && !found)
		fprintf(out, "%s\n", real);
	fflush(out);
	fsync(fileno(out));
	fclose(out);
	if (rename(tmp, CONF) != 0) { unlink(tmp); return 1; }
	chmod(CONF, 0644);

	if (!add && !found)
		fprintf(stderr, "secure-sudo pheonixbox: %s was not listed\n", real);
	else
		printf("%s %s\n", add ? "added" : "removed", real);
	if (is_enabled())
		printf("note: run `secure-sudo pheonixbox snapshot` after disabling, "
		       "or toggle off/on, for the change to take effect\n");
	return 0;
}

/*
 * check-config (TODO P2-2): pheonixbox.conf is checked strictly. It must be
 * root-owned and not group/world writable (whoever can edit it chooses what
 * is snapshotted and repaired); every line is blank, a '#' comment, or one
 * absolute path with no whitespace, control characters or "."/".."
 * components, listed once. A path that does not exist yet is a note, not an
 * error. Returns the number of errors; each problem goes to @r.
 */
static int conf_check(FILE *r)
{
	FILE *f = fopen(CONF, "re");
	char *line = NULL, **seen = NULL;
	size_t cap = 0, nseen = 0, i;
	ssize_t len;
	struct stat st;
	int errs = 0, ln = 0;

	if (!f) {
		if (errno != ENOENT) {
			fprintf(r, "%s: cannot read: %s\n", CONF, strerror(errno));
			return 1;
		}
		return 0;		/* nothing protected yet */
	}
	if (fstat(fileno(f), &st) == 0) {
		if (st.st_uid != 0) {
			fprintf(r, "%s: not owned by root\n", CONF);
			errs++;
		}
		if (st.st_mode & (S_IWGRP | S_IWOTH)) {
			fprintf(r, "%s: writable by group or others\n", CONF);
			errs++;
		}
	}
	while ((len = getline(&line, &cap, f)) >= 0) {
		char *p = line, **g;
		struct stat ps;

		ln++;
		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p || *p == '#')
			continue;
		if ((size_t)len >= PATH_MAX) {
			fprintf(r, "%s:%d: line too long\n", CONF, ln);
			errs++;
			continue;
		}
		if (*p != '/') {
			fprintf(r, "%s:%d: not an absolute path: %.80s\n", CONF, ln, p);
			errs++;
			continue;
		}
		{
			size_t pl = strlen(p);

			while (pl > 1 && p[pl - 1] == '/')
				p[--pl] = '\0';	/* "/etc/x/" is "/etc/x" */
		}
		if (!manifest_path_ok(p)) {
			fprintf(r, "%s:%d: path has whitespace, a control character or a "
				"./.. component: %.80s\n", CONF, ln, p);
			errs++;
			continue;
		}
		for (i = 0; i < nseen && strcmp(seen[i], p); i++)
			;
		if (i < nseen) {
			fprintf(r, "%s:%d: %s is listed twice\n", CONF, ln, p);
			errs++;
			continue;
		}
		g = realloc(seen, (nseen + 1) * sizeof(*seen));
		if (g && (g[nseen] = strdup(p))) {
			seen = g;
			nseen++;
		} else if (g) {
			seen = g;
		}
		if (lstat(p, &ps) != 0)
			fprintf(r, "%s:%d: note: %s does not exist (yet); it protects "
				"nothing until it does\n", CONF, ln, p);
		else if (S_ISLNK(ps.st_mode))
			fprintf(r, "%s:%d: note: %s is a symlink; symlinks are not "
				"followed, so it protects nothing\n", CONF, ln, p);
	}
	for (i = 0; i < nseen; i++)
		free(seen[i]);
	free(seen);
	free(line);
	fclose(f);
	return errs;
}

static int cmd_check_config(void)
{
	int e = conf_check(stdout);

	if (e)
		printf("%d configuration problem(s); `on` and `snapshot` refuse to run "
		       "until they are fixed (add/remove still work)\n", e);
	else
		printf("configuration OK\n");
	return e ? 1 : 0;
}

/* `on` and `snapshot` act on the config: not while it has an error. */
static int refuse_bad_conf(const char *what)
{
	int e = conf_check(stderr);

	if (!e)
		return 0;
	fprintf(stderr, "secure-sudo pheonixbox: %s refused: %d problem(s) in %s "
		"(see above; fix them or `remove` the bad lines)\n", what, e, CONF);
	syslog(LOG_ERR, "%s refused: %d configuration problem(s)", what, e);
	return 78;
}

static int cmd_list(void)
{
	FILE *f = fopen(CONF, "re");
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;

	if (!f) {
		printf("(no protected paths configured)\n");
		return 0;
	}
	while ((len = getline(&line, &cap, f)) >= 0) {
		char *p = line;
		while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
			line[--len] = '\0';
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '/')
			printf("%s\n", p);
	}
	free(line);
	fclose(f);
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
"usage: secure-sudo pheonixbox <command> [path]\n"
"  on | enable          snapshot, capture permissions, lock files read-only, start scanning\n"
"  off | disable        restore original permissions and unlock (stop protecting)\n"
"  snapshot             (while off) re-capture contents, hashes and permissions as the baseline\n"
"  scan [--quiet]       check all protected files now and repair any tampering\n"
"  status               show whether protection is on and how many files are covered\n"
"  add <path>           add a file or directory (recursive) to the protected set\n"
"  remove <path>        remove a path from the protected set\n"
"  list                 list the protected paths\n"
"  check-config         check " CONF " strictly; 1 if any problem\n");
}

int main(int argc, char **argv)
{
	const char *cmd;

	if (argc < 2) {
		usage();
		return 2;
	}
	if (require_root() != 0)
		return 1;
	/* Open syslog so PheonixBox's tamper/repair and enable/disable events are
	 * recorded and can be shipped to an external log server via the system's
	 * syslog (rsyslog/syslog-ng forwarding) for off-box backup. */
	openlog("secure-sudo-pheonixbox", LOG_PID, LOG_AUTHPRIV);
	cmd = argv[1];

	if (!strcmp(cmd, "check-config"))
		return cmd_check_config();
	if (!strcmp(cmd, "on") || !strcmp(cmd, "enable")) {
		int rc = refuse_bad_conf("on");

		return rc ? rc : cmd_enable();
	}
	if (!strcmp(cmd, "off") || !strcmp(cmd, "disable"))
		return cmd_disable();
	if (!strcmp(cmd, "snapshot")) {
		if (is_enabled()) {
			fprintf(stderr, "secure-sudo pheonixbox: disable first - a snapshot "
				"while enabled would capture the locked state\n");
			return 1;
		}
		{
			int rc = refuse_bad_conf("snapshot");

			if (rc)
				return rc;
		}
		return do_snapshot() == 0 ? 0 : 1;
	}
	if (!strcmp(cmd, "scan"))
		return cmd_scan(argc > 2 && !strcmp(argv[2], "--quiet"));
	if (!strcmp(cmd, "status"))
		return cmd_status();
	if (!strcmp(cmd, "list"))
		return cmd_list();
	if (!strcmp(cmd, "add") && argc == 3)
		return conf_edit(argv[2], 1);
	if ((!strcmp(cmd, "remove") || !strcmp(cmd, "rm")) && argc == 3)
		return conf_edit(argv[2], 0);

	usage();
	return 2;
}
