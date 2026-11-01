// SPDX-License-Identifier: GPL-2.0
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

/* Read a whole regular file into a malloc'd buffer (caller frees). */
static unsigned char *read_file(const char *path, size_t *out_len)
{
	struct stat st;
	unsigned char *buf;
	FILE *f;
	size_t got;

	if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
		return NULL;
	if ((unsigned long)st.st_size > MAX_FILE) {
		fprintf(stderr, "secure-sudo pheonixbox: %s too large to snapshot\n", path);
		return NULL;
	}
	buf = malloc(st.st_size ? (size_t)st.st_size : 1);
	if (!buf)
		return NULL;
	f = fopen(path, "rbe");
	if (!f) {
		free(buf);
		return NULL;
	}
	got = fread(buf, 1, (size_t)st.st_size, f);
	fclose(f);
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

/* Compress @abspath's current contents into blobs/<psha>.z. */
static int blob_store(const char *abspath)
{
	size_t len = 0;
	unsigned char *buf = read_file(abspath, &len);
	uLongf clen;
	unsigned char *cbuf;
	char bp[PATH_MAX];
	FILE *f;
	uint64_t hdr = len;
	int rc = -1;

	if (!buf)
		return -1;
	clen = compressBound(len);
	cbuf = malloc(clen ? clen : 1);
	if (!cbuf) {
		free(buf);
		return -1;
	}
	if (compress2(cbuf, &clen, buf, len, Z_BEST_COMPRESSION) != Z_OK)
		goto out;
	blob_path(abspath, bp, sizeof(bp), BLOBS, ".z");
	f = fopen(bp, "wbe");
	if (!f)
		goto out;
	/* 8-byte little-endian original length, then the compressed bytes. */
	if (fwrite(&hdr, 1, 8, f) == 8 && fwrite(cbuf, 1, clen, f) == clen)
		rc = 0;
	fclose(f);
	if (rc == 0)
		chmod(bp, 0600);
out:
	free(cbuf);
	free(buf);
	return rc;
}

/* Decompress blobs/<psha>.z and overwrite @abspath with the original bytes.
 * @mode is the original mode to restore afterwards. */
static int blob_restore(const char *abspath, mode_t mode)
{
	char bp[PATH_MAX];
	FILE *f;
	uint64_t orig = 0;
	long csz;
	unsigned char *cbuf, *obuf;
	uLongf olen;
	int fd, rc = -1;

	blob_path(abspath, bp, sizeof(bp), BLOBS, ".z");
	f = fopen(bp, "rbe");
	if (!f)
		return -1;
	if (fread(&orig, 1, 8, f) != 8 || orig > MAX_FILE) {
		fclose(f);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	csz = ftell(f) - 8;
	fseek(f, 8, SEEK_SET);
	if (csz <= 0) {
		fclose(f);
		return -1;
	}
	cbuf = malloc((size_t)csz);
	obuf = malloc(orig ? (size_t)orig : 1);
	if (!cbuf || !obuf || fread(cbuf, 1, (size_t)csz, f) != (size_t)csz) {
		fclose(f);
		free(cbuf);
		free(obuf);
		return -1;
	}
	fclose(f);
	olen = orig;
	if (uncompress(obuf, &olen, cbuf, (uLong)csz) != Z_OK || olen != orig)
		goto out;

	/* Make the file writable for the rewrite (it is normally read-only while
	 * protected), overwrite it in place, fsync, then restore the mode. */
	chmod(abspath, 0600);
	fd = open(abspath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		goto out;
	if (write(fd, obuf, (size_t)orig) == (ssize_t)orig) {
		fsync(fd);
		rc = 0;
	}
	close(fd);
	chmod(abspath, mode & ~(mode_t)(S_IWUSR | S_IWGRP | S_IWOTH)); /* re-lock RO */
out:
	free(cbuf);
	free(obuf);
	return rc;
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
	size_t files;
};

static void snap_one(const char *abspath, void *vctx)
{
	struct snap_ctx *c = vctx;
	struct stat st;
	char csha[65];

	if (stat(abspath, &st) != 0 || !S_ISREG(st.st_mode))
		return;
	if (sha256_file(abspath, csha) != 0)
		return;
	if (blob_store(abspath) != 0) {
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
	fflush(ctx.mf);
	fsync(fileno(ctx.mf));
	fclose(ctx.mf);
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
		if (manifest_parse(line, &csha, &mode, &uid, &gid, &path) == 0) {
			cb(csha, mode, uid, gid, path, ctx);
			n++;
		}
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
	(void)csha; (void)uid; (void)gid; (void)ctx;
	chmod(path, mode & ~(mode_t)(S_IWUSR | S_IWGRP | S_IWOTH));
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
	int rc;

	(void)csha; (void)ctx;
	/* Put ownership and mode back exactly as captured, then ACLs. */
	rc = chown(path, uid, gid);
	(void)rc;			/* best-effort; mode/ACL restore follows */
	chmod(path, mode);
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

	(void)uid; (void)gid;
	c->checked++;

	if (stat(path, &st) != 0) {
		tampered = 1;			/* deleted/replaced */
		c->missing++;
	} else if (sha256_file(path, now) != 0 || strcmp(now, csha) != 0) {
		tampered = 1;			/* contents changed */
	} else if ((st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH))) {
		/* contents fine but someone re-added a write bit: re-lock. */
		chmod(path, mode & ~(mode_t)(S_IWUSR | S_IWGRP | S_IWOTH));
	}

	if (!tampered)
		return;
	if (blob_restore(path, mode) == 0) {
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
	fd = mkstemp(tmp);
	if (fd < 0)
		return 1;
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
	mkdir("/etc/secure_sudo", 0755);
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
"  list                 list the protected paths\n");
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

	if (!strcmp(cmd, "on") || !strcmp(cmd, "enable"))
		return cmd_enable();
	if (!strcmp(cmd, "off") || !strcmp(cmd, "disable"))
		return cmd_disable();
	if (!strcmp(cmd, "snapshot")) {
		if (is_enabled()) {
			fprintf(stderr, "secure-sudo pheonixbox: disable first - a snapshot "
				"while enabled would capture the locked state\n");
			return 1;
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
