// SPDX-License-Identifier: GPL-2.0
/*
 * vault_allow.c - `secure-sudo vault-allow ...`: manage the TimeVault exec
 * allowlist from the CLI itself (no external script needed).
 *
 *   vault-allow scan [-n] [-x] <dir>...   add every executable binary/script
 *   vault-allow add <file>...             add single files
 *   vault-allow remove <file>...          drop entries
 *   vault-allow list                      show the saved allowlist
 *   vault-allow wipe [-y] [--force]       empty the allowlist
 *
 * The persistent copy is /etc/secure_sudo/timevault_allow.conf, one entry per
 * line as "<path> <sha256hex>". Every change rewrites that file atomically and
 * then pushes the whole list to /sys/kernel/security/secure_sudo/timevault_allow
 * in a single write (the kernel replaces its list per write, so it must be one
 * write, not a stream of them).
 *
 * The kernel matches the *resolved* path of the exec'd file, so every path is
 * canonicalised with realpath(3) first; a symlink found during a scan is
 * added as its target. "Executable" means a regular file with an x bit set
 * whose first bytes are an ELF header or a "#!" interpreter line.
 *
 * Root-only: main() has already called require_root() before dispatching here,
 * and the kernel side refuses writes without CAP_SYS_ADMIN regardless.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <ftw.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#include "cli.h"

#define VA_CONF      CONFIG_DIR "/timevault_allow.conf"
#define VA_SECFS     SECFS "/timevault_allow"
#define VA_LOCKFILE  "/run/secure_sudo-vault-allow.lock"

/* Must match TV_MAX_ITEMS / TV_MAX_TEXT in kernel ss_timevault.c. */
#define VA_MAX_ITEMS 16384
#define VA_MAX_TEXT  (4 * 1024 * 1024)

/* One line of the conf file. Comment/blank lines keep path == NULL so the
 * file's header and any notes the admin wrote survive a rewrite. */
struct va_line {
	char *raw;	/* comment/blank line text (path == NULL) */
	char *path;	/* entry path */
	char hash[65];	/* entry hash, "" if none */
};

static struct va_line *va;
static size_t va_n, va_cap;
static int va_dirty;

/* --- scan state (nftw callbacks take no user pointer) --- */
static int scan_dry_run;
static size_t scan_added, scan_updated, scan_same, scan_skipped;

static int va_push(struct va_line *l)
{
	if (va_n == va_cap) {
		size_t cap = va_cap ? va_cap * 2 : 256;
		struct va_line *n = realloc(va, cap * sizeof(*va));

		if (!n)
			return -1;
		va = n;
		va_cap = cap;
	}
	va[va_n++] = *l;
	return 0;
}

static size_t va_entries(void)
{
	size_t i, c = 0;

	for (i = 0; i < va_n; i++)
		if (va[i].path)
			c++;
	return c;
}

static ssize_t va_find(const char *path)
{
	size_t i;

	for (i = 0; i < va_n; i++)
		if (va[i].path && !strcmp(va[i].path, path))
			return (ssize_t)i;
	return -1;
}

/* Parse the conf file (missing file = empty list). */
static int va_load(void)
{
	FILE *f = fopen(VA_CONF, "re");
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;

	if (!f)
		return errno == ENOENT ? 0 : -1;

	while ((len = getline(&line, &cap, f)) >= 0) {
		struct va_line l = { 0 };
		char *p = line, *sp;

		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		while (*p == ' ' || *p == '\t')
			p++;

		if (*p != '/') {
			l.raw = strdup(line);
		} else {
			sp = strchr(p, ' ');
			if (sp) {
				*sp++ = '\0';
				while (*sp == ' ')
					sp++;
				if (strlen(sp) == 64)
					memcpy(l.hash, sp, 65);
			}
			l.path = strdup(p);
		}
		if ((!l.raw && !l.path) || va_push(&l)) {
			fclose(f);
			free(line);
			return -1;
		}
	}
	free(line);
	fclose(f);
	return 0;
}

/* Serialise the list into one buffer (also what the kernel gets). */
static char *va_render(size_t *out_len)
{
	size_t i, cap = 4096, len = 0;
	char *buf = malloc(cap);

	if (!buf)
		return NULL;
	for (i = 0; i < va_n; i++) {
		size_t need = (va[i].path ? strlen(va[i].path) + 66 :
					    strlen(va[i].raw)) + 2;

		if (len + need + 1 > cap) {
			while (len + need + 1 > cap)
				cap *= 2;
			char *n = realloc(buf, cap);
			if (!n) {
				free(buf);
				return NULL;
			}
			buf = n;
		}
		if (!va[i].path)
			len += sprintf(buf + len, "%s\n", va[i].raw);
		else if (va[i].hash[0])
			len += sprintf(buf + len, "%s %s\n", va[i].path, va[i].hash);
		else
			len += sprintf(buf + len, "%s\n", va[i].path);
	}
	buf[len] = '\0';
	*out_len = len;
	return buf;
}

/* Atomically replace the conf file, then push the list into the kernel. */
static int va_save_and_push(void)
{
	char tmp[] = CONFIG_DIR "/.timevault_allow.conf.XXXXXX";
	size_t len;
	char *buf;
	int fd, rc = 0;

	if (va_entries() > VA_MAX_ITEMS) {
		fprintf(stderr, "secure-sudo: %zu entries exceeds the kernel limit of %d; "
			"nothing saved. Scan narrower directories.\n",
			va_entries(), VA_MAX_ITEMS);
		return -1;
	}
	buf = va_render(&len);
	if (!buf) {
		fprintf(stderr, "secure-sudo: out of memory\n");
		return -1;
	}
	if (len > VA_MAX_TEXT) {
		fprintf(stderr, "secure-sudo: allowlist is %zu bytes, kernel limit is %d; "
			"nothing saved.\n", len, VA_MAX_TEXT);
		free(buf);
		return -1;
	}

	mkdir(CONFIG_DIR, 0755);
	fd = mkstemp(tmp);
	if (fd < 0 || fchmod(fd, 0600) ||
	    (len && write(fd, buf, len) != (ssize_t)len) || fsync(fd) ||
	    close(fd) || rename(tmp, VA_CONF)) {
		fprintf(stderr, "secure-sudo: saving %s: %s\n", VA_CONF,
			strerror(errno));
		if (fd >= 0)
			unlink(tmp);
		free(buf);
		return -1;
	}

	if (access(VA_SECFS, F_OK) != 0) {
		printf("secure-sudo: saved %s (kernel LSM not active; it will be "
		       "loaded at next boot)\n", VA_CONF);
	} else {
		/* Empty list: a lone newline clears it. */
		if (len == 0)
			rc = write_file(VA_SECFS, "\n", 1);
		else
			rc = write_file(VA_SECFS, buf, len);
		if (rc != 0)
			fprintf(stderr, "secure-sudo: saved %s but the kernel refused "
				"the update (config locked? it applies after reboot)\n",
				VA_CONF);
		else
			printf("secure-sudo: %zu allowlist entries saved and loaded\n",
			       va_entries());
	}
	free(buf);
	return rc;
}

static int sha256_file(const char *path, char out[65])
{
	unsigned char md[EVP_MAX_MD_SIZE], buf[65536];
	unsigned int mdlen = 0, i;
	EVP_MD_CTX *ctx;
	ssize_t n;
	int fd, rc = -1;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	ctx = EVP_MD_CTX_new();
	if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
		while ((n = read(fd, buf, sizeof(buf))) > 0)
			if (!EVP_DigestUpdate(ctx, buf, n))
				break;
		if (n == 0 && EVP_DigestFinal_ex(ctx, md, &mdlen) && mdlen == 32) {
			for (i = 0; i < 32; i++)
				sprintf(out + i * 2, "%02x", md[i]);
			out[64] = '\0';
			rc = 0;
		}
	}
	EVP_MD_CTX_free(ctx);
	close(fd);
	return rc;
}

/* Regular file, some x bit, and starts with ELF magic or "#!". */
static int is_executable(const char *path, const struct stat *st)
{
	unsigned char magic[4] = { 0 };
	ssize_t n;
	int fd;

	if (!S_ISREG(st->st_mode) || !(st->st_mode & 0111))
		return 0;
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return 0;
	n = read(fd, magic, sizeof(magic));
	close(fd);
	if (n >= 4 && !memcmp(magic, "\x7f" "ELF", 4))
		return 1;
	if (n >= 2 && magic[0] == '#' && magic[1] == '!')
		return 1;
	return 0;
}

/* The kernel splits each line on the first space, so such paths can't be
 * represented; newlines would split the line itself. */
static int path_representable(const char *p)
{
	return !strpbrk(p, " \t\n\r");
}

enum { VA_ADDED, VA_UPDATED, VA_SAME, VA_ERR };

/* Add or refresh one canonical path. */
static int va_upsert(const char *real)
{
	struct va_line l = { 0 };
	char hash[65];
	ssize_t i;

	if (sha256_file(real, hash) != 0) {
		fprintf(stderr, "secure-sudo: cannot hash %s: %s\n", real,
			strerror(errno));
		return VA_ERR;
	}
	i = va_find(real);
	if (i >= 0) {
		if (!strcmp(va[i].hash, hash))
			return VA_SAME;
		memcpy(va[i].hash, hash, 65);
		va_dirty = 1;
		return VA_UPDATED;
	}
	l.path = strdup(real);
	memcpy(l.hash, hash, 65);
	if (!l.path || va_push(&l))
		return VA_ERR;
	va_dirty = 1;
	return VA_ADDED;
}

static int scan_cb(const char *fpath, const struct stat *sb, int type,
		   struct FTW *ftw)
{
	char real[PATH_MAX];
	struct stat st;
	int r;

	(void)ftw;
	if (type != FTW_F && type != FTW_SL)
		return 0;
	/* Canonicalise (resolves symlinks to what the kernel will see). */
	if (!realpath(fpath, real) || stat(real, &st) != 0)
		return 0;
	if (type == FTW_F)
		st = *sb;
	if (!is_executable(real, &st))
		return 0;
	if (!path_representable(real)) {
		fprintf(stderr, "secure-sudo: skipping %s (whitespace in path)\n", real);
		scan_skipped++;
		return 0;
	}
	if (scan_dry_run) {
		printf("%s\n", real);
		scan_added++;
		return 0;
	}
	r = va_upsert(real);
	if (r == VA_ADDED) scan_added++;
	else if (r == VA_UPDATED) scan_updated++;
	else if (r == VA_SAME) scan_same++;
	else scan_skipped++;
	return 0;
}

static int cmd_scan(int argc, char **argv)
{
	int flags = FTW_PHYS, i, first = -1;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-n") || !strcmp(argv[i], "--dry-run"))
			scan_dry_run = 1;
		else if (!strcmp(argv[i], "-x") || !strcmp(argv[i], "--one-file-system"))
			flags |= FTW_MOUNT;
		else if (argv[i][0] == '-')
			return fprintf(stderr, "secure-sudo: unknown option %s\n", argv[i]), 2;
		else if (first < 0)
			first = i;
	}
	if (first < 0)
		return fprintf(stderr, "usage: secure-sudo vault-allow scan [-n] [-x] <dir>...\n"), 2;

	for (i = first; i < argc; i++) {
		char real[PATH_MAX];
		struct stat st;

		if (argv[i][0] == '-')
			continue;
		if (!realpath(argv[i], real) || stat(real, &st) || !S_ISDIR(st.st_mode)) {
			fprintf(stderr, "secure-sudo: %s is not a directory\n", argv[i]);
			return 1;
		}
		if (!strcmp(real, "/"))
			fprintf(stderr, "secure-sudo: warning: scanning all of / "
				"(this may exceed the %d-entry limit)\n", VA_MAX_ITEMS);
		if (nftw(real, scan_cb, 64, flags) != 0)
			fprintf(stderr, "secure-sudo: walk of %s incomplete: %s\n",
				real, strerror(errno));
	}

	if (scan_dry_run) {
		printf("secure-sudo: %zu executables would be added (dry run)\n",
		       scan_added);
		return 0;
	}
	printf("secure-sudo: scan: %zu added, %zu re-hashed, %zu unchanged, %zu skipped\n",
	       scan_added, scan_updated, scan_same, scan_skipped);
	return va_dirty ? (va_save_and_push() == 0 ? 0 : 1) : 0;
}

static int cmd_add(int argc, char **argv)
{
	int i, rc = 0;

	if (argc < 1)
		return fprintf(stderr, "usage: secure-sudo vault-allow add <file>...\n"), 2;
	for (i = 0; i < argc; i++) {
		char real[PATH_MAX];
		struct stat st;
		int r;

		if (!realpath(argv[i], real) || stat(real, &st) != 0) {
			fprintf(stderr, "secure-sudo: %s: %s\n", argv[i], strerror(errno));
			rc = 1;
			continue;
		}
		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr, "secure-sudo: %s is not a regular file\n", real);
			rc = 1;
			continue;
		}
		if (!path_representable(real)) {
			fprintf(stderr, "secure-sudo: %s has whitespace in its path; "
				"the kernel allowlist can't hold it\n", real);
			rc = 1;
			continue;
		}
		if (!is_executable(real, &st))
			fprintf(stderr, "secure-sudo: note: %s is not an executable "
				"binary/script; adding anyway\n", real);
		r = va_upsert(real);
		if (r == VA_ERR)
			rc = 1;
		else
			printf("%s %s\n", r == VA_ADDED ? "added  " :
			       r == VA_UPDATED ? "updated" : "same   ", real);
	}
	if (va_dirty && va_save_and_push() != 0)
		rc = 1;
	return rc;
}

static int cmd_remove(int argc, char **argv)
{
	int i, rc = 0;

	if (argc < 1)
		return fprintf(stderr, "usage: secure-sudo vault-allow remove <file>...\n"), 2;
	for (i = 0; i < argc; i++) {
		char real[PATH_MAX];
		const char *p = realpath(argv[i], real) ? real : argv[i];
		ssize_t at = va_find(p);

		if (at < 0) {
			fprintf(stderr, "secure-sudo: %s is not in the allowlist\n", p);
			rc = 1;
			continue;
		}
		free(va[at].path);
		memmove(&va[at], &va[at + 1], (va_n - at - 1) * sizeof(*va));
		va_n--;
		va_dirty = 1;
		printf("removed %s\n", p);
	}
	if (va_dirty && va_save_and_push() != 0)
		rc = 1;
	return rc;
}

static int cmd_list(void)
{
	size_t i;

	for (i = 0; i < va_n; i++)
		if (va[i].path)
			printf("%s %s\n", va[i].path,
			       va[i].hash[0] ? va[i].hash : "(any hash)");
	fprintf(stderr, "%zu entries in %s\n", va_entries(), VA_CONF);
	return 0;
}

static int vault_engaged(void)
{
	char c = '0';
	int fd = open(SYSFS "/timevault", O_RDONLY);

	if (fd >= 0) {
		if (read(fd, &c, 1) != 1)
			c = '0';
		close(fd);
	}
	return c == '1';
}

static int cmd_wipe(int argc, char **argv)
{
	int yes = 0, force = 0, i;
	size_t w = 0;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-y") || !strcmp(argv[i], "--yes"))
			yes = 1;
		else if (!strcmp(argv[i], "--force"))
			force = 1;
		else
			return fprintf(stderr, "usage: secure-sudo vault-allow wipe [-y] [--force]\n"), 2;
	}
	if (vault_engaged() && !force) {
		fprintf(stderr, "secure-sudo: TimeVault is engaged; an empty allowlist "
			"would block nearly every exec. Disengage it first, or pass --force.\n");
		return 1;
	}
	if (!yes) {
		char ans[16] = "";

		fprintf(stderr, "Wipe all %zu TimeVault allowlist entries? Type 'yes': ",
			va_entries());
		if (!fgets(ans, sizeof(ans), stdin) || strcmp(ans, "yes\n")) {
			fprintf(stderr, "aborted\n");
			return 1;
		}
	}
	/* Keep comments/header lines, drop every entry. */
	for (i = 0; (size_t)i < va_n; i++) {
		if (va[i].path)
			free(va[i].path);
		else
			va[w++] = va[i];
	}
	va_n = w;
	return va_save_and_push() == 0 ? 0 : 1;
}

void vault_allow_usage(void)
{
	fprintf(stderr,
"  vault-allow scan [-n] [-x] <dir>...  hash + allow every executable binary/script\n"
"                                       (-n dry run, -x stay on one filesystem)\n"
"  vault-allow add <file>...            hash + allow single files\n"
"  vault-allow remove <file>...         remove entries\n"
"  vault-allow list                     show the saved allowlist\n"
"  vault-allow wipe [-y] [--force]      empty the allowlist\n");
}

int cmd_vault_allow(int argc, char **argv)
{
	const char *sub;
	int lockfd, rc;

	if (argc < 1) {
		vault_allow_usage();
		return 2;
	}
	sub = argv[0];

	/* Serialise concurrent edits (another admin, the daemon, a cron scan). */
	lockfd = open(VA_LOCKFILE, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (lockfd < 0 || flock(lockfd, LOCK_EX) != 0) {
		fprintf(stderr, "secure-sudo: cannot lock %s: %s\n", VA_LOCKFILE,
			strerror(errno));
		return 1;
	}
	if (va_load() != 0) {
		fprintf(stderr, "secure-sudo: cannot read %s: %s\n", VA_CONF,
			strerror(errno));
		close(lockfd);
		return 1;
	}

	if (!strcmp(sub, "scan"))
		rc = cmd_scan(argc - 1, argv + 1);
	else if (!strcmp(sub, "add"))
		rc = cmd_add(argc - 1, argv + 1);
	else if (!strcmp(sub, "remove") || !strcmp(sub, "rm"))
		rc = cmd_remove(argc - 1, argv + 1);
	else if (!strcmp(sub, "list") || !strcmp(sub, "ls"))
		rc = cmd_list();
	else if (!strcmp(sub, "wipe"))
		rc = cmd_wipe(argc - 1, argv + 1);
	else {
		vault_allow_usage();
		rc = 2;
	}
	close(lockfd);
	return rc;
}
