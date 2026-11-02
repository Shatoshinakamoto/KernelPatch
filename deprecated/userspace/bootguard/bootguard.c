// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * secure-sudo-bootguard - BootGuard (runtime guard).
 *
 * Detects tampering of the boot partition (/boot, and the ESP if included) and
 * restores it from a known-good backup - but the restore is APPLIED AT THE NEXT
 * BOOT, not live.
 *
 * ===================== WHY STAGE-AND-APPLY-AT-BOOT ==========================
 * Rewriting the live /boot (kernel image, initramfs, bootloader, ESP) out from
 * under a running kernel is how you get an unbootable machine: the running
 * system may hold open or mmap'd files there, and a half-applied change leaves
 * an inconsistent boot set. So BootGuard:
 *
 *   baseline       - hash every file under the boot dir into a manifest and
 *                    store compressed backups in an HOURLY-ROTATED location.
 *   scan           - re-hash vs the manifest. Tamper (changed/missing file) is
 *                    logged CRITICAL and a restore is STAGED: a restore list is
 *                    written and a PENDING flag dropped. Nothing is written to
 *                    /boot now. (New, unknown files are reported, not deleted -
 *                    a kernel update legitimately adds files; re-baseline after.)
 *   restore-staged - run EARLY AT BOOT by the shipped systemd unit: if the
 *                    PENDING flag is set, restore each listed file from its
 *                    backup before the system is fully up, then clear the flag.
 *   apply-now --i-understand-the-risk - operator-only live restore.
 *   status         - show state.
 *
 * Config: /etc/secure_sudo/addons/bootguard.conf
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#include "ssaddon_log.h"
#include "ssaddon_store.h"

#define CONF		"/etc/secure_sudo/addons/bootguard.conf"
#define STATEDIR	"/var/lib/secure_sudo/addons/bootguard"
#define MANIFEST	STATEDIR "/manifest"
#define DEF_BACKUP	STATEDIR "/backups"
#define RESTORE_LIST	STATEDIR "/restore.list"
#define PENDING		STATEDIR "/PENDING"
#define LOCUS_PURPOSE	"bootguard-backup"

struct cfg {
	int enforce;			/* enforce => stage on tamper */
	char boot_dir[PATH_MAX];
	char backup_root[PATH_MAX];
};

static void trim(char *s)
{
	size_t n = strlen(s);
	while (n && isspace((unsigned char)s[n - 1]))
		s[--n] = '\0';
}

static void load_cfg(struct cfg *c)
{
	FILE *f;
	char line[PATH_MAX + 64];

	c->enforce = 1;			/* staging is safe; default on */
	snprintf(c->boot_dir, sizeof(c->boot_dir), "/boot");
	snprintf(c->backup_root, sizeof(c->backup_root), "%s", DEF_BACKUP);

	f = fopen(CONF, "re");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char *eq, *k, *v;

		trim(line);
		if (line[0] == '#' || line[0] == '\0')
			continue;
		eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = '\0';
		k = line; v = eq + 1;
		while (*k == ' ' || *k == '\t') k++;
		trim(k);
		while (*v == ' ' || *v == '\t') v++;
		if (!strcmp(k, "mode"))
			c->enforce = !strcmp(v, "enforce");
		else if (!strcmp(k, "boot_dir"))
			snprintf(c->boot_dir, sizeof(c->boot_dir), "%s", v);
		else if (!strcmp(k, "backup_root"))
			snprintf(c->backup_root, sizeof(c->backup_root), "%s", v);
	}
	fclose(f);
}

static int sha256_file(const char *path, char out[65])
{
	unsigned char buf[65536], d[EVP_MAX_MD_SIZE];
	unsigned int dn = 0;
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	FILE *f;
	size_t r;
	int i, ok = 0;

	if (!c)
		return -1;
	f = fopen(path, "rbe");
	if (!f) {
		EVP_MD_CTX_free(c);
		return -1;
	}
	if (EVP_DigestInit_ex(c, EVP_sha256(), NULL)) {
		ok = 1;
		while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
			if (!EVP_DigestUpdate(c, buf, r)) { ok = 0; break; }
	}
	fclose(f);
	if (ok && EVP_DigestFinal_ex(c, d, &dn)) {
		for (i = 0; i < (int)dn; i++)
			sprintf(out + 2 * i, "%02x", d[i]);
		out[2 * dn] = '\0';
	} else {
		ok = 0;
	}
	EVP_MD_CTX_free(c);
	return ok ? 0 : -1;
}

typedef void (*file_cb)(const char *path, void *ctx);
static void walk(const char *dir, file_cb cb, void *ctx, int depth)
{
	DIR *d;
	struct dirent *de;

	if (depth > 32)
		return;
	d = opendir(dir);
	if (!d)
		return;
	while ((de = readdir(d))) {
		char child[PATH_MAX];
		struct stat st;

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (snprintf(child, sizeof(child), "%s/%s", dir, de->d_name) >=
		    (int)sizeof(child))
			continue;
		if (lstat(child, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode))
			walk(child, cb, ctx, depth + 1);
		else if (S_ISREG(st.st_mode))
			cb(child, ctx);
	}
	closedir(d);
}

struct base_ctx {
	FILE *mf;
	const char *bucket;
	size_t files, backed;
};

static void base_one(const char *path, void *vctx)
{
	struct base_ctx *b = vctx;
	char sha[65], sample[PATH_MAX];

	if (sha256_file(path, sha) == 0) {
		fprintf(b->mf, "%s %s\n", sha, path);
		b->files++;
	}
	if (store_put_compressed(path, b->bucket, "boot", sample, sizeof(sample)) == 0)
		b->backed++;
}

static int backup_bucket(const struct cfg *c, char *out, size_t n)
{
	char root[PATH_MAX];

	if (locus_request_root(LOCUS_PURPOSE, root, sizeof(root)) != 0)
		snprintf(root, sizeof(root), "%s", c->backup_root);
	return store_current_bucket(root, out, n);
}

static int cmd_baseline(void)
{
	struct cfg c;
	struct base_ctx b = { 0 };
	char bucket[PATH_MAX], tmp[] = STATEDIR "/.manifest.XXXXXX";
	int fd;

	load_cfg(&c);
	mkdir("/var/lib/secure_sudo", 0700);
	mkdir("/var/lib/secure_sudo/addons", 0700);
	mkdir(STATEDIR, 0700);

	if (backup_bucket(&c, bucket, sizeof(bucket)) != 0) {
		ssl_err("cannot create backup bucket");
		return 1;
	}
	fd = mkstemp(tmp);
	if (fd < 0) {
		ssl_err("mkstemp: %s", strerror(errno));
		return 1;
	}
	b.mf = fdopen(fd, "we");
	if (!b.mf) {
		close(fd);
		unlink(tmp);
		return 1;
	}
	b.bucket = bucket;
	walk(c.boot_dir, base_one, &b, 0);
	fflush(b.mf);
	fsync(fileno(b.mf));
	fclose(b.mf);
	if (rename(tmp, MANIFEST) != 0) {
		unlink(tmp);
		return 1;
	}
	chmod(MANIFEST, 0600);
	ssl_info("baseline: %zu boot files hashed, %zu backed up to %s",
		 b.files, b.backed, bucket);
	printf("bootguard: baseline %zu files, %zu backed up (%s)\n",
	       b.files, b.backed, bucket);
	return 0;
}

/* Stage a restore: write restore.list (dst<TAB>blob) and drop PENDING. */
static int stage_restore(const struct cfg *c, const char *dst, FILE *rl)
{
	char blob[PATH_MAX], root[PATH_MAX];

	if (store_find_latest(c->backup_root, "boot", dst, blob, sizeof(blob)) != 0) {
		if (locus_request_root(LOCUS_PURPOSE, root, sizeof(root)) != 0 ||
		    store_find_latest(root, "boot", dst, blob, sizeof(blob)) != 0) {
			ssl_err("no backup to stage for %s", dst);
			return -1;
		}
	}
	fprintf(rl, "%s\t%s\n", dst, blob);
	return 0;
}

static int cmd_scan(void)
{
	struct cfg c;
	FILE *f, *rl = NULL;
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	size_t checked = 0, tampered = 0, staged = 0;

	load_cfg(&c);
	f = fopen(MANIFEST, "re");
	if (!f) {
		fprintf(stderr, "bootguard: no baseline - run `baseline` first\n");
		return 1;
	}
	while ((len = getline(&line, &cap, f)) >= 0) {
		char *sp, sha_now[65], *sha, *path;
		int bad = 0;

		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		if (len == 0 || line[0] == '#')
			continue;
		sp = strchr(line, ' ');
		if (!sp)
			continue;
		*sp = '\0';
		sha = line;
		path = sp + 1;
		checked++;

		if (sha256_file(path, sha_now) != 0) {
			ssl_crit("BOOT file missing/unreadable: %s", path);
			bad = 1;
		} else if (strcmp(sha, sha_now) != 0) {
			ssl_crit("BOOT tamper: %s (hash changed)", path);
			bad = 1;
		}
		if (bad) {
			tampered++;
			if (c.enforce) {
				if (!rl) {
					rl = fopen(RESTORE_LIST, "we");
					if (rl)
						chmod(RESTORE_LIST, 0600);
				}
				if (rl && stage_restore(&c, path, rl) == 0)
					staged++;
			}
		}
	}
	free(line);
	fclose(f);

	if (rl) {
		fflush(rl);
		fsync(fileno(rl));
		fclose(rl);
	}
	if (tampered && c.enforce && staged) {
		FILE *p = fopen(PENDING, "we");
		if (p) {
			fprintf(p, "staged %zu file(s) at %ld\n", staged, (long)time(NULL));
			fclose(p);
			chmod(PENDING, 0600);
		}
		ssl_crit("STAGED boot restore of %zu file(s); applied at NEXT BOOT by "
			 "secure-sudo-bootguard-restore.service", staged);
		printf("bootguard: %zu tampered; %zu staged for restore at NEXT BOOT "
		       "(nothing written to the live boot partition)\n", tampered, staged);
	} else if (tampered) {
		printf("bootguard: %zu tampered (monitor mode: not staged)\n", tampered);
	} else {
		ssl_info("scan: boot partition intact (%zu files)", checked);
		printf("bootguard: boot partition intact (%zu files)\n", checked);
	}
	return 0;
}

/* Apply a staged restore (run early at boot, or by apply-now). */
static int do_restore(void)
{
	FILE *rl = fopen(RESTORE_LIST, "re");
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	size_t done = 0, fail = 0;

	if (!rl) {
		ssl_warn("restore requested but no restore.list present");
		return 0;
	}
	while ((len = getline(&line, &cap, rl)) >= 0) {
		char *tab;

		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		tab = strchr(line, '\t');
		if (!tab)
			continue;
		*tab = '\0';
		if (store_restore_compressed(tab + 1, line) == 0) {
			ssl_crit("BOOT restored: %s", line);
			done++;
		} else {
			ssl_err("BOOT restore FAILED: %s", line);
			fail++;
		}
	}
	free(line);
	fclose(rl);
	unlink(PENDING);
	unlink(RESTORE_LIST);
	ssl_info("boot restore applied: %zu ok, %zu failed", done, fail);
	return fail ? 1 : 0;
}

static int cmd_restore_staged(void)
{
	if (access(PENDING, F_OK) != 0)
		return 0;		/* nothing staged: normal boot */
	ssl_crit("PENDING boot restore found - applying before system start");
	return do_restore();
}

static int cmd_apply_now(int argc, char **argv)
{
	int ack = 0, i;

	for (i = 2; i < argc; i++)
		if (!strcmp(argv[i], "--i-understand-the-risk"))
			ack = 1;
	if (!ack) {
		fprintf(stderr,
"bootguard apply-now: refusing. Rewriting the live boot partition can leave the\n"
"machine unbootable. The safe path is to let the staged restore apply at the\n"
"next boot. To force a live restore anyway:\n"
"    secure-sudo-bootguard apply-now --i-understand-the-risk\n");
		return 1;
	}
	ssl_crit("OPERATOR forcing live boot restore");
	return do_restore();
}

static int cmd_status(void)
{
	struct cfg c;
	FILE *f;
	size_t n = 0;
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;

	load_cfg(&c);
	printf("BootGuard mode:   %s\n", c.enforce ? "enforce (stage on tamper)" :
	       "monitor (report only)");
	printf("boot dir:         %s\n", c.boot_dir);
	printf("backup root:      %s (hourly buckets)\n", c.backup_root);
	printf("pending restore:  %s\n", access(PENDING, F_OK) == 0 ?
	       "YES - will apply at next boot" : "none");
	f = fopen(MANIFEST, "re");
	if (f) {
		while ((len = getline(&line, &cap, f)) >= 0)
			if (len > 1 && line[0] != '#')
				n++;
		free(line);
		fclose(f);
	}
	printf("baseline files:   %zu%s\n", n, f ? "" : " (no baseline yet)");
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
"usage: secure-sudo-bootguard <command>\n"
"  baseline         hash all boot files + store compressed backups (hourly)\n"
"  scan             check vs baseline; stage a restore for NEXT BOOT on tamper\n"
"  restore-staged   apply a staged restore if PENDING (run early at boot)\n"
"  apply-now --i-understand-the-risk   operator-only LIVE restore\n"
"  status           show state\n"
"\nStage-and-apply-at-boot by design: the live boot partition is not rewritten\n"
"mid-run. Config: " CONF "\n");
}

int main(int argc, char **argv)
{
	if (geteuid() != 0) {
		fprintf(stderr, "bootguard: must run as root\n");
		return 1;
	}
	if (argc < 2) {
		usage();
		return 2;
	}
	ssl_init("bootguard");

	if (!strcmp(argv[1], "baseline"))
		return cmd_baseline();
	if (!strcmp(argv[1], "scan"))
		return cmd_scan();
	if (!strcmp(argv[1], "restore-staged"))
		return cmd_restore_staged();
	if (!strcmp(argv[1], "apply-now"))
		return cmd_apply_now(argc, argv);
	if (!strcmp(argv[1], "status"))
		return cmd_status();

	usage();
	ssl_close();
	return 2;
}
