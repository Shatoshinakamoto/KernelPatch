// SPDX-License-Identifier: Apache-2.0
/*
 * secure-sudo-driverguard - DriverGuard (v8 temporary add-on).
 *
 * Watches the kernel's on-disk driver (module) files for tampering and can
 * repair a damaged or swapped driver from a failsafe backup.
 *
 *   baseline  - hash every module under the driver tree into a SHA-256 manifest
 *               AND store a compressed failsafe backup of each module file in an
 *               HOURLY-ROTATED backup location (so the backups are versioned by
 *               the hour and a fixed path can't be targeted to poison them).
 *   backup    - refresh the hourly compressed backups (does not touch the
 *               manifest; use when you have legitimately updated drivers and
 *               already re-run baseline).
 *   scan      - re-hash each module vs the manifest. A mismatch, or a module
 *               that has gone missing, is a tamper/"driver infection". In
 *               enforce mode the module is restored from the newest backup that
 *               has it; in monitor mode it is only reported.
 *   refresh R - re-baseline after a legitimate change (a package or DKMS
 *               update), logging it CRITICAL with the reason, so enforce mode
 *               does not roll the update back. Run by the package hooks.
 *               No baseline yet: does nothing.
 *   arm       - let enforce mode act. Turned to enforce, DriverGuard reports
 *               only, until a pass finds nothing to repair (it then arms
 *               itself) or the operator arms it after reading the report.
 *   status    - show configuration and manifest size.
 *
 * A scan while a package manager holds its lock is deferred.
 *
 * All output goes through the shared ssaddon_log (local + optional off-box);
 * backups use the shared ssaddon_store (same compressed format as everywhere).
 *
 * Note: this protects the driver FILES on disk. A module already loaded into a
 * running kernel is the kernel LSM's job (#6 driver-BYOVD hashes the loaded
 * bytes). DriverGuard makes sure the files the kernel will load next boot - and
 * that modprobe pulls in at runtime - are the known-good ones, and heals them
 * if something rewrote them.
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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <openssl/evp.h>

#include "ssaddon_log.h"
#include "ssaddon_store.h"
#include "ssaddon_conf.h"
#include "ssaddon_trust.h"

/* Overridable for the tests only (tests/userspace/test-addons.sh). */
#ifndef DG_CONF
#define DG_CONF		"/etc/secure_sudo/addons/driverguard.conf"
#endif
#ifndef DG_STATEDIR
#define DG_STATEDIR	"/var/lib/secure_sudo/addons/driverguard"
#endif
#define CONF		DG_CONF
#define STATEDIR	DG_STATEDIR
#define MANIFEST	STATEDIR "/manifest"
#define DEF_BACKUP	STATEDIR "/backups"
#define LOCUS_PURPOSE	"driverguard-backup"

struct cfg {
	int enforce;
	int trust;			/* SST_LOCAL or SST_SIGNED (baseline_trust) */
	int rotate;			/* 1 = hourly-rotating backups, 0 = fixed */
	char driver_dir[PATH_MAX];	/* module tree root */
	char backup_root[PATH_MAX];
};

static void default_driver_dir(char *out, size_t n)
{
	struct utsname u;

	if (uname(&u) == 0)
		snprintf(out, n, "/lib/modules/%s", u.release);
	else
		snprintf(out, n, "/lib/modules");
}

static int load_cfg(struct cfg *c, FILE *report)
{
	static const char *const modes[] = { "monitor", "enforce", NULL };
	const struct ssc_key keys[] = {
		{ "mode", SSC_ENUM, &c->enforce, 0, 0, 0, modes },
		{ "rotate", SSC_INT, &c->rotate, 0, 0, 1, NULL },
		{ "driver_dir", SSC_PATH, c->driver_dir, sizeof(c->driver_dir), 1, 0, NULL },
		{ "backup_root", SSC_PATH, c->backup_root, sizeof(c->backup_root), 1, 0, NULL },
		{ "baseline_trust", SSC_ENUM, &c->trust, 0, 0, 0, sst_modes },
		SSC_END
	};

	c->enforce = 0;
	c->trust = SST_LOCAL;
	c->rotate = 1;
	default_driver_dir(c->driver_dir, sizeof(c->driver_dir));
	snprintf(c->backup_root, sizeof(c->backup_root), "%s", DEF_BACKUP);
	return ssc_parse(CONF, keys, NULL, NULL, report);
}

/* Every file DriverGuard reads, checked strictly (P2-2). */
static int conf_errors(FILE *r)
{
	struct cfg c;

	return load_cfg(&c, r) + ssl_check_conf(r) + locus_check_conf(r);
}

/* Does this filename look like a kernel module? */
static int is_module(const char *name)
{
	const char *dot = strrchr(name, '.');

	if (!dot)
		return 0;
	return !strcmp(dot, ".ko") || !strcmp(dot, ".zst") ||
	       !strcmp(dot, ".xz") || !strcmp(dot, ".gz");
}

/* Walk the module tree, calling cb(abspath) for each module file. */
typedef void (*mod_cb)(const char *path, void *ctx);
static void walk_modules(const char *dir, mod_cb cb, void *ctx, int depth)
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
			walk_modules(child, cb, ctx, depth + 1);
		else if (S_ISREG(st.st_mode) && is_module(de->d_name))
			cb(child, ctx);
	}
	closedir(d);
}

/* ---- baseline / backup ---- */
struct base_ctx {
	FILE *mf;			/* manifest (NULL when only backing up) */
	const char *backup_bucket;
	const char *root;		/* the driver tree */
	size_t files, backed, failed;
};

static void base_one(const char *path, void *vctx)
{
	struct base_ctx *b = vctx;
	char sha[65], sample[PATH_MAX];

	/* one entry per line: a name that could break the manifest's format
	 * (a newline) or step out of the tree is never recorded */
	if (!sst_path_within(b->root, path)) {
		ssl_crit("DRIVER odd file name skipped (not baselined): %s", path);
		return;
	}
	if (b->backup_bucket) {
		/* the manifest records the hash of exactly the bytes backed up,
		 * so a file rewritten mid-baseline cannot leave a baseline that
		 * its own backup does not match */
		if (store_put_compressed_sha(path, b->backup_bucket, "drv", sample,
					     sizeof(sample), b->mf ? sha : NULL) == 0) {
			b->backed++;
		} else {
			ssl_crit("DRIVER backup FAILED for %s (disk full, a symlink, or "
				 "it changed while being read)", path);
			b->failed++;
			return;
		}
	} else if (b->mf && sst_sha256_file(path, sha) != 0) {
		ssl_warn("could not hash %s", path);
		b->failed++;
		return;
	}
	if (b->mf) {
		fprintf(b->mf, "%s %s\n", sha, path);
		b->files++;
	}
}

/* Allocate (Locus or fallback) and create the backup bucket. Rotating mode may
 * use a Locus-allocated root; a fixed (rotation-off) backup stays local. */
static int backup_bucket(const struct cfg *c, char *out, size_t n)
{
	char root[PATH_MAX];

	if (c->rotate && locus_request_root(LOCUS_PURPOSE, root, sizeof(root)) == 0)
		;
	else
		snprintf(root, sizeof(root), "%s", c->backup_root);
	return store_bucket(root, c->rotate, out, n);
}

static int baseline_why(const char *why)
{
	struct cfg c;
	struct base_ctx b = { 0 };
	char bucket[PATH_MAX], tmp[] = STATEDIR "/.manifest.XXXXXX";
	int fd;

	load_cfg(&c, NULL);
	if (!strncmp(STATEDIR, "/var/lib/secure_sudo/", 21)) {
		mkdir("/var/lib/secure_sudo", 0700);
		mkdir("/var/lib/secure_sudo/addons", 0700);
	}
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
	b.backup_bucket = bucket;
	b.root = c.driver_dir;
	walk_modules(c.driver_dir, base_one, &b, 0);
	if (fflush(b.mf) != 0 || fsync(fileno(b.mf)) != 0 || ferror(b.mf)) {
		b.failed++;
		ssl_crit("DRIVER baseline: writing the manifest failed: %s", strerror(errno));
	}
	if (fclose(b.mf) != 0)
		b.failed++;
	if (b.failed) {
		/* A baseline that cannot back up what it records would make every
		 * later repair of those files impossible: keep the old one. */
		unlink(tmp);
		ssl_crit("DRIVER baseline REFUSED (%s): %zu module(s) could not be "
			 "backed up or recorded; the previous baseline is kept. Free "
			 "space under %s (or fix the files named above) and run it again",
			 why, b.failed, bucket);
		fprintf(stderr, "driverguard: baseline refused: %zu module(s) could not "
			"be backed up (see the log)\n", b.failed);
		return 1;
	}
	if (rename(tmp, MANIFEST) != 0) {
		unlink(tmp);
		return 1;
	}
	chmod(MANIFEST, 0600);
	sst_announce("driverguard", MANIFEST, why, c.trust);
	ssl_info("baseline: %zu modules hashed, %zu backed up to %s",
		 b.files, b.backed, bucket);
	printf("driverguard: baseline %zu modules, %zu backed up (%s)\n",
	       b.files, b.backed, bucket);
	return 0;
}

static int cmd_baseline(void)
{
	return baseline_why("baseline");
}

static int cmd_backup(void)
{
	struct cfg c;
	struct base_ctx b = { 0 };
	char bucket[PATH_MAX];

	load_cfg(&c, NULL);
	if (backup_bucket(&c, bucket, sizeof(bucket)) != 0) {
		ssl_err("cannot create backup bucket");
		return 1;
	}
	b.backup_bucket = bucket;
	b.root = c.driver_dir;
	walk_modules(c.driver_dir, base_one, &b, 0);
	if (b.failed) {
		ssl_crit("DRIVER backup incomplete: %zu module(s) could not be backed "
			 "up to %s", b.failed, bucket);
		return 1;
	}
	ssl_info("backup refreshed: %zu modules -> %s", b.backed, bucket);
	printf("driverguard: backed up %zu modules to %s\n", b.backed, bucket);
	return 0;
}

/* ---- scan / repair ---- */
static int repair_module(const struct cfg *c, const char *path, const char *sha)
{
	char root[PATH_MAX], used[PATH_MAX], why[PATH_MAX + 128];

	/* keep what is there now before it is overwritten; if it cannot be
	 * kept (disk full), it is not overwritten either */
	if (sst_evidence("driverguard", path, "repair", sha, NULL) != 0) {
		ssl_crit("DRIVER not repaired: %s: its current bytes could not be kept "
			 "as evidence", path);
		return -1;
	}
	/* Backups may live under the configured root or the Locus-named one;
	 * only one whose bytes match the baseline is ever written back. */
	if (sst_restore_from_backups(c->backup_root, "drv", path, sha, used,
				     sizeof(used), why, sizeof(why)) != 0 &&
	    (locus_request_root(LOCUS_PURPOSE, root, sizeof(root)) != 0 ||
	     sst_restore_from_backups(root, "drv", path, sha, used, sizeof(used),
				      why, sizeof(why)) != 0)) {
		ssl_err("DRIVER not repaired: %s: %s", path, why);
		return -1;
	}
	ssl_crit("DRIVER repaired: %s restored from %s (sha256 verified)", path, used);
	return 0;
}

static int cmd_scan(void)
{
	struct cfg c;
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	size_t checked = 0, tampered = 0, repaired = 0;
	char why[512];
	int untrusted = 0, act, armed;
	size_t outside = 0;
	struct stat lst;

	load_cfg(&c, NULL);
	{
		char lock[PATH_MAX];

		if (ssaddon_pkg_busy(lock, sizeof(lock))) {
			ssl_info("scan deferred: a package manager holds %s", lock);
			printf("driverguard: scan deferred: a package manager is "
			       "running (%s)\n", lock);
			return 0;
		}
	}
	f = fopen(MANIFEST, "re");
	if (!f) {
		fprintf(stderr, "driverguard: no baseline - run `baseline` first\n");
		return 1;
	}
	if (!sst_manifest_trusted(MANIFEST, c.trust, why, sizeof(why))) {
		untrusted = 1;
		ssl_crit("DRIVER baseline NOT TRUSTED (%s): reporting only, nothing "
			 "is repaired", why);
		printf("driverguard: baseline not trusted (%s): reporting only\n", why);
	}
	if (!c.enforce)
		sst_disarm("driverguard", STATEDIR);
	armed = c.enforce && sst_armed(STATEDIR);
	if (c.enforce && !armed)
		printf("driverguard: enforce mode is not armed yet: reporting only\n");
	act = c.enforce && !untrusted && armed;
	while ((len = getline(&line, &cap, f)) >= 0) {
		char *sp, sha_now[65];
		char *sha, *path;

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

		if (strlen(sha) != 64 || !sst_path_within(c.driver_dir, path)) {
			/* not written by `baseline`: never repaired over */
			ssl_crit("DRIVER baseline entry IGNORED: %s is not a file under "
				 "%s (edited baseline, or driver_dir changed: re-baseline)",
				 path, c.driver_dir);
			outside++;
			continue;
		}
		if (lstat(path, &lst) == 0 && S_ISLNK(lst.st_mode)) {
			ssl_crit("DRIVER tamper: %s was replaced by a symlink", path);
			tampered++;
			if (act && repair_module(&c, path, sha) == 0)
				repaired++;
			else if (c.enforce && !act)
				ssl_warn("DRIVER would repair %s (not armed)", path);
		} else if (sst_sha256_file(path, sha_now) != 0) {
			ssl_crit("DRIVER missing/unreadable: %s", path);
			tampered++;
			if (act && repair_module(&c, path, sha) == 0)
				repaired++;
			else if (c.enforce && !act)
				ssl_warn("DRIVER would repair %s (not armed)", path);
		} else if (strcmp(sha, sha_now) != 0) {
			ssl_crit("DRIVER tamper: %s (hash changed)", path);
			tampered++;
			if (act && repair_module(&c, path, sha) == 0)
				repaired++;
			else if (c.enforce && !act)
				ssl_warn("DRIVER would repair %s (not armed)", path);
		}
	}
	free(line);
	fclose(f);
	ssl_info("scan: %zu checked, %zu tampered, %zu repaired (%s)",
		 checked, tampered, repaired, c.enforce ? "enforce" : "monitor");
	printf("driverguard: %zu checked, %zu tampered, %zu repaired (%s)\n",
	       checked, tampered, repaired, c.enforce ? "enforce" : "monitor");
	if (c.enforce && !armed && !untrusted) {
		if (!tampered && !outside)
			sst_arm("driverguard", STATEDIR, "a clean enforce pass");
		else
			ssl_crit("ENFORCE NOT ARMED: driverguard would have repaired %zu "
				 "module(s); read the report, then run "
				 "`secure-sudo-driverguard arm` to let it act", tampered);
	}
	return untrusted || outside ? 3 : 0;	/* a failed unit is reported */
}

static int cmd_arm(void)
{
	struct cfg c;

	load_cfg(&c, NULL);
	if (!c.enforce) {
		fprintf(stderr, "driverguard: mode is monitor; set mode = enforce first\n");
		return 1;
	}
	return sst_arm("driverguard", STATEDIR, "armed by the operator") ? 1 : 0;
}

static int cmd_refresh(const char *reason)
{
	char why[64];
	size_t i, j = 0;
	int rc;

	for (i = 0; reason && reason[i] && j + 1 < sizeof(why); i++)
		if (isalnum((unsigned char)reason[i]) || strchr("._-", reason[i]))
			why[j++] = reason[i];
	why[j] = '\0';
	if (access(MANIFEST, F_OK) != 0) {
		printf("driverguard: no baseline; nothing to refresh\n");
		return 0;
	}
	rc = baseline_why(j ? why : "refresh");
	if (rc == 0)
		ssl_crit("DRIVER baseline refreshed (%s): the current module files "
			 "are now the known-good ones", j ? why : "manual");
	return rc;
}

static int cmd_status(void)
{
	struct cfg c;
	FILE *f;
	size_t n = 0;
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;

	load_cfg(&c, NULL);
	printf("DriverGuard mode:  %s\n", c.enforce ? "enforce (auto-repair)" :
	       "monitor (report only)");
	{
		char a[160];

		sst_describe_arming(STATEDIR, c.enforce, a, sizeof(a));
		printf("enforce arming:    %s\n", a);
	}
	printf("driver tree:       %s\n", c.driver_dir);
	printf("backup root:       %s (hourly buckets)\n", c.backup_root);
	f = fopen(MANIFEST, "re");
	if (f) {
		while ((len = getline(&line, &cap, f)) >= 0)
			if (len > 1 && line[0] != '#')
				n++;
		free(line);
		fclose(f);
	}
	printf("baseline modules:  %zu%s\n", n, f ? "" : " (no baseline yet)");
	{
		char t[640];

		sst_describe(MANIFEST, c.trust, t, sizeof(t));
		printf("baseline trust:    %s\n", t);
	}
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
"usage: secure-sudo-driverguard <command>\n"
"  baseline   hash all modules + store compressed failsafe backups (hourly bucket)\n"
"  backup     refresh the hourly compressed backups only\n"
"  scan       check modules vs baseline; repair from backup in enforce mode\n"
"  refresh [REASON]  re-baseline after a legitimate update (logged)\n"
"  arm        let enforce mode act (it reports only until a clean pass or this)\n"
"  status     show configuration and baseline size\n"
"  check-config  check every config file strictly; 1 if any problem\n"
"\nConfig: " CONF "\n");
}

int main(int argc, char **argv)
{
	if (geteuid() != 0) {
		fprintf(stderr, "driverguard: must run as root\n");
		return 1;
	}
	if (argc < 2) {
		usage();
		return 2;
	}
	ssl_init("driverguard");

	if (!strcmp(argv[1], "check-config"))
		return ssc_verdict(conf_errors(stdout));
	if (strcmp(argv[1], "status")) {
		int rc = ssc_refuse(argv[1], conf_errors(stderr));

		if (rc)
			return rc;
	}

	if (!strcmp(argv[1], "baseline"))
		return cmd_baseline();
	if (!strcmp(argv[1], "backup"))
		return cmd_backup();
	if (!strcmp(argv[1], "scan"))
		return cmd_scan();
	if (!strcmp(argv[1], "refresh"))
		return cmd_refresh(argc > 2 ? argv[2] : "manual");
	if (!strcmp(argv[1], "status"))
		return cmd_status();
	if (!strcmp(argv[1], "arm"))
		return cmd_arm();

	usage();
	ssl_close();
	return 2;
}
