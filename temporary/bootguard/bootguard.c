// SPDX-License-Identifier: GPL-2.0
/*
 * secure-sudo-bootguard - BootGuard (v8 temporary add-on).
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
 *   refresh REASON - re-baseline after a legitimate change, logging every
 *                    file that changed (CRITICAL, shipped off-box). Run by the
 *                    package-manager and kernel hooks (hooks/), so a kernel,
 *                    initramfs or GRUB update is not mistaken for tampering
 *                    and rolled back at the next boot. No baseline yet: does
 *                    nothing.
 *   status         - show state.
 *
 * A scan while a package manager holds its lock (dpkg, rpm) is deferred:
 * /boot is being rewritten on purpose, and the hook re-baselines when the
 * transaction ends.
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
#include "ssaddon_conf.h"
#include "ssaddon_trust.h"

/* Overridable for the tests only (tests/userspace/test-addons.sh). */
#ifndef BG_CONF
#define BG_CONF		"/etc/secure_sudo/addons/bootguard.conf"
#endif
#ifndef BG_STATEDIR
#define BG_STATEDIR	"/var/lib/secure_sudo/addons/bootguard"
#endif
#define CONF		BG_CONF
#define STATEDIR	BG_STATEDIR
#define MANIFEST	STATEDIR "/manifest"
#define DEF_BACKUP	STATEDIR "/backups"
#define RESTORE_LIST	STATEDIR "/restore.list"
#define PENDING		STATEDIR "/PENDING"
#define LOCUS_PURPOSE	"bootguard-backup"

struct cfg {
	int enforce;			/* enforce => stage on tamper */
	int trust;			/* SST_LOCAL or SST_SIGNED (baseline_trust) */
	int rotate;			/* 1 = hourly-rotating backups, 0 = fixed */
	char boot_dir[PATH_MAX];
	char backup_root[PATH_MAX];
};

static int load_cfg(struct cfg *c, FILE *report)
{
	static const char *const modes[] = { "monitor", "enforce", NULL };
	const struct ssc_key keys[] = {
		{ "mode", SSC_ENUM, &c->enforce, 0, 0, 0, modes },
		{ "rotate", SSC_INT, &c->rotate, 0, 0, 1, NULL },
		{ "boot_dir", SSC_PATH, c->boot_dir, sizeof(c->boot_dir), 1, 0, NULL },
		{ "backup_root", SSC_PATH, c->backup_root, sizeof(c->backup_root), 1, 0, NULL },
		{ "baseline_trust", SSC_ENUM, &c->trust, 0, 0, 0, sst_modes },
		SSC_END
	};

	c->enforce = 1;			/* staging is safe; default on */
	c->trust = SST_LOCAL;
	c->rotate = 1;
	snprintf(c->boot_dir, sizeof(c->boot_dir), "/boot");
	snprintf(c->backup_root, sizeof(c->backup_root), "%s", DEF_BACKUP);
	return ssc_parse(CONF, keys, NULL, NULL, report);
}

/* Every file BootGuard reads, checked strictly (P2-2). */
static int conf_errors(FILE *r)
{
	struct cfg c;

	return load_cfg(&c, r) + ssl_check_conf(r) + locus_check_conf(r);
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

	if (c->rotate && locus_request_root(LOCUS_PURPOSE, root, sizeof(root)) == 0)
		;
	else
		snprintf(root, sizeof(root), "%s", c->backup_root);
	return store_bucket(root, c->rotate, out, n);
}

/* path -> hash of a manifest, for refresh's change report */
struct mf_ent { char *path; char sha[65]; };
struct mf { struct mf_ent *e; size_t n; };

static int mf_cmp(const void *a, const void *b)
{
	return strcmp(((const struct mf_ent *)a)->path,
		      ((const struct mf_ent *)b)->path);
}

static void mf_load(const char *file, struct mf *m)
{
	FILE *f = fopen(file, "re");
	char *line = NULL, *sp;
	size_t cap = 0, mcap = 0;
	ssize_t len;

	m->e = NULL;
	m->n = 0;
	if (!f)
		return;
	while ((len = getline(&line, &cap, f)) >= 0) {
		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		sp = strchr(line, ' ');
		if (!sp || sp - line != 64)
			continue;
		if (m->n == mcap) {
			struct mf_ent *g = realloc(m->e, (mcap = mcap ? mcap * 2 : 256) *
						   sizeof(*m->e));
			if (!g)
				break;
			m->e = g;
		}
		memcpy(m->e[m->n].sha, line, 64);
		m->e[m->n].sha[64] = '\0';
		m->e[m->n].path = strdup(sp + 1);
		if (m->e[m->n].path)
			m->n++;
	}
	free(line);
	fclose(f);
	if (m->n)
		qsort(m->e, m->n, sizeof(*m->e), mf_cmp);
}

static void mf_free(struct mf *m)
{
	size_t i;

	for (i = 0; i < m->n; i++)
		free(m->e[i].path);
	free(m->e);
}

/* Log every difference between two manifests; returns how many. */
static size_t mf_report(const struct mf *old, const struct mf *new,
			const char *reason)
{
	size_t i = 0, j = 0, n = 0;

	while (i < old->n || j < new->n) {
		int c = i >= old->n ? 1 : j >= new->n ? -1 :
			strcmp(old->e[i].path, new->e[j].path);

		if (c == 0) {
			if (strcmp(old->e[i].sha, new->e[j].sha)) {
				ssl_crit("BOOT baseline refreshed (%s): %s changed %.12s -> %.12s",
					 reason, new->e[j].path, old->e[i].sha,
					 new->e[j].sha);
				n++;
			}
			i++;
			j++;
		} else if (c < 0) {
			ssl_crit("BOOT baseline refreshed (%s): %s removed", reason,
				 old->e[i++].path);
			n++;
		} else {
			ssl_crit("BOOT baseline refreshed (%s): %s added", reason,
				 new->e[j++].path);
			n++;
		}
	}
	return n;
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
	sst_announce("bootguard", MANIFEST, why, c.trust);
	ssl_info("baseline: %zu boot files hashed, %zu backed up to %s",
		 b.files, b.backed, bucket);
	printf("bootguard: baseline %zu files, %zu backed up (%s)\n",
	       b.files, b.backed, bucket);
	return 0;
}

static int cmd_baseline(void)
{
	return baseline_why("baseline");
}

/*
 * After a legitimate change (a package transaction, a kernel install):
 * re-baseline and log, CRITICAL, every file that changed, so the change is on
 * record off-box. A staged restore from before the change is dropped: it
 * would put the old files back. No baseline yet: BootGuard is not in use.
 */
static int cmd_refresh(const char *reason)
{
	struct mf old, now;
	char why[64];
	size_t i, j = 0, changed;
	int rc;

	for (i = 0; reason && reason[i] && j + 1 < sizeof(why); i++)
		if (isalnum((unsigned char)reason[i]) || strchr("._-", reason[i]))
			why[j++] = reason[i];
	why[j] = '\0';
	if (!j)
		snprintf(why, sizeof(why), "manual");
	if (access(MANIFEST, F_OK) != 0) {
		printf("bootguard: no baseline; nothing to refresh\n");
		return 0;
	}
	mf_load(MANIFEST, &old);
	rc = baseline_why(why);
	if (rc == 0) {
		mf_load(MANIFEST, &now);
		changed = mf_report(&old, &now, why);
		mf_free(&now);
		if (access(PENDING, F_OK) == 0) {
			unlink(PENDING);
			unlink(RESTORE_LIST);
			ssl_crit("BOOT staged restore DROPPED by refresh (%s): it "
				 "predates the change", why);
		}
		ssl_info("refresh (%s): %zu file(s) changed since the last baseline",
			 why, changed);
		printf("bootguard: refreshed (%s): %zu file(s) changed\n", why,
		       changed);
	}
	mf_free(&old);
	return rc;
}

/* Stage a restore: one "dst<TAB>sha256" line in restore.list per file. The
 * backup is chosen, and checked against that hash, when it is applied. */
static int stage_restore(const char *dst, const char *sha, FILE *rl)
{
	fprintf(rl, "%s\t%s\n", dst, sha);
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
	char why[512];
	int untrusted = 0;

	load_cfg(&c, NULL);
	{
		char lock[PATH_MAX];

		if (ssaddon_pkg_busy(lock, sizeof(lock))) {
			ssl_info("scan deferred: a package manager holds %s", lock);
			printf("bootguard: scan deferred: a package manager is "
			       "running (%s)\n", lock);
			return 0;
		}
	}
	f = fopen(MANIFEST, "re");
	if (!f) {
		fprintf(stderr, "bootguard: no baseline - run `baseline` first\n");
		return 1;
	}
	if (!sst_manifest_trusted(MANIFEST, c.trust, why, sizeof(why))) {
		untrusted = 1;
		ssl_crit("BOOT baseline NOT TRUSTED (%s): reporting only, nothing is "
			 "staged", why);
		printf("bootguard: baseline not trusted (%s): reporting only\n", why);
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
			if (c.enforce && !untrusted) {
				if (!rl) {
					rl = fopen(RESTORE_LIST, "we");
					if (rl)
						chmod(RESTORE_LIST, 0600);
				}
				if (rl && stage_restore(path, sha, rl) == 0)
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
		printf("bootguard: %zu tampered (%s: not staged)\n", tampered,
		       untrusted ? "baseline not trusted" : "monitor mode");
	} else {
		ssl_info("scan: boot partition intact (%zu files)", checked);
		printf("bootguard: boot partition intact (%zu files)\n", checked);
	}
	return untrusted ? 3 : 0;	/* a failed unit is reported */
}

static int is_sha(const char *s)
{
	size_t i;

	for (i = 0; i < 64; i++)
		if (!isxdigit((unsigned char)s[i]))
			return 0;
	return s[64] == '\0';
}

/* The baseline hash of @path, for a restore.list line staged before the
 * hash was recorded there. */
static int manifest_sha(const char *path, char out[65])
{
	struct mf m;
	struct mf_ent key, *e;

	mf_load(MANIFEST, &m);
	key.path = (char *)path;
	e = m.n ? bsearch(&key, m.e, m.n, sizeof(*m.e), mf_cmp) : NULL;
	if (e)
		snprintf(out, 65, "%s", e->sha);
	mf_free(&m);
	return e ? 0 : -1;
}

/* Apply a staged restore (run early at boot, or by apply-now). Every file
 * written back is a backup whose bytes match the baseline; what was there is
 * kept as evidence first. */
static int do_restore(void)
{
	struct cfg c;
	FILE *rl = fopen(RESTORE_LIST, "re");
	char *line = NULL, why[PATH_MAX + 128], used[PATH_MAX], root[PATH_MAX];
	size_t cap = 0;
	ssize_t len;
	size_t done = 0, fail = 0;

	if (!rl) {
		ssl_warn("restore requested but no restore.list present");
		return 0;
	}
	load_cfg(&c, NULL);
	if (!sst_manifest_trusted(MANIFEST, c.trust, why, sizeof(why))) {
		ssl_crit("BOOT restore REFUSED: the baseline is not trusted (%s); "
			 "the staged restore is kept for the operator", why);
		fclose(rl);
		return 3;
	}
	while ((len = getline(&line, &cap, rl)) >= 0) {
		char *tab, sha[65];

		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		tab = strchr(line, '\t');
		if (!tab)
			continue;
		*tab = '\0';
		if (is_sha(tab + 1)) {
			snprintf(sha, sizeof(sha), "%s", tab + 1);
		} else if (manifest_sha(line, sha) != 0) {	/* staged by an older release */
			ssl_err("BOOT restore FAILED: %s is not in the baseline", line);
			fail++;
			continue;
		}
		sst_evidence("bootguard", line, "restore", sha, NULL);
		if (sst_restore_from_backups(c.backup_root, "boot", line, sha, used,
					     sizeof(used), why, sizeof(why)) == 0 ||
		    (locus_request_root(LOCUS_PURPOSE, root, sizeof(root)) == 0 &&
		     sst_restore_from_backups(root, "boot", line, sha, used, sizeof(used),
					      why, sizeof(why)) == 0)) {
			ssl_crit("BOOT restored: %s from %s (sha256 verified)", line, used);
			done++;
		} else {
			ssl_err("BOOT restore FAILED: %s: %s", line, why);
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

	load_cfg(&c, NULL);
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
	{
		char t[640];

		sst_describe(MANIFEST, c.trust, t, sizeof(t));
		printf("baseline trust:   %s\n", t);
	}
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
"  refresh [REASON] re-baseline after a legitimate change, logging what changed\n"
"  status           show state\n"
"  check-config     check every config file strictly; 1 if any problem\n"
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

	if (!strcmp(argv[1], "check-config"))
		return ssc_verdict(conf_errors(stdout));
	if (strcmp(argv[1], "status")) {
		int rc = ssc_refuse(argv[1], conf_errors(stderr));

		if (rc)
			return rc;
	}

	if (!strcmp(argv[1], "baseline"))
		return cmd_baseline();
	if (!strcmp(argv[1], "scan"))
		return cmd_scan();
	if (!strcmp(argv[1], "restore-staged"))
		return cmd_restore_staged();
	if (!strcmp(argv[1], "refresh"))
		return cmd_refresh(argc > 2 ? argv[2] : "manual");
	if (!strcmp(argv[1], "apply-now"))
		return cmd_apply_now(argc, argv);
	if (!strcmp(argv[1], "status"))
		return cmd_status();

	usage();
	ssl_close();
	return 2;
}
