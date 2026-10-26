// SPDX-License-Identifier: GPL-2.0
/*
 * secure-sudo-biosguard - BiosGuard (v8 temporary add-on).
 *
 * Detects tampering of the platform firmware (BIOS/UEFI) and STAGES a restore
 * from a known-good image. It deliberately does NOT reflash automatically.
 *
 * ========================= WHY DETECT-AND-STAGE =============================
 * You cannot safely reflash a running machine's firmware from generic Linux
 * userspace. A reflash needs vendor/chipset-specific tooling (flashrom with the
 * right programmer, or the vendor capsule-update path), and a bad or
 * interrupted write BRICKS the board - there is no "undo" for a half-written
 * BIOS. So BiosGuard:
 *
 *   baseline  - fingerprint the firmware: hash the DMI identity fields and the
 *               ACPI tables the firmware exposes, and - if you have supplied a
 *               known-good full flash image - store it compressed as the
 *               restore source.
 *   scan      - recompute the fingerprint and compare. A mismatch is logged
 *               CRITICAL and, if a known-good image exists, STAGED: the good
 *               image is placed in a staging area with a marker, ready for an
 *               operator to apply. Nothing is flashed.
 *   apply     - the ONLY path that can actually write firmware. It refuses
 *               unless `--i-understand-the-risk` is given AND `flashrom` plus a
 *               configured programmer are present; it is operator-invoked, never
 *               run by a timer or a daemon.
 *
 * Config: /etc/secure_sudo/addons/biosguard.conf
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

#include "ssaddon_log.h"
#include "ssaddon_store.h"

#define CONF		"/etc/secure_sudo/addons/biosguard.conf"
#define STATEDIR	"/var/lib/secure_sudo/addons/biosguard"
#define MANIFEST	STATEDIR "/fingerprint"
#define GOODIMG		STATEDIR "/good-image.z"	/* compressed known-good */
#define STAGEDIR	STATEDIR "/staged"
#define DMI_DIR		"/sys/class/dmi/id"
#define ACPI_DIR	"/sys/firmware/acpi/tables"

struct cfg {
	char flashrom[64];		/* flashrom binary name */
	char programmer[128];		/* flashrom -p argument, e.g. internal */
	char good_image[PATH_MAX];	/* path to a known-good full flash image */
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

	snprintf(c->flashrom, sizeof(c->flashrom), "flashrom");
	snprintf(c->programmer, sizeof(c->programmer), "internal");
	c->good_image[0] = '\0';

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
		if (!strcmp(k, "flashrom"))
			snprintf(c->flashrom, sizeof(c->flashrom), "%s", v);
		else if (!strcmp(k, "programmer"))
			snprintf(c->programmer, sizeof(c->programmer), "%s", v);
		else if (!strcmp(k, "good_image"))
			snprintf(c->good_image, sizeof(c->good_image), "%s", v);
	}
	fclose(f);
}

static int have_tool(const char *t)
{
	char cmd[128];

	snprintf(cmd, sizeof(cmd), "command -v %s >/dev/null 2>&1", t);
	return system(cmd) == 0;
}

/* SHA-256 one file into out[65]. */
static int sha_file(const char *path, char out[65])
{
	char cmd[PATH_MAX + 64];
	FILE *p;
	int ok = 0;

	/* sha256sum keeps this small and avoids pulling a hashing loop in; the
	 * firmware sources are tiny. */
	snprintf(cmd, sizeof(cmd), "sha256sum '%s' 2>/dev/null", path);
	p = popen(cmd, "re");
	if (!p)
		return -1;
	if (fscanf(p, "%64s", out) == 1 && strlen(out) == 64)
		ok = 1;
	pclose(p);
	return ok ? 0 : -1;
}

/* Append a fingerprint line "<sha> <label>" for one source into @mf. */
static void fp_one(FILE *mf, const char *path, const char *label, size_t *n)
{
	char sha[65];

	if (sha_file(path, sha) == 0) {
		fprintf(mf, "%s %s\n", sha, label);
		(*n)++;
	}
}

/* Build the firmware fingerprint into @mf. Returns the number of sources. */
static size_t build_fingerprint(FILE *mf)
{
	static const char *dmi[] = {
		"bios_vendor", "bios_version", "bios_date", "bios_release",
		"board_vendor", "board_name", "board_version",
		"product_name", "product_version", "sys_vendor", NULL
	};
	size_t n = 0;
	DIR *d;
	int i;

	for (i = 0; dmi[i]; i++) {
		char p[256], label[64];

		snprintf(p, sizeof(p), "%s/%s", DMI_DIR, dmi[i]);
		if (access(p, R_OK) != 0)
			continue;
		snprintf(label, sizeof(label), "dmi:%s", dmi[i]);
		fp_one(mf, p, label, &n);
	}

	d = opendir(ACPI_DIR);
	if (d) {
		struct dirent *de;

		while ((de = readdir(d))) {
			char p[PATH_MAX], label[320];
			struct stat st;

			if (de->d_name[0] == '.')
				continue;
			if (snprintf(p, sizeof(p), "%s/%s", ACPI_DIR, de->d_name) >=
			    (int)sizeof(p))
				continue;
			if (stat(p, &st) != 0 || !S_ISREG(st.st_mode))
				continue;
			snprintf(label, sizeof(label), "acpi:%s", de->d_name);
			fp_one(mf, p, label, &n);
		}
		closedir(d);
	}
	return n;
}

static int cmd_baseline(void)
{
	struct cfg c;
	FILE *mf;
	char tmp[] = STATEDIR "/.fp.XXXXXX";
	size_t n;
	int fd;

	load_cfg(&c);
	mkdir("/var/lib/secure_sudo", 0700);
	mkdir("/var/lib/secure_sudo/addons", 0700);
	mkdir(STATEDIR, 0700);

	fd = mkstemp(tmp);
	if (fd < 0) {
		ssl_err("mkstemp: %s", strerror(errno));
		return 1;
	}
	mf = fdopen(fd, "we");
	if (!mf) {
		close(fd);
		unlink(tmp);
		return 1;
	}
	n = build_fingerprint(mf);
	fflush(mf);
	fsync(fileno(mf));
	fclose(mf);
	if (rename(tmp, MANIFEST) != 0) {
		unlink(tmp);
		return 1;
	}
	chmod(MANIFEST, 0600);

	/* Store the operator-supplied known-good image as the restore source. */
	if (c.good_image[0] && access(c.good_image, R_OK) == 0) {
		char sample[PATH_MAX];

		if (store_put_compressed(c.good_image, STATEDIR, "good", sample,
					 sizeof(sample)) == 0) {
			rename(sample, GOODIMG);
			chmod(GOODIMG, 0600);
			ssl_info("stored known-good firmware image (%s)", c.good_image);
		} else {
			ssl_warn("could not store known-good image %s", c.good_image);
		}
	} else {
		ssl_warn("no known-good firmware image configured - detection only, "
			 "no restore source");
	}
	ssl_info("baseline: %zu firmware sources fingerprinted", n);
	printf("biosguard: baseline captured %zu firmware sources%s\n", n,
	       access(GOODIMG, F_OK) == 0 ? " + known-good image" : " (no image)");
	return 0;
}

/* Recompute and compare; returns the number of mismatches. */
static int fingerprint_diff(void)
{
	FILE *base = fopen(MANIFEST, "re");
	FILE *now;
	char tmp[] = STATEDIR "/.now.XXXXXX";
	char lb[256];
	int fd, mism = 0;

	if (!base) {
		fprintf(stderr, "biosguard: no baseline - run `baseline` first\n");
		return -1;
	}
	fd = mkstemp(tmp);
	if (fd < 0) {
		fclose(base);
		return -1;
	}
	now = fdopen(fd, "w+e");
	if (!now) {
		close(fd);
		unlink(tmp);
		fclose(base);
		return -1;
	}
	build_fingerprint(now);
	rewind(now);

	/* For each baseline line, find its label in the fresh set and compare. */
	while (fgets(lb, sizeof(lb), base)) {
		char bsha[65], blabel[160], nsha[65], nlabel[160], nl[256];
		int matched = 0;

		if (sscanf(lb, "%64s %159s", bsha, blabel) != 2)
			continue;
		rewind(now);
		while (fgets(nl, sizeof(nl), now)) {
			if (sscanf(nl, "%64s %159s", nsha, nlabel) != 2)
				continue;
			if (!strcmp(blabel, nlabel)) {
				matched = 1;
				if (strcmp(bsha, nsha) != 0) {
					ssl_crit("FIRMWARE tamper: %s changed", blabel);
					mism++;
				}
				break;
			}
		}
		if (!matched) {
			ssl_crit("FIRMWARE source vanished: %s", blabel);
			mism++;
		}
	}
	fclose(now);
	unlink(tmp);
	fclose(base);
	return mism;
}

/* Stage the known-good image for an operator to apply. Flashes nothing. */
static void stage_restore(void)
{
	char dst[PATH_MAX];

	if (access(GOODIMG, F_OK) != 0) {
		ssl_err("tamper detected but NO known-good image is stored - "
			"cannot stage a restore. Reflash manually from vendor media.");
		return;
	}
	mkdir(STAGEDIR, 0700);
	snprintf(dst, sizeof(dst), "%s/firmware-restore.bin", STAGEDIR);
	if (store_restore_compressed(GOODIMG, dst) == 0) {
		ssl_crit("STAGED firmware restore image at %s - apply with "
			 "`biosguard apply --i-understand-the-risk` (operator only)", dst);
		printf("biosguard: tamper detected; known-good image STAGED at %s\n"
		       "  NOT flashed. To apply (DANGEROUS, can brick): \n"
		       "    secure-sudo-biosguard apply --i-understand-the-risk\n", dst);
	} else {
		ssl_err("failed to stage restore image");
	}
}

static int cmd_scan(void)
{
	int mism = fingerprint_diff();

	if (mism < 0)
		return 1;
	if (mism == 0) {
		ssl_info("scan: firmware fingerprint intact");
		printf("biosguard: firmware fingerprint intact\n");
		return 0;
	}
	ssl_crit("scan: %d firmware fingerprint mismatch(es)", mism);
	printf("biosguard: %d firmware mismatch(es) - see log; staging restore\n", mism);
	stage_restore();
	return 0;
}

static int cmd_apply(int argc, char **argv)
{
	struct cfg c;
	char staged[PATH_MAX], cmd[2 * PATH_MAX + 128];
	int ack = 0, i, rc;

	for (i = 2; i < argc; i++)
		if (!strcmp(argv[i], "--i-understand-the-risk"))
			ack = 1;
	if (!ack) {
		fprintf(stderr,
"biosguard apply: refusing. Reflashing firmware can PERMANENTLY BRICK this\n"
"machine. This is an operator action, never automatic. If you have a verified\n"
"known-good image staged and a working flashrom programmer, re-run with:\n"
"    secure-sudo-biosguard apply --i-understand-the-risk\n");
		return 1;
	}
	load_cfg(&c);
	snprintf(staged, sizeof(staged), "%s/firmware-restore.bin", STAGEDIR);
	if (access(staged, R_OK) != 0) {
		fprintf(stderr, "biosguard: no staged image at %s - run `scan` first\n",
			staged);
		return 1;
	}
	if (!have_tool(c.flashrom)) {
		fprintf(stderr, "biosguard: '%s' not found - install it and configure a "
			"programmer before applying\n", c.flashrom);
		ssl_err("apply aborted: %s not present", c.flashrom);
		return 1;
	}
	ssl_crit("OPERATOR applying firmware restore from %s via %s -p %s",
		 staged, c.flashrom, c.programmer);
	snprintf(cmd, sizeof(cmd), "%s -p %s -w '%s'", c.flashrom, c.programmer, staged);
	printf("biosguard: running: %s\n", cmd);
	rc = system(cmd);
	if (rc == 0) {
		ssl_crit("firmware reflash completed - verify and reboot");
		printf("biosguard: reflash completed. Verify, then reboot.\n");
	} else {
		ssl_err("flashrom returned %d - firmware MAY be in a bad state; do "
			"NOT power off until resolved", rc);
		printf("biosguard: flashrom failed (rc=%d). Do NOT power off.\n", rc);
	}
	return rc == 0 ? 0 : 1;
}

static int cmd_status(void)
{
	struct cfg c;

	load_cfg(&c);
	printf("BiosGuard\n");
	printf("baseline:       %s\n", access(MANIFEST, F_OK) == 0 ? "present" : "none");
	printf("known-good img: %s\n", access(GOODIMG, F_OK) == 0 ? "stored" :
	       "none (detection only)");
	printf("flashrom:       %s\n", have_tool(c.flashrom) ? c.flashrom : "not installed");
	printf("programmer:     %s\n", c.programmer);
	printf("note: reflash is operator-only (`apply --i-understand-the-risk`).\n");
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
"usage: secure-sudo-biosguard <command>\n"
"  baseline   fingerprint the firmware (+ store a configured known-good image)\n"
"  scan       check for firmware tamper; STAGE a restore if a good image exists\n"
"  apply --i-understand-the-risk   operator-only reflash of the staged image\n"
"  status     show state\n"
"\nDetect-and-stage by design: nothing is ever auto-flashed. Config: " CONF "\n");
}

int main(int argc, char **argv)
{
	if (geteuid() != 0) {
		fprintf(stderr, "biosguard: must run as root\n");
		return 1;
	}
	if (argc < 2) {
		usage();
		return 2;
	}
	ssl_init("biosguard");

	if (!strcmp(argv[1], "baseline"))
		return cmd_baseline();
	if (!strcmp(argv[1], "scan"))
		return cmd_scan();
	if (!strcmp(argv[1], "apply"))
		return cmd_apply(argc, argv);
	if (!strcmp(argv[1], "status"))
		return cmd_status();

	usage();
	ssl_close();
	return 2;
}
