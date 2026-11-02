// SPDX-License-Identifier: GPL-2.0
/*
 * secure-sudo-biosguard - BiosGuard (temporary add-on): firmware tamper
 * DETECTION, log and notify ONLY.
 *
 * ========================= DETECT, LOG, NOTIFY =============================
 * BiosGuard does not repair, reflash, or stage any firmware change. By explicit
 * design it only *detects* a change to the platform firmware (BIOS/UEFI) and
 * raises the alarm - because reflashing a running machine's firmware from
 * generic Linux userspace is unsafe (it needs vendor/chipset tooling and a bad
 * write bricks the board). Repair, if ever wanted, is a deliberate manual step
 * with vendor media, outside this tool.
 *
 *   baseline  - fingerprint the firmware: hash the DMI identity fields and the
 *               ACPI tables the firmware exposes, and save the manifest.
 *   scan      - recompute the fingerprint and compare. Any change is logged
 *               CRITICAL and raised as a notification (ssl_notify -> the
 *               configured notify_cmd, e.g. wall/logger/ops hook). Nothing is
 *               written to the firmware.
 *   status    - show state.
 *
 * Config: /etc/secure_sudo/addons/biosguard.conf (notify_cmd lives in the
 * shared logging.conf).
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
#include "ssaddon_conf.h"

#ifndef BIOS_CONF
#define BIOS_CONF	"/etc/secure_sudo/addons/biosguard.conf"
#endif
#define CONF		BIOS_CONF
#define STATEDIR	"/var/lib/secure_sudo/addons/biosguard"
#define MANIFEST	STATEDIR "/fingerprint"
#define DMI_DIR		"/sys/class/dmi/id"
#define ACPI_DIR	"/sys/firmware/acpi/tables"

/* SHA-256 one file into out[65] via sha256sum (the firmware sources are tiny). */
static int sha_file(const char *path, char out[65])
{
	char cmd[PATH_MAX + 64];
	FILE *p;
	int ok = 0;

	snprintf(cmd, sizeof(cmd), "sha256sum '%s' 2>/dev/null", path);
	p = popen(cmd, "re");
	if (!p)
		return -1;
	if (fscanf(p, "%64s", out) == 1 && strlen(out) == 64)
		ok = 1;
	pclose(p);
	return ok ? 0 : -1;
}

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
	FILE *mf;
	char tmp[] = STATEDIR "/.fp.XXXXXX";
	size_t n;
	int fd;

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
	ssl_info("baseline: %zu firmware sources fingerprinted", n);
	printf("biosguard: baseline captured %zu firmware sources\n", n);
	return 0;
}

/* Recompute and compare; returns the number of mismatches, or -1 on error. */
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
					ssl_notify(SSL_CRIT,
						"FIRMWARE tamper detected: %s changed", blabel);
					mism++;
				}
				break;
			}
		}
		if (!matched) {
			ssl_notify(SSL_CRIT, "FIRMWARE source vanished: %s", blabel);
			mism++;
		}
	}
	fclose(now);
	unlink(tmp);
	fclose(base);
	return mism;
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
	/* Detection only - we log + notify and stop. No repair by design. */
	ssl_crit("scan: %d firmware fingerprint mismatch(es) - DETECTION ONLY, "
		 "no repair performed", mism);
	printf("biosguard: %d firmware mismatch(es) detected and reported (see log/"
	       "notification). BiosGuard does not repair firmware.\n", mism);
	return 0;
}

static int cmd_status(void)
{
	printf("BiosGuard (detect + log + notify only; no repair)\n");
	printf("baseline:  %s\n", access(MANIFEST, F_OK) == 0 ? "present" : "none");
	printf("sources:   %s DMI ids + %s ACPI tables\n", DMI_DIR, ACPI_DIR);
	printf("on tamper: logged CRITICAL + notify_cmd (see logging.conf). Firmware "
	       "is never written by this tool.\n");
	return 0;
}

/* BiosGuard has no settings of its own yet: any line in biosguard.conf is an
 * error rather than a setting that silently does nothing. */
static int conf_errors(FILE *r)
{
	const struct ssc_key none[] = { SSC_END };

	return ssc_parse(CONF, none, NULL, NULL, r) + ssl_check_conf(r);
}

static void usage(void)
{
	fprintf(stderr,
"usage: secure-sudo-biosguard <command>\n"
"  baseline   fingerprint the firmware (DMI ids + ACPI tables)\n"
"  scan       check for firmware tamper; log + notify on any change (no repair)\n"
"  status     show state\n"
"  check-config  check every config file strictly; 1 if any problem\n"
"\nDetection only by design: BiosGuard never writes firmware. Config: " CONF "\n");
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
	if (!strcmp(argv[1], "status"))
		return cmd_status();

	usage();
	ssl_close();
	return 2;
}
