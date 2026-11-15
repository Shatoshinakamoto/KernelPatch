// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
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
 *   baseline  - fingerprint the firmware: hash the sources below and save
 *               the manifest.
 *   scan      - recompute the fingerprint and compare. Any change is logged
 *               CRITICAL and raised as a notification (ssl_notify -> the
 *               configured notify_cmd, e.g. wall/logger/ops hook). Nothing is
 *               written to the firmware.
 *   refresh REASON - after a legitimate firmware or Secure Boot database
 *               update (fwupd, a BIOS flash): re-baseline, logging CRITICAL
 *               every source that changed so the change is on record off-box.
 *   status    - show state and what this host actually exposes.
 *
 * What is measured (docs/BOOT_ASSURANCE.md "BiosGuard coverage and limits"):
 *   dmi:      the DMI identity strings (/sys/class/dmi/id)
 *   acpi:     every ACPI table the firmware hands the kernel
 *   smbios:   the raw SMBIOS table and entry point (/sys/firmware/dmi/tables)
 *   efi:      the Secure Boot state and key databases (SecureBoot, SetupMode,
 *             PK, KEK, db, dbx) from efivarfs
 *   esrt:     the UEFI System Resource Table: version and update status of
 *             each firmware component that takes capsule updates
 *   tpm:      the TPM PCRs that measure firmware (default 0, 2, 7)
 * Every source is read as the running kernel reports it. None of it is
 * authenticated by a signature here: a quote of the same PCRs, checked by a
 * remote verifier, is `secure-sudo attest` (docs/ATTESTATION.md).
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
#include "ssaddon_trust.h"

#ifndef BIOS_CONF
#define BIOS_CONF	"/etc/secure_sudo/addons/biosguard.conf"
#endif
#define CONF		BIOS_CONF
#ifndef BIOS_STATEDIR
#define BIOS_STATEDIR	"/var/lib/secure_sudo/addons/biosguard"
#endif
#define STATEDIR	BIOS_STATEDIR
#define MANIFEST	STATEDIR "/fingerprint"
/* Overridable for the tests only (tests/userspace/test-addons.sh). */
#ifndef BIOS_DMI_DIR
#define BIOS_DMI_DIR	"/sys/class/dmi/id"
#endif
#ifndef BIOS_ACPI_DIR
#define BIOS_ACPI_DIR	"/sys/firmware/acpi/tables"
#endif
#ifndef BIOS_SMBIOS_DIR
#define BIOS_SMBIOS_DIR	"/sys/firmware/dmi/tables"
#endif
#ifndef BIOS_EFI_DIR
#define BIOS_EFI_DIR	"/sys/firmware/efi"
#endif
#ifndef BIOS_TPM_DIR
#define BIOS_TPM_DIR	"/sys/class/tpm/tpm0"
#endif
#define DMI_DIR		BIOS_DMI_DIR
#define ACPI_DIR	BIOS_ACPI_DIR
#define SMBIOS_DIR	BIOS_SMBIOS_DIR
#define EFI_DIR		BIOS_EFI_DIR
#define TPM_DIR		BIOS_TPM_DIR

/* what to measure, from biosguard.conf */
struct cfg {
	int trust;
	int smbios;			/* SMBIOS tables */
	int efi;			/* Secure Boot variables + ESRT */
	char pcrs[64];			/* "0,2,7": TPM PCRs; empty = none */
	unsigned pcr_mask;		/* the same, parsed */
};

/* SHA-256 one file into out[65]. It is hashed in-process: this used to run
 * `sha256sum '<path>'` through a shell, so a table name with a quote in it
 * would have been a command (P2-2 part 3). */
static int sha_file(const char *path, char out[65])
{
	return sst_sha256_file(path, out);
}

/* A label goes in the fingerprint as one whitespace-free token. */
static int label_ok(const char *s)
{
	for (; *s; s++)
		if ((unsigned char)*s <= 0x20 || *s == 0x7f)
			return 0;
	return 1;
}

static void fp_one(FILE *mf, const char *path, const char *label, size_t *n)
{
	char sha[65];

	if (sha_file(path, sha) == 0) {
		fprintf(mf, "%s %s\n", sha, label);
		(*n)++;
	}
}

struct counts {
	size_t dmi, acpi, smbios, efi, esrt, tpm;
};

static size_t counts_total(const struct counts *k)
{
	return k->dmi + k->acpi + k->smbios + k->efi + k->esrt + k->tpm;
}

/* The Secure Boot variables, by name and vendor GUID (UEFI spec). */
#define GUID_GLOBAL	"8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define GUID_SECDB	"d719b2cb-3d3a-4596-a3bc-dad00e67656f"

static void fp_dmi_acpi(FILE *mf, struct counts *k)
{
	static const char *dmi[] = {
		"bios_vendor", "bios_version", "bios_date", "bios_release",
		"board_vendor", "board_name", "board_version",
		"product_name", "product_version", "sys_vendor", NULL
	};
	DIR *d;
	int i;

	for (i = 0; dmi[i]; i++) {
		char p[256], label[64];

		snprintf(p, sizeof(p), "%s/%s", DMI_DIR, dmi[i]);
		if (access(p, R_OK) != 0)
			continue;
		snprintf(label, sizeof(label), "dmi:%s", dmi[i]);
		fp_one(mf, p, label, &k->dmi);
	}

	d = opendir(ACPI_DIR);
	if (d) {
		struct dirent *de;

		while ((de = readdir(d))) {
			char p[PATH_MAX], label[320];
			struct stat st;

			if (de->d_name[0] == '.')
				continue;
			if (!label_ok(de->d_name)) {
				ssl_notify(SSL_CRIT, "FIRMWARE table with an odd name: %s/%s "
					   "(not fingerprinted)", ACPI_DIR, de->d_name);
				continue;
			}
			if (snprintf(p, sizeof(p), "%s/%s", ACPI_DIR, de->d_name) >=
			    (int)sizeof(p))
				continue;
			if (stat(p, &st) != 0 || !S_ISREG(st.st_mode))
				continue;
			snprintf(label, sizeof(label), "acpi:%s", de->d_name);
			fp_one(mf, p, label, &k->acpi);
		}
		closedir(d);
	}
}

/* The raw SMBIOS structure table and its entry point: what DMI strings are
 * parsed from, so a changed table that kept the same strings still shows. */
static void fp_smbios(FILE *mf, struct counts *k)
{
	static const char *const f[] = { "DMI", "smbios_entry_point", NULL };
	int i;

	for (i = 0; f[i]; i++) {
		char p[PATH_MAX], label[64];

		snprintf(p, sizeof(p), "%s/%s", SMBIOS_DIR, f[i]);
		snprintf(label, sizeof(label), "smbios:%s", f[i]);
		fp_one(mf, p, label, &k->smbios);
	}
}

/* Secure Boot state and key databases from efivarfs, and the ESRT. A
 * legacy-BIOS boot has neither: nothing is fingerprinted, and `status` says
 * so. An EFI variable file starts with its 4-byte attributes; the whole file
 * is hashed. */
static void fp_efi(FILE *mf, struct counts *k)
{
	static const struct { const char *name, *guid; } v[] = {
		{ "SecureBoot", GUID_GLOBAL }, { "SetupMode", GUID_GLOBAL },
		{ "PK", GUID_GLOBAL }, { "KEK", GUID_GLOBAL },
		{ "db", GUID_SECDB }, { "dbx", GUID_SECDB }, { NULL, NULL }
	};
	static const char *const attr[] = {
		"fw_class", "fw_type", "fw_version", "lowest_supported_fw_version",
		"capsule_flags", "last_attempt_version", "last_attempt_status", NULL
	};
	char dir[PATH_MAX];
	DIR *d;
	int i;

	for (i = 0; v[i].name; i++) {
		char p[PATH_MAX], label[64];

		snprintf(p, sizeof(p), "%s/efivars/%s-%s", EFI_DIR, v[i].name, v[i].guid);
		snprintf(label, sizeof(label), "efi:%s", v[i].name);
		fp_one(mf, p, label, &k->efi);
	}

	snprintf(dir, sizeof(dir), "%s/esrt/entries", EFI_DIR);
	d = opendir(dir);
	if (d) {
		struct dirent *de;

		while ((de = readdir(d))) {
			if (de->d_name[0] == '.' || !label_ok(de->d_name))
				continue;
			for (i = 0; attr[i]; i++) {
				char p[PATH_MAX], label[320];

				if (snprintf(p, sizeof(p), "%s/%s/%s", dir, de->d_name,
					     attr[i]) >= (int)sizeof(p))
					continue;
				snprintf(label, sizeof(label), "esrt:%s:%s", de->d_name,
					 attr[i]);
				fp_one(mf, p, label, &k->esrt);
			}
		}
		closedir(d);
	}
}

/* The TPM's measurements of the firmware. PCR 0 is the firmware code, 2 the
 * option ROMs and other executable firmware, 7 the Secure Boot policy. The
 * sha256 bank is used, the sha1 bank only where there is no sha256. */
static void fp_tpm(FILE *mf, const struct cfg *c, struct counts *k)
{
	int n;

	for (n = 0; n < 24; n++) {
		char p[PATH_MAX], label[48];

		if (!(c->pcr_mask & (1u << n)))
			continue;
		snprintf(p, sizeof(p), "%s/pcr-sha256/%d", TPM_DIR, n);
		if (access(p, R_OK) == 0) {
			snprintf(label, sizeof(label), "tpm:pcr%d:sha256", n);
		} else {
			snprintf(p, sizeof(p), "%s/pcr-sha1/%d", TPM_DIR, n);
			snprintf(label, sizeof(label), "tpm:pcr%d:sha1", n);
		}
		fp_one(mf, p, label, &k->tpm);
	}
}

/* Build the firmware fingerprint into @mf. */
static void build_fingerprint(FILE *mf, const struct cfg *c, struct counts *k)
{
	memset(k, 0, sizeof(*k));
	fp_dmi_acpi(mf, k);
	if (c->smbios)
		fp_smbios(mf, k);
	if (c->efi)
		fp_efi(mf, k);
	if (c->pcr_mask)
		fp_tpm(mf, c, k);
}

static void describe_counts(const struct counts *k, char *out, size_t n)
{
	snprintf(out, n, "dmi %zu, acpi %zu, smbios %zu, efi %zu, esrt %zu, tpm %zu",
		 k->dmi, k->acpi, k->smbios, k->efi, k->esrt, k->tpm);
}

static int load_cfg(struct cfg *c, FILE *r);

static int baseline_why(const char *why)
{
	struct cfg c;
	struct counts k;
	char desc[160];
	FILE *mf;
	char tmp[] = STATEDIR "/.fp.XXXXXX";
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
	load_cfg(&c, NULL);
	build_fingerprint(mf, &c, &k);
	if (fflush(mf) != 0 || fsync(fileno(mf)) != 0 || ferror(mf)) {
		fclose(mf);
		unlink(tmp);
		ssl_err("baseline: the fingerprint could not be written");
		return 1;
	}
	fclose(mf);
	if (rename(tmp, MANIFEST) != 0) {
		unlink(tmp);
		return 1;
	}
	chmod(MANIFEST, 0600);
	sst_announce("biosguard", MANIFEST, why, c.trust);
	describe_counts(&k, desc, sizeof(desc));
	ssl_info("baseline: %zu firmware sources fingerprinted (%s)",
		 counts_total(&k), desc);
	printf("biosguard: baseline captured %zu firmware sources (%s)\n",
	       counts_total(&k), desc);
	return 0;
}

static int cmd_baseline(void)
{
	return baseline_why("baseline");
}

/* Recompute and compare; returns the number of mismatches, or -1 on error. */
static int fingerprint_diff(const char *refresh)
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
	{
		struct cfg c;
		struct counts k;

		load_cfg(&c, NULL);
		build_fingerprint(now, &c, &k);
	}
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
					if (refresh)
						ssl_crit("FIRMWARE changed (refresh: %s): %s",
							 refresh, blabel);
					else
						ssl_notify(SSL_CRIT,
							"FIRMWARE tamper detected: %s changed", blabel);
					mism++;
				}
				break;
			}
		}
		if (!matched) {
			if (refresh)
				ssl_crit("FIRMWARE source gone (refresh: %s): %s", refresh,
					 blabel);
			else
				ssl_notify(SSL_CRIT, "FIRMWARE source vanished: %s", blabel);
			mism++;
		}
	}
	/* and the other way: a source the baseline does not have (an extra
	 * ACPI table is how firmware-level code is often injected) */
	rewind(now);
	while (fgets(lb, sizeof(lb), now)) {
		char nsha[65], nlabel[160], bl[256], bsha[65], blabel[160];
		int known = 0;

		if (sscanf(lb, "%64s %159s", nsha, nlabel) != 2)
			continue;
		rewind(base);
		while (fgets(bl, sizeof(bl), base))
			if (sscanf(bl, "%64s %159s", bsha, blabel) == 2 &&
			    !strcmp(blabel, nlabel)) {
				known = 1;
				break;
			}
		if (!known) {
			if (refresh)
				ssl_crit("FIRMWARE source added (refresh: %s): %s", refresh,
					 nlabel);
			else
				ssl_notify(SSL_CRIT, "FIRMWARE source appeared: %s (not in "
					   "the baseline)", nlabel);
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
	char why[512];
	struct cfg c;
	int mism;

	load_cfg(&c, NULL);
	if (!sst_manifest_trusted(MANIFEST, c.trust, why, sizeof(why))) {
		/* a fingerprint that may have been rewritten proves nothing */
		ssl_notify(SSL_CRIT, "FIRMWARE fingerprint NOT TRUSTED (%s): the scan "
			   "cannot vouch for the firmware", why);
		printf("biosguard: fingerprint not trusted (%s)\n", why);
		return 3;
	}
	mism = fingerprint_diff(NULL);

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

/*
 * After a legitimate firmware change (a BIOS flash, a capsule update, a
 * Secure Boot database update from fwupd): record every source that changed,
 * CRITICAL so it is shipped off-box, and take a new baseline. A host with no
 * baseline yet is not in use: nothing to refresh.
 */
static int cmd_refresh(const char *reason)
{
	char why[64];
	size_t i, j = 0;
	int mism, rc;

	for (i = 0; reason && reason[i] && j + 1 < sizeof(why); i++)
		if (isalnum((unsigned char)reason[i]) || strchr("._-", reason[i]))
			why[j++] = reason[i];
	why[j] = '\0';
	if (!j)
		snprintf(why, sizeof(why), "manual");
	if (access(MANIFEST, F_OK) != 0) {
		printf("biosguard: no baseline; nothing to refresh\n");
		return 0;
	}
	mism = fingerprint_diff(why);
	if (mism < 0)
		return 1;
	rc = baseline_why(why);
	if (rc == 0)
		ssl_info("refresh (%s): %d firmware source(s) changed since the last "
			 "baseline", why, mism);
	return rc;
}

static void describe_pcrs(const struct cfg *c, char *out, size_t n)
{
	snprintf(out, n, "%s", c->pcr_mask ? c->pcrs : "none configured");
}

static int cmd_status(void)
{
	struct cfg c;
	struct counts k;
	char desc[160], t[640];
	FILE *null = fopen("/dev/null", "we");

	load_cfg(&c, NULL);
	printf("BiosGuard (detect + log + notify only; no repair)\n");
	printf("baseline:  %s\n", access(MANIFEST, F_OK) == 0 ? "present" : "none");
	sst_describe(MANIFEST, c.trust, t, sizeof(t));
	printf("trust:     %s\n", t);
	/* what this host exposes right now, which is all the baseline can hold */
	if (null) {
		build_fingerprint(null, &c, &k);
		fclose(null);
		describe_counts(&k, desc, sizeof(desc));
		printf("sources:   %s\n", desc);
	}
	printf("EFI:       %s\n", access(EFI_DIR, F_OK) == 0 ?
	       (c.efi ? "booted by UEFI; Secure Boot variables and ESRT measured" :
		"booted by UEFI; efi = 0 so Secure Boot variables and ESRT are not measured") :
	       "not booted by UEFI (legacy BIOS): no Secure Boot or ESRT data exists");
	describe_pcrs(&c, desc, sizeof(desc));
	printf("TPM PCRs:  %s (%s)\n", desc, access(TPM_DIR, F_OK) == 0 ?
	       "TPM present" : "no TPM exposed: none can be measured");
	printf("on tamper: logged CRITICAL + notify_cmd (see logging.conf). Firmware "
	       "is never written by this tool.\n");
	return 0;
}

/* "0,2,7" -> a PCR bitmask. Empty is none. Returns 0, or -1 with @err. */
static int parse_pcrs(const char *v, unsigned *mask, char *err, size_t n)
{
	const char *p = v;

	*mask = 0;
	while (*p) {
		char *end;
		long x = strtol(p, &end, 10);

		if (end == p || x < 0 || x > 23 || (*end != ',' && *end != '\0')) {
			snprintf(err, n, "tpm_pcrs = %s: a comma-separated list of PCR "
				 "numbers 0..23 (or empty for none)", v);
			return -1;
		}
		*mask |= 1u << x;
		p = *end ? end + 1 : end;
		if (*end == ',' && !*p) {
			snprintf(err, n, "tpm_pcrs = %s: trailing comma", v);
			return -1;
		}
	}
	return 0;
}

/* biosguard.conf: the trust in the recorded fingerprint and what to measure. */
static int load_cfg(struct cfg *c, FILE *r)
{
	const struct ssc_key keys[] = {
		{ "baseline_trust", SSC_ENUM, &c->trust, 0, 0, 0, sst_modes },
		{ "smbios", SSC_INT, &c->smbios, 0, 0, 1, NULL },
		{ "efi", SSC_INT, &c->efi, 0, 0, 1, NULL },
		{ "tpm_pcrs", SSC_STR, c->pcrs, sizeof(c->pcrs), 0, 0, NULL },
		SSC_END
	};
	char err[160];
	int errs;

	c->trust = SST_LOCAL;
	c->smbios = 1;
	c->efi = 1;
	snprintf(c->pcrs, sizeof(c->pcrs), "0,2,7");
	errs = ssc_parse(CONF, keys, NULL, NULL, r);
	if (parse_pcrs(c->pcrs, &c->pcr_mask, err, sizeof(err)) != 0) {
		if (r)
			fprintf(r, "%s: %s\n", CONF, err);
		snprintf(c->pcrs, sizeof(c->pcrs), "0,2,7");
		parse_pcrs(c->pcrs, &c->pcr_mask, err, sizeof(err));
		errs++;
	}
	return errs;
}

static int conf_errors(FILE *r)
{
	struct cfg c;

	return load_cfg(&c, r) + ssl_check_conf(r);
}

static void usage(void)
{
	fprintf(stderr,
"usage: secure-sudo-biosguard <command>\n"
"  baseline   fingerprint the firmware (DMI, ACPI, SMBIOS, Secure Boot variables,\n"
"             ESRT, TPM PCRs: see status for what this host exposes)\n"
"  scan       check for firmware tamper; log + notify on any change (no repair)\n"
"  refresh [REASON]  after a legitimate firmware/Secure Boot update: log what\n"
"             changed (CRITICAL) and take a new baseline\n"
"  status     show state and what this host exposes\n"
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
	if (!strcmp(argv[1], "refresh"))
		return cmd_refresh(argc > 2 ? argv[2] : NULL);
	if (!strcmp(argv[1], "status"))
		return cmd_status();

	usage();
	ssl_close();
	return 2;
}
