// SPDX-License-Identifier: GPL-2.0
/*
 * secure-sudo - control-plane CLI for the secure_sudo LSM.
 *
 * Every secure_sudo policy knob lives in the kernel under:
 *   /sys/kernel/secure_sudo/          (scalar toggles, read/write by root)
 *   /sys/kernel/security/secure_sudo/ (policy list files, read/write by root)
 *
 * This tool is the single supported way to drive them. It reads the config in
 * /etc/secure_sudo/ and pushes it into those kernel files ("load"), flips
 * individual knobs ("set", "net", "timevault", "lock"), prints current state
 * ("status"), manages the TimeVault allowlist ("vault-allow", vault_allow.c),
 * re-detects admin groups ("detect-admins", detect_admins.c), and hands OTP
 * subcommands to the otp helper.
 *
 * Only root may run it: the TODO requires that only sudo users administer the
 * patch, and the kernel files are root-only anyway. We fail early with a clear
 * message rather than a confusing EACCES from a sysfs write.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#include "cli.h"

#define OTP_HELPER "/usr/bin/secure-sudo-otp"
#define PHEONIXBOX_HELPER "/usr/bin/secure-sudo-pheonixbox"

static int require_root(void)
{
	if (geteuid() != 0) {
		fprintf(stderr, "secure-sudo: must be run as root (try: sudo secure-sudo ...)\n");
		return -1;
	}
	return 0;
}

/* Write @len bytes to a kernel file in one write(). Silent: on failure
 * returns -1 with the errno (the kernel's verdict, e.g. ERANGE) in *err. */
int write_file_err(const char *path, const char *data, size_t len, int *err)
{
	int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
	ssize_t n;

	if (fd < 0) {
		*err = errno;
		return -1;
	}
	n = write(fd, data, len);
	if (n < 0 || (size_t)n != len) {
		*err = n < 0 ? errno : EIO;
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/* Same, printing the reason; returns 0 on success. */
int write_file(const char *path, const char *data, size_t len)
{
	int err;

	if (write_file_err(path, data, len, &err) == 0)
		return 0;
	fprintf(stderr, "secure-sudo: write %s: %s\n", path, strerror(err));
	return -1;
}

static int cat_file(const char *path)
{
	char buf[4096];
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, n, stdout);
	close(fd);
	return 0;
}

static int set_knob(const char *key, const char *val)
{
	const struct knob *k = find_knob(key);
	char path[256];

	if (!k) {
		fprintf(stderr, "secure-sudo: unknown knob '%s'\n", key);
		return -1;
	}
	snprintf(path, sizeof(path), SYSFS "/%s", k->sysfs);
	return write_file(path, val, strlen(val));
}

/* Also persist a knob to secure-sudo.conf so it survives a reboot/reload. */
static int persist_knob(const char *key, const char *val)
{
	const char *conf = CONFIG_DIR "/secure-sudo.conf";
	char tmp[320], line[1024];
	FILE *in, *out;
	int fd, done = 0;

	snprintf(tmp, sizeof(tmp), "%s/.secure-sudo.conf.XXXXXX", CONFIG_DIR);
	fd = mkstemp(tmp);
	if (fd < 0 || !(out = fdopen(fd, "w"))) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	in = fopen(conf, "re");
	while (in && fgets(line, sizeof(line), in)) {
		char *p = line;

		while (*p == ' ' || *p == '\t')
			p++;
		if (!done && !strncmp(p, key, strlen(key)) &&
		    (p[strlen(key)] == ' ' || p[strlen(key)] == '=' ||
		     p[strlen(key)] == '\t')) {
			fprintf(out, "%s = %s\n", key, val);
			done = 1;
		} else {
			fputs(line, out);
		}
	}
	if (in)
		fclose(in);
	if (!done)
		fprintf(out, "%s = %s\n", key, val);
	fchmod(fileno(out), 0644);
	if (fflush(out) || fsync(fileno(out)) || fclose(out) ||
	    rename(tmp, conf)) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

/* `get <knob>` or `get` (all): print the live kernel value(s). */
static int cmd_get(const char *key)
{
	char path[256];
	size_t i;

	if (key) {
		const struct knob *k = find_knob(key);

		if (!k) {
			fprintf(stderr, "secure-sudo: unknown setting '%s'\n", key);
			return -1;
		}
		snprintf(path, sizeof(path), SYSFS "/%s", k->sysfs);
		return cat_file(path) == 0 ? 0 : -1;
	}
	for (i = 0; i < ss_nknobs; i++) {
		snprintf(path, sizeof(path), SYSFS "/%s", ss_knobs[i].sysfs);
		printf("%-22s ", ss_knobs[i].cfg_key);
		if (cat_file(path) != 0)
			printf("(unavailable)\n");
	}
	return 0;
}

/* `settings`: list every configurable knob and policy list by name. */
static int cmd_settings(void)
{
	size_t i;

	printf("Scalar settings (get/set; set persists to secure-sudo.conf):\n");
	for (i = 0; i < ss_nknobs; i++)
		printf("  %s\n", ss_knobs[i].cfg_key);
	printf("\nPolicy lists (list/load; edit the .conf then `load`):\n");
	for (i = 0; i < ss_nlists; i++)
		printf("  %-22s (%s/%s)\n", ss_lists[i].secfs, CONFIG_DIR,
		       ss_lists[i].cfg_file);
	printf("\nTimeVault allowlist has its own command: vault-allow\n");
	printf("Config lock: `secure-sudo lock` (one-way, until reboot)\n");
	return 0;
}

/* `list <name>`: show a policy list's current kernel contents. */
static int cmd_list_one(const char *name)
{
	const struct listmap *m = find_list(name);
	char path[256];

	if (!m) {
		fprintf(stderr, "secure-sudo: unknown policy list '%s'\n", name);
		return -1;
	}
	snprintf(path, sizeof(path), SECFS "/%s", m->secfs);
	return cat_file(path) == 0 ? 0 : -1;
}

/*
 * `load`: push /etc/secure_sudo into the kernel (TODO P0-6).
 *
 * The same checks as `secure-sudo lint` run first; if they find an error,
 * nothing is written (--force overrides). Then the lists are loaded before
 * the settings, so a protection is switched on only after its allowlist is in
 * place, and every list and setting is reported as accepted, rejected (with
 * the kernel's reason) or skipped. Any rejection means the kernel is running
 * a partial policy; load says so and exits non-zero.
 */
struct load_tally {
	int accepted, rejected, skipped;
};

static void report(struct load_tally *t, const char *verdict, const char *what,
		   int line, const char *detail)
{
	if (!strcmp(verdict, "rejected"))
		t->rejected++;
	else if (!strcmp(verdict, "skipped"))
		t->skipped++;
	else
		t->accepted++;
	if (line)
		printf("  %-9s %-34s line %-4d %s\n", verdict, what, line,
		       detail ? detail : "");
	else
		printf("  %-9s %-34s %s\n", verdict, what, detail ? detail : "");
}

/* Push a config list file into its securityfs target. Missing file = clear. */
static void load_list(const struct listmap *m, struct load_tally *t)
{
	char cfg[256], sec[256], detail[96], *buf = NULL;
	size_t cap = 0, len = 0;
	int err = 0, entries = 0;
	FILE *f;

	snprintf(cfg, sizeof(cfg), CONFIG_DIR "/%s", m->cfg_file);
	snprintf(sec, sizeof(sec), SECFS "/%s", m->secfs);

	f = fopen(cfg, "re");
	if (f) {
		for (;;) {
			char chunk[4096];
			size_t n = fread(chunk, 1, sizeof(chunk), f);

			if (n == 0)
				break;
			if (len + n + 1 > cap) {
				char *grown;

				cap = (len + n + 1) * 2;
				grown = realloc(buf, cap);
				if (!grown) {
					free(buf);
					fclose(f);
					report(t, "rejected", m->secfs, 0, "out of memory");
					return;
				}
				buf = grown;
			}
			memcpy(buf + len, chunk, n);
			len += n;
		}
		fclose(f);
	}
	if (buf) {
		char *p, *save = NULL, *copy;

		buf[len] = '\0';
		copy = strdup(buf);
		for (p = copy; p && (p = strtok_r(p == copy ? copy : NULL, "\n", &save)); p = NULL) {
			while (*p == ' ' || *p == '\t')
				p++;
			if (*p && *p != '#')
				entries++;
		}
		free(copy);
	}
	if (write_file_err(sec, buf ? buf : "\n", buf ? len : 1, &err) != 0) {
		snprintf(detail, sizeof(detail), "%s", strerror(err));
		report(t, "rejected", m->secfs, 0, detail);
	} else if (!f) {
		report(t, "accepted", m->secfs, 0, "cleared (no config file)");
	} else {
		snprintf(detail, sizeof(detail), "%d entr%s", entries,
			 entries == 1 ? "y" : "ies");
		report(t, "accepted", m->secfs, 0, detail);
	}
	free(buf);
}

/* Push every setting in secure-sudo.conf, in file order. */
static void load_knobs(struct load_tally *t)
{
	struct cfg_file c;
	char what[96], why[160], path[256];
	int i, err;

	if (cfg_parse(CONFIG_DIR "/secure-sudo.conf", &c) != 0) {
		report(t, "skipped", "secure-sudo.conf", 0,
		       "not found: kernel settings keep their current values");
		return;
	}
	for (i = 0; i < c.n; i++) {
		const struct cfg_entry *e = &c.e[i];
		const struct knob *k = e->bad ? NULL : find_knob(e->key);

		snprintf(what, sizeof(what), "%.40s = %.48s", e->key, e->val);
		if (e->bad) {
			report(t, "rejected", e->key, e->line, e->bad);
		} else if (k) {
			if (check_value(k, e->val, why, sizeof(why))) {
				report(t, "rejected", what, e->line, why);
				continue;
			}
			snprintf(path, sizeof(path), SYSFS "/%s", k->sysfs);
			if (write_file_err(path, e->val, strlen(e->val), &err) == 0)
				report(t, "accepted", what, e->line, NULL);
			else
				report(t, "rejected", what, e->line, strerror(err));
		} else if (is_daemon_key(e->key)) {
			report(t, "skipped", e->key, e->line, "read by secure-sudod, not the kernel");
		} else if (!strcmp(e->key, "timevault_enabled")) {
			report(t, "skipped", e->key, e->line,
			       "TimeVault is only engaged by hand (it locks the config)");
		} else {
			report(t, "rejected", e->key, e->line, "unknown setting");
		}
	}
	cfg_free(&c);
}

static int cmd_load(int force)
{
	struct lint_opts o = {
		.cfgdir = CONFIG_DIR, .pamdir = "/etc/pam.d",
		.otpdir = "/var/lib/secure_sudo/otp", .sysfs = SYSFS, .secfs = SECFS,
		.quiet = 1, .pam_soft = 1,
	};
	struct load_tally t = { 0, 0, 0 };
	size_t i;

	printf("secure-sudo load: %s\n", CONFIG_DIR);
	if (access(SYSFS, F_OK) != 0) {
		fprintf(stderr, "secure-sudo: LSM not active (no %s); nothing loaded\n", SYSFS);
		return -1;
	}
	if (policy_lint(&o) > 0) {
		if (!force) {
			fprintf(stderr, "secure-sudo: load refused: fix the errors above "
				"(nothing was changed), or use `load --force`\n");
			return -1;
		}
		fprintf(stderr, "secure-sudo: --force: loading despite the errors above\n");
	}
	for (i = 0; i < ss_nlists; i++)
		load_list(&ss_lists[i], &t);
	load_knobs(&t);

	printf("load: %d accepted, %d rejected, %d skipped\n",
	       t.accepted, t.rejected, t.skipped);
	if (t.rejected) {
		fprintf(stderr, "secure-sudo: load INCOMPLETE: the kernel is running a "
			"partial policy; fix the rejected lines and run load again\n");
		return -1;
	}
	return 0;
}

static int cmd_status(void)
{
	size_t i;
	char path[256];

	printf("secure_sudo status\n==================\n");
	if (access(SYSFS, F_OK) != 0) {
		printf("LSM not active (no %s). Is secure_sudo in CONFIG_LSM?\n",
		       SYSFS);
		return 1;
	}
	for (i = 0; i < ss_nknobs; i++) {
		snprintf(path, sizeof(path), SYSFS "/%s", ss_knobs[i].sysfs);
		printf("%-24s ", ss_knobs[i].cfg_key);
		if (cat_file(path) != 0)
			printf("(unavailable)\n");
	}
	snprintf(path, sizeof(path), SYSFS "/timevault");
	printf("%-24s ", "timevault");
	if (cat_file(path) != 0) printf("(unavailable)\n");
	snprintf(path, sizeof(path), SYSFS "/timevault_denied");
	printf("%-24s ", "timevault_denied");
	if (cat_file(path) != 0) printf("(unavailable)\n");
	snprintf(path, sizeof(path), SYSFS "/lock");
	printf("%-24s ", "lock");
	if (cat_file(path) != 0) printf("(unavailable)\n");
	/* #17: whether THIS boot has BinaryVault open for maintenance. */
	snprintf(path, sizeof(path), SYSFS "/binvault_maint");
	printf("%-24s ", "binvault_maint");
	if (cat_file(path) != 0) printf("(unavailable)\n");
	return 0;
}

/*
 * `secure-sudo radio <wifi|bluetooth|ethernet-only|status> [on|off]`
 *
 * Friendly wrapper over the block_wifi / block_bluetooth / ethernet_only
 * knobs. Note the sense: "radio wifi off" means turn the RADIO off, i.e. set
 * block_wifi=1; "radio wifi on" re-enables it (block_wifi=0). ethernet-only is
 * the master switch (ethernet_only knob). Each change goes to the kernel first
 * and is persisted only if the kernel accepts it, exactly like `set`.
 */
static int cmd_radio(int argc, char **argv)
{
	const char *knob;
	const char *val;

	if (argc == 1 && !strcmp(argv[0], "status")) {
		/* Show the three live values. */
		char path[256];
		const char *names[] = { "block_wifi", "block_bluetooth",
					"ethernet_only" };
		size_t i;
		for (i = 0; i < 3; i++) {
			snprintf(path, sizeof(path), SYSFS "/%s", names[i]);
			printf("%-18s ", names[i]);
			if (cat_file(path) != 0)
				printf("(unavailable)\n");
		}
		return 0;
	}
	if (argc != 2) {
		fprintf(stderr,
			"usage: secure-sudo radio <wifi|bluetooth|ethernet-only> <on|off>\n"
			"       secure-sudo radio status\n"
			"  (\"off\" turns the radio OFF; \"on\" allows it)\n");
		return 2;
	}

	if      (!strcmp(argv[0], "wifi"))          knob = "block_wifi";
	else if (!strcmp(argv[0], "bluetooth"))     knob = "block_bluetooth";
	else if (!strcmp(argv[0], "bt"))            knob = "block_bluetooth";
	else if (!strcmp(argv[0], "ethernet-only")) knob = "ethernet_only";
	else if (!strcmp(argv[0], "ethernet_only")) knob = "ethernet_only";
	else { fprintf(stderr, "secure-sudo: unknown radio '%s'\n", argv[0]); return 2; }

	/* radio off => block = 1; radio on => block = 0. */
	if      (!strcmp(argv[1], "off")) val = "1";
	else if (!strcmp(argv[1], "on"))  val = "0";
	else { fprintf(stderr, "secure-sudo: radio value must be on|off\n"); return 2; }

	if (set_knob(knob, val) != 0)
		return 1;
	if (persist_knob(knob, val) != 0)
		fprintf(stderr, "secure-sudo: set live, but failed to persist '%s'\n", knob);
	printf("secure-sudo: %s %s (%s=%s)\n", argv[0], argv[1], knob, val);
	return 0;
}


/*
 * `secure-sudo prguard <on|off|status|list|add|remove> [path]`
 *
 * on/off      -> set prguard_enabled (kernel + persisted)
 * status      -> print prguard_enabled
 * list        -> print the live kernel exemption list
 * add <path>  -> add an absolute exe path to prguard_allow.conf and push it
 * remove <p>  -> remove it
 *
 * The exemption list file is /etc/secure_sudo/prguard_allow.conf, pushed to the
 * securityfs file /sys/kernel/security/secure_sudo/prguard_allow as a whole-
 * list replacement (same model as every other policy list).
 */
#define PRGUARD_CONF  CONFIG_DIR "/prguard_allow.conf"
#define PRGUARD_SECFS SECFS "/prguard_allow"

static int prguard_push_file(void)
{
	/* Read the conf file and write it verbatim to the securityfs node. */
	char *buf = NULL;
	long n = 0;
	FILE *f = fopen(PRGUARD_CONF, "re");
	int rc = 0;

	if (f) {
		fseek(f, 0, SEEK_END);
		n = ftell(f);
		if (n < 0) n = 0;
		fseek(f, 0, SEEK_SET);
		buf = malloc((size_t)n + 1);
		if (buf && n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
			free(buf); buf = NULL;
		}
		fclose(f);
	}
	if (!buf) { buf = malloc(1); n = 0; }
	if (!buf) return -1;
	buf[n] = '\0';
	if (write_file(PRGUARD_SECFS, buf, (size_t)n) != 0) {
		fprintf(stderr, "secure-sudo: could not push prguard list to the kernel "
			"(is the LSM active and unlocked?)\n");
		rc = -1;
	}
	free(buf);
	return rc;
}

static int prguard_edit(const char *path, int add)
{
	/* Load lines, add/remove the exact path, rewrite the file. */
	char real[PATH_MAX];
	char **lines = NULL; size_t n = 0, i; int found = 0, rc = 0;
	char linebuf[PATH_MAX + 8];
	FILE *f;

	if (!realpath(path, real))
		snprintf(real, sizeof(real), "%s", path);	/* keep as given */
	if (real[0] != '/') {
		fprintf(stderr, "secure-sudo: prguard paths must be absolute\n");
		return 1;
	}
	f = fopen(PRGUARD_CONF, "re");
	if (f) {
		while (fgets(linebuf, sizeof(linebuf), f)) {
			char *p = linebuf, *e;
			while (*p == ' ' || *p == '\t') p++;
			e = p + strlen(p);
			while (e > p && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' '))
				*--e = '\0';
			if (!strcmp(p, real)) { found = 1; if (!add) continue; }
			if (*p) {
				char **nl = realloc(lines, (n + 1) * sizeof(*lines));
				if (!nl) { rc = 1; break; }
				lines = nl; lines[n++] = strdup(p);
			}
		}
		fclose(f);
	}
	if (add && !found) {
		char **nl = realloc(lines, (n + 1) * sizeof(*lines));
		if (nl) { lines = nl; lines[n++] = strdup(real); }
		else rc = 1;
	}
	if (!add && !found)
		fprintf(stderr, "secure-sudo: %s was not in the list\n", real);

	if (!rc) {
		mkdir(CONFIG_DIR, 0700);
		f = fopen(PRGUARD_CONF, "we");
		if (!f) { fprintf(stderr, "secure-sudo: %s: %s\n", PRGUARD_CONF, strerror(errno)); rc = 1; }
		else {
			fprintf(f, "# Process Runtime Guard (#20) exemption list - absolute exe paths.\n");
			for (i = 0; i < n; i++) fprintf(f, "%s\n", lines[i]);
			fclose(f);
		}
	}
	for (i = 0; i < n; i++) free(lines[i]);
	free(lines);
	if (rc) return 1;
	if (prguard_push_file() != 0) return 1;
	printf("%s %s\n", add ? "added" : "removed", real);
	return 0;
}

static int cmd_prguard(int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "usage: secure-sudo prguard <on|off|status|list|add|remove> [path]\n");
		return 2;
	}
	if (!strcmp(argv[0], "on") || !strcmp(argv[0], "off")) {
		const char *v = argv[0][1] == 'n' ? "1" : "0";
		if (set_knob("prguard_enabled", v) != 0)
			return 1;
		persist_knob("prguard_enabled", v);
		printf("prguard %s\n", argv[0]);
		return 0;
	}
	if (!strcmp(argv[0], "status")) {
		char path[256];
		snprintf(path, sizeof(path), SYSFS "/prguard_enabled");
		printf("prguard_enabled ");
		if (cat_file(path) != 0) printf("(unavailable)\n");
		return 0;
	}
	if (!strcmp(argv[0], "list"))
		return cmd_list_one("prguard_allow") == 0 ? 0 : 1;
	if (!strcmp(argv[0], "add") && argc == 2)
		return prguard_edit(argv[1], 1);
	if ((!strcmp(argv[0], "remove") || !strcmp(argv[0], "rm")) && argc == 2)
		return prguard_edit(argv[1], 0);
	fprintf(stderr, "usage: secure-sudo prguard <on|off|status|list|add|remove> [path]\n");
	return 2;
}

static int cmd_otp(int argc, char **argv)
{
	/* Hand off to the OTP helper, preserving argv. */
	char **nargv = calloc(argc + 1, sizeof(char *));
	int i;

	if (!nargv)
		return -1;
	nargv[0] = (char *)OTP_HELPER;
	for (i = 1; i < argc; i++)
		nargv[i] = argv[i];
	nargv[argc] = NULL;
	execv(OTP_HELPER, nargv);
	fprintf(stderr, "secure-sudo: cannot exec %s: %s\n", OTP_HELPER,
		strerror(errno));
	free(nargv);
	return -1;
}

static int cmd_pheonixbox(int argc, char **argv)
{
	/* Hand off to the PheonixBox helper, preserving argv (so
	 * `secure-sudo pheonixbox enable` becomes `secure-sudo-pheonixbox
	 * enable`). The helper does its own root check. */
	char **nargv = calloc(argc, sizeof(char *));
	int i;

	if (!nargv)
		return -1;
	nargv[0] = (char *)PHEONIXBOX_HELPER;
	for (i = 2; i < argc; i++)		/* skip argv[1] == "pheonixbox" */
		nargv[i - 1] = argv[i];
	nargv[argc - 1] = NULL;
	execv(PHEONIXBOX_HELPER, nargv);
	fprintf(stderr, "secure-sudo: cannot exec %s: %s\n", PHEONIXBOX_HELPER,
		strerror(errno));
	free(nargv);
	return -1;
}

static void usage(void)
{
	fprintf(stderr,
"Usage: secure-sudo <command> [args]\n"
"  lint [--config-dir D] check the policy, admin groups, allowlists and PAM\n"
"                       order before enforcing (read-only; any user)\n"
"  load [--force]       lint, then push /etc/secure_sudo/* into the kernel and\n"
"                       report every setting as accepted/rejected/skipped\n"
"  status               show current kernel policy state\n"
"  settings             list every configurable knob and policy list\n"
"  get [<knob>]         show one (or all) live scalar knob value(s)\n"
"  set <knob> <value>   set a scalar knob and persist it to the config\n"
"  list <name>          show a policy list's current kernel contents\n"
"  net <mode>           monitor | host | lan-only | public-only\n"
"  radio <w|bt|ethernet-only> <on|off>   toggle Wi-Fi/Bluetooth (off = radio off)\n"
"  prguard <on|off|status|list|add|remove> [path]   process runtime (memory) guard\n"
"  timevault <on|off>   engage/disengage TimeVault lockdown\n"
"  lock                 lock the config until reboot (irreversible)\n"
"  detect-admins [-n]   re-detect admin groups (sudo/wheel/admin/sudoers)\n"
"  otp <...>            OTP setup/show-qr/show-key/verify/reset/disable\n"
"  pheonixbox <...>     on/off/snapshot/scan/status/add/remove/list snapshot tamper protection\n"
"\nEvery configurable kernel setting is reachable here; `settings` lists them.\n"
"All commands but lint are root-only and refused once the config is locked.\n");
	vault_allow_usage();
}

int main(int argc, char **argv)
{
	/* Reports mix stdout and stderr; keep them in order through a pipe. */
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2) {
		usage();
		return 2;
	}

	/* otp and pheonixbox are delegated; they do their own privilege checks. */
	if (!strcmp(argv[1], "otp"))
		return cmd_otp(argc, argv) == 0 ? 0 : 1;
	if (!strcmp(argv[1], "pheonixbox"))
		return cmd_pheonixbox(argc, argv) == 0 ? 0 : 1;

	/* lint is read-only and may run as anyone (e.g. before install). */
	if (!strcmp(argv[1], "lint"))
		return cmd_lint(argc - 2, argv + 2);

	if (require_root() != 0)
		return 1;

	if (!strcmp(argv[1], "load") &&
	    (argc == 2 || (argc == 3 && !strcmp(argv[2], "--force"))))
		return cmd_load(argc == 3) == 0 ? 0 : 1;
	if (!strcmp(argv[1], "status"))
		return cmd_status();
	if (!strcmp(argv[1], "settings"))
		return cmd_settings();
	if (!strcmp(argv[1], "get") && argc <= 3)
		return cmd_get(argc == 3 ? argv[2] : NULL) == 0 ? 0 : 1;
	if (!strcmp(argv[1], "set") && argc == 4) {
		/* Push to the kernel first; only persist if the kernel accepted
		 * it, so the saved config can never diverge from live policy. */
		if (set_knob(argv[2], argv[3]) != 0)
			return 1;
		if (persist_knob(argv[2], argv[3]) != 0)
			fprintf(stderr, "secure-sudo: set live, but failed to persist "
				"'%s' to the config\n", argv[2]);
		return 0;
	}
	if (!strcmp(argv[1], "list") && argc == 3)
		return cmd_list_one(argv[2]) == 0 ? 0 : 1;
	if (!strcmp(argv[1], "net") && argc == 3) {
		if (set_knob("net_mode", argv[2]) != 0)
			return 1;
		persist_knob("net_mode", argv[2]);
		return 0;
	}
	if (!strcmp(argv[1], "timevault") && argc == 3) {
		const char *v = !strcmp(argv[2], "on") ? "1" :
				!strcmp(argv[2], "off") ? "0" : NULL;
		if (!v) { usage(); return 2; }
		/* Not persisted: engaging TimeVault also locks the config, so
		 * it is never re-engaged automatically by `load` at boot. */
		return write_file(SYSFS "/timevault", v, 1) == 0 ? 0 : 1;
	}
	if (!strcmp(argv[1], "radio"))
		return cmd_radio(argc - 2, argv + 2) == 0 ? 0 : 1;
	if (!strcmp(argv[1], "prguard"))
		return cmd_prguard(argc - 2, argv + 2) == 0 ? 0 : 1;
	if (!strcmp(argv[1], "vault-allow"))
		return cmd_vault_allow(argc - 2, argv + 2);
	if (!strcmp(argv[1], "detect-admins"))
		return cmd_detect_admins(argc - 2, argv + 2);
	if (!strcmp(argv[1], "lock")) {
		/* Confirm unless -y: this cannot be undone without a reboot. */
		if (!(argc == 3 && !strcmp(argv[2], "-y"))) {
			char ans[8] = "";

			fprintf(stderr, "Lock the configuration until the next reboot? "
				"No setting can change after this. Type 'yes': ");
			if (!fgets(ans, sizeof(ans), stdin) || strcmp(ans, "yes\n")) {
				fprintf(stderr, "aborted\n");
				return 1;
			}
		}
		return write_file(SYSFS "/lock", "1", 1) == 0 ? 0 : 1;
	}

	usage();
	return 2;
}
