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
 * ("status"), and hands OTP subcommands to the otp helper.
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

#define SYSFS  "/sys/kernel/secure_sudo"
#define SECFS  "/sys/kernel/security/secure_sudo"
#define CONFIG_DIR "/etc/secure_sudo"
#define OTP_HELPER "/usr/bin/secure-sudo-otp"

/* scalar knob  <- config key  (sysfs file under SYSFS) */
struct knob {
	const char *cfg_key;	/* key in secure-sudo.conf */
	const char *sysfs;	/* file under SYSFS */
};

static const struct knob knobs[] = {
	{ "admin_gid",            "admin_gid" },
	{ "block_setid",          "block_setid" },
	{ "block_userns",         "block_userns" },
	{ "block_flash",          "block_flash" },
	{ "ram_spike_enabled",    "ram_spike_enabled" },
	{ "max_ram_percent",      "max_ram_percent" },
	{ "check_interval_ms",    "check_interval_ms" },
	{ "drop_cooldown_ms",     "drop_cooldown_ms" },
	{ "block_tmp_exec",       "block_tmp_exec" },
	{ "net_mode",             "net_mode" },
	{ "sudo_max_fails",       "sudo_max_fails" },
	{ "sudo_window_sec",      "sudo_window_sec" },
	{ "sudo_block_time_sec",  "sudo_block_time_sec" },
	{ "sudo_cooldown_enabled","sudo_cooldown_enabled" },
	{ "block_home_write",     "block_home_write" },
};

/* policy list  config file  ->  securityfs file */
struct listmap {
	const char *cfg_file;	/* file in CONFIG_DIR */
	const char *secfs;	/* file under SECFS */
};

static const struct listmap lists[] = {
	{ "blacklist.conf",             "blacklist" },
	{ "tmp_exec_allow.conf",        "tmp_exec_allow" },
	{ "node_allowed_children.conf", "node_allowed_children" },
	{ "node_sea_binaries.conf",     "node_sea_binaries" },
	{ "driver_blacklist.conf",      "driver_blacklist" },
	{ "timevault_allow.conf",       "timevault_allow" },
	{ "home_map.conf",              "home_map" },
	{ "home_write_allow.conf",      "home_write_allow" },
};

static int require_root(void)
{
	if (geteuid() != 0) {
		fprintf(stderr, "secure-sudo: must be run as root (try: sudo secure-sudo ...)\n");
		return -1;
	}
	return 0;
}

/* Write a NUL-terminated string to a kernel file; returns 0 on success. */
static int write_file(const char *path, const char *data, size_t len)
{
	int fd = open(path, O_WRONLY | O_TRUNC);
	ssize_t n;

	if (fd < 0) {
		fprintf(stderr, "secure-sudo: open %s: %s\n", path,
			strerror(errno));
		return -1;
	}
	n = write(fd, data, len);
	if (n < 0) {
		fprintf(stderr, "secure-sudo: write %s: %s\n", path,
			strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
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

static const struct knob *find_knob(const char *key)
{
	size_t i;

	for (i = 0; i < sizeof(knobs) / sizeof(knobs[0]); i++)
		if (!strcmp(knobs[i].cfg_key, key))
			return &knobs[i];
	return NULL;
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

/* Push a config list file into its securityfs target. Missing file = clear. */
static int load_list(const struct listmap *m)
{
	char cfg[256], sec[256], *buf = NULL;
	size_t cap = 0, len = 0;
	FILE *f;
	int ret;

	snprintf(cfg, sizeof(cfg), CONFIG_DIR "/%s", m->cfg_file);
	snprintf(sec, sizeof(sec), SECFS "/%s", m->secfs);

	f = fopen(cfg, "re");
	if (!f) {
		/* No config file: write a single newline to clear the list. */
		return write_file(sec, "\n", 1);
	}

	/* Slurp the whole file. */
	for (;;) {
		char chunk[4096];
		size_t n = fread(chunk, 1, sizeof(chunk), f);

		if (n == 0)
			break;
		if (len + n + 1 > cap) {
			cap = (len + n + 1) * 2;
			buf = realloc(buf, cap);
			if (!buf) {
				fclose(f);
				fprintf(stderr, "secure-sudo: out of memory\n");
				return -1;
			}
		}
		memcpy(buf + len, chunk, n);
		len += n;
	}
	fclose(f);
	if (!buf) {
		return write_file(sec, "\n", 1);
	}
	buf[len] = '\0';
	ret = write_file(sec, buf, len);
	free(buf);
	return ret;
}

/* Parse secure-sudo.conf (key = value, # comments) and push every knob. */
static int load_knobs(void)
{
	char path[256], line[512];
	FILE *f;
	int rc = 0;

	snprintf(path, sizeof(path), CONFIG_DIR "/secure-sudo.conf");
	f = fopen(path, "re");
	if (!f) {
		fprintf(stderr, "secure-sudo: %s not found, skipping knobs\n",
			path);
		return 0;
	}

	while (fgets(line, sizeof(line), f)) {
		char *key, *val, *eq, *p;

		p = line;
		while (isspace((unsigned char)*p))
			p++;
		if (*p == '#' || *p == '\0' || *p == '\n')
			continue;
		eq = strchr(p, '=');
		if (!eq)
			continue;
		*eq = '\0';
		key = p;
		val = eq + 1;

		/* trim key */
		for (char *e = key + strlen(key) - 1; e >= key && isspace((unsigned char)*e); e--)
			*e = '\0';
		/* trim val */
		while (isspace((unsigned char)*val))
			val++;
		for (char *e = val + strlen(val) - 1; e >= val && isspace((unsigned char)*e); e--)
			*e = '\0';

		if (!find_knob(key))
			continue;	/* non-kernel key (daemon-only), skip */
		if (set_knob(key, val) != 0)
			rc = -1;
	}
	fclose(f);
	return rc;
}

static int cmd_load(void)
{
	size_t i;
	int rc = 0;

	if (load_knobs() != 0)
		rc = -1;
	for (i = 0; i < sizeof(lists) / sizeof(lists[0]); i++)
		if (load_list(&lists[i]) != 0)
			rc = -1;

	if (rc == 0)
		printf("secure-sudo: policy loaded from %s\n", CONFIG_DIR);
	else
		fprintf(stderr, "secure-sudo: policy load finished with errors\n");
	return rc;
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
	for (i = 0; i < sizeof(knobs) / sizeof(knobs[0]); i++) {
		snprintf(path, sizeof(path), SYSFS "/%s", knobs[i].sysfs);
		printf("%-24s ", knobs[i].cfg_key);
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
	return 0;
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

static void usage(void)
{
	fprintf(stderr,
"Usage: secure-sudo <command> [args]\n"
"  load                 push /etc/secure_sudo/* into the kernel\n"
"  status               show current kernel policy state\n"
"  set <knob> <value>   set one scalar knob (see secure-sudo.conf keys)\n"
"  net <mode>           monitor | host | lan-only | public-only\n"
"  timevault <on|off>   engage/disengage TimeVault lockdown\n"
"  lock                 lock the config until reboot (irreversible)\n"
"  otp <...>            OTP setup/show-qr/show-key/verify/reset/disable\n");
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 2;
	}

	/* otp is delegated; it does its own privilege checks per subcommand. */
	if (!strcmp(argv[1], "otp"))
		return cmd_otp(argc, argv) == 0 ? 0 : 1;

	if (require_root() != 0)
		return 1;

	if (!strcmp(argv[1], "load"))
		return cmd_load() == 0 ? 0 : 1;
	if (!strcmp(argv[1], "status"))
		return cmd_status();
	if (!strcmp(argv[1], "set") && argc == 4)
		return set_knob(argv[2], argv[3]) == 0 ? 0 : 1;
	if (!strcmp(argv[1], "net") && argc == 3)
		return set_knob("net_mode", argv[2]) == 0 ? 0 : 1;
	if (!strcmp(argv[1], "timevault") && argc == 3) {
		const char *v = !strcmp(argv[2], "on") ? "1" :
				!strcmp(argv[2], "off") ? "0" : NULL;
		if (!v) { usage(); return 2; }
		return write_file(SYSFS "/timevault", v, 1) == 0 ? 0 : 1;
	}
	if (!strcmp(argv[1], "lock"))
		return write_file(SYSFS "/lock", "1", 1) == 0 ? 0 : 1;

	usage();
	return 2;
}
