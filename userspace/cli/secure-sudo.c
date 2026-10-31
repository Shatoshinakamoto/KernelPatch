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
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>

#include "cli.h"

#define OTP_HELPER "/usr/bin/secure-sudo-otp"
#define PHEONIXBOX_HELPER "/usr/bin/secure-sudo-pheonixbox"
#define EVIDENCE_HELPER "/usr/libexec/secure-sudo/evidence-export.sh"
#define EVIDENCE_VERIFY_HELPER "/usr/libexec/secure-sudo/evidence-verify.py"
#ifndef SYSTEMCTL
#define SYSTEMCTL "/usr/bin/systemctl"
#endif
#ifndef ADDON_STATE_DIR
#define ADDON_STATE_DIR "/var/lib/secure_sudo/addons"
#endif
#ifndef HEALTH_FILE
#define HEALTH_FILE "/var/lib/secure_sudo/daemon.health"
#endif
#ifndef LOAD_HEALTH_FILE
#define LOAD_HEALTH_FILE "/var/lib/secure_sudo/load.health"
#endif
#ifndef AUDIT_ENABLED_FILE
#define AUDIT_ENABLED_FILE "/proc/sys/kernel/audit_enabled"
#endif
#ifndef BOOT_ID_FILE
#define BOOT_ID_FILE "/proc/sys/kernel/random/boot_id"
#endif

static int require_root(void)
{
#ifdef SS_TESTING
	if (getenv("SS_TEST_ALLOW_ROOT"))
		return 0;
#endif
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
	char rejected_keys[8][64];
	int rejected_keys_count;
	int rejected_keys_omitted;
};

static int read_value(const char *path, char *buf, size_t size);

static int persist_load_health(const char *state, const struct load_tally *t)
{
	char temporary[512] = { 0 }, parent[512], record[768], boot_id[64];
	struct stat st;
	char *slash;
	int fd = -1, dirfd = -1, saved_errno = 0;
	int length, result = -1;
	ssize_t written;
	size_t offset = 0;
	size_t used;
	int i;

	length = snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX",
			  LOAD_HEALTH_FILE);
	if (length < 0 || (size_t)length >= sizeof(temporary)) {
		errno = ENAMETOOLONG;
		goto done;
	}
	length = snprintf(parent, sizeof(parent), "%s", LOAD_HEALTH_FILE);
	if (length < 0 || (size_t)length >= sizeof(parent)) {
		errno = ENAMETOOLONG;
		goto done;
	}
	slash = strrchr(parent, '/');
	if (slash) {
		if (slash == parent)
			slash[1] = '\0';
		else
			*slash = '\0';
	} else {
		snprintf(parent, sizeof(parent), ".");
	}
	if (mkdir(parent, 0700) != 0 && errno != EEXIST)
		goto done;
	if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode) ||
	    st.st_uid != 0 || (st.st_mode & 0022)) {
		errno = EPERM;
		goto done;
	}
	if (read_value(BOOT_ID_FILE, boot_id, sizeof(boot_id)) != 0)
		goto done;
	length = snprintf(record, sizeof(record), "updated=%lld boot_id=%s "
			  "state=%s accepted=%d rejected=%d skipped=%d "
			  "rejected_keys=",
			  (long long)time(NULL), boot_id, state, t->accepted,
			  t->rejected, t->skipped);
	if (length < 0 || (size_t)length >= sizeof(record)) {
		errno = EOVERFLOW;
		goto done;
	}
	used = (size_t)length;
	for (i = 0; i < t->rejected_keys_count; i++) {
		length = snprintf(record + used, sizeof(record) - used, "%s%s",
				  i ? "," : "", t->rejected_keys[i]);
		if (length < 0 || (size_t)length >= sizeof(record) - used) {
			errno = EOVERFLOW;
			goto done;
		}
		used += (size_t)length;
	}
	if (!t->rejected_keys_count) {
		length = snprintf(record + used, sizeof(record) - used, "-");
		if (length < 0 || (size_t)length >= sizeof(record) - used) {
			errno = EOVERFLOW;
			goto done;
		}
		used += (size_t)length;
	}
	length = snprintf(record + used, sizeof(record) - used,
			  " omitted=%d\n", t->rejected_keys_omitted);
	if (length < 0 || (size_t)length >= sizeof(record) - used) {
		errno = EOVERFLOW;
		goto done;
	}
	used += (size_t)length;
	fd = mkstemp(temporary);
	if (fd < 0)
		goto done;
	if (fchmod(fd, 0600) != 0)
		goto done;
	while (offset < used) {
		written = write(fd, record + offset, used - offset);
		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0) {
			if (written == 0)
				errno = EIO;
			goto done;
		}
		offset += (size_t)written;
	}
	if (fsync(fd) != 0)
		goto done;
	if (close(fd) != 0) {
		fd = -1;
		goto done;
	}
	fd = -1;
	if (rename(temporary, LOAD_HEALTH_FILE) != 0)
		goto done;
	dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0 || fsync(dirfd) != 0)
		goto done;
	result = 0;

done:
	saved_errno = errno;
	if (fd >= 0)
		close(fd);
	if (dirfd >= 0)
		close(dirfd);
	if (result != 0 && temporary[0])
		unlink(temporary);
	errno = saved_errno;
	return result;
}

static void report(struct load_tally *t, const char *verdict, const char *what,
		   int line, const char *detail)
{
	if (!strcmp(verdict, "rejected")) {
		char key[64];
		const char *end = strchr(what, '=');
		size_t i, len = end ? (size_t)(end - what) : strlen(what);

		t->rejected++;
		while (len && (what[len - 1] == ' ' || what[len - 1] == '\t'))
			len--;
		if (len > sizeof(key) - 1)
			len = sizeof(key) - 1;
		for (i = 0; i < len; i++) {
			unsigned char c = what[i];

			key[i] = ((c >= 'a' && c <= 'z') ||
				  (c >= 'A' && c <= 'Z') ||
				  (c >= '0' && c <= '9') ||
				  c == '_' || c == '-' || c == '.') ?
				 (char)c : '_';
		}
		key[len] = '\0';
		if (t->rejected_keys_count <
		    (int)(sizeof(t->rejected_keys) / sizeof(t->rejected_keys[0])))
			snprintf(t->rejected_keys[t->rejected_keys_count++],
				 sizeof(t->rejected_keys[0]), "%s", key);
		else
			t->rejected_keys_omitted++;
	} else if (!strcmp(verdict, "skipped"))
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
	struct load_tally t = { 0 };
	size_t i;

	printf("secure-sudo load: %s\n", CONFIG_DIR);
	if (access(SYSFS, F_OK) != 0) {
		fprintf(stderr, "secure-sudo: LSM not active (no %s); nothing loaded\n", SYSFS);
		if (persist_load_health("refused", &t) != 0)
			fprintf(stderr, "secure-sudo: could not persist load health: %s\n",
				strerror(errno));
		return -1;
	}
	if (policy_lint(&o) > 0) {
		if (!force) {
			fprintf(stderr, "secure-sudo: load refused: fix the errors above "
				"(nothing was changed), or use `load --force`\n");
			if (persist_load_health("refused", &t) != 0)
				fprintf(stderr, "secure-sudo: could not persist load health: %s\n",
					strerror(errno));
			return -1;
		}
		fprintf(stderr, "secure-sudo: --force: loading despite the errors above\n");
	}
	for (i = 0; i < ss_nlists; i++)
		load_list(&ss_lists[i], &t);
	load_knobs(&t);

	printf("load: %d accepted, %d rejected, %d skipped\n",
	       t.accepted, t.rejected, t.skipped);
	if (persist_load_health(t.rejected ? "partial" : "complete", &t) != 0) {
		fprintf(stderr, "secure-sudo: load was applied but could not persist "
			"load health: %s\n", strerror(errno));
		return -1;
	}
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

static int read_value(const char *path, char *buf, size_t size)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, size - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
			 buf[n - 1] == ' ' || buf[n - 1] == '\t'))
		buf[--n] = '\0';
	return 0;
}

static int read_counter(const char *name, unsigned long long *value)
{
	char path[256], buf[64], *end;

	snprintf(path, sizeof(path), SYSFS "/%s", name);
	if (read_value(path, buf, sizeof(buf)) != 0)
		return -1;
	errno = 0;
	*value = strtoull(buf, &end, 10);
	return errno || end == buf || *end ? -1 : 0;
}

static const char *audit_feed_health(void)
{
	char path[256], value[32], *end;
	unsigned long enabled;

	snprintf(path, sizeof(path), SYSFS "/audit_events");
	if (read_value(path, value, sizeof(value)) != 0)
		return "unavailable";
	errno = 0;
	enabled = strtoul(value, &end, 10);
	if (errno || end == value || *end || enabled > 1)
		return "unavailable";
	if (!enabled)
		return "disabled";
	if (read_value(AUDIT_ENABLED_FILE, value, sizeof(value)) != 0)
		return "unavailable";
	errno = 0;
	enabled = strtoul(value, &end, 10);
	if (errno || end == value || *end)
		return "unavailable";
	return enabled ? "active" : "inactive";
}

/*
 * Find "name=" as a whole key: at the start of the record or after a space.
 * A plain strstr() would let "state=" match inside "retention_state=".
 */
static const char *heartbeat_key(const char *heartbeat, const char *key)
{
	const char *p = heartbeat;

	while ((p = strstr(p, key))) {
		if (p == heartbeat || p[-1] == ' ' || p[-1] == '\t' ||
		    p[-1] == '\n')
			return p;
		p++;
	}
	return NULL;
}

static int heartbeat_counter(const char *heartbeat, const char *name,
			     unsigned long long *value)
{
	char key[64], *end;
	const char *p;

	snprintf(key, sizeof(key), "%s=", name);
	p = heartbeat_key(heartbeat, key);
	if (!p)
		return -1;
	p += strlen(key);
	errno = 0;
	*value = strtoull(p, &end, 10);
	return errno || end == p ? -1 : 0;
}

static int heartbeat_value(const char *heartbeat, const char *name,
			   char *value, size_t size)
{
	char key[64], *end;
	const char *p;
	size_t len;

	snprintf(key, sizeof(key), "%s=", name);
	p = heartbeat_key(heartbeat, key);
	if (!p)
		return -1;
	p += strlen(key);
	end = strpbrk(p, " \t\r\n");
	len = end ? (size_t)(end - p) : strlen(p);
	if (!len || len >= size)
		return -1;
	memcpy(value, p, len);
	value[len] = '\0';
	return 0;
}

static int read_load_health(char *state, size_t state_size,
			    unsigned long long *updated,
			    unsigned long long *accepted,
			    unsigned long long *rejected,
			    unsigned long long *skipped,
			    unsigned long long *rejected_omitted,
			    char *rejected_keys, size_t rejected_keys_size,
			    int test_override)
{
	char record[768], updated_text[32], record_boot_id[64];
	char current_boot_id[64], *end;
	struct stat st;

	if (lstat(LOAD_HEALTH_FILE, &st) != 0)
		return errno == ENOENT ? 1 : -1;
	if (!S_ISREG(st.st_mode) ||
	    (!test_override &&
	     (st.st_uid != 0 || (st.st_mode & 07777) != 0600)) ||
	    read_value(LOAD_HEALTH_FILE, record, sizeof(record)) != 0)
		return -1;
	if (heartbeat_value(record, "state", state, state_size) != 0 ||
	    (strcmp(state, "complete") && strcmp(state, "partial") &&
	     strcmp(state, "refused") && strcmp(state, "stale")) ||
	    heartbeat_value(record, "updated", updated_text,
			    sizeof(updated_text)) != 0 ||
	    heartbeat_value(record, "boot_id", record_boot_id,
			    sizeof(record_boot_id)) != 0 ||
	    heartbeat_value(record, "rejected_keys", rejected_keys,
			    rejected_keys_size) != 0 ||
	    read_value(BOOT_ID_FILE, current_boot_id,
		       sizeof(current_boot_id)) != 0)
		return -1;
	errno = 0;
	*updated = strtoull(updated_text, &end, 10);
	if (errno || end == updated_text || *end ||
	    heartbeat_counter(record, "accepted", accepted) != 0 ||
	    heartbeat_counter(record, "rejected", rejected) != 0 ||
	    heartbeat_counter(record, "skipped", skipped) != 0 ||
	    heartbeat_counter(record, "omitted", rejected_omitted) != 0)
		return -1;
	if (strcmp(record_boot_id, current_boot_id))
		snprintf(state, state_size, "stale");
	return 0;
}

static int settings_equal(const struct knob *k, const char *configured,
			  const char *live)
{
	char *end_cfg, *end_live;
	unsigned long cfg_num, live_num;

	if (k->type == K_BOOL) {
		int cfg_true = !strcasecmp(configured, "1") ||
			       !strcasecmp(configured, "yes") ||
			       !strcasecmp(configured, "on") ||
			       !strcasecmp(configured, "true") ||
			       !strcasecmp(configured, "y");
		int live_true = !strcasecmp(live, "1") ||
				!strcasecmp(live, "yes") ||
				!strcasecmp(live, "on") ||
				!strcasecmp(live, "true") ||
				!strcasecmp(live, "y");
		return cfg_true == live_true;
	}
	if (k->type == K_U32) {
		errno = 0;
		cfg_num = strtoul(configured, &end_cfg, 10);
		if (errno || end_cfg == configured || *end_cfg)
			return 0;
		errno = 0;
		live_num = strtoul(live, &end_live, 10);
		return !errno && end_live != live && !*end_live &&
		       cfg_num == live_num;
	}
	return !strcmp(configured, live);
}

struct health_unit {
	const char *unit;
	int check_active;
	const char *baseline;
	const char *scan_key;
	int is_timer;
};

static int query_health_unit(const char *unit, char *load, size_t load_size,
			     char *active, size_t active_size,
			     char *enabled, size_t enabled_size,
			     char *last_trigger, size_t trigger_size,
			     char *result, size_t result_size,
			     char *exit_status, size_t exit_status_size,
			     char *last_exit, size_t last_exit_size,
			     unsigned long long *last_exit_monotonic)
{
	char output[384], *save = NULL, *line;
	size_t used = 0;
	int pipefd[2], status, fd;
	int output_overflow = 0;
	pid_t child;
	ssize_t n;

	if (pipe(pipefd) != 0)
		return -1;
	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}
	if (child == 0) {
		char *const argv[] = {
			(char *)SYSTEMCTL, "show", "--property=LoadState",
			"--property=ActiveState", "--property=UnitFileState",
			"--property=LastTriggerUSec",
			"--property=Result", "--property=ExecMainStatus",
			"--property=ExecMainExitTimestamp",
			"--property=ExecMainExitTimestampMonotonic",
			(char *)unit, NULL
		};

		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(127);
		close(pipefd[1]);
		fd = open("/dev/null", O_WRONLY);
		if (fd >= 0) {
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
		execv(SYSTEMCTL, argv);
		_exit(127);
	}
	close(pipefd[1]);
	while (used < sizeof(output) - 1) {
		n = read(pipefd[0], output + used, sizeof(output) - 1 - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		used += (size_t)n;
	}
	output_overflow = used == sizeof(output) - 1;
	close(pipefd[0]);
	output[used] = '\0';
	if (waitpid(child, &status, 0) != child ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
	    output_overflow)
		return -1;

	*load = *active = *enabled = '\0';
	snprintf(result, result_size, "unknown");
	snprintf(exit_status, exit_status_size, "unknown");
	snprintf(last_exit, last_exit_size, "n/a");
	*last_exit_monotonic = 0;
	for (line = strtok_r(output, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *value = strchr(line, '=');

		if (!value)
			continue;
		*value++ = '\0';
		if (!strcmp(line, "LoadState"))
			snprintf(load, load_size, "%s", value);
		else if (!strcmp(line, "ActiveState"))
			snprintf(active, active_size, "%s", value);
		else if (!strcmp(line, "UnitFileState"))
			snprintf(enabled, enabled_size, "%s", value);
		else if (!strcmp(line, "LastTriggerUSec")) {
			size_t i;

			for (i = 0; value[i] && i + 1 < trigger_size; i++) {
				unsigned char c = value[i];

				last_trigger[i] =
					(c >= 'a' && c <= 'z') ||
					(c >= 'A' && c <= 'Z') ||
					(c >= '0' && c <= '9') ||
					c == ' ' || c == ':' || c == '-' ||
					c == '_' ? c : '?';
			}
			last_trigger[i] = '\0';
		} else if (!strcmp(line, "Result")) {
			snprintf(result, result_size, "%s", value);
		} else if (!strcmp(line, "ExecMainStatus")) {
			snprintf(exit_status, exit_status_size, "%s", value);
		} else if (!strcmp(line, "ExecMainExitTimestamp")) {
			size_t i;

			for (i = 0; value[i] && i + 1 < last_exit_size; i++) {
				unsigned char c = value[i];

				last_exit[i] =
					(c >= 'a' && c <= 'z') ||
					(c >= 'A' && c <= 'Z') ||
					(c >= '0' && c <= '9') ||
					c == ' ' || c == ':' || c == '-' ||
					c == '_' ? c : '?';
			}
			last_exit[i] = '\0';
			if (!*last_exit)
				snprintf(last_exit, last_exit_size, "n/a");
		} else if (!strcmp(line, "ExecMainExitTimestampMonotonic")) {
			char *end;

			errno = 0;
			*last_exit_monotonic = strtoull(value, &end, 10);
			if (errno || end == value || *end)
				*last_exit_monotonic = 0;
		}
	}
	return *load && *active && *enabled ? 0 : -1;
}

static int unit_is_enabled(const char *state)
{
	return !strcmp(state, "enabled") ||
	       !strcmp(state, "enabled-runtime") ||
	       !strcmp(state, "linked") ||
	       !strcmp(state, "linked-runtime");
}

static const char *baseline_health(const char *relative, time_t now,
				   unsigned long long *age, int test_override)
{
	char path[512];
	struct stat st;

	*age = 0;
	if (!relative)
		return "not_applicable";
	if (snprintf(path, sizeof(path), "%s/%s", ADDON_STATE_DIR,
		     relative) >= (int)sizeof(path))
		return "unavailable";
	if (lstat(path, &st) != 0)
		return errno == ENOENT ? "missing" : "unavailable";
	if (!S_ISREG(st.st_mode) || (!test_override && st.st_uid != 0))
		return "untrusted";
	if (st.st_mtime > now + 300)
		return "future";
	*age = now > st.st_mtime ? (unsigned long long)(now - st.st_mtime) : 0;
	return *age > 30ULL * 24 * 60 * 60 ? "stale" : "current";
}

static int cmd_health(int json)
{
	static const struct health_unit units[] = {
		{ .unit = "secure-sudo-procguard.service", .check_active = 1 },
		{ .unit = "secure-sudo-driverguard.service",
		  .scan_key = "driverguard" },
		{ .unit = "secure-sudo-biosguard.service",
		  .scan_key = "biosguard" },
		{ .unit = "secure-sudo-bootguard.service",
		  .scan_key = "bootguard" },
		{ .unit = "secure-sudo-bootguard-restore.service" },
		{ .unit = "secure-sudo-locus.service", .check_active = 1 },
		{ .unit = "secure-sudo-tamperwatch.service", .check_active = 1 },
		{ .unit = "secure-sudo-gui.service", .check_active = 1 },
		{ .unit = "secure-sudo-driverguard.timer", .check_active = 1,
		  .baseline = "driverguard/manifest",
		  .scan_key = "driverguard", .is_timer = 1 },
		{ .unit = "secure-sudo-biosguard.timer", .check_active = 1,
		  .baseline = "biosguard/fingerprint",
		  .scan_key = "biosguard", .is_timer = 1 },
		{ .unit = "secure-sudo-bootguard.timer", .check_active = 1,
		  .baseline = "bootguard/manifest",
		  .scan_key = "bootguard", .is_timer = 1 },
	};
	struct cfg_file cfg;
	struct stat st;
	char path[256], live[512], healthbuf[512], units_json[4096];
	char transport[16] = "unknown", remote_value[32] = "unknown";
	char retention_state[16] = "unknown";
	char load_state[24] = "unknown";
	char rejected_keys[512] = "unknown";
	const char *audit_feed;
	char scan_keys[3][16] = { "driverguard", "biosguard", "bootguard" };
	char scan_results[3][32] = { "unknown", "unknown", "unknown" };
	char scan_statuses[3][16] = { "unknown", "unknown", "unknown" };
	char scan_last_exits[3][64] = { "n/a", "n/a", "n/a" };
	unsigned long long scan_ages[3] = { 0, 0, 0 };
	int scan_age_known[3] = { 0, 0, 0 };
	const char *policy = "ok", *daemon = "inactive", *remote = remote_value;
	const char *addon_health;
	const char *overall;
	unsigned long long event_drops = 0, audit_drops = 0;
	unsigned long long remote_sent = 0, remote_failures = 0;
	unsigned long long queue_records = 0, queue_bytes = 0, queue_dropped = 0;
	unsigned long long local_log_failures = 0;
	unsigned long long event_gaps = 0, events_missing = 0;
	unsigned long long load_updated = 0, load_accepted = 0;
	unsigned long long load_rejected = 0, load_skipped = 0;
	unsigned long long load_rejected_omitted = 0;
	int counters_ok, mismatches = 0, errors = 0, i, lsm_active, healthy;
	int audit_configured = 0;
	int heartbeat_stat, heartbeat_metrics = 0, test_override = 0;
	int load_health;
	int systemd_available = 1, unit_errors = 0;
	size_t units_used = 0;
	time_t now = time(NULL);
	struct sysinfo uptime_info;
	int uptime_available = sysinfo(&uptime_info) == 0;

#ifdef SS_TESTING
	test_override = getenv("SS_TEST_ALLOW_ROOT") != NULL;
#endif
	load_health = read_load_health(load_state, sizeof(load_state),
				       &load_updated, &load_accepted,
				       &load_rejected, &load_skipped,
				       &load_rejected_omitted, rejected_keys,
				       sizeof(rejected_keys),
				       test_override);
	if (load_health < 0)
		snprintf(load_state, sizeof(load_state), "untrusted");
	lsm_active = access(SYSFS, F_OK) == 0;
	counters_ok = read_counter("events_dropped", &event_drops) == 0 &&
		      read_counter("audit_events_dropped", &audit_drops) == 0;
	heartbeat_stat = lstat(HEALTH_FILE, &st);
	if (heartbeat_stat == 0 && S_ISREG(st.st_mode) &&
	    (test_override || (st.st_uid == 0 && (st.st_mode & 07777) == 0600)) &&
	    now >= st.st_mtime &&
	    now - st.st_mtime <= 15) {
		daemon = "active";
		if (read_value(HEALTH_FILE, healthbuf, sizeof(healthbuf)) == 0) {
			heartbeat_value(healthbuf, "remote_state", remote_value,
					sizeof(remote_value));
			heartbeat_metrics =
				heartbeat_counter(healthbuf, "remote_sent",
						  &remote_sent) == 0 &&
				heartbeat_counter(healthbuf, "remote_failures",
						  &remote_failures) == 0 &&
				heartbeat_counter(healthbuf, "remote_queue_records",
						  &queue_records) == 0 &&
				heartbeat_counter(healthbuf, "remote_queue_bytes",
						  &queue_bytes) == 0 &&
				heartbeat_counter(healthbuf, "remote_queue_dropped",
						  &queue_dropped) == 0 &&
				heartbeat_counter(healthbuf, "local_log_failures",
						  &local_log_failures) == 0 &&
				heartbeat_counter(healthbuf, "event_gaps",
						  &event_gaps) == 0 &&
				heartbeat_counter(healthbuf, "events_missing",
						  &events_missing) == 0 &&
				heartbeat_value(healthbuf, "remote_transport",
						transport,
						sizeof(transport)) == 0 &&
				heartbeat_value(healthbuf, "retention_state",
						retention_state,
						sizeof(retention_state)) == 0;
			if (heartbeat_metrics &&
			    strcmp(retention_state, "active") &&
			    strcmp(retention_state, "held") &&
			    strcmp(retention_state, "hold_error"))
				heartbeat_metrics = 0;
		}
	} else if (heartbeat_stat == 0 || errno != ENOENT)
		daemon = heartbeat_stat == 0 && !test_override &&
			 (st.st_uid != 0 || (st.st_mode & 07777) != 0600) ?
			 "untrusted" : "stale";

	if (cfg_parse(CONFIG_DIR "/secure-sudo.conf", &cfg) != 0) {
		policy = "unavailable";
		errors++;
	} else {
		for (i = 0; i < cfg.n; i++) {
			const struct cfg_entry *e = &cfg.e[i];
			const struct knob *k = e->bad ? NULL : find_knob(e->key);
			char why[128];

			if (e->bad) {
				errors++;
				continue;
			}
			if (!k && is_daemon_key(e->key)) {
				if (check_daemon_value(e->key, e->val, why,
						       sizeof(why)))
					errors++;
				continue;
			}
			if (!k && !strcmp(e->key, "timevault_enabled"))
				continue;
			if (!k) {
				errors++;
				continue;
			}
			if (check_value(k, e->val, why, sizeof(why))) {
				errors++;
				continue;
			}
			if (!strcmp(e->key, "audit_events"))
				audit_configured = settings_equal(k, e->val, "1");
			snprintf(path, sizeof(path), SYSFS "/%s", k->sysfs);
			if (read_value(path, live, sizeof(live)) != 0 ||
			    !settings_equal(k, e->val, live))
				mismatches++;
		}
		cfg_free(&cfg);
		if (errors)
			policy = "invalid";
		else if (mismatches)
			policy = "mismatch";
	}
	audit_feed = audit_feed_health();

	units_json[0] = '[';
	units_json[1] = '\0';
	units_used = 1;
	for (i = 0; i < (int)(sizeof(units) / sizeof(units[0])); i++) {
		char load[32], active[32], enabled[32];
		char last_trigger[64] = "n/a";
		char result[32], exit_status[16], last_exit[64];
		unsigned long long last_exit_monotonic = 0;
		char baseline[24];
		char scan_state[32] = "not_applicable";
		char scan_exit[16] = "unknown";
		char scan_last_exit[64] = "n/a";
		unsigned long long scan_age = 0;
		int scan_age_known_here = 0;
		unsigned long long baseline_age = 0;
		int added;
		int scan_index;

		if (query_health_unit(units[i].unit, load, sizeof(load),
				      active, sizeof(active), enabled,
				      sizeof(enabled), last_trigger,
				      sizeof(last_trigger), result,
				      sizeof(result), exit_status,
				      sizeof(exit_status), last_exit,
				      sizeof(last_exit),
				      &last_exit_monotonic) != 0) {
			systemd_available = 0;
			break;
		}
		scan_index = -1;
		if (units[i].scan_key) {
			int scan_i;

			for (scan_i = 0; scan_i < 3; scan_i++)
				if (!strcmp(units[i].scan_key, scan_keys[scan_i])) {
					scan_index = scan_i;
					break;
				}
		}
		if (scan_index >= 0 && !units[i].is_timer) {
			snprintf(scan_results[scan_index],
				 sizeof(scan_results[scan_index]), "%s", result);
			snprintf(scan_statuses[scan_index],
				 sizeof(scan_statuses[scan_index]), "%s", exit_status);
			snprintf(scan_last_exits[scan_index],
				 sizeof(scan_last_exits[scan_index]), "%s", last_exit);
			if (uptime_available && last_exit_monotonic &&
			    last_exit_monotonic <=
				    (unsigned long long)uptime_info.uptime * 1000000ULL) {
				scan_ages[scan_index] =
					(unsigned long long)uptime_info.uptime -
					last_exit_monotonic / 1000000ULL;
				scan_age_known[scan_index] = 1;
			}
#ifdef SS_TESTING
			if (getenv("SS_TEST_STALE_SCAN")) {
				scan_ages[scan_index] = 26ULL * 60 * 60 + 1;
				scan_age_known[scan_index] = 1;
				scan_age = scan_ages[scan_index];
				scan_age_known_here = 1;
			}
#endif
			if (strcmp(last_exit, "n/a") &&
			    (strcmp(result, "success") || strcmp(exit_status, "0")))
				unit_errors++;
		} else if (scan_index >= 0) {
			snprintf(scan_state, sizeof(scan_state), "%s",
				 scan_results[scan_index]);
			snprintf(scan_exit, sizeof(scan_exit), "%s",
				 scan_statuses[scan_index]);
			snprintf(scan_last_exit, sizeof(scan_last_exit), "%s",
				 scan_last_exits[scan_index]);
			scan_age = scan_ages[scan_index];
			scan_age_known_here = scan_age_known[scan_index];
			if (unit_is_enabled(enabled) &&
			    (strcmp(scan_state, "success") ||
			     strcmp(scan_exit, "0") ||
			     !strcmp(scan_last_exit, "n/a") ||
			     !scan_age_known_here || scan_age > 26ULL * 60 * 60))
				unit_errors++;
		}
		if (units[i].baseline) {
			const char *state = baseline_health(units[i].baseline, now,
						    &baseline_age,
						    test_override);

			snprintf(baseline, sizeof(baseline), "%s", state);
			if (unit_is_enabled(enabled) &&
			    strcmp(load, "not-found") &&
			    strcmp(baseline, "current"))
				unit_errors++;
		} else {
			snprintf(baseline, sizeof(baseline), "not_applicable");
		}
		if (strcmp(load, "not-found") &&
		    ((!strcmp(active, "failed")) ||
		     (units[i].check_active && unit_is_enabled(enabled) &&
		      strcmp(active, "active"))))
			unit_errors++;
		added = snprintf(units_json + units_used,
				 sizeof(units_json) - units_used,
				 "%s{\"unit\":\"%s\",\"load\":\"%s\","
				 "\"active\":\"%s\",\"enabled\":\"%s\","
				 "\"last_trigger\":\"%s\",\"baseline\":\"%s\","
				 "\"baseline_age_seconds\":%llu,"
				 "\"scan_result\":\"%s\",\"scan_exit_status\":\"%s\","
				 "\"last_scan\":\"%s\",\"scan_age_seconds\":",
				 units_used ? "," : "", units[i].unit, load,
				 active, enabled, last_trigger, baseline,
				 baseline_age, scan_state, scan_exit, scan_last_exit);
		if (added < 0 || (size_t)added >= sizeof(units_json) - units_used) {
			systemd_available = 0;
			break;
		}
		units_used += (size_t)added;
		if (scan_age_known_here)
			added = snprintf(units_json + units_used,
					 sizeof(units_json) - units_used,
					 "%llu}", scan_age);
		else
			added = snprintf(units_json + units_used,
					 sizeof(units_json) - units_used,
					 "null}");
		if (added < 0 || (size_t)added >= sizeof(units_json) - units_used) {
			systemd_available = 0;
			break;
		}
		units_used += (size_t)added;
	}
	if (systemd_available) {
		if (units_used + 2 > sizeof(units_json))
			systemd_available = 0;
		else {
			units_json[units_used++] = ']';
			units_json[units_used] = '\0';
		}
	}
	if (!systemd_available)
		snprintf(units_json, sizeof(units_json), "null");
	addon_health = !systemd_available ? "unavailable" :
		       unit_errors ? "degraded" : "healthy";

	healthy = lsm_active && !strcmp(daemon, "active") &&
		  !strcmp(policy, "ok") && counters_ok && heartbeat_metrics &&
		  systemd_available && unit_errors == 0 &&
		  event_drops == 0 && audit_drops == 0 &&
		  queue_records == 0 && queue_bytes == 0 && queue_dropped == 0;
	if (!strcmp(retention_state, "hold_error"))
		healthy = 0;
	if (!strcmp(transport, "udp") && strcmp(remote, "disabled"))
		healthy = 0;
	if (!strcmp(transport, "tls") && remote_sent == 0)
		healthy = 0;
	if (remote_failures)
		healthy = 0;
	if (local_log_failures)
		healthy = 0;
	if (events_missing)	/* the daemon saw records go missing */
		healthy = 0;
	if (audit_configured && strcmp(audit_feed, "active"))
		healthy = 0;
	if (load_health != 0 || !strcmp(load_state, "partial") ||
	    !strcmp(load_state, "refused") || !strcmp(load_state, "stale"))
		healthy = 0;
	overall = healthy ? "healthy" : "degraded";

	if (json) {
		printf("{\"overall\":\"%s\",\"lsm\":\"%s\","
		       "\"daemon\":\"%s\",\"policy\":\"%s\","
		       "\"audit_feed\":\"%s\","
		       "\"remote_transport\":\"%s\","
		       "\"remote_forwarding\":\"%s\","
		       "\"remote_sent\":%llu,\"remote_failures\":%llu,"
		       "\"remote_queue_records\":%llu,"
		       "\"remote_queue_bytes\":%llu,"
		       "\"remote_queue_dropped\":%llu,"
		       "\"local_log_failures\":%llu,"
		       "\"event_gaps\":%llu,\"events_missing\":%llu,"
		       "\"retention_state\":\"%s\","
		       "\"heartbeat_metrics\":\"%s\","
		       "\"last_load\":\"%s\",\"load_updated\":%llu,"
		       "\"load_accepted\":%llu,\"load_rejected\":%llu,"
		       "\"load_skipped\":%llu,\"load_rejected_keys\":\"%s\","
		       "\"load_rejected_keys_omitted\":%llu,"
		       "\"systemd\":\"%s\",\"addon_health\":\"%s\","
		       "\"addon_units\":%s,"
		       "\"policy_mismatches\":%d,\"events_dropped\":",
		       overall, lsm_active ? "active" : "inactive", daemon,
		       policy, audit_feed, transport, remote, remote_sent, remote_failures,
		       queue_records, queue_bytes, queue_dropped, local_log_failures,
		       event_gaps, events_missing,
		       retention_state,
		       heartbeat_metrics ? "available" : "unavailable",
		       load_state, load_updated, load_accepted, load_rejected,
		       load_skipped, rejected_keys, load_rejected_omitted,
		       systemd_available ? "available" : "unavailable",
		       addon_health,
		       units_json, mismatches);
		if (counters_ok)
			printf("%llu,\"audit_events_dropped\":%llu}\n",
			       event_drops, audit_drops);
		else
			printf("null,\"audit_events_dropped\":null}\n");
	} else {
		printf("secure_sudo health: %s\n", overall);
		printf("LSM: %s\nDaemon heartbeat: %s\nPolicy: %s\nAudit feed: %s\n"
		       "Remote forwarding: %s via %s (%llu sent, %llu failures; "
		       "%llu queued records, %llu bytes, %llu dropped)\n"
		       "Local log write failures: %llu",
		       lsm_active ? "active" : "inactive", daemon, policy, audit_feed,
		       remote,
		       transport, remote_sent, remote_failures, queue_records,
		       queue_bytes, queue_dropped, local_log_failures);
		if (mismatches)
			printf(" (%d configured/live mismatch(es))", mismatches);
		putchar('\n');
		printf("Event stream gaps seen by the daemon: %llu (%llu records missing)\n",
		       event_gaps, events_missing);
		printf("Log retention: %s\n", retention_state);
		printf("Add-on/timer health: %s (%d enabled unit failure(s))\n",
		       addon_health, unit_errors);
		printf("Last policy load: %s (%llu accepted, %llu rejected, "
		       "%llu skipped; updated %llu; rejected keys: %s; "
		       "%llu omitted)\n",
		       load_state, load_accepted, load_rejected, load_skipped,
		       load_updated, rejected_keys, load_rejected_omitted);
		if (counters_ok)
			printf("Event ring loss: %llu\nAudit backlog loss: %llu\n",
			       event_drops, audit_drops);
		else
			printf("Event loss counters: unavailable\n");
	}
	return strcmp(overall, "healthy") != 0;
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

static int cmd_evidence_export(int argc, char **argv)
{
	char **nargv = calloc((size_t)argc, sizeof(char *));
	int i;

	if (!nargv)
		return 1;
	nargv[0] = (char *)EVIDENCE_HELPER;
	for (i = 2; i < argc; i++)
		nargv[i - 1] = argv[i];
	nargv[argc - 1] = NULL;
	execv(EVIDENCE_HELPER, nargv);
	fprintf(stderr, "secure-sudo: cannot exec %s: %s\n", EVIDENCE_HELPER,
		strerror(errno));
	free(nargv);
	return 1;
}

static int cmd_evidence_verify(int argc, char **argv)
{
	char **nargv = calloc((size_t)argc, sizeof(char *));
	int i;

	if (!nargv)
		return 1;
	nargv[0] = (char *)EVIDENCE_VERIFY_HELPER;
	for (i = 2; i < argc; i++)
		nargv[i - 1] = argv[i];
	nargv[argc - 1] = NULL;
	execv(EVIDENCE_VERIFY_HELPER, nargv);
	fprintf(stderr, "secure-sudo: cannot exec %s: %s\n",
		EVIDENCE_VERIFY_HELPER, strerror(errno));
	free(nargv);
	return 1;
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
"  health [--json]      compare config/live policy and report component health\n"
"  evidence-export FILE [--signing-key EXTERNAL.pem] export incident evidence\n"
"  evidence-verify FILE [--trusted-key PUBLIC.pem] [--checkpoints COLLECTOR.log]\n"
"                       verify an evidence bundle (and against off-host checkpoints)\n"
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
"Kernel policy commands are root-only and refused once the config is locked;\n"
"lint and evidence-verify are read-only and do not require root.\n");
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
	if (!strcmp(argv[1], "evidence-export"))
		return cmd_evidence_export(argc, argv);
	if (!strcmp(argv[1], "evidence-verify"))
		return cmd_evidence_verify(argc, argv);

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
	if (!strcmp(argv[1], "health") &&
	    (argc == 2 || (argc == 3 && !strcmp(argv[2], "--json"))))
		return cmd_health(argc == 3);
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
