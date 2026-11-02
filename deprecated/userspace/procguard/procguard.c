// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * secure-sudo-procguard - ProcGuard (runtime guard).
 *
 * Watches every running process and compares its on-disk executable against an
 * allowlist. A process whose executable is NOT allowed is treated as an
 * intruder:
 *
 *   1. it is killed (SIGKILL);
 *   2. if the SAME executable path keeps coming back - respawning repeatedly
 *      within a time window - it is classified as an INFECTION (a persistent
 *      implant, not a one-off);
 *   3. on infection the binary is located from /proc/<pid>/exe, its bytes are
 *      compressed into an HOURLY-ROTATED quarantine bucket (so a fixed path can
 *      never be used to re-expand it and reinfect), the on-disk file is
 *      removed, and - if configured - the compressed sample is synced off-box
 *      for later analysis.
 *
 * ===================== SAFETY (read before enabling enforce) ================
 * "Kill everything not on the list" can take a machine down if the list is
 * incomplete. So ProcGuard is deliberately cautious:
 *   - it refuses to run with an EMPTY allowlist (that would mean "kill all");
 *   - it ALWAYS exempts PID 1, kernel threads (no /proc/pid/exe), its own
 *     process tree, and the secure_sudo binaries, whatever the list says;
 *   - the default mode is `monitor` (log what WOULD be killed, touch nothing).
 *     Only `mode = enforce` actually kills and removes. Populate and verify the
 *     allowlist in monitor mode first.
 *
 * Config:  /etc/secure_sudo/addons/procguard.conf        (knobs)
 *          /etc/secure_sudo/addons/procguard_allow.conf   (allowed exe paths)
 * Logs via the shared ssaddon_log; quarantine via the shared ssaddon_store.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ssaddon_log.h"
#include "ssaddon_store.h"

#define CONF		"/etc/secure_sudo/addons/procguard.conf"
#define ALLOW		"/etc/secure_sudo/addons/procguard_allow.conf"
#define DEF_QROOT	"/var/lib/secure_sudo/addons/procguard/quarantine"
#define LOCUS_PURPOSE	"procguard-quarantine"

/* ---- config ---- */
struct cfg {
	int enforce;			/* 0 monitor, 1 enforce */
	int interval;			/* scan period (s) */
	int respawn_threshold;		/* kills before "infection" */
	int respawn_window;		/* within this many seconds */
	int remove_on_infection;
	char quarantine_root[PATH_MAX];
	char sync_cmd[512];		/* %f -> compressed sample path; empty = off */
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
	char line[640];

	c->enforce = 0;
	c->interval = 5;
	c->respawn_threshold = 3;
	c->respawn_window = 60;
	c->remove_on_infection = 1;
	snprintf(c->quarantine_root, sizeof(c->quarantine_root), "%s", DEF_QROOT);
	c->sync_cmd[0] = '\0';

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
		else if (!strcmp(k, "interval"))
			c->interval = atoi(v) > 0 ? atoi(v) : 5;
		else if (!strcmp(k, "respawn_threshold"))
			c->respawn_threshold = atoi(v) > 0 ? atoi(v) : 3;
		else if (!strcmp(k, "respawn_window"))
			c->respawn_window = atoi(v) > 0 ? atoi(v) : 60;
		else if (!strcmp(k, "remove_on_infection"))
			c->remove_on_infection = atoi(v);
		else if (!strcmp(k, "quarantine_root"))
			snprintf(c->quarantine_root, sizeof(c->quarantine_root), "%s", v);
		else if (!strcmp(k, "sync_cmd"))
			snprintf(c->sync_cmd, sizeof(c->sync_cmd), "%s", v);
	}
	fclose(f);
}

/* ---- allowlist ---- */
struct allowlist {
	char **paths;
	size_t n;
};

static int allow_load(struct allowlist *a)
{
	FILE *f = fopen(ALLOW, "re");
	char line[PATH_MAX];
	size_t cap = 0;

	a->paths = NULL;
	a->n = 0;
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *p = line;

		trim(line);
		while (*p == ' ' || *p == '\t') p++;
		if (*p != '/')
			continue;
		if (a->n == cap) {
			size_t nc = cap ? cap * 2 : 64;
			char **np = realloc(a->paths, nc * sizeof(char *));
			if (!np)
				break;
			a->paths = np;
			cap = nc;
		}
		a->paths[a->n++] = strdup(p);
	}
	fclose(f);
	return 0;
}

static int allow_has(const struct allowlist *a, const char *path)
{
	size_t i;

	for (i = 0; i < a->n; i++)
		if (!strcmp(a->paths[i], path))
			return 1;
	return 0;
}

static void allow_free(struct allowlist *a)
{
	size_t i;

	for (i = 0; i < a->n; i++)
		free(a->paths[i]);
	free(a->paths);
	a->paths = NULL;
	a->n = 0;
}

/* ---- respawn tracking ---- */
struct track {
	char path[PATH_MAX];
	int kills;
	time_t first_kill;
	int quarantined;		/* already handled as infection */
};

static struct track *tracks;
static size_t ntracks, captracks;

static struct track *track_get(const char *path)
{
	size_t i;

	for (i = 0; i < ntracks; i++)
		if (!strcmp(tracks[i].path, path))
			return &tracks[i];
	if (ntracks == captracks) {
		size_t nc = captracks ? captracks * 2 : 32;
		struct track *nt = realloc(tracks, nc * sizeof(*tracks));
		if (!nt)
			return NULL;
		tracks = nt;
		captracks = nc;
	}
	memset(&tracks[ntracks], 0, sizeof(tracks[ntracks]));
	snprintf(tracks[ntracks].path, sizeof(tracks[ntracks].path), "%s", path);
	return &tracks[ntracks++];
}

/* ---- helpers ---- */

/* Is @path one of ours (secure_sudo stack)? Never kill our own tooling. */
static int is_secure_sudo(const char *path)
{
	return strstr(path, "secure-sudo") || strstr(path, "secure-sudod") ||
	       strstr(path, "secure_sudo");
}

/* Resolve /proc/<pid>/exe to the on-disk path. Returns 0 on success; a kernel
 * thread (no exe) returns -1. */
static int pid_exe(pid_t pid, char *out, size_t n)
{
	char link[64];
	ssize_t r;

	snprintf(link, sizeof(link), "/proc/%d/exe", pid);
	r = readlink(link, out, n - 1);
	if (r < 0)
		return -1;
	out[r] = '\0';
	/* A deleted exe shows up as "<path> (deleted)"; keep the real path. */
	{
		char *d = strstr(out, " (deleted)");
		if (d)
			*d = '\0';
	}
	return 0;
}

/* Sync a quarantined sample off-box via the configured command (%f -> path). */
static void run_sync(const struct cfg *c, const char *sample)
{
	char cmd[1024];
	const char *p;
	size_t o = 0;
	int rc;

	if (!c->sync_cmd[0])
		return;
	for (p = c->sync_cmd; *p && o < sizeof(cmd) - 1; p++) {
		if (p[0] == '%' && p[1] == 'f') {
			o += snprintf(cmd + o, sizeof(cmd) - o, "'%s'", sample);
			p++;
		} else {
			cmd[o++] = *p;
		}
	}
	cmd[o] = '\0';
	rc = system(cmd);
	if (rc != 0)
		ssl_warn("sync command failed (rc=%d) for %s", rc, sample);
	else
		ssl_info("synced quarantined sample off-box: %s", sample);
}

/* Handle a confirmed infection: quarantine (compressed, hourly bucket), remove,
 * optionally sync. */
static void handle_infection(const struct cfg *c, const char *path)
{
	char root[PATH_MAX], bucket[PATH_MAX], sample[PATH_MAX];

	/* Prefer a Locus-allocated root; fall back to the configured one. */
	if (locus_request_root(LOCUS_PURPOSE, root, sizeof(root)) != 0)
		snprintf(root, sizeof(root), "%s", c->quarantine_root);

	if (store_current_bucket(root, bucket, sizeof(bucket)) != 0) {
		ssl_err("cannot create quarantine bucket under %s", root);
		return;
	}
	if (store_put_compressed(path, bucket, "proc", sample, sizeof(sample)) != 0) {
		ssl_err("failed to quarantine %s", path);
		return;
	}
	ssl_crit("INFECTION quarantined: %s -> %s", path, sample);

	if (c->remove_on_infection) {
		if (unlink(path) == 0)
			ssl_crit("INFECTION removed from disk: %s", path);
		else
			ssl_err("could not remove %s: %s", path, strerror(errno));
	}
	run_sync(c, sample);
}

/* One pass over /proc. Returns the number of offenders seen. */
static int scan_once(const struct cfg *c, const struct allowlist *a)
{
	DIR *d = opendir("/proc");
	struct dirent *de;
	pid_t self = getpid(), parent = getppid();
	int offenders = 0;
	time_t now = time(NULL);

	if (!d) {
		ssl_err("cannot open /proc: %s", strerror(errno));
		return 0;
	}
	while ((de = readdir(d))) {
		pid_t pid;
		char exe[PATH_MAX];
		struct track *t;

		if (!isdigit((unsigned char)de->d_name[0]))
			continue;
		pid = (pid_t)atoi(de->d_name);
		if (pid <= 1 || pid == self || pid == parent)
			continue;		/* never touch init or ourselves */
		if (pid_exe(pid, exe, sizeof(exe)) != 0)
			continue;		/* kernel thread: no on-disk exe */
		if (is_secure_sudo(exe))
			continue;
		if (allow_has(a, exe))
			continue;		/* allowed */

		offenders++;

		if (!c->enforce) {
			ssl_warn("MONITOR: would kill pid %d (%s) - not on allowlist",
				 pid, exe);
			continue;
		}

		/* enforce: kill it, and track respawns. */
		if (kill(pid, SIGKILL) == 0)
			ssl_warn("killed pid %d (%s) - not on allowlist", pid, exe);

		t = track_get(exe);
		if (!t)
			continue;
		if (t->kills == 0 || now - t->first_kill > c->respawn_window) {
			t->first_kill = now;	/* new window */
			t->kills = 1;
			t->quarantined = 0;
		} else {
			t->kills++;
		}
		if (!t->quarantined && t->kills >= c->respawn_threshold) {
			ssl_crit("respawn threshold hit for %s (%d kills in %ds)",
				 exe, t->kills, c->respawn_window);
			handle_infection(c, exe);
			t->quarantined = 1;
		}
	}
	closedir(d);
	return offenders;
}

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static int run_daemon(void)
{
	struct cfg c;
	struct allowlist a;

	load_cfg(&c);
	if (allow_load(&a) != 0 || a.n == 0) {
		ssl_err("refusing to run: allowlist %s is empty or missing "
			"(an empty list would mean 'kill everything')", ALLOW);
		fprintf(stderr, "procguard: empty/missing allowlist %s - refusing\n", ALLOW);
		return 1;
	}
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	ssl_info("procguard started: mode=%s interval=%ds allow=%zu entries",
		 c.enforce ? "enforce" : "monitor", c.interval, a.n);

	while (!stop) {
		scan_once(&c, &a);
		sleep(c.interval);
	}
	ssl_info("procguard stopping");
	allow_free(&a);
	return 0;
}

static int run_once(void)
{
	struct cfg c;
	struct allowlist a;
	int off;

	load_cfg(&c);
	if (allow_load(&a) != 0 || a.n == 0) {
		fprintf(stderr, "procguard: empty/missing allowlist %s - refusing\n", ALLOW);
		return 1;
	}
	off = scan_once(&c, &a);
	printf("procguard: %d offending process(es) %s\n", off,
	       c.enforce ? "handled" : "detected (monitor mode)");
	allow_free(&a);
	return 0;
}

static int cmd_status(void)
{
	struct cfg c;
	struct allowlist a;

	load_cfg(&c);
	allow_load(&a);
	printf("ProcGuard mode:        %s\n", c.enforce ? "enforce" : "monitor");
	printf("scan interval:         %ds\n", c.interval);
	printf("respawn -> infection:  %d kills / %ds\n", c.respawn_threshold,
	       c.respawn_window);
	printf("remove on infection:   %s\n", c.remove_on_infection ? "yes" : "no");
	printf("quarantine root:       %s (hourly buckets)\n", c.quarantine_root);
	printf("off-box sync:          %s\n", c.sync_cmd[0] ? c.sync_cmd : "(disabled)");
	printf("allowlist entries:     %zu\n", a.n);
	allow_free(&a);
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
"usage: secure-sudo-procguard <command>\n"
"  daemon        run the watch loop (monitor or enforce per config)\n"
"  scan          one pass now (detect in monitor, act in enforce)\n"
"  status        show the current configuration\n"
"\nConfig: " CONF "\nAllowlist: " ALLOW "\n");
}

int main(int argc, char **argv)
{
	if (geteuid() != 0) {
		fprintf(stderr, "procguard: must run as root\n");
		return 1;
	}
	if (argc < 2) {
		usage();
		return 2;
	}
	ssl_init("procguard");

	if (!strcmp(argv[1], "daemon"))
		return run_daemon();
	if (!strcmp(argv[1], "scan"))
		return run_once();
	if (!strcmp(argv[1], "status"))
		return cmd_status();

	usage();
	ssl_close();
	return 2;
}
