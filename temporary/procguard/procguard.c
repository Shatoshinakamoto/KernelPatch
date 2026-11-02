// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * secure-sudo-procguard - ProcGuard (v8 temporary add-on).
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
 *   - it ALWAYS exempts PID 1, kernel threads (no /proc/pid/exe), itself and
 *     every process it runs under (the shell, sudo, systemd), and the
 *     installed secure_sudo binaries (by exact root-owned path, not by name:
 *     a /tmp/secure-sudo-x is not exempt), whatever the list says;
 *   - it never deletes an executable from a system directory (/usr, /bin,
 *     /sbin, /lib*, /boot, /etc): there an "infection" is far more likely a
 *     service that systemd keeps restarting, so the file is quarantined
 *     (copied) and left for the operator;
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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ssaddon_log.h"
#include "ssaddon_store.h"
#include "ssaddon_conf.h"
#include "ssaddon_trust.h"

/* Overridable for the tests only (tests/userspace/test-addons.sh). */
#ifndef PG_CONF
#define PG_CONF		"/etc/secure_sudo/addons/procguard.conf"
#endif
#ifndef PG_ALLOW
#define PG_ALLOW	"/etc/secure_sudo/addons/procguard_allow.conf"
#endif
#ifndef PG_QROOT
#define PG_QROOT	"/var/lib/secure_sudo/addons/procguard/quarantine"
#endif
#ifndef PG_STATEDIR
#define PG_STATEDIR	"/var/lib/secure_sudo/addons/procguard"
#endif
#define STATEDIR	PG_STATEDIR
#define CONF		PG_CONF
#define ALLOW		PG_ALLOW
#define DEF_QROOT	PG_QROOT
#define LOCUS_PURPOSE	"procguard-quarantine"

/* ---- config ---- */
struct cfg {
	int enforce;			/* 0 monitor, 1 enforce */
	int interval;			/* scan period (s) */
	int respawn_threshold;		/* kills before "infection" */
	int respawn_window;		/* within this many seconds */
	int remove_on_infection;
	int rotate;			/* 1 = hourly-rotating quarantine, 0 = fixed */
	char quarantine_root[PATH_MAX];
	char sync_cmd[512];		/* %f -> compressed sample path; empty = off */
};

static void trim(char *s)
{
	size_t n = strlen(s);
	while (n && isspace((unsigned char)s[n - 1]))
		s[--n] = '\0';
}

static int load_cfg(struct cfg *c, FILE *report)
{
	static const char *const modes[] = { "monitor", "enforce", NULL };
	const struct ssc_key keys[] = {
		{ "mode", SSC_ENUM, &c->enforce, 0, 0, 0, modes },
		{ "interval", SSC_INT, &c->interval, 0, 1, 3600, NULL },
		{ "respawn_threshold", SSC_INT, &c->respawn_threshold, 0, 1, 1000, NULL },
		{ "respawn_window", SSC_INT, &c->respawn_window, 0, 1, 86400, NULL },
		{ "remove_on_infection", SSC_INT, &c->remove_on_infection, 0, 0, 1, NULL },
		{ "rotate", SSC_INT, &c->rotate, 0, 0, 1, NULL },
		{ "quarantine_root", SSC_PATH, c->quarantine_root,
		  sizeof(c->quarantine_root), 1, 0, NULL },
		{ "sync_cmd", SSC_STR, c->sync_cmd, sizeof(c->sync_cmd), 0, 0, NULL },
		SSC_END
	};

	c->enforce = 0;
	c->interval = 5;
	c->respawn_threshold = 3;
	c->respawn_window = 60;
	c->remove_on_infection = 1;
	c->rotate = 1;
	snprintf(c->quarantine_root, sizeof(c->quarantine_root), "%s", DEF_QROOT);
	c->sync_cmd[0] = '\0';
	return ssc_parse(CONF, keys, NULL, NULL, report);
}

/* Every file ProcGuard reads, checked strictly (P2-2). */
static int conf_errors(FILE *r)
{
	struct cfg c;

	return load_cfg(&c, r) + ssc_check_list(ALLOW, "allowlist entry", r) +
	       ssl_check_conf(r) + locus_check_conf(r);
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

/* Is @path one of ours? See ssaddon_is_stack_exe (exact installed paths). */
#define is_secure_sudo ssaddon_is_stack_exe

/* A system directory: an executable there is never deleted, only copied. */
static int in_system_dir(const char *path)
{
	static const char *const sys[] = {
		"/usr/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/",
		"/libx32/", "/boot/", "/etc/", NULL
	};
	int i;

	for (i = 0; sys[i]; i++)
		if (!strncmp(path, sys[i], strlen(sys[i])))
			return 1;
	return 0;
}

/* The processes this one runs under: never killed (sudo, the shell, ...). */
static pid_t ancestors[64];
static int nancestors;

static void load_ancestors(void)
{
	pid_t p = getppid();

	nancestors = 0;
	while (p > 1 && nancestors < (int)(sizeof(ancestors) / sizeof(ancestors[0]))) {
		char path[64], buf[512], *rp;
		FILE *f;
		int pp = 0;

		ancestors[nancestors++] = p;
		snprintf(path, sizeof(path), "/proc/%d/stat", p);
		f = fopen(path, "re");
		if (!f)
			break;
		if (!fgets(buf, sizeof(buf), f))
			buf[0] = '\0';
		fclose(f);
		rp = strrchr(buf, ')');		/* comm may contain spaces */
		if (!rp || sscanf(rp + 1, " %*c %d", &pp) != 1)
			break;
		p = pp;
	}
}

static int is_ancestor(pid_t pid)
{
	int i;

	for (i = 0; i < nancestors; i++)
		if (ancestors[i] == pid)
			return 1;
	return 0;
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
	if (strchr(sample, '\'')) {		/* it is quoted below */
		ssl_warn("sync_cmd not run: the sample path contains a quote: %s", sample);
		return;
	}
	for (p = c->sync_cmd; *p && o < sizeof(cmd) - 1; p++) {
		if (p[0] == '%' && p[1] == 'f') {
			size_t l = strlen(sample) + 2;

			/* never cut the quoted path short (this used to run past
			 * the end of cmd[]) */
			if (o + l >= sizeof(cmd)) {
				ssl_warn("sync_cmd not run: the command would be longer "
					 "than %zu bytes", sizeof(cmd) - 1);
				return;
			}
			o += (size_t)snprintf(cmd + o, sizeof(cmd) - o, "'%s'", sample);
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
 * optionally sync. @exefd is the binary the killed process ran (opened via
 * /proc/PID/exe before the kill), so what is quarantined is that binary even
 * if @path has since been replaced; @path is removed only while it is still
 * that same file (same device and inode, not a symlink). 0 when quarantined. */
static int handle_infection(const struct cfg *c, const char *path, int exefd)
{
	char root[PATH_MAX], bucket[PATH_MAX], sample[PATH_MAX];
	struct stat ran, now;
	int remove = c->remove_on_infection && !in_system_dir(path);

	/* Rotating mode may use a Locus-allocated root; a fixed (rotation-off)
	 * quarantine always stays local so the location never moves. */
	if (c->rotate && locus_request_root(LOCUS_PURPOSE, root, sizeof(root)) == 0)
		;
	else
		snprintf(root, sizeof(root), "%s", c->quarantine_root);

	if (exefd < 0 || fstat(exefd, &ran) != 0) {
		ssl_err("failed to quarantine %s: the binary could not be opened", path);
		return -1;
	}
	if (store_bucket(root, c->rotate, bucket, sizeof(bucket)) != 0) {
		ssl_err("cannot create quarantine bucket under %s", root);
		return -1;
	}
	if (store_put_fd(exefd, path, bucket, "proc", sample, sizeof(sample), NULL) != 0) {
		ssl_err("failed to quarantine %s (disk full?): it is left on disk", path);
		return -1;
	}
	ssl_crit("INFECTION quarantined: %s -> %s", path, sample);
	if (lstat(path, &now) != 0 || !S_ISREG(now.st_mode) ||
	    now.st_dev != ran.st_dev || now.st_ino != ran.st_ino) {
		/* swapped after the kill: whatever is there now is not what ran */
		ssl_crit("INFECTION: %s is no longer the binary that ran (replaced or "
			 "a symlink): the quarantined copy is the one that ran; the path "
			 "is left alone", path);
		sst_evidence("procguard", path, "quarantine", NULL, sample);
		run_sync(c, sample);
		return 0;
	}
	/* hash, owner, mode and times of the original, before it goes */
	if (sst_evidence("procguard", path, remove ? "remove" : "quarantine", NULL,
			 sample) != 0 && remove) {
		ssl_crit("INFECTION left on disk: %s: the evidence record could not be "
			 "written, so it is not removed", path);
		remove = 0;
	}

	if (c->remove_on_infection && in_system_dir(path)) {
		ssl_warn("INFECTION left on disk: %s is in a system directory (a "
			 "service being restarted?); remove it yourself if it is "
			 "malicious; sample: %s", path, sample);
	} else if (remove) {
		/* re-checked just before: still the file that ran */
		if (lstat(path, &now) == 0 && now.st_dev == ran.st_dev &&
		    now.st_ino == ran.st_ino && unlink(path) == 0)
			ssl_crit("INFECTION removed from disk: %s", path);
		else
			ssl_err("could not remove %s: %s", path, strerror(errno));
	}
	run_sync(c, sample);
	return 0;
}

/* One pass over /proc. Returns the number of offenders seen. */
static int scan_once(const struct cfg *c, const struct allowlist *a)
{
	static time_t not_armed_said;	/* said at most every 10 minutes */
	DIR *d = opendir("/proc");
	struct dirent *de;
	pid_t self = getpid();
	int offenders = 0, exefd = -1;
	int armed = c->enforce && sst_armed(STATEDIR);
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
		if (pid <= 1 || pid == self || is_ancestor(pid))
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
		if (!armed) {
			ssl_warn("NOT ARMED: would kill pid %d (%s) - not on allowlist",
				 pid, exe);
			continue;
		}

		/* enforce: hold on to the binary it runs, kill it, and track
		 * respawns. */
		{
			char lk[64];

			snprintf(lk, sizeof(lk), "/proc/%d/exe", pid);
			if (exefd >= 0)
				close(exefd);
			exefd = open(lk, O_RDONLY | O_CLOEXEC);
		}
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
			/* not marked handled unless it was: a failed quarantine
			 * is tried again at the next respawn */
			if (handle_infection(c, exe, exefd) == 0)
				t->quarantined = 1;
		}
	}
	if (exefd >= 0)
		close(exefd);
	closedir(d);
	if (!c->enforce) {
		sst_disarm("procguard", STATEDIR);
	} else if (!armed) {
		if (!offenders)
			sst_arm("procguard", STATEDIR, "a clean enforce pass");
		else if (now - not_armed_said >= 600 && (not_armed_said = now))
			ssl_crit("ENFORCE NOT ARMED: procguard would have killed %d "
				 "process(es) not on the allowlist; complete the allowlist "
				 "(or run `secure-sudo-procguard arm` to accept)", offenders);
	}
	return offenders;
}

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static int run_daemon(void)
{
	struct cfg c;
	struct allowlist a;
	int rc;

	if ((rc = ssc_refuse("start ProcGuard", conf_errors(stderr))))
		return rc;
	load_cfg(&c, NULL);
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
	int off, rc;

	if ((rc = ssc_refuse("scan", conf_errors(stderr))))
		return rc;
	load_cfg(&c, NULL);
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

static int cmd_arm(void)
{
	struct cfg c;

	load_cfg(&c, NULL);
	if (!c.enforce) {
		fprintf(stderr, "procguard: mode is monitor; set mode = enforce first\n");
		return 1;
	}
	mkdir(STATEDIR, 0700);
	return sst_arm("procguard", STATEDIR, "armed by the operator") ? 1 : 0;
}

static int cmd_status(void)
{
	struct cfg c;
	struct allowlist a;

	int bad = conf_errors(NULL);

	load_cfg(&c, NULL);
	allow_load(&a);
	if (bad)
		printf("CONFIG:                %d problem(s) - run check-config\n", bad);
	printf("ProcGuard mode:        %s\n", c.enforce ? "enforce" : "monitor");
	{
		char ar[160];

		sst_describe_arming(STATEDIR, c.enforce, ar, sizeof(ar));
		printf("enforce arming:        %s\n", ar);
	}
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
"  arm           let enforce mode act (it reports only until a clean pass or this)\n"
"  status        show the current configuration\n"
"  check-config  check every config file strictly; 1 if any problem\n"
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
	load_ancestors();

	if (!strcmp(argv[1], "daemon"))
		return run_daemon();
	if (!strcmp(argv[1], "scan"))
		return run_once();
	if (!strcmp(argv[1], "status"))
		return cmd_status();
	if (!strcmp(argv[1], "arm")) {
		int rc = ssc_refuse("arm", conf_errors(stderr));

		return rc ? rc : cmd_arm();
	}
	if (!strcmp(argv[1], "check-config"))
		return ssc_verdict(conf_errors(stdout));

	usage();
	ssl_close();
	return 2;
}
