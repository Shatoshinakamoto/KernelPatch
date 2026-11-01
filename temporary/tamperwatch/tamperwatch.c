// SPDX-License-Identifier: GPL-2.0
/*
 * secure-sudo-tamperwatch - real-time tamper ATTRIBUTION (temporary add-on).
 *
 * PheonixBox (the kernel-adjacent snapshot feature) detects *that* a protected
 * file changed, on a timer - but not *who* changed it. tamperwatch fills that
 * gap: it uses fanotify to watch the protected files in real time and, the
 * moment one is modified, records WHICH process did it (pid + on-disk exe),
 * logs it, and can quarantine that process by pinpointing its executable on the
 * filesystem - exactly the "pinpoint what tampered it and quarantine it" need.
 *
 *   - Watches every regular file under the PheonixBox protected set
 *     (/etc/secure_sudo/pheonixbox.conf) plus any extra paths in
 *     /etc/secure_sudo/addons/tamperwatch.conf.
 *   - On a modify/close-write event it resolves the writer's pid -> exe and
 *     logs CRITICAL (shippable off-box via the shared logger, and visible in
 *     the GUI).
 *   - mode = quarantine (opt-in) additionally compresses the offender's exe
 *     into the hourly-rotated quarantine and kills it; mode = log (default)
 *     only records. Never killed, whatever the mode: PID 1, tamperwatch
 *     itself, the installed secure_sudo programs (PheonixBox writes the
 *     protected files when it repairs them), and any writer while a package
 *     manager holds its lock (an update rewriting a protected file); those
 *     are logged as "not killed" with the reason.
 *
 * Needs fanotify (CONFIG_FANOTIFY) and root (CAP_SYS_ADMIN). Honest limits: it
 * marks regular files that exist when it starts / rescans; a brand-new file
 * created after start under a protected dir is covered on the next rescan.
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
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ssaddon_log.h"
#include "ssaddon_store.h"
#include "ssaddon_conf.h"
#include "ssaddon_trust.h"

/* Overridable for the tests only (tests/userspace/test-addons.sh). */
#ifndef TW_PBOX_CONF
#define TW_PBOX_CONF	"/etc/secure_sudo/pheonixbox.conf"
#endif
#ifndef TW_CONF
#define TW_CONF		"/etc/secure_sudo/addons/tamperwatch.conf"
#endif
#ifndef TW_QROOT
#define TW_QROOT	"/var/lib/secure_sudo/addons/tamperwatch/quarantine"
#endif
#ifndef TW_STATEDIR
#define TW_STATEDIR	"/var/lib/secure_sudo/addons/tamperwatch"
#endif
#define STATEDIR	TW_STATEDIR
#define PBOX_CONF	TW_PBOX_CONF
#define CONF		TW_CONF
#define DEF_QROOT	TW_QROOT
#define LOCUS_PURPOSE	"tamperwatch-quarantine"

struct cfg {
	int quarantine;			/* 0 = log only, 1 = quarantine+kill */
	int rotate;
	char quarantine_root[PATH_MAX];
};

static void trim(char *s)
{
	size_t n = strlen(s);
	while (n && isspace((unsigned char)s[n - 1]))
		s[--n] = '\0';
}

/* tamperwatch.conf may also list extra protected files, one absolute path
 * per line. */
static int path_line(char *line, char *err, size_t errlen, void *ctx)
{
	(void)ctx;
	if (line[0] != '/' || strchr(line, '='))
		return 0;
	return ssc_path_ok(line, err, errlen) ? 1 : -1;
}

static int load_cfg(struct cfg *c, FILE *report)
{
	static const char *const modes[] = { "log", "quarantine", NULL };
	const struct ssc_key keys[] = {
		{ "mode", SSC_ENUM, &c->quarantine, 0, 0, 0, modes },
		{ "rotate", SSC_INT, &c->rotate, 0, 0, 1, NULL },
		{ "quarantine_root", SSC_PATH, c->quarantine_root,
		  sizeof(c->quarantine_root), 1, 0, NULL },
		SSC_END
	};

	c->quarantine = 0;
	c->rotate = 1;
	snprintf(c->quarantine_root, sizeof(c->quarantine_root), "%s", DEF_QROOT);
	return ssc_parse(CONF, keys, path_line, NULL, report);
}

/* Every file tamperwatch reads, checked strictly (P2-2). */
static int conf_errors(FILE *r)
{
	struct cfg c;

	return load_cfg(&c, r) + ssl_check_conf(r) + locus_check_conf(r);
}

/* ---- marking the protected set ---- */

static int g_fan = -1;
static size_t g_marked;

static void mark_file(const char *path)
{
	/* FAN_CLOSE_WRITE + FAN_MODIFY on each regular file; pid comes with the
	 * event in the classic (non-FID) fanotify mode. */
	if (fanotify_mark(g_fan, FAN_MARK_ADD,
			  FAN_CLOSE_WRITE | FAN_MODIFY, AT_FDCWD, path) == 0)
		g_marked++;
}

static void walk_mark(const char *path, int depth)
{
	struct stat st;
	DIR *d;
	struct dirent *de;

	if (depth > 24 || lstat(path, &st) != 0)
		return;
	if (S_ISREG(st.st_mode)) {
		mark_file(path);
		return;
	}
	if (!S_ISDIR(st.st_mode))
		return;
	d = opendir(path);
	if (!d)
		return;
	while ((de = readdir(d))) {
		char child[PATH_MAX];

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (snprintf(child, sizeof(child), "%s/%s", path, de->d_name) >=
		    (int)sizeof(child))
			continue;
		walk_mark(child, depth + 1);
	}
	closedir(d);
}

/* Read absolute paths (one per line) from a config file and mark each. */
static void mark_from(const char *conf)
{
	FILE *f = fopen(conf, "re");
	char line[PATH_MAX];

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char *p = line;

		trim(line);
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '/')
			walk_mark(p, 0);
	}
	fclose(f);
}

/* ---- offender handling ---- */

static int pid_exe(pid_t pid, char *out, size_t n)
{
	char link[64];
	ssize_t r;

	snprintf(link, sizeof(link), "/proc/%d/exe", pid);
	r = readlink(link, out, n - 1);
	if (r < 0)
		return -1;
	out[r] = '\0';
	return 0;
}

/* Why this writer must not be killed, or NULL. */
static const char *never_kill(pid_t pid, const char *exe, char *why, size_t n)
{
	if (pid <= 1)
		return "PID 1";
	if (pid == getpid())
		return "tamperwatch itself";
	if (ssaddon_is_stack_exe(exe))
		return "a secure_sudo program (e.g. a PheonixBox repair)";
	if (ssaddon_pkg_busy(why, n))
		return "a package manager is running";
	return NULL;
}

static void quarantine_offender(const struct cfg *c, pid_t pid, const char *exe)
{
	char root[PATH_MAX], bucket[PATH_MAX], sample[PATH_MAX], lock[PATH_MAX];
	const char *no = never_kill(pid, exe, lock, sizeof(lock));
	int efd;

	if (no) {
		ssl_warn("not killed: pid %d (%s): %s", pid, exe, no);
		return;
	}
	if (!sst_armed(STATEDIR)) {
		/* quarantine mode reports until the operator arms it */
		ssl_warn("NOT ARMED: would kill pid %d (%s) and quarantine it; run "
			 "`secure-sudo-tamperwatch arm` to let it act", pid, exe);
		return;
	}

	if (c->rotate && locus_request_root(LOCUS_PURPOSE, root, sizeof(root)) == 0)
		;
	else
		snprintf(root, sizeof(root), "%s", c->quarantine_root);
	if (store_bucket(root, c->rotate, bucket, sizeof(bucket)) != 0) {
		ssl_err("cannot create quarantine bucket under %s", root);
		return;
	}
	/* The binary that is running, via /proc/PID/exe: the right file even
	 * if its path was replaced (or it was deleted) after it started. */
	{
		char lk[64];

		snprintf(lk, sizeof(lk), "/proc/%d/exe", pid);
		efd = open(lk, O_RDONLY | O_CLOEXEC);
	}
	if (efd >= 0 &&
	    store_put_fd(efd, exe, bucket, "tamper", sample, sizeof(sample), NULL) == 0) {
		ssl_crit("quarantined tamperer exe %s -> %s", exe, sample);
		sst_evidence("tamperwatch", exe, "quarantine", NULL, sample);
	} else {
		/* the kill still goes ahead: it stops the tampering, and the
		 * record below says the copy is missing */
		ssl_err("failed to quarantine exe %s (disk full?)", exe);
		sst_evidence("tamperwatch", exe, "quarantine", NULL, NULL);
	}
	if (efd >= 0)
		close(efd);
	if (kill(pid, SIGKILL) == 0)
		ssl_crit("killed tamperer pid %d (%s)", pid, exe);
}

/* Resolve the path the event refers to from its fd. */
static void fd_path(int fd, char *out, size_t n)
{
	char link[64];
	ssize_t r;

	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	r = readlink(link, out, n - 1);
	if (r < 0)
		snprintf(out, n, "(unknown)");
	else
		out[r] = '\0';
}

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static int run_daemon(void)
{
	struct cfg c;
	struct pollfd pfd;

	load_cfg(&c, NULL);
	g_fan = fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY | O_CLOEXEC);
	if (g_fan < 0) {
		ssl_err("fanotify_init failed: %s (need root + CONFIG_FANOTIFY)",
			strerror(errno));
		fprintf(stderr, "tamperwatch: fanotify_init: %s\n", strerror(errno));
		return 1;
	}
	mark_from(PBOX_CONF);		/* the PheonixBox protected set */
	mark_from(CONF);		/* any extra absolute paths listed here */
	if (g_marked == 0) {
		ssl_warn("tamperwatch: no files marked (empty protected set) - idle");
		fprintf(stderr, "tamperwatch: nothing to watch; configure "
			PBOX_CONF " or " CONF "\n");
	}
	if (!c.quarantine)
		sst_disarm("tamperwatch", STATEDIR);
	ssl_info("tamperwatch started: %zu files watched, mode=%s%s", g_marked,
		 c.quarantine ? "quarantine" : "log",
		 c.quarantine && !sst_armed(STATEDIR) ? " (NOT ARMED: reporting only)" : "");

	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	pfd.fd = g_fan;
	pfd.events = POLLIN;

	while (!stop) {
		char buf[8192];
		ssize_t len;
		struct fanotify_event_metadata *m;

		if (poll(&pfd, 1, 1000) <= 0)
			continue;
		len = read(g_fan, buf, sizeof(buf));
		if (len <= 0)
			continue;
		m = (struct fanotify_event_metadata *)buf;
		while (FAN_EVENT_OK(m, len)) {
			char fpath[PATH_MAX], exe[PATH_MAX];

			if (m->vers == FANOTIFY_METADATA_VERSION && m->fd >= 0) {
				fd_path(m->fd, fpath, sizeof(fpath));
				if (pid_exe(m->pid, exe, sizeof(exe)) != 0)
					snprintf(exe, sizeof(exe), "(exited pid %d)",
						 m->pid);
				ssl_crit("TAMPER: %s modified by pid %d (%s)",
					 fpath, m->pid, exe);
				if (c.quarantine && exe[0] == '/')
					quarantine_offender(&c, m->pid, exe);
				close(m->fd);
			}
			m = FAN_EVENT_NEXT(m, len);
		}
	}
	ssl_info("tamperwatch stopping");
	close(g_fan);
	return 0;
}

static int cmd_status(void)
{
	struct cfg c;

	load_cfg(&c, NULL);
	printf("tamperwatch\n");
	printf("mode:            %s\n", c.quarantine ? "quarantine (kill + compress exe)" :
	       "log (attribute only)");
	{
		char a[160];

		sst_describe_arming(STATEDIR, c.quarantine, a, sizeof(a));
		if (c.quarantine && !sst_armed(STATEDIR))
			snprintf(a, sizeof(a), "NOT ARMED: reporting only until `arm`");
		printf("arming:          %s\n", a);
	}
	printf("watched set:     " PBOX_CONF " + " CONF "\n");
	printf("quarantine root: %s%s\n", c.quarantine_root,
	       c.rotate ? " (hourly)" : " (fixed)");
	return 0;
}

static int cmd_arm(void)
{
	struct cfg c;

	load_cfg(&c, NULL);
	if (!c.quarantine) {
		fprintf(stderr, "tamperwatch: mode is log; set mode = quarantine first\n");
		return 1;
	}
	return sst_arm("tamperwatch", STATEDIR, "armed by the operator") ? 1 : 0;
}

static void usage(void)
{
	fprintf(stderr,
"usage: secure-sudo-tamperwatch <daemon|arm|status|check-config>\n"
"  daemon   watch the protected set and attribute (and optionally quarantine) tampering\n"
"  arm      let quarantine mode act (until then it reports only)\n"
"  status   show configuration\n"
"  check-config  check every config file strictly; 1 if any problem\n"
"\nNeeds root + CONFIG_FANOTIFY. Config: " CONF "\n");
}

int main(int argc, char **argv)
{
	if (geteuid() != 0) {
		fprintf(stderr, "tamperwatch: must run as root\n");
		return 1;
	}
	if (argc < 2) {
		usage();
		return 2;
	}
	ssl_init("tamperwatch");

	if (!strcmp(argv[1], "check-config"))
		return ssc_verdict(conf_errors(stdout));
	if (strcmp(argv[1], "status")) {
		int rc = ssc_refuse(argv[1], conf_errors(stderr));

		if (rc)
			return rc;
	}

	if (!strcmp(argv[1], "daemon"))
		return run_daemon();
	if (!strcmp(argv[1], "status"))
		return cmd_status();
	if (!strcmp(argv[1], "arm"))
		return cmd_arm();

	usage();
	ssl_close();
	return 2;
}
