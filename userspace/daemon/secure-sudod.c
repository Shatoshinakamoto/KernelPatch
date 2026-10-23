// SPDX-License-Identifier: GPL-2.0
/*
 * secure-sudod - userspace companion to the secure_sudo LSM.
 *
 * The kernel enforces policy and emits events; this daemon does the work that
 * must not happen in kernel context:
 *
 *   #9  Logging: drain the kernel event ring (securityfs "events", blocking
 *       read + poll) into /var/log/secure_sudo/YYYY-MM-DD.log with wall-clock
 *       timestamps, enforce retain_days and max_total_mb, and optionally
 *       forward to a remote syslog (which TimeVault relies on so logs survive
 *       a locked-down box).
 *   #8  Cooldown enforcement: when the kernel reports a UID blocked for sudo
 *       brute force, freeze (SIGSTOP) then kill (SIGKILL) that user's sudo/su
 *       processes - the "detect and shut down the offender" the TODO asks for.
 *   #10 Network modes: watch net_mode and (re)apply one nft table for the
 *       lan-only / public-only modes via the apply-net helper, deleting it on
 *       every change. (host mode's raw/packet block is the kernel's job.)
 *   #13 TimeVault: while engaged, scan the watched trees, and move any new or
 *       changed file to quarantine via the quarantine helper, keeping a
 *       sha256 manifest so only genuine changes trigger.
 *
 * Network detection and zip packaging are shelled out to helper scripts
 * (/usr/libexec/secure-sudo/{apply-net,quarantine}.sh) to keep this core small
 * and auditable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/evp.h>

#define EVENTS   "/sys/kernel/security/secure_sudo/events"
#define SYSFS    "/sys/kernel/secure_sudo"
#define CONFIG   "/etc/secure_sudo/secure-sudo.conf"
#define LOGDIR   "/var/log/secure_sudo"
#define STATEDIR "/var/lib/secure_sudo"
#define MANIFEST STATEDIR "/manifest"
#define QUARANTINE STATEDIR "/quarantine"
#define HELPER_NET  "/usr/libexec/secure-sudo/apply-net.sh"
#define HELPER_QUAR "/usr/libexec/secure-sudo/quarantine.sh"

/* ---- configuration (daemon-relevant keys) ---- */
struct cfg {
	int retain_days;
	long max_total_mb;
	char remote_syslog[256];	/* "host:port" or empty */
	char vault_action[16];		/* quarantine | wipe */
	char vault_watch[1024];		/* comma-separated dirs */
};

static volatile sig_atomic_t want_reload;
static volatile sig_atomic_t want_stop;

/* Forward declaration: used by kill_offenders() before its definition. */
static void syslog_line(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

static void on_hup(int sig)  { (void)sig; want_reload = 1; }
static void on_term(int sig) { (void)sig; want_stop = 1; }

static void trim(char *s)
{
	char *e;

	while (isspace((unsigned char)*s))
		memmove(s, s + 1, strlen(s));
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = '\0';
}

static void load_cfg(struct cfg *c)
{
	FILE *f;
	char line[1200];

	/* defaults */
	c->retain_days = 14;
	c->max_total_mb = 512;
	c->remote_syslog[0] = '\0';
	strcpy(c->vault_action, "quarantine");
	strcpy(c->vault_watch, "/etc,/usr/local/bin,/opt,/usr/local/sbin");

	f = fopen(CONFIG, "re");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char *eq = strchr(line, '=');
		char *key, *val;

		if (line[0] == '#' || !eq)
			continue;
		*eq = '\0';
		key = line; val = eq + 1;
		trim(key); trim(val);
		if (!strcmp(key, "retain_days"))
			c->retain_days = atoi(val);
		else if (!strcmp(key, "max_total_mb"))
			c->max_total_mb = atol(val);
		else if (!strcmp(key, "remote_syslog"))
			snprintf(c->remote_syslog, sizeof(c->remote_syslog), "%s", val);
		else if (!strcmp(key, "vault_action"))
			snprintf(c->vault_action, sizeof(c->vault_action), "%s", val);
		else if (!strcmp(key, "vault_watch"))
			snprintf(c->vault_watch, sizeof(c->vault_watch), "%s", val);
	}
	fclose(f);
}

/* ---- #9 logging ---- */

static void todays_logpath(char *buf, size_t n)
{
	time_t t = time(NULL);
	struct tm tm;

	localtime_r(&t, &tm);
	snprintf(buf, n, LOGDIR "/%04d-%02d-%02d.log",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

static void forward_remote(const struct cfg *c, const char *line, size_t len)
{
	char host[256], *colon;
	const char *port = "514";
	struct addrinfo hints = { .ai_socktype = SOCK_DGRAM }, *res = NULL;
	int fd;

	if (!c->remote_syslog[0])
		return;
	snprintf(host, sizeof(host), "%s", c->remote_syslog);
	colon = strrchr(host, ':');
	if (colon) {
		*colon = '\0';
		port = colon + 1;
	}
	if (getaddrinfo(host, port, &hints, &res) != 0 || !res)
		return;
	fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd >= 0) {
		char msg[600];
		int m = snprintf(msg, sizeof(msg), "<85>secure_sudo: %.*s",
				 (int)len, line);
		sendto(fd, msg, m, 0, res->ai_addr, res->ai_addrlen);
		close(fd);
	}
	freeaddrinfo(res);
}

static void write_log(const struct cfg *c, const char *line, size_t len)
{
	char path[512];
	FILE *f;

	todays_logpath(path, sizeof(path));
	f = fopen(path, "ae");
	if (f) {
		fwrite(line, 1, len, f);
		if (len == 0 || line[len - 1] != '\n')
			fputc('\n', f);
		fclose(f);
	}
	forward_remote(c, line, len);
}

/* Delete logs older than retain_days and trim oldest until under max_total_mb. */
static void enforce_retention(const struct cfg *c)
{
	DIR *d = opendir(LOGDIR);
	struct dirent *de;
	time_t now = time(NULL);
	long total = 0;
	/* simple two-pass: first delete by age, then by total size */

	if (!d)
		return;
	while ((de = readdir(d))) {
		char p[512];
		struct stat st;

		if (de->d_name[0] == '.')
			continue;
		snprintf(p, sizeof(p), LOGDIR "/%s", de->d_name);
		if (stat(p, &st) != 0)
			continue;
		if (c->retain_days > 0 &&
		    now - st.st_mtime > (time_t)c->retain_days * 86400) {
			unlink(p);
			continue;
		}
		total += st.st_size;
	}
	closedir(d);

	/* Size cap: delete oldest files until under the cap. */
	while (c->max_total_mb > 0 && total > c->max_total_mb * 1024 * 1024) {
		char oldest[512] = "";
		time_t oldest_t = 0;
		struct stat ost = { 0 };
		long freed = 0;

		d = opendir(LOGDIR);
		if (!d)
			break;
		while ((de = readdir(d))) {
			char p[512];
			struct stat st;

			if (de->d_name[0] == '.')
				continue;
			snprintf(p, sizeof(p), LOGDIR "/%s", de->d_name);
			if (stat(p, &st) != 0)
				continue;
			if (!oldest[0] || st.st_mtime < oldest_t) {
				oldest_t = st.st_mtime;
				snprintf(oldest, sizeof(oldest), "%s", p);
				ost = st;
			}
		}
		closedir(d);
		if (!oldest[0])
			break;
		freed = ost.st_size;
		unlink(oldest);
		total -= freed;
	}
}

/* ---- #8 cooldown: freeze + kill the offending sudo/su processes ---- */

static int proc_ruid(const char *pid, uid_t *ruid)
{
	char path[256], line[256];
	FILE *f;
	int ok = 0;

	snprintf(path, sizeof(path), "/proc/%s/status", pid);
	f = fopen(path, "re");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		unsigned u;

		if (sscanf(line, "Uid:\t%u", &u) == 1) {
			*ruid = u;
			ok = 1;
			break;
		}
	}
	fclose(f);
	return ok ? 0 : -1;
}

static int proc_is_sudo(const char *pid)
{
	char path[256], comm[64] = "";
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%s/comm", pid);
	f = fopen(path, "re");
	if (!f)
		return 0;
	if (fgets(comm, sizeof(comm), f))
		trim(comm);
	fclose(f);
	return !strcmp(comm, "sudo") || !strcmp(comm, "su");
}

static void kill_offenders(uid_t uid)
{
	DIR *d = opendir("/proc");
	struct dirent *de;
	pid_t victims[256];
	int n = 0, i;

	if (!d)
		return;
	while ((de = readdir(d)) && n < (int)(sizeof(victims) / sizeof(victims[0]))) {
		uid_t ruid;

		if (de->d_name[0] < '0' || de->d_name[0] > '9')
			continue;
		if (proc_ruid(de->d_name, &ruid) != 0 || ruid != uid)
			continue;
		if (!proc_is_sudo(de->d_name))
			continue;
		victims[n++] = (pid_t)atoi(de->d_name);
	}
	closedir(d);

	/* Freeze first so the offender cannot spawn more retries, then kill. */
	for (i = 0; i < n; i++)
		kill(victims[i], SIGSTOP);
	for (i = 0; i < n; i++)
		kill(victims[i], SIGKILL);
	if (n)
		syslog_line("cooldown: froze+killed %d sudo/su pid(s) for UID %u",
			    n, (unsigned)uid);
}

/* Minimal local logger (also goes to our own event log via write path). */
static struct cfg *g_cfg;
static void syslog_line(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (g_cfg)
		write_log(g_cfg, buf, n);
}

/* Parse an event line for "cooldown: UID <n> blocked ..." and act. */
static void maybe_cooldown(const char *line)
{
	const char *p = strstr(line, "cooldown: UID ");
	unsigned uid;

	if (!p)
		return;
	if (sscanf(p, "cooldown: UID %u blocked", &uid) == 1)
		kill_offenders((uid_t)uid);
}

/* ---- #10 network mode ---- */

static int read_sysfs_str(const char *name, char *out, size_t n)
{
	char path[256];
	int fd;
	ssize_t r;

	snprintf(path, sizeof(path), SYSFS "/%s", name);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	r = read(fd, out, n - 1);
	close(fd);
	if (r < 0)
		return -1;
	out[r] = '\0';
	trim(out);
	return 0;
}

static void run_helper(const char *helper, const char *arg)
{
	pid_t pid = fork();

	if (pid == 0) {
		execl(helper, helper, arg, (char *)NULL);
		_exit(127);
	} else if (pid > 0) {
		int st;

		waitpid(pid, &st, 0);
	}
}

static void apply_net_mode(void)
{
	static char last[32] = "";
	char mode[32];

	if (read_sysfs_str("net_mode", mode, sizeof(mode)) != 0)
		return;
	if (!strcmp(mode, last))
		return;
	snprintf(last, sizeof(last), "%s", mode);
	syslog_line("net: applying mode %s", mode);
	run_helper(HELPER_NET, mode);
}

/* ---- #13 TimeVault scan ---- */

static int sha256_hex(const char *path, char out[65])
{
	unsigned char buf[65536], digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;
	EVP_MD_CTX *ctx;
	FILE *f;
	size_t r;
	int i;

	f = fopen(path, "rbe");
	if (!f)
		return -1;
	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fclose(f);
		return -1;
	}
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
		goto err;
	while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
		if (EVP_DigestUpdate(ctx, buf, r) != 1)
			goto err;
	if (EVP_DigestFinal_ex(ctx, digest, &dlen) != 1)
		goto err;
	for (i = 0; i < (int)dlen; i++)
		sprintf(out + i * 2, "%02x", digest[i]);
	out[dlen * 2] = '\0';
	EVP_MD_CTX_free(ctx);
	fclose(f);
	return 0;
err:
	EVP_MD_CTX_free(ctx);
	fclose(f);
	return -1;
}

/* Look up a path's previously recorded hash in the manifest. */
static int manifest_lookup(const char *path, char out[65])
{
	FILE *f = fopen(MANIFEST, "re");
	char line[1200];
	int found = 0;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *sp = strchr(line, ' ');

		if (!sp)
			continue;
		*sp = '\0';
		trim(sp + 1);
		if (!strcmp(line, path)) {
			snprintf(out, 65, "%s", sp + 1);
			found = 1;
			break;
		}
	}
	fclose(f);
	return found ? 0 : -1;
}

static void manifest_record(const char *path, const char *hash)
{
	FILE *f = fopen(MANIFEST, "ae");

	if (f) {
		fprintf(f, "%s %s\n", path, hash);
		fclose(f);
	}
}

static void vault_scan_dir(const struct cfg *c, const char *dir, int depth)
{
	DIR *d;
	struct dirent *de;

	if (depth > 12)
		return;
	d = opendir(dir);
	if (!d)
		return;
	while ((de = readdir(d))) {
		char path[1024], have[65], prev[65];
		struct stat st;

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
		if (lstat(path, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			vault_scan_dir(c, path, depth + 1);
			continue;
		}
		if (!S_ISREG(st.st_mode))
			continue;
		if (sha256_hex(path, have) != 0)
			continue;
		if (manifest_lookup(path, prev) == 0 && !strcmp(prev, have))
			continue;	/* known and unchanged */

		/* New or changed file while the vault is engaged. */
		syslog_line("timevault: %s %s (action=%s)",
			    prev[0] ? "changed" : "new", path, c->vault_action);
		if (!strcmp(c->vault_action, "wipe"))
			unlink(path);
		else
			run_helper(HELPER_QUAR, path);
		manifest_record(path, have);
	}
	closedir(d);
}

static void vault_scan(const struct cfg *c)
{
	char buf[1024], *p, *tok, *save;
	char enabled[8];

	if (read_sysfs_str("timevault", enabled, sizeof(enabled)) != 0)
		return;
	if (strcmp(enabled, "1"))
		return;

	snprintf(buf, sizeof(buf), "%s", c->vault_watch);
	p = buf;
	while ((tok = strtok_r(p, ",", &save))) {
		p = NULL;
		trim(tok);
		if (*tok)
			vault_scan_dir(c, tok, 0);
	}
}

/* ---- main loop ---- */

int main(void)
{
	struct cfg cfg;
	struct pollfd pfd;
	time_t last_periodic = 0;

	signal(SIGHUP, on_hup);
	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);
	signal(SIGCHLD, SIG_DFL);

	mkdir(LOGDIR, 0700);
	mkdir(STATEDIR, 0700);
	mkdir(QUARANTINE, 0700);

	load_cfg(&cfg);
	g_cfg = &cfg;

	pfd.fd = open(EVENTS, O_RDONLY);
	pfd.events = POLLIN;
	if (pfd.fd < 0) {
		fprintf(stderr, "secure-sudod: cannot open %s: %s\n", EVENTS,
			strerror(errno));
		fprintf(stderr, "Is the secure_sudo LSM active?\n");
		return 1;
	}

	syslog_line("secure-sudod started");

	while (!want_stop) {
		int rc = poll(&pfd, 1, 1000);
		time_t now = time(NULL);

		if (want_reload) {
			want_reload = 0;
			load_cfg(&cfg);
			syslog_line("config reloaded");
		}

		if (rc > 0 && (pfd.revents & POLLIN)) {
			char buf[4096];
			ssize_t n = read(pfd.fd, buf, sizeof(buf) - 1);

			if (n > 0) {
				char *line, *save;

				buf[n] = '\0';
				for (line = strtok_r(buf, "\n", &save); line;
				     line = strtok_r(NULL, "\n", &save)) {
					write_log(&cfg, line, strlen(line));
					maybe_cooldown(line);
				}
			}
		}

		/* Periodic work roughly every 5s. */
		if (now - last_periodic >= 5) {
			last_periodic = now;
			apply_net_mode();
			enforce_retention(&cfg);
			vault_scan(&cfg);
		}
	}

	syslog_line("secure-sudod stopping");
	close(pfd.fd);
	return 0;
}
