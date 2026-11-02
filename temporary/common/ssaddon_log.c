// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * ssaddon_log - shared logging for the secure_sudo temporary/ add-ons.
 * See ssaddon_log.h for the interface and the design notes.
 */
#define _GNU_SOURCE
#include "ssaddon_log.h"
#include "ssaddon_conf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <netdb.h>

/* Overridable for the tests only (tests/userspace/test-addons.sh). */
#ifndef SSL_CONF
#define SSL_CONF	"/etc/secure_sudo/addons/logging.conf"
#endif
#define CONF		SSL_CONF
#ifndef SSL_DEF_DIR
#define SSL_DEF_DIR	"/var/log/secure_sudo/addons"
#endif
#define DEF_DIR		SSL_DEF_DIR
#define DEF_MAX		(8UL * 1024 * 1024)	/* rotate at 8 MiB */

/* Module state, set up once by ssl_init(). */
static struct {
	char feature[64];
	char dir[256];
	unsigned long max_bytes;
	int remote_enabled;
	int remote_tcp;			/* 1 = TCP, 0 = UDP */
	char host[256];
	char port[16];
	int sock;			/* remote socket, -1 if none */
	char logpath[512];
	char notify_cmd[512];		/* run on ssl_notify(); %m %l %f subst */
	int conf_errors;
	int ready;
} S = { .sock = -1, .max_bytes = DEF_MAX };

static const char *level_name(enum ssl_level l)
{
	switch (l) {
	case SSL_DEBUG: return "DEBUG";
	case SSL_INFO:  return "INFO";
	case SSL_WARN:  return "WARN";
	case SSL_ERR:   return "ERR";
	case SSL_CRIT:  return "CRIT";
	}
	return "INFO";
}

/* Map our level onto a syslog severity (RFC 5424 PRI = facility*8+severity).
 * Facility 13 (log audit) is a sensible home for security-tool output. */
static int syslog_pri(enum ssl_level l)
{
	int sev;

	switch (l) {
	case SSL_DEBUG: sev = 7; break;
	case SSL_INFO:  sev = 6; break;
	case SSL_WARN:  sev = 4; break;
	case SSL_ERR:   sev = 3; break;
	case SSL_CRIT:  sev = 2; break;
	default:        sev = 6; break;
	}
	return 13 * 8 + sev;
}

/* Parse logging.conf strictly (ssaddon_conf). A key with an error keeps its
 * safe default; the add-ons' acting commands refuse to run while
 * ssl_check_conf() reports errors. The file may be absent. */
static int load_conf(FILE *report)
{
	static const char *const protos[] = { "udp", "tcp", NULL };
	int max = (int)DEF_MAX;
	const struct ssc_key keys[] = {
		{ "log_dir", SSC_PATH, S.dir, sizeof(S.dir), 1, 0, NULL },
		{ "log_max_bytes", SSC_INT, &max, 0, 65536, 1L << 30, NULL },
		{ "remote_enabled", SSC_INT, &S.remote_enabled, 0, 0, 1, NULL },
		{ "remote_proto", SSC_ENUM, &S.remote_tcp, 0, 0, 0, protos },
		{ "remote_host", SSC_HOST, S.host, sizeof(S.host), 0, 0, NULL },
		{ "remote_port", SSC_PORT, S.port, sizeof(S.port), 0, 0, NULL },
		{ "notify_cmd", SSC_STR, S.notify_cmd, sizeof(S.notify_cmd), 0, 0, NULL },
		{ NULL, 0, NULL, 0, 0, 0, NULL }
	};
	int errors;

	snprintf(S.dir, sizeof(S.dir), "%s", DEF_DIR);
	S.remote_enabled = 0;
	S.remote_tcp = 0;
	S.host[0] = S.notify_cmd[0] = '\0';
	snprintf(S.port, sizeof(S.port), "514");
	errors = ssc_parse(CONF, keys, NULL, NULL, report);
	S.max_bytes = (unsigned long)max;
	if (!errors && S.remote_enabled && !S.host[0]) {
		if (report)
			fprintf(report, "%s: remote_enabled = 1 needs remote_host\n", CONF);
		errors++;
	}
	S.conf_errors = errors;
	return errors;
}

int ssl_check_conf(FILE *report)
{
	return load_conf(report);
}

int ssl_conf_errors(void)
{
	return S.conf_errors;
}

static void open_remote(void)
{
	struct addrinfo hints, *res, *rp;

	if (!S.remote_enabled || !S.host[0] || !S.port[0])
		return;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = S.remote_tcp ? SOCK_STREAM : SOCK_DGRAM;
	if (getaddrinfo(S.host, S.port, &hints, &res) != 0)
		return;
	for (rp = res; rp; rp = rp->ai_next) {
		int fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC,
				rp->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
			S.sock = fd;
			break;
		}
		close(fd);
	}
	freeaddrinfo(res);
}

void ssl_init(const char *feature)
{
	snprintf(S.feature, sizeof(S.feature), "%s", feature ? feature : "addon");
	load_conf(NULL);

	/* Local log dir is root-only: the logs name quarantined malware paths
	 * and host state that should not leak to unprivileged users. */
	if (!strncmp(S.dir, "/var/log/secure_sudo/", 21))
		mkdir("/var/log/secure_sudo", 0700);
	mkdir(S.dir, 0700);
	snprintf(S.logpath, sizeof(S.logpath), "%s/%s.log", S.dir, S.feature);

	open_remote();
	S.ready = 1;
}

/* Rotate the local log to "<path>.1" when it exceeds the size cap. One
 * generation is kept locally; the remote server is the real archive. */
static void maybe_rotate(void)
{
	struct stat st;
	char old[520];

	if (stat(S.logpath, &st) != 0 || (unsigned long)st.st_size < S.max_bytes)
		return;
	snprintf(old, sizeof(old), "%s.1", S.logpath);
	rename(S.logpath, old);		/* best-effort */
}

static void ship_remote(int pri, const char *ts, const char *msg)
{
	char host[64] = "localhost";
	char buf[1200];
	int n;

	if (S.sock < 0)
		return;
	gethostname(host, sizeof(host) - 1);
	/* RFC 5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID MSG */
	n = snprintf(buf, sizeof(buf), "<%d>1 %s %s secure_sudo-%s %ld - %s",
		     pri, ts, host, S.feature, (long)getpid(), msg);
	if (n <= 0)
		return;
	if ((size_t)n >= sizeof(buf))	/* snprintf says what it wanted */
		n = (int)sizeof(buf) - 1;
	/* best-effort; never block the guard on log shipping, so a failed
	 * send() is deliberately ignored. */
	if (S.remote_tcp) {
		/* octet-count framing so the collector can split the stream. */
		char framed[1300];
		int m = snprintf(framed, sizeof(framed), "%d %s", n, buf);
		ssize_t w;

		if (m > 0 && (size_t)m >= sizeof(framed))
			m = 0;		/* never send past framed[] */
		if (m > 0) {
			w = send(S.sock, framed, (size_t)m, MSG_NOSIGNAL);
			(void)w;
		}
	} else {
		ssize_t w = send(S.sock, buf, (size_t)n, 0);
		(void)w;
	}
}

/* Make @s safe to write as one log line (P2-2 part 3, log injection): a file
 * name or process title is attacker-chosen, and a newline in one could forge
 * a whole log entry ("... CRIT BASELINE ...") or an RFC 5424 frame. Control
 * bytes and backslash are written as \xNN, so the escaping is unambiguous;
 * the rest (UTF-8 included) is kept. Cut short rather than overflow. */
static void sanitize(const char *s, char *out, size_t n)
{
	static const char hex[] = "0123456789abcdef";
	size_t o = 0;

	for (; *s && o + 5 < n; s++) {
		unsigned char c = (unsigned char)*s;

		if (c < 0x20 || c == 0x7f || c == '\\') {
			out[o++] = '\\'; out[o++] = 'x';
			out[o++] = hex[c >> 4]; out[o++] = hex[c & 15];
		} else {
			out[o++] = (char)c;
		}
	}
	out[o] = '\0';
}

void ssl_log(enum ssl_level level, const char *fmt, ...)
{
	char raw[1024], msg[1024], ts[40];
	struct tm tm;
	time_t now;
	va_list ap;
	FILE *f;

	if (!S.ready)
		ssl_init("addon");

	va_start(ap, fmt);
	vsnprintf(raw, sizeof(raw), fmt, ap);
	va_end(ap);
	sanitize(raw, msg, sizeof(msg));

	now = time(NULL);
	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);

	/* Local append (with rotation). */
	maybe_rotate();
	f = fopen(S.logpath, "ae");
	if (f) {
		fprintf(f, "%s %-5s %s\n", ts, level_name(level), msg);
		fclose(f);
		chmod(S.logpath, 0600);
	}

	/* Remote shipping (RFC 5424 wants a Zulu-ish stamp; reuse local ts). */
	ship_remote(syslog_pri(level), ts, msg);
}

/*
 * notify_cmd (TODO P2-3). The template is split into words here (single and
 * double quotes group, a backslash escapes the next character) and run with
 * execvp under a fixed PATH: no shell ever sees the message, so text an
 * attacker put in a file name, unit name or table name cannot become a
 * command. %m, %l and %f inside a word are replaced by the message, level and
 * feature, with control bytes written as \xNN.
 *
 * The same notification (level and message) within NOTIFY_DEDUP_SECS is
 * counted, not run again, and the next one says how many were held back; at
 * most NOTIFY_MAX_PER_MIN run per minute. A command that cannot start, exits
 * non-zero or runs past NOTIFY_TIMEOUT_SECS (then killed) is logged ERROR, so
 * the failure is in the local and forwarded log.
 */
#define NOTIFY_ARGS		32
#define NOTIFY_DEDUP_SECS	300
#define NOTIFY_MAX_PER_MIN	10
#ifndef NOTIFY_TIMEOUT_SECS
#define NOTIFY_TIMEOUT_SECS	10
#endif
#define NOTIFY_SLOTS		32

static struct {
	unsigned long long key;
	time_t last;
	unsigned long held;
} notify_seen[NOTIFY_SLOTS];
static time_t notify_window;
static unsigned notify_window_n;
static unsigned long notify_window_dropped;

static int notify_split(const char *tmpl, char *buf, size_t n, char *words[], int max)
{
	size_t o = 0;
	int w = 0;
	const char *p = tmpl;

	while (*p) {
		char q = 0;

		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			break;
		if (w >= max - 1)
			return -1;
		words[w++] = buf + o;
		while (*p && (q || (*p != ' ' && *p != '\t'))) {
			if (!q && (*p == '\'' || *p == '"')) {
				q = *p++;
				continue;
			}
			if (q && *p == q) {
				q = 0;
				p++;
				continue;
			}
			if (*p == '\\' && q != '\'' && p[1])
				p++;
			if (o + 1 >= n)
				return -1;
			buf[o++] = *p++;
		}
		if (q)
			return -1;
		buf[o++] = '\0';
	}
	words[w] = NULL;
	return w;
}

/* Run argv; wait up to NOTIFY_TIMEOUT_SECS. Returns the exit status, 127 if
 * it could not start, -1 if it was killed for running too long. */
static int notify_run(char *const argv[])
{
	struct timespec tick = { 0, 50 * 1000 * 1000 };
	time_t start = time(NULL);
	pid_t pid = fork(), r;
	int st;

	if (pid == 0) {
		int fd = open("/dev/null", O_RDWR | O_CLOEXEC);

		if (fd >= 0) {
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
		}
		for (fd = 3; fd < 1024; fd++)
			close(fd);
		setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
		execvp(argv[0], argv);
		_exit(127);
	}
	if (pid < 0)
		return 127;
	for (;;) {
		r = waitpid(pid, &st, WNOHANG);
		if (r == pid)
			return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
		if (r < 0)
			return 127;
		if (time(NULL) - start >= NOTIFY_TIMEOUT_SECS) {
			kill(pid, SIGKILL);
			waitpid(pid, &st, 0);
			return -1;
		}
		nanosleep(&tick, NULL);
	}
}

void ssl_notify(enum ssl_level level, const char *fmt, ...)
{
	char raw[1024], msg[1024], buf[1024], *words[NOTIFY_ARGS];
	char args[NOTIFY_ARGS][1200], *argv[NOTIFY_ARGS], held_s[96] = "";
	unsigned long long key = 0xcbf29ce484222325ULL;
	time_t now = time(NULL);
	const char *s;
	int w, i, rc, slot = -1, oldest = 0;
	unsigned long held;
	va_list ap;

	if (!S.ready)
		ssl_init("addon");

	va_start(ap, fmt);
	vsnprintf(raw, sizeof(raw), fmt, ap);
	va_end(ap);
	/* the notify command gets the same one-line text as the log */
	sanitize(raw, msg, sizeof(msg));

	/* Always log it too, so a notification is never only transient. */
	ssl_log(level, "NOTIFY: %s", raw);

	if (!S.notify_cmd[0])
		return;

	key = (key ^ (unsigned)level) * 0x100000001b3ULL;
	for (s = msg; *s; s++)
		key = (key ^ (unsigned char)*s) * 0x100000001b3ULL;
	for (i = 0; i < NOTIFY_SLOTS; i++) {
		if (notify_seen[i].last && notify_seen[i].key == key) {
			slot = i;
			break;
		}
		if (notify_seen[i].last < notify_seen[oldest].last)
			oldest = i;
	}
	if (slot >= 0 && now >= notify_seen[slot].last &&
	    now - notify_seen[slot].last < NOTIFY_DEDUP_SECS) {
		notify_seen[slot].held++;
		return;		/* the log line above is the record */
	}
	if (!notify_window || now - notify_window >= 60) {
		if (notify_window_dropped)
			ssl_log(SSL_WARN, "notify_cmd: %lu notification(s) not run in the "
				"last minute (more than %d)", notify_window_dropped,
				NOTIFY_MAX_PER_MIN);
		notify_window = now;
		notify_window_n = 0;
		notify_window_dropped = 0;
	}
	if (notify_window_n >= NOTIFY_MAX_PER_MIN) {
		notify_window_dropped++;
		return;
	}
	if (slot < 0) {
		slot = oldest;
		notify_seen[slot].key = key;
		notify_seen[slot].held = 0;
	}
	held = notify_seen[slot].held;
	notify_seen[slot].held = 0;
	notify_seen[slot].last = now;
	if (held)
		snprintf(held_s, sizeof(held_s), " (%lu more like this in the last %d s)",
			 held, NOTIFY_DEDUP_SECS);

	w = notify_split(S.notify_cmd, buf, sizeof(buf), words, NOTIFY_ARGS);
	if (w <= 0) {
		ssl_log(SSL_ERR, "notify_cmd not run: unbalanced quotes or more than %d "
			"words", NOTIFY_ARGS - 1);
		return;
	}
	for (i = 0; i < w; i++) {
		const char *p;
		size_t o = 0;

		for (p = words[i]; *p && o + 1 < sizeof(args[i]); p++) {
			const char *v;

			if (p[0] != '%' || (p[1] != 'm' && p[1] != 'l' && p[1] != 'f')) {
				args[i][o++] = *p;
				continue;
			}
			v = p[1] == 'm' ? msg : p[1] == 'l' ? level_name(level) : S.feature;
			p++;
			for (; *v && o + 5 < sizeof(args[i]); v++) {
				unsigned char ch = (unsigned char)*v;

				if (ch < 0x20 || ch == 0x7f)
					o += (size_t)snprintf(args[i] + o, sizeof(args[i]) - o,
							      "\\x%02x", ch);
				else
					args[i][o++] = (char)ch;
			}
			if (p[-1] == '%' && p[0] == 'm' && held_s[0])
				for (v = held_s; *v && o + 1 < sizeof(args[i]); v++)
					args[i][o++] = *v;
		}
		args[i][o] = '\0';
		argv[i] = args[i];
	}
	argv[w] = NULL;
	notify_window_n++;
	rc = notify_run(argv);
	if (rc == -1)
		ssl_log(SSL_ERR, "notify_cmd FAILED: killed after %d s", NOTIFY_TIMEOUT_SECS);
	else if (rc == 127)
		ssl_log(SSL_ERR, "notify_cmd FAILED: %s could not be started", argv[0]);
	else if (rc != 0)
		ssl_log(SSL_ERR, "notify_cmd FAILED: exited %d", rc);
}

void ssl_close(void)
{
	if (S.sock >= 0) {
		close(S.sock);
		S.sock = -1;
	}
	S.ready = 0;
}
