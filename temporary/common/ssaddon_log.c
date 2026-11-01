// SPDX-License-Identifier: GPL-2.0
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

void ssl_notify(enum ssl_level level, const char *fmt, ...)
{
	char raw[1024], msg[1024], cmd[1600];
	va_list ap;
	const char *p;
	size_t o = 0;
	int rc;

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
	/* Build the command, substituting %m=message %l=level %f=feature. Each
	 * substitution is single-quoted so the operator's template cannot be
	 * broken by message content (the tools are root-only regardless). */
	for (p = S.notify_cmd; *p && o < sizeof(cmd) - 1; p++) {
		if (p[0] == '%' && (p[1] == 'm' || p[1] == 'l' || p[1] == 'f')) {
			const char *val = p[1] == 'm' ? msg :
					  p[1] == 'l' ? level_name(level) : S.feature;
			char q[1100];
			const char *s;
			size_t qo = 0;

			q[qo++] = '\'';
			for (s = val; *s && qo < sizeof(q) - 6; s++) {
				if (*s == '\'') {	/* ' -> '\'' */
					q[qo++] = '\''; q[qo++] = '\\';
					q[qo++] = '\''; q[qo++] = '\'';
				} else {
					q[qo++] = *s;
				}
			}
			q[qo++] = '\'';
			q[qo] = '\0';
			/* never cut a quoted value short: a half-quoted command
			 * is not run at all (it used to write past cmd[]) */
			if (o + qo >= sizeof(cmd)) {
				ssl_log(SSL_WARN, "notify_cmd not run: the command would be "
					"longer than %zu bytes", sizeof(cmd) - 1);
				return;
			}
			memcpy(cmd + o, q, qo + 1);
			o += qo;
			p++;
		} else {
			cmd[o++] = *p;
		}
	}
	cmd[o] = '\0';
	rc = system(cmd);
	if (rc != 0)
		ssl_log(SSL_WARN, "notify_cmd returned %d", rc);
}

void ssl_close(void)
{
	if (S.sock >= 0) {
		close(S.sock);
		S.sock = -1;
	}
	S.ready = 0;
}
