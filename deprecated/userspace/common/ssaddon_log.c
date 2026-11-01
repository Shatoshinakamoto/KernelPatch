// SPDX-License-Identifier: GPL-2.0
/*
 * ssaddon_log - shared logging for the secure_sudo runtime guards.
 * See ssaddon_log.h for the interface and the design notes.
 */
#define _GNU_SOURCE
#include "ssaddon_log.h"

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

#define CONF		"/etc/secure_sudo/addons/logging.conf"
#define DEF_DIR		"/var/log/secure_sudo/addons"
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

static void trim(char *s)
{
	size_t n = strlen(s);

	while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' ||
		     s[n - 1] == '\t'))
		s[--n] = '\0';
}

/* Parse logging.conf. Unknown keys are ignored; the file may be absent. */
static void load_conf(void)
{
	FILE *f = fopen(CONF, "re");
	char line[512];

	snprintf(S.dir, sizeof(S.dir), "%s", DEF_DIR);
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
		k = line;
		v = eq + 1;
		while (*k == ' ' || *k == '\t') k++;
		trim(k);
		while (*v == ' ' || *v == '\t') v++;

		if (!strcmp(k, "log_dir"))
			snprintf(S.dir, sizeof(S.dir), "%s", v);
		else if (!strcmp(k, "log_max_bytes"))
			S.max_bytes = strtoul(v, NULL, 10);
		else if (!strcmp(k, "remote_enabled"))
			S.remote_enabled = atoi(v);
		else if (!strcmp(k, "remote_proto"))
			S.remote_tcp = !strcmp(v, "tcp");
		else if (!strcmp(k, "remote_host"))
			snprintf(S.host, sizeof(S.host), "%s", v);
		else if (!strcmp(k, "remote_port"))
			snprintf(S.port, sizeof(S.port), "%s", v);
	}
	fclose(f);
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
	load_conf();

	/* Local log dir is root-only: the logs name quarantined malware paths
	 * and host state that should not leak to unprivileged users. */
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
	/* best-effort; never block the guard on log shipping, so a failed
	 * send() is deliberately ignored. */
	if (S.remote_tcp) {
		/* octet-count framing so the collector can split the stream. */
		char framed[1300];
		int m = snprintf(framed, sizeof(framed), "%d %s", n, buf);
		ssize_t w;

		if (m > 0) {
			w = send(S.sock, framed, (size_t)m, MSG_NOSIGNAL);
			(void)w;
		}
	} else {
		ssize_t w = send(S.sock, buf, (size_t)n, 0);
		(void)w;
	}
}

void ssl_log(enum ssl_level level, const char *fmt, ...)
{
	char msg[1024], ts[40];
	struct tm tm;
	time_t now;
	va_list ap;
	FILE *f;

	if (!S.ready)
		ssl_init("addon");

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

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

void ssl_close(void)
{
	if (S.sock >= 0) {
		close(S.sock);
		S.sock = -1;
	}
	S.ready = 0;
}
