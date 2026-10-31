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
#define _GNU_SOURCE		/* O_PATH */
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
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define EVENTS   "/sys/kernel/security/secure_sudo/events"
#define SYSFS    "/sys/kernel/secure_sudo"
#define CONFIG   "/etc/secure_sudo/secure-sudo.conf"
#ifndef LOGDIR
#define LOGDIR   "/var/log/secure_sudo"
#endif
#define STATEDIR "/var/lib/secure_sudo"
#define HEALTH_FILE STATEDIR "/daemon.health"
#define RETENTION_HOLD STATEDIR "/retention.hold"
#define MANIFEST STATEDIR "/manifest"
#ifndef QUARANTINE
#define QUARANTINE STATEDIR "/quarantine"
#endif
#define HELPER_NET  "/usr/libexec/secure-sudo/apply-net.sh"
#ifndef HELPER_QUAR
#define HELPER_QUAR "/usr/libexec/secure-sudo/quarantine.sh"
#endif
#define HELPER_PBOX "/usr/bin/secure-sudo-pheonixbox"	/* #21 PheonixBox */
#define REMOTE_QUEUE_MAX_RECORDS 4096
#ifndef REMOTE_QUEUE
#define REMOTE_QUEUE STATEDIR "/remote-queue"
#endif

/* ---- configuration (daemon-relevant keys) ---- */
struct cfg {
	int retain_days;
	long max_total_mb;
	char remote_syslog[256];	/* "host:port" or empty */
	char remote_transport[8];	/* udp | tls */
	char remote_ca_file[512];
	long remote_queue_max_mb;
	char vault_action[16];		/* quarantine | wipe */
	char vault_watch[1024];		/* comma-separated dirs */
};

static struct cfg *g_cfg;
static volatile sig_atomic_t want_reload;
static volatile sig_atomic_t want_stop;
static char remote_state[32] = "disabled";
static char retention_state[16] = "active";
static unsigned long long remote_sent;
static unsigned long long remote_failures;
static unsigned long long remote_queue_bytes;
static unsigned long long remote_queue_records;
static unsigned long long remote_queue_dropped;
static unsigned long long remote_queue_sequence;
static unsigned long long local_log_failures;

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
	strcpy(c->remote_transport, "udp");
	strcpy(c->remote_ca_file, "/etc/ssl/certs/ca-certificates.crt");
	c->remote_queue_max_mb = 10;
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
		else if (!strcmp(key, "remote_syslog_transport")) {
			if (!strcmp(val, "udp") || !strcmp(val, "tls"))
				snprintf(c->remote_transport,
					 sizeof(c->remote_transport), "%s", val);
			else {
				snprintf(c->remote_transport,
					 sizeof(c->remote_transport), "invalid");
				fprintf(stderr, "secure-sudod: invalid remote_syslog_transport\n");
			}
		} else if (!strcmp(key, "remote_syslog_ca_file")) {
			if (*val)
				snprintf(c->remote_ca_file,
					 sizeof(c->remote_ca_file), "%s", val);
		} else if (!strcmp(key, "remote_queue_max_mb")) {
			char *end;
			long limit = strtol(val, &end, 10);

			if (*val && !*end && limit >= 1 && limit <= 1024)
				c->remote_queue_max_mb = limit;
			else {
				c->remote_queue_max_mb = 0;
				fprintf(stderr, "secure-sudod: invalid remote_queue_max_mb\n");
			}
		} else if (!strcmp(key, "vault_action"))
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

static int send_remote(const struct cfg *c, const char *line, size_t len)
{
	char target[256], host[256], *port;
	struct addrinfo hints = { 0 }, *res = NULL, *ai;
	int fd;

	if (!c->remote_syslog[0]) {
		snprintf(remote_state, sizeof(remote_state), "disabled");
		return 0;
	}
	if (strcmp(c->remote_transport, "tls") &&
	    strcmp(c->remote_transport, "udp")) {
		snprintf(remote_state, sizeof(remote_state), "config_error");
		remote_failures++;
		return 0;
	}
	snprintf(target, sizeof(target), "%s", c->remote_syslog);
	if (target[0] == '[') {
		char *end = strchr(target, ']');

		if (!end || end[1] != ':' || !end[2]) {
			snprintf(remote_state, sizeof(remote_state), "config_error");
			remote_failures++;
			return 0;
		}
		*end = '\0';
		snprintf(host, sizeof(host), "%s", target + 1);
		port = end + 2;
	} else {
		char *colon = strrchr(target, ':');

		if (!colon || colon == target || !colon[1]) {
			snprintf(remote_state, sizeof(remote_state), "config_error");
			remote_failures++;
			return 0;
		}
		*colon = '\0';
		snprintf(host, sizeof(host), "%s", target);
		port = colon + 1;
	}
	hints.ai_socktype = !strcmp(c->remote_transport, "tls") ?
			    SOCK_STREAM : SOCK_DGRAM;
	if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
		snprintf(remote_state, sizeof(remote_state), "dns_error");
		remote_failures++;
		return 0;
	}
	for (ai = res; ai; ai = ai->ai_next) {
		int flags, connected = 0;

		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		if (!strcmp(c->remote_transport, "tls")) {
			struct pollfd pfd;
			int error = 0;
			socklen_t error_len = sizeof(error);

			flags = fcntl(fd, F_GETFL);
			if (flags >= 0 &&
			    fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0) {
				if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
					connected = 1;
				} else if (errno == EINPROGRESS) {
					pfd.fd = fd;
					pfd.events = POLLOUT;
					pfd.revents = 0;
					if (poll(&pfd, 1, 3000) > 0 &&
					    getsockopt(fd, SOL_SOCKET, SO_ERROR,
						       &error, &error_len) == 0 &&
					    error == 0)
						connected = 1;
				}
				fcntl(fd, F_SETFL, flags);
			}
		} else {
			connected = connect(fd, ai->ai_addr,
					    ai->ai_addrlen) == 0;
		}
		if (connected)
			break;
		close(fd);
	}
	if (!ai) {
		freeaddrinfo(res);
		snprintf(remote_state, sizeof(remote_state), "connect_error");
		remote_failures++;
		return 0;
	}
	if (!strcmp(c->remote_transport, "udp")) {
		char msg[600];
		int m = snprintf(msg, sizeof(msg), "<85>secure_sudo: %.*s",
				 (int)len, line);

		if (send(fd, msg, (size_t)m, 0) == m) {
			snprintf(remote_state, sizeof(remote_state), "udp_unconfirmed");
			remote_sent++;
			close(fd);
			freeaddrinfo(res);
			return 1;
		} else {
			snprintf(remote_state, sizeof(remote_state), "send_error");
			remote_failures++;
		}
		close(fd);
	} else {
		SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
		SSL *ssl = NULL;
		struct timeval timeout = { .tv_sec = 3, .tv_usec = 0 };
		unsigned char addr[sizeof(struct in6_addr)];
		char msg[1200], frame[1232], hostname[256] = "localhost";
		struct tm tm;
		time_t now = time(NULL);
		int m, framed, verified = 0, sent = 0;

		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		if (ctx &&
		    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 1 &&
		    SSL_CTX_load_verify_locations(ctx, c->remote_ca_file,
						  NULL) == 1) {
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
			ssl = SSL_new(ctx);
		}
		if (ssl) {
			X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

			if (inet_pton(AF_INET, host, addr) == 1 ||
			    inet_pton(AF_INET6, host, addr) == 1)
				verified = X509_VERIFY_PARAM_set1_ip_asc(param, host) == 1;
			else
				verified = SSL_set1_host(ssl, host) == 1;
			if (verified && inet_pton(AF_INET, host, addr) != 1 &&
			    inet_pton(AF_INET6, host, addr) != 1 &&
			    SSL_set_tlsext_host_name(ssl, host) != 1)
				verified = 0;
			if (SSL_set_fd(ssl, fd) != 1)
				verified = 0;
		}
		if (!verified || !ssl || SSL_connect(ssl) != 1 ||
		    SSL_get_verify_result(ssl) != X509_V_OK) {
			snprintf(remote_state, sizeof(remote_state), "tls_error");
			remote_failures++;
		} else {
			char timestamp[40];

			gmtime_r(&now, &tm);
			strftime(timestamp, sizeof(timestamp),
				 "%Y-%m-%dT%H:%M:%SZ", &tm);
			gethostname(hostname, sizeof(hostname) - 1);
			m = snprintf(msg, sizeof(msg),
				     "<85>1 %s %s secure_sudo - - - %.*s",
				     timestamp, hostname, (int)len, line);
			framed = snprintf(frame, sizeof(frame), "%d ", m);
			if (m > 0 && framed > 0 &&
			    (size_t)framed + (size_t)m < sizeof(frame)) {
				memcpy(frame + framed, msg, (size_t)m);
				if (SSL_write(ssl, frame, framed + m) == framed + m) {
					snprintf(remote_state, sizeof(remote_state),
						 "tls_sent_unconfirmed");
					remote_sent++;
					sent = 1;
				} else {
					snprintf(remote_state, sizeof(remote_state),
						 "tls_error");
					remote_failures++;
				}
			} else {
				snprintf(remote_state, sizeof(remote_state),
					 "message_error");
				remote_failures++;
			}
		}
		if (ssl)
			SSL_free(ssl);
		if (ctx)
			SSL_CTX_free(ctx);
		close(fd);
		freeaddrinfo(res);
		return sent;
	}
	freeaddrinfo(res);
	return 0;
}

static int remote_queue_dir(void)
{
	struct stat st;

	if (mkdir(REMOTE_QUEUE, 0700) != 0 && errno != EEXIST)
		return -1;
	if (lstat(REMOTE_QUEUE, &st) != 0 || !S_ISDIR(st.st_mode) ||
	    st.st_uid != 0 || (st.st_mode & 0777) != 0700) {
		errno = EPERM;
		return -1;
	}
	return 0;
}

static int remote_queue_stats(void)
{
	struct dirent **entries = NULL;
	int count, i;
	unsigned long long bytes = 0, records = 0;

	if (remote_queue_dir() != 0)
		return -1;
	count = scandir(REMOTE_QUEUE, &entries, NULL, alphasort);
	if (count < 0)
		return -1;
	for (i = 0; i < count; i++) {
		struct stat st;
		char path[512];

		if (strncmp(entries[i]->d_name, "event-", 6)) {
			free(entries[i]);
			continue;
		}
		snprintf(path, sizeof(path), "%s/%s", REMOTE_QUEUE,
			 entries[i]->d_name);
		if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
		    st.st_uid != 0 || (st.st_mode & 0777) != 0600) {
			free(entries[i]);
			while (++i < count)
				free(entries[i]);
			free(entries);
			errno = EPERM;
			return -1;
		}
		bytes += (unsigned long long)st.st_size;
		records++;
		free(entries[i]);
	}
	free(entries);
	remote_queue_bytes = bytes;
	remote_queue_records = records;
	return 0;
}

static int write_all(int fd, const char *buf, size_t len)
{
	size_t written = 0;

	while (written < len) {
		ssize_t n = write(fd, buf + written, len - written);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		written += (size_t)n;
	}
	return 0;
}

static int remote_queue_event(const struct cfg *c, const char *line, size_t len)
{
	struct timespec ts;
	char path[512], buf[1024];
	int fd, n, dirfd;
	unsigned long long limit;

	if (len > sizeof(buf) - 2 || remote_queue_stats() != 0)
		return -1;
	limit = (unsigned long long)c->remote_queue_max_mb * 1024 * 1024;
	if (remote_queue_bytes + len + 1 > limit ||
	    remote_queue_records >= REMOTE_QUEUE_MAX_RECORDS) {
		snprintf(remote_state, sizeof(remote_state), "queue_full");
		remote_queue_dropped++;
		errno = ENOSPC;
		return -1;
	}
	clock_gettime(CLOCK_REALTIME, &ts);
	n = snprintf(path, sizeof(path), "%s/event-%020llu-%08llu.msg",
		     REMOTE_QUEUE, (unsigned long long)ts.tv_sec * 1000000000ULL +
		     ts.tv_nsec, ++remote_queue_sequence);
	if (n < 0 || (size_t)n >= sizeof(path))
		return -1;
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
		  0600);
	if (fd < 0)
		return -1;
	memcpy(buf, line, len);
	if (!len || line[len - 1] != '\n')
		buf[len++] = '\n';
	if (write_all(fd, buf, len) != 0 || fsync(fd) != 0) {
		int saved = errno ? errno : EIO;

		close(fd);
		unlink(path);
		errno = saved;
		return -1;
	}
	if (close(fd) != 0) {
		unlink(path);
		return -1;
	}
	dirfd = open(REMOTE_QUEUE, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0)
		return -1;
	if (fsync(dirfd) != 0) {
		int saved = errno;

		close(dirfd);
		errno = saved;
		return -1;
	}
	close(dirfd);
	return remote_queue_stats();
}

static void flush_remote_queue(const struct cfg *c)
{
	struct dirent **entries = NULL;
	int count, i;

	if (remote_queue_stats() != 0) {
		snprintf(remote_state, sizeof(remote_state), "queue_error");
		remote_failures++;
		return;
	}
	count = scandir(REMOTE_QUEUE, &entries, NULL, alphasort);
	if (count < 0) {
		snprintf(remote_state, sizeof(remote_state), "queue_error");
		remote_failures++;
		return;
	}
	if (!remote_queue_records) {
		snprintf(remote_state, sizeof(remote_state), "tls_idle");
		for (i = 0; i < count; i++)
			free(entries[i]);
		free(entries);
		return;
	}
	for (i = 0; i < count; i++) {
		char path[512], event[1024];
		ssize_t n;
		int fd;

		if (strncmp(entries[i]->d_name, "event-", 6)) {
			free(entries[i]);
			continue;
		}
		snprintf(path, sizeof(path), "%s/%s", REMOTE_QUEUE,
			 entries[i]->d_name);
		fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (fd < 0) {
			snprintf(remote_state, sizeof(remote_state), "queue_error");
			remote_failures++;
			free(entries[i]);
			for (++i; i < count; i++)
				free(entries[i]);
			free(entries);
			return;
		}
		n = read(fd, event, sizeof(event) - 1);
		close(fd);
		if (n <= 0 || (n == sizeof(event) - 1 && event[n - 1] != '\n')) {
			snprintf(remote_state, sizeof(remote_state), "queue_error");
			remote_failures++;
			free(entries[i]);
			for (++i; i < count; i++)
				free(entries[i]);
			free(entries);
			return;
		}
		if (!send_remote(c, event, (size_t)n) || unlink(path) != 0) {
			free(entries[i]);
			for (++i; i < count; i++)
				free(entries[i]);
			free(entries);
			remote_queue_stats();
			if (remote_queue_records)
				snprintf(remote_state, sizeof(remote_state), "tls_queued");
			return;
		}
		free(entries[i]);
	}
	free(entries);
	if (remote_queue_stats() == 0 && !remote_queue_records)
		snprintf(remote_state, sizeof(remote_state), "tls_idle");
}

static void forward_remote(const struct cfg *c, const char *line, size_t len)
{
	if (!c->remote_syslog[0]) {
		snprintf(remote_state, sizeof(remote_state), "disabled");
		return;
	}
	if (!strcmp(c->remote_transport, "tls")) {
		if (remote_queue_event(c, line, len) != 0) {
			if (strcmp(remote_state, "queue_full"))
				snprintf(remote_state, sizeof(remote_state), "queue_error");
			remote_failures++;
			return;
		}
		flush_remote_queue(c);
		return;
	}
	send_remote(c, line, len);
}

static void write_log(const struct cfg *c, const char *line, size_t len)
{
	char path[512];
	FILE *f;
	int failed = 0, saved = 0;

	todays_logpath(path, sizeof(path));
	f = fopen(path, "ae");
	if (f) {
		if (fwrite(line, 1, len, f) != len ||
		    ((len == 0 || line[len - 1] != '\n') && fputc('\n', f) == EOF) ||
		    ferror(f))
			failed = 1;
		if (fclose(f) != 0)
			failed = 1;
	} else {
		failed = 1;
	}
	if (failed) {
		saved = errno ? errno : EIO;
		local_log_failures++;
		fprintf(stderr, "secure-sudod: cannot write local event log %s: %s\n",
			path, strerror(saved));
	}
	forward_remote(c, line, len);
}

/* Delete logs older than retain_days and trim oldest until under max_total_mb. */
static void enforce_retention(const struct cfg *c)
{
	DIR *d;
	struct dirent *de;
	time_t now = time(NULL);
	long total = 0;
	struct stat hold;
	/* simple two-pass: first delete by age, then by total size */

	if (lstat(RETENTION_HOLD, &hold) == 0) {
		if (!S_ISREG(hold.st_mode) || hold.st_uid != 0 ||
		    (hold.st_mode & 07777) != 0600) {
			if (strcmp(retention_state, "hold_error"))
				fprintf(stderr, "secure-sudod: invalid retention hold "
					"marker; preserving logs\n");
			snprintf(retention_state, sizeof(retention_state),
				 "hold_error");
			return;
		}
		snprintf(retention_state, sizeof(retention_state), "held");
		return;
	}
	if (errno != ENOENT) {
		if (strcmp(retention_state, "hold_error"))
			fprintf(stderr, "secure-sudod: cannot inspect retention hold "
				"marker: %s; preserving logs\n", strerror(errno));
		snprintf(retention_state, sizeof(retention_state), "hold_error");
		return;
	}
	snprintf(retention_state, sizeof(retention_state), "active");

	d = opendir(LOGDIR);
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

static int write_health_heartbeat(void)
{
	char path[256];
	int fd, n;
	char buf[512];

	snprintf(path, sizeof(path), "%s", HEALTH_FILE);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
		  0600);
	if (fd < 0)
		return -1;
	n = snprintf(buf, sizeof(buf),
		     "pid=%ld updated=%lld remote_transport=%s "
		     "retention_state=%s "
		     "remote_state=%s remote_sent=%llu remote_failures=%llu "
		     "remote_queue_records=%llu remote_queue_bytes=%llu "
		     "remote_queue_dropped=%llu local_log_failures=%llu\n",
		     (long)getpid(), (long long)time(NULL),
		     g_cfg ? g_cfg->remote_transport : "unknown",
		     retention_state, remote_state,
		     remote_sent, remote_failures, remote_queue_records,
		     remote_queue_bytes, remote_queue_dropped,
		     local_log_failures);
	if (write(fd, buf, (size_t)n) != n) {
		int saved = errno ? errno : EIO;
		close(fd);
		errno = saved;
		return -1;
	}
	if (fsync(fd) != 0) {
		int saved = errno;
		close(fd);
		errno = saved;
		return -1;
	}
	return close(fd);
}

/* ---- #8 cooldown: freeze + kill the offending sudo/su processes ---- */

static int proc_ruid(const char *pid, uid_t *ruid)
{
	char path[320], line[256];
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
	char path[320], comm[64] = "";
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

/*
 * ---- reading kernel events ----
 *
 * Each ring line is one schema-v1 JSON object written by ss_log.c. The
 * daemon acts on two of them as root: it kills a UID's sudo/su processes
 * (cooldown) and quarantines or deletes a file (TimeVault). Earlier
 * versions found both by searching the whole decoded message for
 * "cooldown: UID " or "timevault: denied exec ". A message often carries
 * a path the user chose, so a file named, say,
 *   /home/u/x/timevault: denied exec /usr/bin/sudo (hash mismatch)
 * showing up in any other denial was enough to make the daemon quarantine
 * /usr/bin/sudo. Now the action is chosen only from the typed fields,
 * whose values are kernel constants. The cooldown UID comes from
 * target_uid. The TimeVault path is taken from a message that must match
 * the kernel's format from its first byte to its last, and never from a
 * truncated record.
 */
struct ss_ev {
	long long schema;		/* schema_version, -1 if absent */
	char event_type[64];
	char operation[32];
	char decision[24];
	char reason[64];
	char message[1024];		/* JSON-decoded */
	long long target_uid;		/* -1 if null or absent */
	int truncated;			/* 1 / 0, -1 if absent */
};

static const char *json_ws(const char *p)
{
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
		p++;
	return p;
}

static int hexval(char c)
{
	return c >= '0' && c <= '9' ? c - '0' :
	       c >= 'a' && c <= 'f' ? c - 'a' + 10 :
	       c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/*
 * Parse the JSON string at @p (which points at its opening quote). With
 * @out, store the decoded bytes: ss_log.c writes bytes >= 0x80 as \u00XX,
 * so those become the original byte again. Returns the position after the
 * closing quote, or NULL if the string is malformed or does not fit.
 */
static const char *json_string(const char *p, char *out, size_t size)
{
	size_t n = 0;

	if (*p++ != '"')
		return NULL;
	while (*p != '"') {
		char c = *p++;

		if (!c || (unsigned char)c < 0x20)
			return NULL;
		if (c == '\\') {
			c = *p++;
			switch (c) {
			case '"': case '\\': case '/': break;
			case 'b': c = '\b'; break;
			case 'f': c = '\f'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			case 't': c = '\t'; break;
			case 'u': {
				int h[4], i;

				for (i = 0; i < 4; i++)
					if ((h[i] = hexval(p[i])) < 0)
						return NULL;
				p += 4;
				/* only the kernel's byte escapes are meaningful */
				c = h[0] || h[1] ? '?' : (char)(h[2] << 4 | h[3]);
				if (!c)
					return NULL;	/* no NUL inside a value */
				break;
			}
			default:
				return NULL;
			}
		}
		if (out) {
			if (n + 1 >= size)
				return NULL;
			out[n++] = c;
		}
	}
	if (out)
		out[n] = '\0';
	return p + 1;
}

/* Skip any JSON value (nested objects and arrays included). */
static const char *json_skip(const char *p, int depth)
{
	p = json_ws(p);
	if (depth > 8)
		return NULL;
	if (*p == '"')
		return json_string(p, NULL, 0);
	if (*p == '{' || *p == '[') {
		char close = *p == '{' ? '}' : ']';

		p = json_ws(p + 1);
		if (*p == close)
			return p + 1;
		for (;;) {
			if (close == '}') {
				p = json_string(json_ws(p), NULL, 0);
				if (!p)
					return NULL;
				p = json_ws(p);
				if (*p++ != ':')
					return NULL;
			}
			p = json_skip(p, depth + 1);
			if (!p)
				return NULL;
			p = json_ws(p);
			if (*p == close)
				return p + 1;
			if (*p++ != ',')
				return NULL;
		}
	}
	if (!strncmp(p, "true", 4) || !strncmp(p, "null", 4))
		return p + 4;
	if (!strncmp(p, "false", 5))
		return p + 5;
	if (*p == '-' || (*p >= '0' && *p <= '9')) {
		p++;
		while ((*p >= '0' && *p <= '9') || *p == '.' || *p == 'e' ||
		       *p == 'E' || *p == '+' || *p == '-')
			p++;
		return p;
	}
	return NULL;
}

static const char *json_int(const char *p, long long *out)
{
	char *end;

	p = json_ws(p);
	if (!strncmp(p, "null", 4)) {
		*out = -1;
		return p + 4;
	}
	if (*p < '0' || *p > '9')
		return NULL;
	errno = 0;
	*out = strtoll(p, &end, 10);
	if (errno || *end == '.' || *end == 'e' || *end == 'E')
		return NULL;
	return end;
}

/* Parse one kernel record. Returns 0 if it is a well-formed JSON object. */
static int ev_parse(const char *rec, struct ss_ev *e)
{
	const char *p = json_ws(rec);

	memset(e, 0, sizeof(*e));
	e->schema = -1;
	e->target_uid = -1;
	e->truncated = -1;
	if (*p++ != '{')
		return -1;
	p = json_ws(p);
	if (*p == '}')
		return *json_ws(p + 1) ? -1 : 0;
	for (;;) {
		char key[32];
		char *dst = NULL;
		size_t dsz = 0;

		p = json_string(json_ws(p), key, sizeof(key));
		if (!p)
			return -1;
		p = json_ws(p);
		if (*p++ != ':')
			return -1;
		p = json_ws(p);
		if (!strcmp(key, "event_type"))
			dst = e->event_type, dsz = sizeof(e->event_type);
		else if (!strcmp(key, "operation"))
			dst = e->operation, dsz = sizeof(e->operation);
		else if (!strcmp(key, "decision"))
			dst = e->decision, dsz = sizeof(e->decision);
		else if (!strcmp(key, "reason"))
			dst = e->reason, dsz = sizeof(e->reason);
		else if (!strcmp(key, "message"))
			dst = e->message, dsz = sizeof(e->message);
		if (dst && *p == '"')
			p = json_string(p, dst, dsz);
		else if (!strcmp(key, "schema_version"))
			p = json_int(p, &e->schema);
		else if (!strcmp(key, "target_uid"))
			p = json_int(p, &e->target_uid);
		else if (!strcmp(key, "truncated") && !strncmp(p, "true", 4))
			e->truncated = 1, p += 4;
		else if (!strcmp(key, "truncated") && !strncmp(p, "false", 5))
			e->truncated = 0, p += 5;
		else
			p = json_skip(p, 0);
		if (!p)
			return -1;
		p = json_ws(p);
		if (*p == '}')
			return *json_ws(p + 1) ? -1 : 0;
		if (*p++ != ',')
			return -1;
	}
}

/* The kernel's brute-force block (ss_cooldown.c): 1 and the UID, else 0. */
static int ev_cooldown_uid(const struct ss_ev *e, uid_t *uid)
{
	unsigned int u;
	int end = 0;

	if (e->schema != 1 || strcmp(e->event_type, "sudo_cooldown") ||
	    strcmp(e->operation, "authenticate") ||
	    strcmp(e->decision, "deny") || strcmp(e->reason, "failure_threshold"))
		return 0;
	if (e->target_uid >= 0 && e->target_uid <= 0xfffffffeLL) {
		*uid = (uid_t)e->target_uid;
		return 1;
	}
	/* Kernels before target_uid: the message is the kernel's own text, so
	 * it can be matched from its first byte (never searched). */
	if (sscanf(e->message, "cooldown: UID %u blocked from sudo %n", &u,
		   &end) == 1 && end > 0) {
		*uid = (uid_t)u;
		return 1;
	}
	return 0;
}

/*
 * A TimeVault exec denial for a tampered or unlisted binary: 1 and its
 * path, else 0. ss_timevault.c writes "timevault: denied exec <path>
 * (<reason>)" with the same <reason> as the typed field, so the path is
 * exactly what lies between that prefix and that suffix.
 */
static int ev_vault_path(const struct ss_ev *e, char *path, size_t size)
{
	static const char pre[] = "timevault: denied exec ";
	char suffix[sizeof(e->reason) + 4];
	size_t len, slen;

	if (e->schema != 1 || e->truncated != 0 ||
	    strcmp(e->event_type, "time_vault") ||
	    strcmp(e->operation, "execute") || strcmp(e->decision, "deny") ||
	    (strcmp(e->reason, "hash mismatch") &&
	     strcmp(e->reason, "not on allowlist")))
		return 0;
	if (strncmp(e->message, pre, sizeof(pre) - 1))
		return 0;
	snprintf(suffix, sizeof(suffix), " (%s)", e->reason);
	len = strlen(e->message);
	slen = strlen(suffix);
	if (len < sizeof(pre) - 1 + slen ||
	    strcmp(e->message + len - slen, suffix))
		return 0;
	len -= sizeof(pre) - 1 + slen;
	if (!len || len >= size || e->message[sizeof(pre) - 1] != '/')
		return 0;
	memcpy(path, e->message + sizeof(pre) - 1, len);
	path[len] = '\0';
	return 1;
}

/* ---- #13 acting on a file without trusting its path ---- */

static int run_helper_argv(const char *const argv[]);	/* defined below */

/*
 * Open the directory @path[0..len) names, one component at a time with
 * O_NOFOLLOW, so no symlink anywhere on the way is followed. len 0 is "/".
 */
static int open_dir_nofollow(const char *path, size_t len)
{
	size_t i = 0;
	int fd;

	if (path[0] != '/')
		return -1;
	fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
	while (fd >= 0 && i < len) {
		char comp[256];
		size_t j;
		int next;

		while (i < len && path[i] == '/')
			i++;
		if (i >= len)
			break;
		for (j = i; j < len && path[j] != '/'; j++)
			;
		if (j - i >= sizeof(comp) ||
		    (j - i == 1 && path[i] == '.') ||
		    (j - i == 2 && path[i] == '.' && path[i + 1] == '.')) {
			close(fd);
			errno = EINVAL;
			return -1;
		}
		memcpy(comp, path + i, j - i);
		comp[j - i] = '\0';
		next = openat(fd, comp, O_PATH | O_DIRECTORY | O_NOFOLLOW |
			      O_CLOEXEC);
		close(fd);
		fd = next;
		i = j;
	}
	return fd;
}

/*
 * Copy the open file @fd into a fresh root-only staging directory under
 * QUARANTINE, keeping its name, owner, permission bits and times, and hand
 * that copy to the quarantine helper (which archives it, records @origin
 * as where it came from, and deletes the copy). Returns 0 once archived.
 */
static int vault_archive_copy(const char *origin, const char *base, int fd,
			      const struct stat *st)
{
	char dir[512], staged[1024];
	struct timespec times[2] = { st->st_atim, st->st_mtim };
	struct stat ds;
	char buf[65536];
	ssize_t n;
	int out, rc = -1;

	if ((size_t)snprintf(dir, sizeof(dir), "%s/.incoming", QUARANTINE) >=
	    sizeof(dir))
		return -1;
	if (mkdir(dir, 0700) != 0 && errno != EEXIST)
		return -1;
	if (lstat(dir, &ds) != 0 || !S_ISDIR(ds.st_mode) ||
	    ds.st_uid != geteuid() || (ds.st_mode & 077))
		return -1;
	if ((size_t)snprintf(dir, sizeof(dir), "%s/.incoming/XXXXXX",
			     QUARANTINE) >= sizeof(dir) || !mkdtemp(dir))
		return -1;
	if ((size_t)snprintf(staged, sizeof(staged), "%s/%s", dir, base) >=
	    sizeof(staged))
		goto out_dir;
	out = open(staged, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
		   0600);
	if (out < 0)
		goto out_dir;
	if (lseek(fd, 0, SEEK_SET) != 0)
		goto out_file;
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		if (write_all(out, buf, (size_t)n) != 0)
			goto out_file;
	if (n < 0 || fsync(out) != 0)
		goto out_file;
	/* Best effort: the archive's metadata shows the original's. */
	if (fchown(out, st->st_uid, st->st_gid) != 0 && geteuid() == 0)
		goto out_file;
	if (fchmod(out, st->st_mode & 0777) != 0 || futimens(out, times) != 0)
		goto out_file;
	rc = 0;
out_file:
	if (close(out) != 0)
		rc = -1;
	if (rc == 0) {
		const char *argv[] = { HELPER_QUAR, "--origin", origin, staged,
				       NULL };
		struct stat left;

		rc = run_helper_argv(argv);
		if (rc != 0)
			syslog_line("helper %s for %s failed (status %d)",
				    HELPER_QUAR, origin, rc);
		/* The helper deletes the copy only after checking the archive. */
		else if (lstat(staged, &left) == 0 || errno != ENOENT)
			rc = -1;
	}
	unlink(staged);
out_dir:
	rmdir(dir);
	return rc ? -1 : 0;
}

/*
 * Quarantine (vault_action=quarantine) or delete (wipe) the regular file
 * at @path. @path is text from a kernel event or a directory walk: it
 * named the file then, but the owner of any directory on the way may since
 * have swapped that directory for a symlink so the same text names, say,
 * /etc/shadow. So the path is resolved without following any symlink, the
 * file is archived from the descriptor that was checked, and the name is
 * removed through its pinned parent directory only while it still refers
 * to that same inode. Returns 0 once the file is dealt with.
 */
static int vault_act(const struct cfg *c, const char *path)
{
	const char *slash = strrchr(path, '/');
	const char *base = slash ? slash + 1 : "";
	struct stat st, now;
	int dfd, fd = -1, rc = -1;

	if (path[0] != '/' || !*base || !strcmp(base, ".") ||
	    !strcmp(base, ".."))
		return -1;
	dfd = open_dir_nofollow(path, (size_t)(slash - path));
	if (dfd < 0) {
		syslog_line("timevault: %s not acted on: a directory on its path is missing or is a symlink",
			    path);
		return -1;
	}
	fd = openat(dfd, base, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
		goto out;		/* gone, a symlink, or not a regular file */
	syslog_line("timevault: quarantining tampered/unlisted binary %s (action=%s)",
		    path, c->vault_action);
	if (strcmp(c->vault_action, "wipe") &&
	    vault_archive_copy(path, base, fd, &st) != 0) {
		syslog_line("timevault: quarantine of %s failed; file left in place",
			    path);
		goto out;
	}
	if (fstatat(dfd, base, &now, AT_SYMLINK_NOFOLLOW) != 0 ||
	    now.st_dev != st.st_dev || now.st_ino != st.st_ino) {
		syslog_line("timevault: %s was replaced while being quarantined; left in place",
			    path);
		goto out;
	}
	if (unlinkat(dfd, base, 0) != 0) {
		syslog_line("timevault: cannot remove %s: %s", path,
			    strerror(errno));
		goto out;
	}
	rc = 0;
out:
	if (fd >= 0)
		close(fd);
	close(dfd);
	return rc;
}

/* Act on one complete ring line, after it has been logged. */
static void handle_event(const struct cfg *c, const char *line)
{
	struct ss_ev e;
	char path[1024];
	uid_t uid;

	if (ev_parse(line, &e) != 0)
		return;			/* not a kernel record: never acted on */
	if (ev_cooldown_uid(&e, &uid))
		kill_offenders(uid);
	if (ev_vault_path(&e, path, sizeof(path)))
		vault_act(c, path);
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

/* Run a helper (argv[0]) and wait for it. Returns its exit status (128 +
 * signal if it was killed, -1 if it could not be started). */
static int run_helper_argv(const char *const argv[])
{
	pid_t pid = fork();
	int st, rc = -1;

	if (pid == 0) {
		execv(argv[0], (char *const *)argv);
		_exit(127);
	}
	if (pid > 0 && waitpid(pid, &st, 0) == pid) {
		if (WIFEXITED(st))
			rc = WEXITSTATUS(st);
		else if (WIFSIGNALED(st))
			rc = 128 + WTERMSIG(st);
	}
	return rc;
}

static int run_helper_quiet(const char *helper, const char *arg)
{
	const char *argv[] = { helper, arg, NULL };

	return run_helper_argv(argv);
}


/* ---- #21 PheonixBox periodic scan+repair ----
 * Run `secure-sudo-pheonixbox scan --quiet` on a timer. The helper is a no-op
 * when PheonixBox is disabled (it checks its own `enabled` marker), so this is
 * cheap to call unconditionally; it restores any tampered protected file from
 * the compressed snapshot store. */
static void pheonixbox_scan(void)
{
	pid_t pid = fork();

	if (pid == 0) {
		execl(HELPER_PBOX, HELPER_PBOX, "scan", "--quiet", (char *)NULL);
		_exit(127);
	} else if (pid > 0) {
		int st;

		waitpid(pid, &st, 0);
	}
}

/*
 * Apply the kernel's net_mode with the nft helper. A mode counts as applied
 * only once the helper succeeded; until then it is retried on every periodic
 * pass (e.g. public-only at boot, before the network has a default route),
 * and the failure is logged once rather than every 5 seconds. The helper
 * leaves the previous rules in place when it fails.
 */
static void apply_net_mode(void)
{
	static char applied[32] = "", failing[32] = "";
	char mode[32];

	if (read_sysfs_str("net_mode", mode, sizeof(mode)) != 0)
		return;
	if (!strcmp(mode, applied))
		return;
	if (strcmp(mode, failing))
		syslog_line("net: applying mode %s", mode);
	if (run_helper_quiet(HELPER_NET, mode) == 0) {
		snprintf(applied, sizeof(applied), "%s", mode);
		if (!strcmp(mode, failing))
			syslog_line("net: mode %s applied after retrying", mode);
		failing[0] = '\0';
	} else if (strcmp(mode, failing)) {
		syslog_line("net: mode %s NOT applied yet (helper failed); retrying every 5s",
			    mode);
		snprintf(failing, sizeof(failing), "%s", mode);
	}
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
		if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir,
				     de->d_name) >= sizeof(path))
			continue;	/* never act on a cut-off path */
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
		if (vault_act(c, path) != 0) {
			/* Not recorded: a file that could not be quarantined
			 * must not become "known" and stop being flagged. */
			syslog_line("timevault: %s left in place, will retry", path);
			continue;
		}
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

/*
 * A read of the ring returns whatever bytes are queued, so one record can
 * end in the next read. Keep the unfinished tail and handle only complete
 * lines: logging the two halves as separate lines would corrupt the record
 * and lose the action it calls for.
 */
static char ev_buf[8192];
static size_t ev_have;

static void drain_events(const struct cfg *c, int fd)
{
	ssize_t n = read(fd, ev_buf + ev_have, sizeof(ev_buf) - 1 - ev_have);
	char *line, *nl;

	if (n <= 0)
		return;
	ev_have += (size_t)n;
	ev_buf[ev_have] = '\0';
	line = ev_buf;
	while ((nl = memchr(line, '\n', ev_have - (size_t)(line - ev_buf)))) {
		*nl = '\0';
		if (nl > line) {
			write_log(c, line, (size_t)(nl - line));
			handle_event(c, line);
		}
		line = nl + 1;
	}
	ev_have -= (size_t)(line - ev_buf);
	memmove(ev_buf, line, ev_have);
	if (ev_have >= sizeof(ev_buf) / 2) {
		/* No kernel record is this long: resynchronise. */
		local_log_failures++;
		syslog_line("secure-sudod: discarded %zu bytes of unterminated event data",
			    ev_have);
		ev_have = 0;
	}
}

int main(void)
{
	struct cfg cfg;
	struct pollfd pfd;
	time_t last_periodic = 0;
	time_t last_pbox = 0;
	time_t last_health = 0;

	signal(SIGHUP, on_hup);
	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);
	signal(SIGCHLD, SIG_DFL);

	umask(077);		/* logs and quarantined files must not be world-readable */
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

		if (now - last_health >= 5) {
			last_health = now;
			if (cfg.remote_syslog[0] &&
			    !strcmp(cfg.remote_transport, "tls")) {
				flush_remote_queue(&cfg);
			}
			if (write_health_heartbeat() != 0)
				fprintf(stderr, "secure-sudod: cannot update health heartbeat: %s\n",
					strerror(errno));
		}

		if (rc > 0 && (pfd.revents & POLLIN))
			drain_events(&cfg, pfd.fd);

		/* Periodic work roughly every 5s. */
		if (now - last_periodic >= 5) {
			last_periodic = now;
			apply_net_mode();
			enforce_retention(&cfg);
			vault_scan(&cfg);
		}

		/* PheonixBox scan+repair on a slower (30s) cadence: content
		 * hashing is heavier than the TimeVault directory walk. */
		if (now - last_pbox >= 30) {
			last_pbox = now;
			pheonixbox_scan();
		}
	}

	syslog_line("secure-sudod stopping");
	close(pfd.fd);
	return 0;
}
