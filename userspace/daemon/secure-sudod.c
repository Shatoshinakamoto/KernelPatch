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
#include <sys/resource.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define EVENTS   "/sys/kernel/security/secure_sudo/events"
#ifndef SYSFS
#define SYSFS    "/sys/kernel/secure_sudo"
#endif
#define CONFIG   "/etc/secure_sudo/secure-sudo.conf"
#ifndef LOGDIR
#define LOGDIR   "/var/log/secure_sudo"
#endif
#define STATEDIR "/var/lib/secure_sudo"
#ifndef HEALTH_FILE
#define HEALTH_FILE STATEDIR "/daemon.health"
#endif
#define RETENTION_HOLD STATEDIR "/retention.hold"
#ifndef MANIFEST
#define MANIFEST STATEDIR "/manifest"
#endif
#ifndef EVENT_CURSOR
#define EVENT_CURSOR STATEDIR "/event-cursor"
#endif
#ifndef QUARANTINE
#define QUARANTINE STATEDIR "/quarantine"
#endif
#ifndef HELPER_NET
#define HELPER_NET  "/usr/libexec/secure-sudo/apply-net.sh"
#endif
#ifndef HELPER_QUAR
#define HELPER_QUAR "/usr/libexec/secure-sudo/quarantine.sh"
#endif
#define HELPER_PBOX "/usr/bin/secure-sudo-pheonixbox"	/* #21 PheonixBox */
#ifndef SECURE_SUDO_CLI
#define SECURE_SUDO_CLI "/usr/bin/secure-sudo"	/* node-scan (#11) */
#endif
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
	long node_scan_minutes;		/* 0 = off (#11 node-scan) */
};

static struct cfg *g_cfg;
static char net_state[16] = "unknown";	/* P1-8 heartbeat: off|applied|pending|failing */
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
static int remote_queue_known;		/* the two counters above are current */
static unsigned long long event_gaps;	/* gap records written since start */
static unsigned long long events_missing; /* records those gaps cover */
static time_t remote_next_flush;	/* main loop: next queue flush */
static unsigned int remote_backoff;	/* seconds; 0 = collector healthy */

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
	c->node_scan_minutes = 60;

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
		else if (!strcmp(key, "node_sea_scan_interval")) {
			char *end;
			long m = strtol(val, &end, 10);

			if (*val && !*end && m >= 0 && m <= 10080)
				c->node_scan_minutes = m;
			else
				fprintf(stderr, "secure-sudod: invalid node_sea_scan_interval\n");
		}
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

/*
 * One connection to the collector. TLS events are only queued by
 * forward_remote(); the main loop drains the queue over one connection per
 * batch, and backs off after a failure. Earlier, every event did its own
 * DNS lookup, TCP connect and TLS handshake inline, and also retried the
 * whole queue. While a collector dropped packets, each event therefore
 * held up the daemon (cooldown kills and TimeVault quarantines included)
 * for 3 s or more per address.
 */
struct remote_conn {
	int fd;
	int tls;
	SSL_CTX *ctx;
	SSL *ssl;
};

static void remote_close(struct remote_conn *rc)
{
	if (rc->ssl) {
		char drain[512];

		/*
		 * Close properly: send close_notify, then read what the
		 * collector sent us (TLS 1.3 session tickets, its own
		 * close_notify) until it closes or the 3 s receive timeout.
		 * Closing a socket with unread received data makes the kernel
		 * send a reset, and a reset can make the collector discard
		 * our last events before it has read them.
		 */
		if (SSL_shutdown(rc->ssl) == 0)
			while (SSL_read(rc->ssl, drain, sizeof(drain)) > 0)
				;
		SSL_free(rc->ssl);
	}
	if (rc->ctx)
		SSL_CTX_free(rc->ctx);
	if (rc->fd >= 0)
		close(rc->fd);
	rc->ssl = NULL;
	rc->ctx = NULL;
	rc->fd = -1;
}

/* Connect (and for TLS, handshake and verify). 1 on success. */
static int remote_open(const struct cfg *c, struct remote_conn *rc)
{
	char target[256], host[256], *port;
	struct addrinfo hints = { 0 }, *res = NULL, *ai;
	int fd = -1;

	rc->fd = -1;
	rc->ctx = NULL;
	rc->ssl = NULL;
	rc->tls = !strcmp(c->remote_transport, "tls");
	if (!c->remote_syslog[0]) {
		snprintf(remote_state, sizeof(remote_state), "disabled");
		return 0;
	}
	if (!rc->tls && strcmp(c->remote_transport, "udp")) {
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
	hints.ai_socktype = rc->tls ? SOCK_STREAM : SOCK_DGRAM;
	if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
		snprintf(remote_state, sizeof(remote_state), "dns_error");
		remote_failures++;
		return 0;
	}
	for (ai = res; ai; ai = ai->ai_next) {
		int flags, connected = 0;

		fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
			    ai->ai_protocol);
		if (fd < 0)
			continue;
		if (rc->tls) {
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
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		snprintf(remote_state, sizeof(remote_state), "connect_error");
		remote_failures++;
		return 0;
	}
	rc->fd = fd;
	if (rc->tls) {
		struct timeval timeout = { .tv_sec = 3, .tv_usec = 0 };
		unsigned char addr[sizeof(struct in6_addr)];
		int is_ip = inet_pton(AF_INET, host, addr) == 1 ||
			    inet_pton(AF_INET6, host, addr) == 1;
		int verified = 0;

		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		rc->ctx = SSL_CTX_new(TLS_client_method());
		if (rc->ctx &&
		    SSL_CTX_set_min_proto_version(rc->ctx, TLS1_2_VERSION) == 1 &&
		    SSL_CTX_load_verify_locations(rc->ctx, c->remote_ca_file,
						  NULL) == 1) {
			SSL_CTX_set_verify(rc->ctx, SSL_VERIFY_PEER, NULL);
			rc->ssl = SSL_new(rc->ctx);
		}
		if (rc->ssl) {
			X509_VERIFY_PARAM *param = SSL_get0_param(rc->ssl);

			if (is_ip)
				verified = X509_VERIFY_PARAM_set1_ip_asc(param, host) == 1;
			else
				verified = SSL_set1_host(rc->ssl, host) == 1 &&
					   SSL_set_tlsext_host_name(rc->ssl, host) == 1;
			if (SSL_set_fd(rc->ssl, fd) != 1)
				verified = 0;
		}
		if (!verified || SSL_connect(rc->ssl) != 1 ||
		    SSL_get_verify_result(rc->ssl) != X509_V_OK) {
			snprintf(remote_state, sizeof(remote_state), "tls_error");
			remote_failures++;
			remote_close(rc);
			return 0;
		}
	}
	return 1;
}

/* Send one event over @rc. 1 on success. */
static int remote_write(struct remote_conn *rc, const char *line, size_t len)
{
	char msg[1200], frame[1232], hostname[256] = "localhost";
	char timestamp[40];
	struct tm tm;
	time_t now = time(NULL);
	int m, framed;

	while (len && line[len - 1] == '\n')
		len--;
	if (!rc->tls) {
		m = snprintf(msg, sizeof(msg), "<85>secure_sudo: %.*s",
			     (int)len, line);
		if (m > 0 && (size_t)m < sizeof(msg) &&
		    send(rc->fd, msg, (size_t)m, 0) == m) {
			snprintf(remote_state, sizeof(remote_state), "udp_unconfirmed");
			remote_sent++;
			return 1;
		}
		snprintf(remote_state, sizeof(remote_state), "send_error");
		remote_failures++;
		return 0;
	}
	gmtime_r(&now, &tm);
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm);
	gethostname(hostname, sizeof(hostname) - 1);
	m = snprintf(msg, sizeof(msg), "<85>1 %s %s secure_sudo - - - %.*s",
		     timestamp, hostname, (int)len, line);
	framed = snprintf(frame, sizeof(frame), "%d ", m);
	if (m <= 0 || (size_t)m >= sizeof(msg) || framed <= 0 ||
	    (size_t)framed + (size_t)m >= sizeof(frame)) {
		snprintf(remote_state, sizeof(remote_state), "message_error");
		remote_failures++;
		return 0;
	}
	memcpy(frame + framed, msg, (size_t)m);
	if (SSL_write(rc->ssl, frame, framed + m) != framed + m) {
		snprintf(remote_state, sizeof(remote_state), "tls_error");
		remote_failures++;
		return 0;
	}
	snprintf(remote_state, sizeof(remote_state), "tls_sent_unconfirmed");
	remote_sent++;
	return 1;
}

/* One event on its own connection (UDP, and the tests). 1 on success. */
static int send_remote(const struct cfg *c, const char *line, size_t len)
{
	struct remote_conn rc;
	int sent;

	if (!remote_open(c, &rc))
		return 0;
	sent = remote_write(&rc, line, len);
	remote_close(&rc);
	return sent;
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
	remote_queue_known = 1;
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

	if (len > sizeof(buf) - 2)
		return -1;
	limit = (unsigned long long)c->remote_queue_max_mb * 1024 * 1024;
	/* The counters are kept up to date here and by the flush; rescan the
	 * directory only when they are unknown or say the queue is full, so
	 * a long backlog does not cost a directory scan per event. */
	if ((!remote_queue_known ||
	     remote_queue_bytes + len + 1 > limit ||
	     remote_queue_records >= REMOTE_QUEUE_MAX_RECORDS) &&
	    remote_queue_stats() != 0)
		return -1;
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
	remote_queue_records++;
	remote_queue_bytes += len;
	return 0;
}

#define REMOTE_FLUSH_BATCH 512		/* events per flush call */

/*
 * Send queued events oldest first over one connection, deleting each after
 * its write succeeds. Returns 0 when the queue is empty, 1 when the batch
 * limit left events for the next call, -1 when the collector or the queue
 * failed (the event that failed and all later ones stay queued).
 */
static int flush_remote_queue(const struct cfg *c)
{
	struct dirent **entries = NULL;
	struct remote_conn rc = { .fd = -1 };
	int count, i, sent = 0, ret = 0, open_ok = 0;

	if (remote_queue_stats() != 0) {
		snprintf(remote_state, sizeof(remote_state), "queue_error");
		remote_failures++;
		return -1;
	}
	if (!remote_queue_records) {
		snprintf(remote_state, sizeof(remote_state), "tls_idle");
		return 0;
	}
	count = scandir(REMOTE_QUEUE, &entries, NULL, alphasort);
	if (count < 0) {
		snprintf(remote_state, sizeof(remote_state), "queue_error");
		remote_failures++;
		return -1;
	}
	for (i = 0; i < count && ret == 0; i++) {
		char path[512], event[1024];
		ssize_t n;
		int fd;

		if (strncmp(entries[i]->d_name, "event-", 6))
			continue;
		if (sent == REMOTE_FLUSH_BATCH) {
			ret = 1;
			break;
		}
		snprintf(path, sizeof(path), "%s/%s", REMOTE_QUEUE,
			 entries[i]->d_name);
		fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		n = fd < 0 ? -1 : read(fd, event, sizeof(event) - 1);
		if (fd >= 0)
			close(fd);
		if (n <= 0 || (n == sizeof(event) - 1 && event[n - 1] != '\n')) {
			snprintf(remote_state, sizeof(remote_state), "queue_error");
			remote_failures++;
			ret = -1;
			break;
		}
		if (!open_ok && !(open_ok = remote_open(c, &rc))) {
			ret = -1;
			break;
		}
		if (!remote_write(&rc, event, (size_t)n)) {
			ret = -1;
			break;
		}
		if (unlink(path) != 0) {
			snprintf(remote_state, sizeof(remote_state), "queue_error");
			remote_failures++;
			ret = -1;
			break;
		}
		sent++;
	}
	for (i = 0; i < count; i++)
		free(entries[i]);
	free(entries);
	if (open_ok)
		remote_close(&rc);
	if (remote_queue_stats() != 0)
		return -1;
	/* as before: a send failure with events left reads "tls_queued" */
	if (ret < 0 && remote_queue_records &&
	    strcmp(remote_state, "queue_error"))
		snprintf(remote_state, sizeof(remote_state), "tls_queued");
	if (ret == 0 && !remote_queue_records)
		snprintf(remote_state, sizeof(remote_state), "tls_idle");
	return ret;
}

/*
 * Main loop: flush the TLS queue when it is due. After a failure, wait
 * 5 s, then twice as long after each further failure, up to 5 minutes, so
 * an unreachable collector costs one attempt per wait instead of one per
 * event.
 */
static void maybe_flush_remote(const struct cfg *c, time_t now)
{
	int rc;

	if (!c->remote_syslog[0] || strcmp(c->remote_transport, "tls") ||
	    now < remote_next_flush)
		return;
	rc = flush_remote_queue(c);
	if (rc < 0) {
		remote_backoff = remote_backoff ? remote_backoff * 2 : 5;
		if (remote_backoff > 300)
			remote_backoff = 300;
		remote_next_flush = now + remote_backoff;
	} else {
		remote_backoff = 0;
		remote_next_flush = rc > 0 ? now : now + 5;
	}
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
		/* sent by maybe_flush_remote(); promptly unless backing off */
		if (!remote_backoff)
			remote_next_flush = 0;
		return;
	}
	send_remote(c, line, len);
}

/*
 * ---- P1-3: hash chain over the local log, checkpointed off-host ----
 *
 * The daemon keeps the same per-file chain that `evidence-export` writes
 * and `evidence-verify` checks: c0 = sha256("secure_sudo-event-chain-v1\t"
 * NAME "\n"), then c = sha256(hex(c) "\t" LINE "\n") for every line. Every
 * CHECKPOINT_SECS it logs and forwards a log_checkpoint record with the
 * file name, line count and chain value. The copies at the collector are
 * the anchor that is not stored only on this host: rewriting or truncating
 * a log here afterwards no longer matches them (`evidence-verify
 * --checkpoints`). The records also tell the collector the daemon is alive.
 */
#ifndef CHECKPOINT_SECS
#define CHECKPOINT_SECS 300
#endif
static char chain_name[64];		/* log file the chain covers */
static char chain_hex[65];
static unsigned long long chain_lines;
static unsigned long long chain_bytes;	/* file size the chain accounts for */
static int chain_ok;			/* 0: re-read the file before use */

static void sha256_bytes_hex(const void *a, size_t alen, const void *b,
			     size_t blen, const void *c, size_t clen,
			     char out[65])
{
	unsigned char d[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0, i;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	out[0] = '\0';
	if (!ctx)
		return;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, a, alen) == 1 &&
	    EVP_DigestUpdate(ctx, b, blen) == 1 &&
	    EVP_DigestUpdate(ctx, c, clen) == 1 &&
	    EVP_DigestFinal_ex(ctx, d, &dlen) == 1)
		for (i = 0; i < dlen && i < 32; i++)
			snprintf(out + 2 * i, 3, "%02x", d[i]);
	EVP_MD_CTX_free(ctx);
}

static void chain_step(const char *line, size_t len)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned char d[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0, i;

	if (!ctx) {
		chain_ok = 0;
		return;
	}
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, chain_hex, 64) == 1 &&
	    EVP_DigestUpdate(ctx, "\t", 1) == 1 &&
	    EVP_DigestUpdate(ctx, line, len) == 1 &&
	    EVP_DigestUpdate(ctx, "\n", 1) == 1 &&
	    EVP_DigestFinal_ex(ctx, d, &dlen) == 1 && dlen == 32) {
		for (i = 0; i < dlen; i++)
			snprintf(chain_hex + 2 * i, 3, "%02x", d[i]);
		chain_lines++;
		chain_bytes += len + 1;
	} else {
		chain_ok = 0;
	}
	EVP_MD_CTX_free(ctx);
}

/* Start the chain for @name and replay what @path already holds. */
static void chain_sync(const char *path, const char *name)
{
	char head[128];
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	int len;

	snprintf(chain_name, sizeof(chain_name), "%s", name);
	len = snprintf(head, sizeof(head), "secure_sudo-event-chain-v1\t%s\n",
		       name);
	sha256_bytes_hex(head, (size_t)len, "", 0, "", 0, chain_hex);
	chain_lines = 0;
	chain_bytes = 0;
	chain_ok = chain_hex[0] != '\0';
	f = fopen(path, "re");
	if (!f) {
		if (errno != ENOENT)
			chain_ok = 0;
		return;
	}
	while (chain_ok && (n = getline(&line, &cap, f)) > 0) {
		int nl = line[n - 1] == '\n';

		chain_step(line, (size_t)(n - nl));
		if (!nl)
			chain_bytes--;	/* a last line without its newline */
	}
	if (ferror(f))
		chain_ok = 0;
	free(line);
	fclose(f);
}

static const char *log_basename(const char *path)
{
	const char *b = strrchr(path, '/');

	return b ? b + 1 : path;
}

static void daemon_record(const struct cfg *c, const char *type,
			  const char *fmt, ...);

static void write_local_log(const struct cfg *c, const char *line, size_t len)
{
	char path[512], clean[2048];
	unsigned long long was = 0, found = 0;
	struct stat st;
	FILE *f;
	int failed = 0, saved = 0, changed = 0;

	while (len && line[len - 1] == '\n')
		len--;
	/* One record, one physical line: an embedded newline (a crafted file
	 * name in a daemon message) must not start a forged record. */
	if (memchr(line, '\n', len) || memchr(line, '\r', len)) {
		size_t i;

		if (len > sizeof(clean))
			len = sizeof(clean);
		for (i = 0; i < len; i++)
			clean[i] = line[i] == '\n' || line[i] == '\r' ? '?' : line[i];
		line = clean;
	}
	todays_logpath(path, sizeof(path));
	if (!chain_ok || strcmp(chain_name, log_basename(path)))
		chain_sync(path, log_basename(path));
	f = fopen(path, "ae");
	if (f && chain_ok && fstat(fileno(f), &st) == 0 &&
	    (unsigned long long)st.st_size != chain_bytes) {
		/* Someone else wrote, truncated or replaced the log since we
		 * last did: note it, and chain what the file holds now. */
		was = chain_bytes;
		found = (unsigned long long)st.st_size;
		changed = 1;
		chain_sync(path, log_basename(path));
	}
	if (f) {
		if (fwrite(line, 1, len, f) != len || fputc('\n', f) == EOF ||
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
		chain_ok = 0;		/* re-read the file: it may hold a partial line */
		fprintf(stderr, "secure-sudod: cannot write local event log %s: %s\n",
			path, strerror(saved));
	} else if (chain_ok) {
		chain_step(line, len);
	}
	if (changed)
		daemon_record(c, "log_modified",
			      "\"log\":\"%s\",\"expected_bytes\":%llu,"
			      "\"found_bytes\":%llu", chain_name, was, found);
}

static void tv_checkpoint(const struct cfg *c);	/* G2, below */

/* Log and forward a log_checkpoint record for today's log (P1-3), and the
 * TimeVault manifest's Merkle root with it (G2). */

static void log_checkpoint(const struct cfg *c)
{
	char path[512];

	todays_logpath(path, sizeof(path));
	if (!chain_ok || strcmp(chain_name, log_basename(path)))
		chain_sync(path, log_basename(path));
	if (!chain_ok)
		return;
	/* The values cover the lines before this record; the record itself
	 * is the next line of the chain. */
	daemon_record(c, "log_checkpoint",
		      "\"log\":\"%s\",\"lines\":%llu,\"chain\":\"%s\"",
		      chain_name, chain_lines, chain_hex);
	tv_checkpoint(c);
}

static void write_log(const struct cfg *c, const char *line, size_t len)
{
	write_local_log(c, line, len);
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

/*
 * The heartbeat is written to a temporary file and renamed into place, so
 * `secure-sudo health` never reads a half-written one (it used to be
 * truncated and rewritten in place).
 */
static int write_health_heartbeat(void)
{
	char tmp[sizeof(HEALTH_FILE) + 8];
	int fd, n, saved;
	char buf[768];

	snprintf(tmp, sizeof(tmp), "%s.tmp", HEALTH_FILE);
	n = snprintf(buf, sizeof(buf),
		     "pid=%ld updated=%lld remote_transport=%s "
		     "retention_state=%s "
		     "remote_state=%s remote_sent=%llu remote_failures=%llu "
		     "remote_queue_records=%llu remote_queue_bytes=%llu "
		     "remote_queue_dropped=%llu local_log_failures=%llu "
		     "event_gaps=%llu events_missing=%llu net_state=%s\n",
		     (long)getpid(), (long long)time(NULL),
		     g_cfg ? g_cfg->remote_transport : "unknown",
		     retention_state, remote_state,
		     remote_sent, remote_failures, remote_queue_records,
		     remote_queue_bytes, remote_queue_dropped,
		     local_log_failures, event_gaps, events_missing, net_state);
	if (n <= 0 || (size_t)n >= sizeof(buf)) {
		errno = EOVERFLOW;
		return -1;
	}
	unlink(tmp);
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
		  0600);
	if (fd < 0)
		return -1;
	if (write_all(fd, buf, (size_t)n) != 0 || fsync(fd) != 0) {
		saved = errno ? errno : EIO;
		close(fd);
		unlink(tmp);
		errno = saved;
		return -1;
	}
	if (close(fd) != 0 || rename(tmp, HEALTH_FILE) != 0) {
		saved = errno;
		unlink(tmp);
		errno = saved;
		return -1;
	}
	return 0;
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
	if ((size_t)n >= sizeof(buf))
		n = sizeof(buf) - 1;
	for (int i = 0; i < n; i++)	/* paths can hold any byte */
		if ((unsigned char)buf[i] < 0x20 || buf[i] == 0x7f)
			buf[i] = '?';
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
 * target_uid and the TimeVault path from object (P1-1), never from the
 * message, and never from a truncated record.
 */
struct ss_ev {
	long long schema;		/* schema_version, -1 if absent */
	char boot_id[40];
	long long sequence;		/* -1 if absent */
	char event_type[64];
	char operation[32];
	char decision[24];
	char reason[64];
	char object[320];		/* JSON-decoded; the kernel caps it at 256 */
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
	e->sequence = -1;
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
		else if (!strcmp(key, "boot_id"))
			dst = e->boot_id, dsz = sizeof(e->boot_id);
		else if (!strcmp(key, "operation"))
			dst = e->operation, dsz = sizeof(e->operation);
		else if (!strcmp(key, "decision"))
			dst = e->decision, dsz = sizeof(e->decision);
		else if (!strcmp(key, "reason"))
			dst = e->reason, dsz = sizeof(e->reason);
		else if (!strcmp(key, "object"))
			dst = e->object, dsz = sizeof(e->object);
		else if (!strcmp(key, "message"))
			dst = e->message, dsz = sizeof(e->message);
		if (dst && *p == '"')
			p = json_string(p, dst, dsz);
		else if (!strcmp(key, "schema_version"))
			p = json_int(p, &e->schema);
		else if (!strcmp(key, "target_uid"))
			p = json_int(p, &e->target_uid);
		else if (!strcmp(key, "sequence"))
			p = json_int(p, &e->sequence);
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
 * path, else 0. ss_timevault.c puts the resolved path in the typed object
 * field. A record with any field cut short ("truncated":true) is never
 * acted on, so a long path can only fail to act, never name another file.
 */
static int ev_vault_path(const struct ss_ev *e, char *path, size_t size)
{
	size_t len = strlen(e->object);

	if (e->schema != 1 || e->truncated != 0 ||
	    strcmp(e->event_type, "time_vault") ||
	    strcmp(e->operation, "execute") || strcmp(e->decision, "deny") ||
	    (strcmp(e->reason, "hash mismatch") &&
	     strcmp(e->reason, "not on allowlist")))
		return 0;
	if (!len || len >= size || e->object[0] != '/')
		return 0;
	memcpy(path, e->object, len + 1);
	return 1;
}

/* The kernel's record of `timevault on` (typed fields only, as above). */
static int ev_vault_engaged(const struct ss_ev *e)
{
	return e->schema == 1 && !strcmp(e->event_type, "time_vault") &&
	       !strcmp(e->operation, "engage") &&
	       !strcmp(e->decision, "enforce");
}

static int tv_engage_seen;		/* G2: set from the ring, see below */

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

/*
 * ---- P1-1: make lost events visible in the log itself ----
 *
 * Kernel records carry a per-boot boot_id and a sequence number given in
 * ring order. A jump in the sequence therefore means records were lost:
 * dropped from a full ring, or produced while the daemon was down. The
 * daemon writes a record of its own for each gap and each new boot, so the
 * local log, the forwarded stream and any evidence bundle say where history
 * is missing. Without such a record, a missing stretch would look like a
 * quiet one. The last position is kept in EVENT_CURSOR so that loss
 * while the daemon was stopped is reported too. A crash can leave the
 * cursor a few records behind; then a gap can be overstated, never hidden.
 */
static char ev_boot[40];		/* boot_id of the last record seen */
static unsigned long long ev_seq;	/* and its sequence */
static int ev_cursor_dirty;

static void daemon_record(const struct cfg *c, const char *type,
			  const char *fmt, ...)
{
	char buf[640], rest[512];
	struct timespec ts;
	va_list ap;
	int n;

	va_start(ap, fmt);
	vsnprintf(rest, sizeof(rest), fmt, ap);
	va_end(ap);
	clock_gettime(CLOCK_REALTIME, &ts);
	n = snprintf(buf, sizeof(buf),
		     "{\"schema_version\":1,\"source\":\"secure-sudod\","
		     "\"realtime_ns\":%llu,\"event_type\":\"%s\",%s}",
		     (unsigned long long)ts.tv_sec * 1000000000ULL +
		     (unsigned long long)ts.tv_nsec, type, rest);
	if (n > 0 && (size_t)n < sizeof(buf))
		write_log(c, buf, (size_t)n);
}

static int read_sysfs_str(const char *name, char *out, size_t n);

static unsigned long long sysfs_counter(const char *name)
{
	char v[32];

	return read_sysfs_str(name, v, sizeof(v)) == 0 ?
	       strtoull(v, NULL, 10) : 0;
}

static void cursor_load(void)
{
	char buf[128], id[40];
	unsigned long long seq;
	struct stat st;
	ssize_t n;
	int fd = open(EVENT_CURSOR, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);

	if (fd < 0)
		return;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_uid != geteuid() || (st.st_mode & 077)) {
		close(fd);
		return;			/* not ours: ignore it */
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';
	if (sscanf(buf, "boot_id=%39s sequence=%llu", id, &seq) == 2 &&
	    strspn(id, "0123456789abcdef") == strlen(id)) {
		snprintf(ev_boot, sizeof(ev_boot), "%s", id);
		ev_seq = seq;
	}
}

static void cursor_save(void)
{
	char tmp[sizeof(EVENT_CURSOR) + 8], buf[128];
	int fd, n;

	if (!ev_cursor_dirty || !ev_boot[0])
		return;
	snprintf(tmp, sizeof(tmp), "%s.tmp", EVENT_CURSOR);
	n = snprintf(buf, sizeof(buf), "boot_id=%s sequence=%llu\n", ev_boot,
		     ev_seq);
	unlink(tmp);
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
		  0600);
	if (fd < 0)
		return;
	if (write_all(fd, buf, (size_t)n) != 0 || fsync(fd) != 0) {
		close(fd);
		unlink(tmp);
		return;
	}
	close(fd);
	if (rename(tmp, EVENT_CURSOR) == 0)
		ev_cursor_dirty = 0;
	else
		unlink(tmp);
}

static void track_sequence(const struct cfg *c, const struct ss_ev *e)
{
	unsigned long long seq;

	if (e->schema != 1 || strlen(e->boot_id) != 32 ||
	    strspn(e->boot_id, "0123456789abcdef") != 32 || e->sequence <= 0)
		return;
	seq = (unsigned long long)e->sequence;
	if (strcmp(e->boot_id, ev_boot)) {
		/* the first record of a boot this daemon has not seen before */
		daemon_record(c, "event_stream",
			      "\"boot_id\":\"%s\",\"first_sequence\":%llu,"
			      "\"previous_boot_id\":%s%s%s,"
			      "\"previous_last_sequence\":%llu",
			      e->boot_id, seq, ev_boot[0] ? "\"" : "",
			      ev_boot[0] ? ev_boot : "null",
			      ev_boot[0] ? "\"" : "", ev_seq);
		if (seq > 1) {
			event_gaps++;
			events_missing += seq - 1;
			daemon_record(c, "event_gap",
				      "\"boot_id\":\"%s\",\"first_missing\":1,"
				      "\"last_missing\":%llu,\"missing\":%llu,"
				      "\"kernel_events_dropped\":%llu",
				      e->boot_id, seq - 1, seq - 1,
				      sysfs_counter("events_dropped"));
		}
		snprintf(ev_boot, sizeof(ev_boot), "%s", e->boot_id);
	} else if (seq > ev_seq + 1) {
		event_gaps++;
		events_missing += seq - ev_seq - 1;
		daemon_record(c, "event_gap",
			      "\"boot_id\":\"%s\",\"first_missing\":%llu,"
			      "\"last_missing\":%llu,\"missing\":%llu,"
			      "\"kernel_events_dropped\":%llu",
			      e->boot_id, ev_seq + 1, seq - 1, seq - ev_seq - 1,
			      sysfs_counter("events_dropped"));
	} else if (seq <= ev_seq) {
		daemon_record(c, "event_sequence_error",
			      "\"boot_id\":\"%s\",\"sequence\":%llu,"
			      "\"after_sequence\":%llu",
			      e->boot_id, seq, ev_seq);
	}
	ev_seq = seq;
	ev_cursor_dirty = 1;
}

/* Act on one complete ring line, after it has been logged. */
static void handle_event(const struct cfg *c, const char *line)
{
	struct ss_ev e;
	char path[1024];
	uid_t uid;

	if (ev_parse(line, &e) != 0)
		return;			/* not a kernel record: never acted on */
	track_sequence(c, &e);
	if (ev_cooldown_uid(&e, &uid))
		kill_offenders(uid);
	if (ev_vault_path(&e, path, sizeof(path)))
		vault_act(c, path);
	if (ev_vault_engaged(&e))
		tv_engage_seen = 1;
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
 * #11: register SEA / pkg / renamed node runtimes for the Node guard. The
 * scan reads every new or changed executable under node_sea_scan_dirs, which
 * can take a while the first time, so it runs as a niced child that the main
 * loop reaps; events keep draining meanwhile. One scan at a time.
 */
static pid_t node_scan_pid;

static void node_scan_start(void)
{
	pid_t pid;

	if (node_scan_pid > 0)
		return;
	pid = fork();
	if (pid == 0) {
		if (setpriority(PRIO_PROCESS, 0, 10) != 0)
			_exit(126);
		execl(SECURE_SUDO_CLI, SECURE_SUDO_CLI, "node-scan", "--quiet",
		      (char *)NULL);
		_exit(127);
	} else if (pid > 0) {
		node_scan_pid = pid;
	}
}

static void node_scan_reap(void)
{
	int st;

	if (node_scan_pid <= 0 || waitpid(node_scan_pid, &st, WNOHANG) != node_scan_pid)
		return;
	node_scan_pid = 0;
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
		syslog_line("node-scan: did not complete (status %d); "
			    "`secure-sudo node-scan` shows why",
			    WIFEXITED(st) ? WEXITSTATUS(st) : -1);
}

/*
 * Apply the kernel's net_mode with the nft helper (TODO P1-8). A mode counts
 * as applied only once the helper succeeded; until then it is retried on
 * every periodic pass, and the failure is logged once rather than every 5
 * seconds. The helper leaves the previous rules in place when it fails, and
 * exits 3 when it could not find a LAN subnet and loaded its fail-closed
 * "pending" rules instead (e.g. lan-only at boot before DHCP).
 *
 * Once applied, lan-only and public-only are re-checked every
 * NET_REFRESH_SECS: a DHCP renewal onto another subnet, a new interface or a
 * lost address changes what "LAN" means. The helper does not touch nft when
 * nothing changed, and logs the change itself when something did.
 */
#ifndef NET_REFRESH_SECS
#define NET_REFRESH_SECS 15
#endif

static void apply_net_mode(void)
{
	static char applied[32] = "", failing[32] = "";
	static time_t last_refresh;
	char mode[32];
	int rc, ruled;
	time_t now = time(NULL);

	if (read_sysfs_str("net_mode", mode, sizeof(mode)) != 0)
		return;
	ruled = !strcmp(mode, "lan-only") || !strcmp(mode, "public-only");
	if (!strcmp(mode, applied)) {
		if (!ruled || now - last_refresh < NET_REFRESH_SECS)
			return;
		last_refresh = now;
		rc = run_helper_quiet(HELPER_NET, mode);
		if (rc == 0) {
			snprintf(net_state, sizeof(net_state), "applied");
			return;
		}
		/* fell back to pending or failed: retry every pass from now */
		applied[0] = '\0';
		snprintf(failing, sizeof(failing), "%s", mode);
		snprintf(net_state, sizeof(net_state), rc == 3 ? "pending" : "failing");
		syslog_line(rc == 3 ?
			    "net: mode %s: no LAN subnet found any more; fail-closed pending rules loaded" :
			    "net: mode %s: refresh failed (status %d); the loaded rules stay",
			    mode, rc);
		return;
	}
	if (strcmp(mode, failing))
		syslog_line("net: applying mode %s", mode);
	rc = run_helper_quiet(HELPER_NET, mode);
	if (rc == 0) {
		snprintf(applied, sizeof(applied), "%s", mode);
		last_refresh = now;
		snprintf(net_state, sizeof(net_state), "%s", ruled ? "applied" : "off");
		if (!strcmp(mode, failing))
			syslog_line("net: mode %s applied after retrying", mode);
		failing[0] = '\0';
		return;
	}
	snprintf(net_state, sizeof(net_state), rc == 3 ? "pending" : "failing");
	if (strcmp(mode, failing)) {
		if (rc == 3)
			syslog_line("net: mode %s: no LAN subnet yet; fail-closed pending rules loaded, retrying every 5s",
				    mode);
		else
			syslog_line("net: mode %s NOT applied yet (helper status %d); retrying every 5s",
				    mode, rc);
		snprintf(failing, sizeof(failing), "%s", mode);
	}
}

/* Clean stop: the helper applies net.conf's on_stop (keep by default). */
static void net_on_stop(void)
{
	run_helper_quiet(HELPER_NET, "stop");
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

/*
 * ---- G2: the TimeVault manifest and its Merkle tree ----
 *
 * The manifest is the set of files (path + SHA-256) the watched trees held
 * when TimeVault engaged: the first scan of an engagement records every
 * file and acts on none (the baseline). Every later scan compares against
 * it; a new or changed file is quarantined (or wiped) and the manifest is
 * left as it was, so a file that comes back is caught again. TimeVault
 * cannot be disengaged until reboot, so the manifest never changes during
 * an engagement and its Merkle root stays the same from scan to scan.
 *
 * The root (RFC 6962 tree hash over the entries sorted by path, leaf =
 * SHA-256(0x00 || path || 0x00 || hex hash), node = SHA-256(0x01 || l ||
 * r)) is logged and forwarded off the host at the baseline, when the
 * daemon loads the manifest, after every scan that finds something and at
 * each log checkpoint. So a collector holds the root the host started
 * with: a legitimate rescan repeats it, a rewritten manifest cannot. The
 * daemon also notices a rewrite itself (timevault_manifest_modified) and
 * puts its own copy back. `evidence-verify --timevault` checks the
 * collector's records and a bundle's copy of the manifest against them.
 *
 * Earlier versions appended to a flat manifest with no baseline, so the
 * first scan after `timevault on` quarantined every file under /etc, and a
 * quarantined file's hash was recorded as known, so the same file dropped
 * again was let be.
 *
 * On disk: a header line, then "HASH PATH" per entry, sorted by path, with
 * '\\', newline and carriage return in the path written as \\\\, \\n, \\r.
 */
#ifndef TV_MAX_ENTRIES
#define TV_MAX_ENTRIES 1000000
#endif
#define TV_HEADER "# secure_sudo timevault manifest v2"

struct tv_ent {
	char *path;
	char hash[65];
	int have_stat;			/* the stat key below is valid */
	dev_t dev;
	ino_t ino;
	off_t size;
	struct timespec mtim, ctim;
};

struct tv_set {
	struct tv_ent *e;
	size_t n, cap;
	int overflow;
};

static struct tv_set tv;		/* the manifest of this engagement */
static int tv_loaded;			/* tv holds it */
static char tv_root[65];
static struct stat tv_disk;		/* the manifest file as we left it */

static void tv_free(struct tv_set *s)
{
	size_t i;

	for (i = 0; i < s->n; i++)
		free(s->e[i].path);
	free(s->e);
	memset(s, 0, sizeof(*s));
}

static struct tv_ent *tv_add(struct tv_set *s, const char *path,
			     const char *hash)
{
	struct tv_ent *e;

	if (s->n >= TV_MAX_ENTRIES) {
		s->overflow = 1;
		return NULL;
	}
	if (s->n == s->cap) {
		size_t cap = s->cap ? s->cap * 2 : 1024;
		struct tv_ent *ne = realloc(s->e, cap * sizeof(*ne));

		if (!ne) {
			s->overflow = 1;
			return NULL;
		}
		s->e = ne;
		s->cap = cap;
	}
	e = &s->e[s->n];
	memset(e, 0, sizeof(*e));
	e->path = strdup(path);
	if (!e->path) {
		s->overflow = 1;
		return NULL;
	}
	snprintf(e->hash, sizeof(e->hash), "%s", hash);
	s->n++;
	return e;
}

static int tv_cmp(const void *a, const void *b)
{
	return strcmp(((const struct tv_ent *)a)->path,
		      ((const struct tv_ent *)b)->path);
}

/* Sort by path; of two entries for one path the first added is kept. */
static void tv_sort(struct tv_set *s)
{
	size_t i, o = 0;

	for (i = 0; i < s->n; i++)	/* stable: break ties on position */
		s->e[i].size = (off_t)i;
	qsort(s->e, s->n, sizeof(*s->e), tv_cmp);
	for (i = 0; i < s->n; i++) {
		if (o && !strcmp(s->e[o - 1].path, s->e[i].path)) {
			if (s->e[i].size < s->e[o - 1].size) {
				free(s->e[o - 1].path);
				s->e[o - 1] = s->e[i];
			} else {
				free(s->e[i].path);
			}
			continue;
		}
		s->e[o++] = s->e[i];
	}
	s->n = o;
	for (i = 0; i < s->n; i++) {
		s->e[i].size = 0;
		s->e[i].have_stat = 0;
	}
}

static struct tv_ent *tv_find(const struct tv_set *s, const char *path)
{
	struct tv_ent key = { .path = (char *)path };

	return s->n ? bsearch(&key, s->e, s->n, sizeof(*s->e), tv_cmp) : NULL;
}

static int tv_sha(const void *buf, size_t len, unsigned char out[32])
{
	unsigned int dlen = 0;

	return EVP_Digest(buf, len, out, &dlen, EVP_sha256(), NULL) == 1 &&
	       dlen == 32 ? 0 : -1;
}

static int tv_leaf(const struct tv_ent *e, unsigned char out[32])
{
	size_t pl = strlen(e->path);
	unsigned char *b = malloc(pl + 66);
	int rc;

	if (!b)
		return -1;
	b[0] = 0x00;
	memcpy(b + 1, e->path, pl);
	b[1 + pl] = 0x00;
	memcpy(b + 2 + pl, e->hash, 64);
	rc = tv_sha(b, pl + 66, out);
	free(b);
	return rc;
}

/* RFC 6962 MTH over h[0..n), n >= 1; the leaf hashes are overwritten. */
static int tv_mth(unsigned char (*h)[32], size_t n, unsigned char out[32])
{
	unsigned char node[65], l[32];
	size_t k = 1;

	if (n == 1) {
		memcpy(out, h[0], 32);
		return 0;
	}
	while (k * 2 < n)
		k *= 2;
	if (tv_mth(h, k, l) != 0 || tv_mth(h + k, n - k, node + 33) != 0)
		return -1;
	node[0] = 0x01;
	memcpy(node + 1, l, 32);
	return tv_sha(node, sizeof(node), out);
}

static int tv_root_hex(const struct tv_set *s, char out[65])
{
	unsigned char (*h)[32], r[32];
	size_t i;
	int rc = 0;

	if (!s->n)
		rc = tv_sha("", 0, r);
	else {
		h = malloc(s->n * sizeof(*h));
		if (!h)
			return -1;
		for (i = 0; i < s->n && !rc; i++)
			rc = tv_leaf(&s->e[i], h[i]);
		if (!rc)
			rc = tv_mth(h, s->n, r);
		free(h);
	}
	if (rc)
		return -1;
	for (i = 0; i < 32; i++)
		sprintf(out + i * 2, "%02x", r[i]);
	out[64] = '\0';
	return 0;
}

static int tv_hexhash(const char *s)
{
	int i;

	for (i = 0; i < 64; i++)
		if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
			return 0;
	return s[64] == '\0';
}

/*
 * Read a manifest file. Returns 0, or -1 with errno (ENOENT: none there;
 * EBADMSG: not a manifest). A v1 file ("PATH HASH" lines, appended) is
 * read too, once, so an engagement that began under the old daemon keeps
 * its entries; it is rewritten as v2.
 */
static int tv_read(const char *file, struct tv_set *s, struct stat *st)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	int v2 = -1, bad = 0;
	int fd = open(file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);

	memset(s, 0, sizeof(*s));
	if (fd < 0)
		return -1;
	f = fdopen(fd, "r");
	if (!f) {
		close(fd);
		return -1;
	}
	if (st && fstat(fd, st) != 0)
		bad = 1;
	while (!bad && (n = getline(&line, &cap, f)) > 0) {
		char path[1100], *p, *o, *hash;

		if (line[n - 1] == '\n')
			line[--n] = '\0';
		if (v2 < 0) {
			v2 = !strcmp(line, TV_HEADER);
			if (v2)
				continue;
		}
		if (v2) {
			if (n < 67 || line[64] != ' ' || line[65] != '/') {
				bad = 1;
				break;
			}
			line[64] = '\0';
			hash = line;
			for (p = line + 65, o = path; *p; p++) {
				if ((size_t)(o - path) >= sizeof(path) - 1) {
					bad = 1;
					break;
				}
				if (*p != '\\') {
					*o++ = *p;
					continue;
				}
				p++;
				if (*p == '\\')
					*o++ = '\\';
				else if (*p == 'n')
					*o++ = '\n';
				else if (*p == 'r')
					*o++ = '\r';
				else {
					bad = 1;
					break;
				}
			}
			*o = '\0';
		} else {
			char *sp = strrchr(line, ' ');

			if (!sp || line[0] != '/' ||
			    (size_t)(sp - line) >= sizeof(path)) {
				bad = 1;
				break;
			}
			*sp = '\0';
			hash = sp + 1;
			snprintf(path, sizeof(path), "%s", line);
		}
		if (bad || !tv_hexhash(hash)) {
			bad = 1;
			break;
		}
		if (!tv_add(s, path, hash))
			bad = 1;
	}
	if (ferror(f))
		bad = 1;
	free(line);
	fclose(f);
	if (bad) {
		tv_free(s);
		errno = EBADMSG;
		return -1;
	}
	tv_sort(s);
	return 0;
}

static void tv_put_path(FILE *f, const char *p)
{
	for (; *p; p++) {
		if (*p == '\\')
			fputs("\\\\", f);
		else if (*p == '\n')
			fputs("\\n", f);
		else if (*p == '\r')
			fputs("\\r", f);
		else
			fputc(*p, f);
	}
}

/* Write the in-memory manifest, atomically, and remember the result. */
static int tv_write(void)
{
	char tmp[600];
	FILE *f;
	size_t i;
	int fd, failed = 0;

	snprintf(tmp, sizeof(tmp), "%s.tmp", MANIFEST);
	unlink(tmp);
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
		  0600);
	if (fd < 0)
		return -1;
	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		unlink(tmp);
		return -1;
	}
	fprintf(f, "%s\n", TV_HEADER);
	for (i = 0; i < tv.n; i++) {
		fprintf(f, "%s ", tv.e[i].hash);
		tv_put_path(f, tv.e[i].path);
		fputc('\n', f);
	}
	if (fflush(f) != 0 || fsync(fd) != 0)
		failed = 1;
	if (fclose(f) != 0)
		failed = 1;
	if (failed || rename(tmp, MANIFEST) != 0 ||
	    lstat(MANIFEST, &tv_disk) != 0) {
		unlink(tmp);
		memset(&tv_disk, 0, sizeof(tv_disk));
		return -1;
	}
	return 0;
}

static int tv_same_stat(const struct stat *a, const struct stat *b)
{
	return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
	       a->st_size == b->st_size &&
	       a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
	       a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
	       a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
	       a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static void tv_merkle_record(const struct cfg *c, const char *reason,
			     unsigned long newf, unsigned long changed,
			     unsigned long acted)
{
	daemon_record(c, "timevault_merkle",
		      "\"reason\":\"%s\",\"root\":\"%s\",\"leaves\":%zu,"
		      "\"new\":%lu,\"changed\":%lu,\"acted\":%lu",
		      reason, tv_root, tv.n, newf, changed, acted);
}

/* With each log checkpoint: the root again, so a collector keeps it. */
static void tv_checkpoint(const struct cfg *c)
{
	if (tv_loaded)
		tv_merkle_record(c, "checkpoint", 0, 0, 0);
}

/* Walk one tree: record (baseline) or check every regular file. */
static void vault_scan_dir(const struct cfg *c, const char *dir, int depth,
			   struct tv_set *base, unsigned long *newf,
			   unsigned long *changed, unsigned long *acted)
{
	DIR *d;
	struct dirent *de;

	if (depth > 12)
		return;
	d = opendir(dir);
	if (!d)
		return;
	while ((de = readdir(d))) {
		char path[1024], have[65];
		struct tv_ent *e;
		struct stat st;

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir,
				     de->d_name) >= sizeof(path))
			continue;	/* never act on a cut-off path */
		if (lstat(path, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			vault_scan_dir(c, path, depth + 1, base, newf, changed,
				       acted);
			continue;
		}
		if (!S_ISREG(st.st_mode))
			continue;
		if (base) {
			if (sha256_hex(path, have) == 0 && !tv_add(base, path, have))
				break;		/* over the limit: caller gives up */
			continue;
		}
		e = tv_find(&tv, path);
		if (e && e->have_stat && e->dev == st.st_dev &&
		    e->ino == st.st_ino && e->size == st.st_size &&
		    e->mtim.tv_sec == st.st_mtim.tv_sec &&
		    e->mtim.tv_nsec == st.st_mtim.tv_nsec &&
		    e->ctim.tv_sec == st.st_ctim.tv_sec &&
		    e->ctim.tv_nsec == st.st_ctim.tv_nsec)
			continue;	/* untouched since it last matched */
		if (sha256_hex(path, have) != 0)
			continue;
		if (e && !strcmp(e->hash, have)) {
			e->have_stat = 1;
			e->dev = st.st_dev;
			e->ino = st.st_ino;
			e->size = st.st_size;
			e->mtim = st.st_mtim;
			e->ctim = st.st_ctim;
			continue;	/* as it was at the baseline */
		}

		/* New or changed since TimeVault engaged. */
		if (e)
			(*changed)++;
		else
			(*newf)++;
		syslog_line("timevault: %s %s (action=%s)",
			    e ? "changed" : "new", path, c->vault_action);
		if (vault_act(c, path) != 0) {
			syslog_line("timevault: %s left in place, will retry", path);
			continue;
		}
		(*acted)++;
		/* The manifest keeps the baseline: if the file comes back,
		 * it is caught again. */
	}
	closedir(d);
}

static void vault_walk(const struct cfg *c, struct tv_set *base,
		       unsigned long *newf, unsigned long *changed,
		       unsigned long *acted)
{
	char buf[1024], *p, *tok, *save;

	snprintf(buf, sizeof(buf), "%s", c->vault_watch);
	p = buf;
	while ((tok = strtok_r(p, ",", &save))) {
		p = NULL;
		trim(tok);
		if (*tok)
			vault_scan_dir(c, tok, 0, base, newf, changed, acted);
		if (base && base->overflow)
			return;
	}
}

/* TimeVault is off: an old engagement's manifest is kept aside. */
static void tv_disengaged(const struct cfg *c)
{
	char prev[600];
	struct tv_set old;
	struct stat st;

	if (!tv_loaded && lstat(MANIFEST, &st) != 0)
		return;
	if (!tv_loaded && tv_read(MANIFEST, &old, NULL) == 0) {
		tv_free(&tv);
		tv = old;
		if (tv_root_hex(&tv, tv_root) != 0)
			snprintf(tv_root, sizeof(tv_root), "unknown");
	} else if (!tv_loaded) {
		snprintf(tv_root, sizeof(tv_root), "unreadable");
	}
	snprintf(prev, sizeof(prev), "%s.prev", MANIFEST);
	if (rename(MANIFEST, prev) != 0 && errno != ENOENT)
		syslog_line("timevault: cannot set the old manifest aside: %s",
			    strerror(errno));
	daemon_record(c, "timevault_disengaged",
		      "\"root\":\"%s\",\"leaves\":%zu", tv_root, tv.n);
	tv_free(&tv);
	tv_loaded = 0;
	tv_root[0] = '\0';
}

/* Engaged and no manifest in memory: load it, or take the baseline. */
static void tv_start(const struct cfg *c)
{
	struct tv_set s;
	unsigned long z = 0;

	if (tv_read(MANIFEST, &s, &tv_disk) == 0) {
		int legacy = 0;
		char line[64];
		FILE *f = fopen(MANIFEST, "re");

		if (f) {
			legacy = !fgets(line, sizeof(line), f) ||
				 strncmp(line, TV_HEADER, strlen(TV_HEADER));
			fclose(f);
		}
		tv = s;
		if (tv_root_hex(&tv, tv_root) != 0) {
			tv_free(&tv);
			return;
		}
		tv_loaded = 1;
		if (legacy && tv_write() != 0)
			syslog_line("timevault: cannot rewrite the manifest: %s",
				    strerror(errno));
		tv_merkle_record(c, legacy ? "loaded_v1" : "loaded", 0, 0, 0);
		return;
	}
	if (errno != ENOENT) {
		/* There is a manifest we cannot read: acting on its absence
		 * would quarantine the whole tree, so do nothing but say so. */
		static time_t said;
		time_t now = time(NULL);

		if (now - said >= 3600) {
			said = now;
			daemon_record(c, "timevault_manifest_unreadable",
				      "\"error\":\"%s\"", strerror(errno));
		}
		return;
	}
	memset(&s, 0, sizeof(s));
	vault_walk(c, &s, &z, &z, &z);
	if (s.overflow) {
		daemon_record(c, "timevault_manifest_unreadable",
			      "\"error\":\"more than %d files to record\"",
			      TV_MAX_ENTRIES);
		tv_free(&s);
		return;
	}
	tv_sort(&s);
	tv = s;
	if (tv_root_hex(&tv, tv_root) != 0) {
		tv_free(&tv);
		return;
	}
	tv_loaded = 1;
	if (tv_write() != 0)
		syslog_line("timevault: cannot write the manifest: %s",
			    strerror(errno));
	/* "engaged": the kernel's engage record came first. "no_manifest":
	 * the daemon found TimeVault on and no manifest (a daemon started
	 * after `timevault on`, or a manifest deleted); a collector that
	 * already holds a root for this engagement treats it as tampering. */
	daemon_record(c, "timevault_baseline",
		      "\"reason\":\"%s\",\"root\":\"%s\",\"leaves\":%zu",
		      tv_engage_seen ? "engaged" : "no_manifest", tv_root,
		      tv.n);
	tv_engage_seen = 0;
}

/* Has someone else changed the manifest file? Put ours back if so. */
static void tv_check_disk(const struct cfg *c)
{
	struct stat st;
	struct tv_set s;
	char found[65] = "";

	if (lstat(MANIFEST, &st) == 0 && tv_same_stat(&st, &tv_disk))
		return;
	if (tv_read(MANIFEST, &s, &st) == 0) {
		int same = tv_root_hex(&s, found) == 0 &&
			   !strcmp(found, tv_root);

		if (!same && !found[0])
			snprintf(found, sizeof(found), "unknown");
		tv_free(&s);
		if (same) {
			tv_disk = st;	/* touched, not changed */
			return;
		}
	} else {
		snprintf(found, sizeof(found), "%s",
			 errno == ENOENT ? "missing" : "unreadable");
	}
	daemon_record(c, "timevault_manifest_modified",
		      "\"expected_root\":\"%s\",\"found_root\":\"%s\","
		      "\"restored\":%s", tv_root, found,
		      tv_write() == 0 ? "true" : "false");
}

static void vault_scan(const struct cfg *c)
{
	char enabled[8];
	unsigned long newf = 0, changed = 0, acted = 0;

	if (read_sysfs_str("timevault", enabled, sizeof(enabled)) != 0)
		return;
	if (strcmp(enabled, "1")) {
		tv_disengaged(c);
		return;
	}
	if (!tv_loaded) {
		tv_start(c);
		return;		/* the baseline scan acts on nothing */
	}
	tv_check_disk(c);
	vault_walk(c, NULL, &newf, &changed, &acted);
	if (newf || changed)
		tv_merkle_record(c, "scan", newf, changed, acted);
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
			/* act before forwarding, so a slow queue never delays it */
			write_local_log(c, line, (size_t)(nl - line));
			handle_event(c, line);
			forward_remote(c, line, (size_t)(nl - line));
		}
		line = nl + 1;
	}
	ev_have -= (size_t)(line - ev_buf);
	memmove(ev_buf, line, ev_have);
	cursor_save();
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
	time_t last_checkpoint = 0;
	time_t last_node_scan = 0;

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
	cursor_load();

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
			remote_backoff = 0;	/* try a new collector at once */
			remote_next_flush = 0;
			syslog_line("config reloaded");
		}

		if (now - last_health >= 5) {
			last_health = now;
			if (write_health_heartbeat() != 0)
				fprintf(stderr, "secure-sudod: cannot update health heartbeat: %s\n",
					strerror(errno));
		}

		if (rc > 0 && (pfd.revents & POLLIN))
			drain_events(&cfg, pfd.fd);
		maybe_flush_remote(&cfg, time(NULL));

		if (now - last_checkpoint >= CHECKPOINT_SECS) {
			last_checkpoint = now;
			log_checkpoint(&cfg);
		}

		/* Periodic work roughly every 5s. */
		if (now - last_periodic >= 5) {
			last_periodic = now;
			apply_net_mode();
			enforce_retention(&cfg);
			vault_scan(&cfg);
		}

		node_scan_reap();
		if (cfg.node_scan_minutes > 0 &&
		    (!last_node_scan || now - last_node_scan >= cfg.node_scan_minutes * 60)) {
			last_node_scan = now;
			node_scan_start();
		}

		/* PheonixBox scan+repair on a slower (30s) cadence: content
		 * hashing is heavier than the TimeVault directory walk. */
		if (now - last_pbox >= 30) {
			last_pbox = now;
			pheonixbox_scan();
		}
	}

	net_on_stop();
	syslog_line("secure-sudod stopping");
	close(pfd.fd);
	return 0;
}
