// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * ssaddon_tls - TLS client for add-on log shipping. See ssaddon_tls.h.
 */
#define _GNU_SOURCE
#include "ssaddon_tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

struct sst {
	int fd;
	SSL_CTX *ctx;
	SSL *ssl;
};

/* A write to a collector that has gone away raises SIGPIPE, which would kill
 * the guard. SSL_write has no MSG_NOSIGNAL, so block SIGPIPE around each call
 * and discard one that became pending (the add-ons are single-threaded). */
static void pipe_block(sigset_t *old)
{
	sigset_t s;

	sigemptyset(&s);
	sigaddset(&s, SIGPIPE);
	sigprocmask(SIG_BLOCK, &s, old);
}

static void pipe_restore(const sigset_t *old)
{
	if (!sigismember(old, SIGPIPE)) {
		struct timespec zero = { 0, 0 };
		sigset_t s, pend;

		sigemptyset(&s);
		sigaddset(&s, SIGPIPE);
		while (sigpending(&pend) == 0 && sigismember(&pend, SIGPIPE) &&
		       sigtimedwait(&s, NULL, &zero) == SIGPIPE)
			;
	}
	sigprocmask(SIG_SETMASK, old, NULL);
}

static void seterr(char *err, size_t errlen, const char *what)
{
	unsigned long e = ERR_get_error();
	char detail[160] = "";

	if (e)
		ERR_error_string_n(e, detail, sizeof(detail));
	ERR_clear_error();
	if (err && errlen)
		snprintf(err, errlen, "%s%s%s", what, detail[0] ? ": " : "", detail);
}

/* TCP connect with a timeout on each address. */
static int tcp_connect(const char *host, const char *port, char *err, size_t errlen)
{
	struct addrinfo hints, *res = NULL, *ai;
	int fd = -1, rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo(host, port, &hints, &res);
	if (rc != 0 || !res) {
		snprintf(err, errlen, "cannot resolve %s: %s", host, gai_strerror(rc));
		return -1;
	}
	for (ai = res; ai; ai = ai->ai_next) {
		int flags, ok = 0;

		fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
		if (fd < 0)
			continue;
		flags = fcntl(fd, F_GETFL);
		if (flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0) {
			if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
				ok = 1;
			} else if (errno == EINPROGRESS) {
				struct pollfd p = { .fd = fd, .events = POLLOUT };
				int soerr = 0;
				socklen_t sl = sizeof(soerr);

				if (poll(&p, 1, SST_TIMEOUT_SECS * 1000) > 0 &&
				    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 &&
				    soerr == 0)
					ok = 1;
			}
			if (fcntl(fd, F_SETFL, flags) != 0)
				ok = 0;
		}
		if (ok)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0)
		snprintf(err, errlen, "cannot connect to %s port %s", host, port);
	return fd;
}

static SSL_CTX *make_ctx(const char *ca_file, char *err, size_t errlen)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

	if (!ctx) {
		seterr(err, errlen, "TLS context");
		return NULL;
	}
	/* SECURITY: TLS 1.2+ only, and the peer must chain to the configured
	 * CA bundle (NIST SC-8, SC-23; CWE-295, CWE-319). */
	if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
		seterr(err, errlen, "TLS minimum version");
		SSL_CTX_free(ctx);
		return NULL;
	}
	if (!ca_file || !ca_file[0] ||
	    SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
		seterr(err, errlen, "cannot load remote_ca_file");
		SSL_CTX_free(ctx);
		return NULL;
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	return ctx;
}

int sst_ca_ok(const char *ca_file, char *err, size_t errlen)
{
	SSL_CTX *ctx = make_ctx(ca_file, err, errlen);

	if (!ctx)
		return -1;
	SSL_CTX_free(ctx);
	return 0;
}

struct sst *sst_open(const char *host, const char *port, const char *ca_file,
		     char *err, size_t errlen)
{
	struct timeval tv = { .tv_sec = SST_TIMEOUT_SECS, .tv_usec = 0 };
	unsigned char addr[sizeof(struct in6_addr)];
	struct sst *t;
	int is_ip, ok, rc;
	long vr;

	if (err && errlen)
		err[0] = '\0';
	t = calloc(1, sizeof(*t));
	if (!t) {
		snprintf(err, errlen, "out of memory");
		return NULL;
	}
	t->fd = -1;
	t->ctx = make_ctx(ca_file, err, errlen);
	if (!t->ctx)
		goto fail;
	t->fd = tcp_connect(host, port, err, errlen);
	if (t->fd < 0)
		goto fail;
	setsockopt(t->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(t->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	t->ssl = SSL_new(t->ctx);
	if (!t->ssl) {
		seterr(err, errlen, "TLS session");
		goto fail;
	}
	/* SECURITY: the certificate must name the collector we asked for, not
	 * just any host the CA vouches for (CWE-297). */
	is_ip = inet_pton(AF_INET, host, addr) == 1 || inet_pton(AF_INET6, host, addr) == 1;
	if (is_ip)
		ok = X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(t->ssl), host) == 1;
	else
		ok = SSL_set1_host(t->ssl, host) == 1 &&
		     SSL_set_tlsext_host_name(t->ssl, host) == 1;
	if (!ok || SSL_set_fd(t->ssl, t->fd) != 1) {
		seterr(err, errlen, "TLS host check setup");
		goto fail;
	}
	{
		sigset_t old;

		pipe_block(&old);
		rc = SSL_connect(t->ssl);
		pipe_restore(&old);
	}
	vr = SSL_get_verify_result(t->ssl);
	if (rc != 1 || vr != X509_V_OK) {
		char what[200];

		snprintf(what, sizeof(what), "TLS handshake with %s failed%s%s", host,
			 vr != X509_V_OK ? ": certificate " : "",
			 vr != X509_V_OK ? X509_verify_cert_error_string(vr) : "");
		seterr(err, errlen, what);
		goto fail;
	}
	return t;
fail:
	if (t->ssl)
		SSL_free(t->ssl);
	if (t->ctx)
		SSL_CTX_free(t->ctx);
	if (t->fd >= 0)
		close(t->fd);
	free(t);
	ERR_clear_error();
	return NULL;
}

int sst_write(struct sst *t, const void *buf, size_t len)
{
	const char *p = buf;
	sigset_t old;
	int rc = 0;

	if (!t || !t->ssl)
		return -1;
	pipe_block(&old);
	while (len) {
		size_t done = 0;

		if (SSL_write_ex(t->ssl, p, len, &done) != 1 || !done) {
			ERR_clear_error();
			rc = -1;
			break;
		}
		p += done;
		len -= done;
	}
	pipe_restore(&old);
	return rc;
}

int sst_fd_closed(int fd)
{
	struct pollfd p = { .fd = fd, .events = POLLRDHUP };

	if (fd < 0)
		return 1;
	if (poll(&p, 1, 0) < 0)
		return 0;
	return (p.revents & (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL)) != 0;
}

int sst_peer_closed(struct sst *t)
{
	return !t || sst_fd_closed(t->fd);
}

void sst_close(struct sst *t)
{
	sigset_t old;

	if (!t)
		return;
	pipe_block(&old);
	if (t->ssl) {
		char drain[512];

		/* close_notify, then read what the collector sent (TLS 1.3
		 * tickets, its close_notify) so close() does not reset the
		 * connection and lose the last lines. Bounded by SO_RCVTIMEO. */
		if (SSL_shutdown(t->ssl) == 0)
			while (SSL_read(t->ssl, drain, sizeof(drain)) > 0)
				;
		SSL_free(t->ssl);
	}
	if (t->ctx)
		SSL_CTX_free(t->ctx);
	if (t->fd >= 0)
		close(t->fd);
	ERR_clear_error();
	free(t);
	pipe_restore(&old);
}
