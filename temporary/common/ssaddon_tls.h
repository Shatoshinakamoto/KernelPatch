/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 Johnathan Edward Brown */
/*
 * ssaddon_tls - the TLS client behind ssaddon_log's `remote_proto = tls`
 * (TODO P2-3: add-on logs were plain UDP/TCP only, CWE-319).
 *
 * Kept apart from ssaddon_log.c because that file's SSL_* level names would
 * clash with OpenSSL's headers. The rules match the core daemon's
 * `remote_syslog_transport = tls` (userspace/daemon/secure-sudod.c):
 *
 *   - TLS 1.2 or newer only;
 *   - the collector's certificate must chain to @ca_file (SSL_VERIFY_PEER)
 *     and match the configured host name (SNI is sent) or IP address, so a
 *     machine in the middle cannot read or drop the log stream unseen;
 *   - connect, handshake and every write time out (SST_TIMEOUT_SECS), so a
 *     dead collector never stalls a guard.
 */
#ifndef SSADDON_TLS_H
#define SSADDON_TLS_H

#include <stddef.h>

#ifndef SST_TIMEOUT_SECS
#define SST_TIMEOUT_SECS 3
#endif

struct sst;

/* Connect to @host:@port over TCP and run the TLS handshake, verifying the
 * collector against @ca_file. NULL on failure, with the reason in @err. */
struct sst *sst_open(const char *host, const char *port, const char *ca_file,
		     char *err, size_t errlen);

/* Write all of @len bytes. 0 on success, -1 on any failure (the caller
 * closes the connection and reconnects later). SIGPIPE is never raised. */
int sst_write(struct sst *t, const void *buf, size_t len);

/* 1 if the collector has closed or reset the connection (checked without
 * blocking before each write, so a restarted collector is reconnected
 * instead of losing the line to a write into a dead socket). */
int sst_peer_closed(struct sst *t);

/* Same check for a plain TCP socket. */
int sst_fd_closed(int fd);

/* Send close_notify and free. NULL is fine. */
void sst_close(struct sst *t);

/* For check-config: 0 if @ca_file can be loaded as a CA bundle, else -1
 * with the reason in @err. */
int sst_ca_ok(const char *ca_file, char *err, size_t errlen);

#endif
