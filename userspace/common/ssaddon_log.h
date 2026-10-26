/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ssaddon_log - shared logging for the secure_sudo runtime guards.
 *
 * Every add-on (ProcGuard, DriverGuard, BootGuard, Locus) logs
 * through this one helper so logging behaves identically everywhere and so
 * there is a single place that implements:
 *
 *   - timestamped, leveled lines written to a per-feature local log file
 *     under a root-only directory, with size-based rotation; and
 *   - optional shipping of each line to an EXTERNAL log server (UDP or TCP
 *     syslog, RFC 5424 framing) for off-box backup, so a compromised host
 *     cannot erase the evidence that something happened.
 *
 * Configuration is read once from /etc/secure_sudo/addons/logging.conf (see
 * userspace/config/addons/logging.conf for the documented template). Missing file or
 * keys fall back to safe local-only defaults.
 */
#ifndef SSADDON_LOG_H
#define SSADDON_LOG_H

#include <stdarg.h>

enum ssl_level {
	SSL_DEBUG = 0,
	SSL_INFO,
	SSL_WARN,
	SSL_ERR,
	SSL_CRIT,
};

/* Initialise logging for @feature (e.g. "procguard"). Reads the config,
 * ensures the local log directory exists (0700), and opens the remote socket
 * if remote shipping is enabled. Safe to call once at program start. */
void ssl_init(const char *feature);

/* Log one line at @level. Formats like printf. The line is written locally
 * and, if remote shipping is on, sent to the external server. */
void ssl_log(enum ssl_level level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/* Convenience wrappers. */
#define ssl_debug(...) ssl_log(SSL_DEBUG, __VA_ARGS__)
#define ssl_info(...)  ssl_log(SSL_INFO,  __VA_ARGS__)
#define ssl_warn(...)  ssl_log(SSL_WARN,  __VA_ARGS__)
#define ssl_err(...)   ssl_log(SSL_ERR,   __VA_ARGS__)
#define ssl_crit(...)  ssl_log(SSL_CRIT,  __VA_ARGS__)

/* Flush and close. */
void ssl_close(void);

#endif /* SSADDON_LOG_H */
