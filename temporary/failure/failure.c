// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * secure-sudo-addon-failure - failure reporting for the temporary/ add-ons
 * (TODO P2-2).
 *
 * Every add-on unit has OnFailure=secure-sudo-addon-failure@%n.service. When
 * a guard dies, is killed, hits its memory cap, or refuses to start because
 * its configuration is invalid, systemd starts that template, which runs
 *
 *     secure-sudo-addon-failure <unit>
 *
 * with the failed unit's result in MONITOR_SERVICE_RESULT, MONITOR_EXIT_CODE
 * and MONITOR_EXIT_STATUS (systemd >= 249; older systemd leaves them unset).
 * The failure goes through ssl_notify(): a CRITICAL line in the local add-on
 * log, the off-box syslog collector when one is configured, and the
 * operator's notify_cmd. A guard that silently stops guarding is the failure
 * this exists for: without it, a crashed ProcGuard looks the same as a quiet
 * host.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "ssaddon_log.h"

/* Copy an environment value that came from systemd, keeping only a safe
 * character set (it ends up in a log line and a notify_cmd argument). */
static const char *clean(const char *v, char *out, size_t n)
{
	size_t o = 0;

	if (!v || !*v)
		return "unknown";
	for (; *v && o < n - 1; v++)
		out[o++] = (isalnum((unsigned char)*v) || strchr("-_.@:", *v)) ? *v : '_';
	out[o] = '\0';
	return out;
}

int main(int argc, char **argv)
{
	char unit[128], res[64], code[64], st[64];
	const char *u, *r, *c, *s, *hint = "";

	if (argc != 2) {
		fprintf(stderr, "usage: secure-sudo-addon-failure UNIT\n"
			"(started by systemd through OnFailure= of the add-on units)\n");
		return 2;
	}
	u = clean(argv[1], unit, sizeof(unit));
	r = clean(getenv("MONITOR_SERVICE_RESULT"), res, sizeof(res));
	c = clean(getenv("MONITOR_EXIT_CODE"), code, sizeof(code));
	s = clean(getenv("MONITOR_EXIT_STATUS"), st, sizeof(st));
	if (!strcmp(s, "78") || !strcmp(s, "CONFIG"))
		hint = " - its configuration is invalid; run its check-config command";
	else if (!strcmp(r, "oom-kill"))
		hint = " - it hit its memory limit (MemoryMax=)";
	else if (!strcmp(r, "start-limit-hit"))
		hint = " - it failed repeatedly and systemd stopped restarting it";

	ssl_init("failure");
	ssl_notify(SSL_CRIT, "ADD-ON FAILED: %s (result=%s, %s=%s)%s", u, r, c, s, hint);
	ssl_close();
	return 0;
}
