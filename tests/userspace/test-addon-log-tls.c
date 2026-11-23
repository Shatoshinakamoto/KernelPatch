// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * Harness for test-addon-log-tls.sh: drives temporary/common/ssaddon_log.c
 * the way an add-on does. "check" runs the config check; otherwise each
 * argument is logged as one WARN line, and "@sleep" waits 600 ms instead.
 */
#include "ssaddon_log.h"
#include <string.h>
#include <time.h>

int main(int argc, char **argv)
{
	int i;

	if (argc > 1 && !strcmp(argv[1], "check"))
		return ssl_check_conf(stdout) ? 1 : 0;
	ssl_init("tlstest");
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "@sleep")) {
			struct timespec ts = { 0, 600 * 1000 * 1000 };

			nanosleep(&ts, NULL);
			continue;
		}
		ssl_log(SSL_WARN, "%s", argv[i]);
	}
	ssl_close();
	return 0;
}
