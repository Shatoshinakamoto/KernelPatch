// SPDX-License-Identifier: GPL-2.0
/*
 * pam_secure_sudo.so - feed sudo/su auth results to the secure_sudo LSM.
 *
 * The kernel cannot see whether a password was accepted; PAM can. This module
 * reports the verdict to /sys/kernel/security/secure_sudo/sudo_auth, and the
 * kernel's cooldown logic (#8) does the blocking. It follows the pam_faillock
 * argument convention so it slots into an auth stack without changing control
 * flow:
 *
 *   auth  [default=die]  pam_unix.so        # or whatever verifies the secret
 *   auth  required       pam_secure_sudo.so authfail
 *   auth  sufficient     pam_unix.so
 *   auth  required       pam_secure_sudo.so authsucc
 *
 * "authfail" records a failure, "authsucc" records a success; the module never
 * alters the result (returns PAM_IGNORE), it only observes. The UID recorded is
 * the invoking user's real UID - the same identity the kernel keys its block on
 * when that user later tries to exec sudo/su.
 */
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define SUDO_AUTH "/sys/kernel/security/secure_sudo/sudo_auth"

static void report(pam_handle_t *pamh, const char *verb)
{
	char line[64];
	int fd, len;

	len = snprintf(line, sizeof(line), "%s %u", verb, (unsigned)getuid());
	fd = open(SUDO_AUTH, O_WRONLY);
	if (fd < 0) {
		/* LSM not present / not root: nothing to report to. */
		pam_syslog(pamh, LOG_DEBUG, "secure_sudo: %s unavailable",
			   SUDO_AUTH);
		return;
	}
	if (write(fd, line, len) < 0)
		pam_syslog(pamh, LOG_WARNING,
			   "secure_sudo: failed to report '%s'", verb);
	close(fd);
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	int i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "authfail"))
			report(pamh, "fail");
		else if (!strcmp(argv[i], "authsucc"))
			report(pamh, "ok");
		/* "preauth" (and anything else): nothing to do - the kernel
		 * enforces the block at sudo/su exec, so we need not deny here. */
	}
	return PAM_IGNORE;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}
