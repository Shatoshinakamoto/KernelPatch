// SPDX-License-Identifier: GPL-2.0
/*
 * pam_secure_sudo.so - feed sudo/su auth results to the secure_sudo LSM.
 *
 * The kernel cannot see whether a password was accepted; PAM can. This module
 * reports the verdict to /sys/kernel/security/secure_sudo/sudo_auth, and the
 * kernel's cooldown logic (#8) does the blocking. It never changes the result
 * (it always returns PAM_IGNORE); it only observes.
 *
 * Use one line, first in the auth section of /etc/pam.d/sudo and /etc/pam.d/su,
 * above whatever verifies the password (an @include, pam_unix, pam_faillock,
 * pam_sss, pam_secure_otp...):
 *
 *   auth  optional  pam_secure_sudo.so
 *
 * pam_authenticate() marks an attempt. sudo and su call pam_setcred() only
 * after authentication and the account check succeeded; that reports "ok".
 * An attempt that never got there - wrong password, ^C, failed account check -
 * is reported as "fail" when PAM discards it: on the next pam_authenticate()
 * of the same handle (a sudo retry) or at pam_end(), whose status also tells
 * a late success from a failure (sudoers "Defaults !pam_setcred"). No jump
 * counts to keep in step, so it works whatever the order and number of the
 * other modules. (It deliberately has no account hook: listed before another
 * account module, that would report "ok" before the account check ran.)
 *
 * Earlier documentation showed a four-line pam_faillock-style stack with
 * "[default=die] pam_unix.so" first; that denies the correct password
 * (PAM_PERM_DENIED) and never reports a failure - tests/userspace/test-pam.sh
 * shows both. The explicit arguments still exist for stacks that already
 * branch on the verifier's result: "authfail" and "authsucc" report at once.
 *
 * The UID recorded is the invoking user's real UID at authentication time -
 * the identity the kernel keys its block on when that user next execs sudo/su.
 */
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#ifndef SUDO_AUTH	/* overridden only by tests/userspace/test-pam.sh */
#define SUDO_AUTH "/sys/kernel/security/secure_sudo/sudo_auth"
#endif

#define SS_ATTEMPT "secure_sudo_attempt"

struct ss_attempt {
	uid_t uid;
	int done;		/* outcome already reported */
};

static void report(pam_handle_t *pamh, const char *verb, uid_t uid)
{
	char line[64];
	int fd, len;

	len = snprintf(line, sizeof(line), "%s %u\n", verb, (unsigned)uid);
	/* O_APPEND changes nothing for the securityfs file; for the plain file
	 * the tests use, it keeps every report. */
	fd = open(SUDO_AUTH, O_WRONLY | O_APPEND | O_CLOEXEC);
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

/* PAM discards the attempt: replaced by a retry, or at pam_end(). */
static void attempt_cleanup(pam_handle_t *pamh, void *data, int status)
{
	struct ss_attempt *a = data;

	if (!a->done) {
		int replaced = status & PAM_DATA_REPLACE;

		status &= ~(PAM_DATA_REPLACE | PAM_DATA_SILENT);
		report(pamh, !replaced && status == PAM_SUCCESS ? "ok" : "fail",
		       a->uid);
	}
	free(a);
}

/* Authentication went through: report it once. */
static void attempt_succeeded(pam_handle_t *pamh)
{
	const void *d = NULL;
	struct ss_attempt *a;

	if (pam_get_data(pamh, SS_ATTEMPT, &d) != PAM_SUCCESS || !d)
		return;			/* no password asked (cached sudo) */
	a = (struct ss_attempt *)d;
	if (!a->done) {
		report(pamh, "ok", a->uid);
		a->done = 1;
	}
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	struct ss_attempt *a;
	int i, explicit = 0;

	(void)flags;	/* fixed PAM signature; no flags are used */
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "authfail")) {
			report(pamh, "fail", getuid());
			explicit = 1;
		} else if (!strcmp(argv[i], "authsucc")) {
			report(pamh, "ok", getuid());
			explicit = 1;
		}
	}
	if (explicit)
		return PAM_IGNORE;

	a = calloc(1, sizeof(*a));
	if (!a)
		return PAM_IGNORE;
	a->uid = getuid();
	/* Replacing a previous, unfinished attempt reports it as a failure. */
	if (pam_set_data(pamh, SS_ATTEMPT, a, attempt_cleanup) != PAM_SUCCESS)
		free(a);
	return PAM_IGNORE;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)argc; (void)argv;	/* fixed PAM signature */
	if (!(flags & PAM_DELETE_CRED))
		attempt_succeeded(pamh);
	return PAM_IGNORE;
}
