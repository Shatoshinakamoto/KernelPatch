// SPDX-License-Identifier: GPL-2.0
/*
 * pam_secure_otp.so - verify a rotating OTP sudo password (#14).
 *
 * The user's password is "prefix" + a 6-digit TOTP code that rotates with
 * time (e.g. whale$482910). This module obtains the entered password and asks
 * the OTP helper to verify it. All the sensitive machinery - the TPM-sealed
 * secret, the mlock'd runtime copy, the yescrypt-hashed prefix - lives in the
 * helper (see the otp component), so this module holds no secrets and simply
 * trusts the helper's exit status. The candidate password is passed on the
 * helper's stdin, never on its argv, so it cannot leak through ps/proc.
 *
 * Stack it where you want OTP enforced, e.g. for sudo:
 *   auth  required  pam_secure_otp.so
 *   auth  ...       (the rest of the stack)
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define OTP_HELPER "/usr/bin/secure-sudo-otp"

/* Run "secure-sudo-otp verify", write @token to its stdin, return exit code
 * (0 = valid). Returns -1 on spawn error. */
static int verify_with_helper(pam_handle_t *pamh, const char *token)
{
	int pipefd[2];
	pid_t pid;
	int status;
	size_t len = strlen(token);

	if (pipe(pipefd) != 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}
	if (pid == 0) {
		/* child */
		close(pipefd[1]);
		if (dup2(pipefd[0], STDIN_FILENO) < 0)
			_exit(127);
		close(pipefd[0]);
		execl(OTP_HELPER, OTP_HELPER, "verify", "--pam", (char *)NULL);
		_exit(127);
	}

	/* parent */
	close(pipefd[0]);
	if (write(pipefd[1], token, len) < 0 || write(pipefd[1], "\n", 1) < 0)
		pam_syslog(pamh, LOG_WARNING, "secure_otp: short write to helper");
	close(pipefd[1]);

	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return -1;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	const char *token = NULL;
	int rc;

	/* Prefer an already-supplied token; otherwise prompt for it. */
	if (pam_get_authtok(pamh, PAM_AUTHTOK, &token, "OTP password: ") != PAM_SUCCESS
	    || token == NULL) {
		return PAM_AUTH_ERR;
	}

	rc = verify_with_helper(pamh, token);
	if (rc == 0)
		return PAM_SUCCESS;
	if (rc == 127 || rc < 0) {
		pam_syslog(pamh, LOG_ERR, "secure_otp: helper %s unavailable",
			   OTP_HELPER);
		return PAM_AUTHINFO_UNAVAIL;
	}
	return PAM_AUTH_ERR;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}
