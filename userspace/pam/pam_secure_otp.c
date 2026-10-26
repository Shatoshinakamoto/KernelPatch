// SPDX-License-Identifier: GPL-2.0
/*
 * pam_secure_otp.so - verify a rotating OTP sudo password (#14).
 *
 * The user's password is "prefix" + a 6-digit TOTP code that rotates with
 * time (e.g. whale$482910). This module asks for it and has the OTP helper
 * verify it. All the sensitive machinery - the AES-GCM-encrypted seed, the
 * mlock'd runtime copy, the yescrypt-hashed prefix, the replay record - lives
 * in the helper (see the otp component), so this module holds no secrets and
 * simply trusts the helper's exit status. The candidate password is passed on
 * the helper's stdin, never on its argv, so it cannot leak through ps/proc.
 *
 * It prompts for its own "OTP password:" and neither reads nor sets PAM's
 * shared password item (PAM_AUTHTOK). Earlier builds took that item, so after
 * pam_unix it verified the Unix password as an OTP, and before pam_unix it
 * handed the OTP to pam_unix as the Unix password: either order failed every
 * login (tests/userspace/test-pam.sh). With "use_first_pass" it does take the
 * password an earlier module collected instead of prompting.
 *
 * As a second factor, for sudo (after the password verifier):
 *   @include common-auth            (or auth include system-auth)
 *   auth  required  pam_secure_otp.so
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

#ifndef OTP_HELPER	/* overridden only by tests/userspace/test-pam.sh */
#define OTP_HELPER "/usr/bin/secure-sudo-otp"
#endif

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
	const void *item = NULL;
	char *answer = NULL;
	const char *token;
	int rc, i, first_pass = 0;

	(void)flags;	/* fixed PAM signature; unused */
	for (i = 0; i < argc; i++)
		if (!strcmp(argv[i], "use_first_pass"))
			first_pass = 1;

	if (first_pass) {
		if (pam_get_item(pamh, PAM_AUTHTOK, &item) != PAM_SUCCESS || !item)
			return PAM_AUTH_ERR;
		token = item;
	} else {
		if (pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &answer,
			       "OTP password: ") != PAM_SUCCESS || !answer)
			return PAM_AUTH_ERR;
		token = answer;
	}

	rc = verify_with_helper(pamh, token);
	if (answer) {
		explicit_bzero(answer, strlen(answer));
		free(answer);
	}
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
	(void)pamh; (void)flags; (void)argc; (void)argv;	/* fixed PAM signature */
	return PAM_IGNORE;
}
