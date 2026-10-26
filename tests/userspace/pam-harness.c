// SPDX-License-Identifier: GPL-2.0
/*
 * pam-harness.c - run one PAM authentication against a private config
 * directory, for tests/userspace/test-pam.sh (TODO P0-2/P0-6).
 *
 *   pam-harness [--tries N] [--acct] [--setcred] <confdir> <service> <user>
 *               [answer]...
 *
 * Like sudo, it calls pam_authenticate() up to N times (default 1) on one
 * handle until one succeeds; after a success, --acct calls pam_acct_mgmt()
 * and --setcred pam_setcred(PAM_ESTABLISH_CRED) (sudo and su do both); then
 * pam_end() with the last status. Each prompt is answered with the next answer in order (none
 * left: the conversation fails, like a user pressing ^D). Prints one line,
 * "result=<auth result> acct=<account result|-> prompts=<n> tries=<n>", and
 * exits 0 if authentication (and account, with --acct) succeeded, else 1.
 * pam_start_confdir() reads <confdir>/<service> only, never /etc/pam.d.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>

static char **answers;
static int nanswers, prompts;

static int conv(int n, const struct pam_message **msg,
		struct pam_response **resp, void *data)
{
	struct pam_response *r = calloc(n, sizeof(*r));
	int i;

	(void)data;
	if (!r)
		return PAM_BUF_ERR;
	for (i = 0; i < n; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			fprintf(stderr, "prompt: %s\n", msg[i]->msg);
			if (prompts >= nanswers) {
				free(r);
				return PAM_CONV_ERR;
			}
			r[i].resp = strdup(answers[prompts++]);
			break;
		default:
			fprintf(stderr, "message: %s\n", msg[i]->msg);
		}
	}
	*resp = r;
	return PAM_SUCCESS;
}

static const char *pam_name(int rc)
{
	switch (rc) {
	case PAM_SUCCESS:		return "PAM_SUCCESS";
	case PAM_PERM_DENIED:		return "PAM_PERM_DENIED";
	case PAM_AUTH_ERR:		return "PAM_AUTH_ERR";
	case PAM_CRED_INSUFFICIENT:	return "PAM_CRED_INSUFFICIENT";
	case PAM_AUTHINFO_UNAVAIL:	return "PAM_AUTHINFO_UNAVAIL";
	case PAM_USER_UNKNOWN:		return "PAM_USER_UNKNOWN";
	case PAM_MAXTRIES:		return "PAM_MAXTRIES";
	case PAM_CONV_ERR:		return "PAM_CONV_ERR";
	case PAM_ABORT:			return "PAM_ABORT";
	case PAM_IGNORE:		return "PAM_IGNORE";
	case PAM_SYSTEM_ERR:		return "PAM_SYSTEM_ERR";
	default:			return "PAM_OTHER";
	}
}

int main(int argc, char **argv)
{
	struct pam_conv pc = { conv, NULL };
	pam_handle_t *pamh = NULL;
	int rc, arc = -1, tries = 0, max = 1, acct = 0, setcred = 0, a = 1;

	for (; a < argc && !strncmp(argv[a], "--", 2); a++) {
		if (!strcmp(argv[a], "--acct"))
			acct = 1;
		else if (!strcmp(argv[a], "--setcred"))
			setcred = 1;
		else if (!strcmp(argv[a], "--tries") && a + 1 < argc)
			max = atoi(argv[++a]);
		else
			break;
	}
	if (argc - a < 3 || max < 1) {
		fprintf(stderr, "usage: %s [--tries N] [--acct] [--setcred] <confdir> <service> <user> [answer]...\n",
			argv[0]);
		return 2;
	}
	answers = argv + a + 3;
	nanswers = argc - a - 3;
	rc = pam_start_confdir(argv[a + 1], argv[a + 2], &pc, argv[a], &pamh);
	if (rc != PAM_SUCCESS) {
		printf("result=start:%s acct=- prompts=0 tries=0\n", pam_name(rc));
		return 1;
	}
	do {
		rc = pam_authenticate(pamh, 0);
		tries++;
	} while (rc != PAM_SUCCESS && rc != PAM_CONV_ERR && tries < max);
	if (rc == PAM_SUCCESS && acct)
		arc = pam_acct_mgmt(pamh, 0);
	if (rc == PAM_SUCCESS && arc <= 0 && setcred)
		pam_setcred(pamh, PAM_ESTABLISH_CRED);
	printf("result=%s acct=%s prompts=%d tries=%d\n", pam_name(rc),
	       arc < 0 ? "-" : pam_name(arc), prompts, tries);
	pam_end(pamh, arc > 0 ? arc : rc);
	return (rc == PAM_SUCCESS && arc <= 0) ? 0 : 1;
}
