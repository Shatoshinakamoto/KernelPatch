/* SPDX-License-Identifier: GPL-2.0 */
/* cli.h - shared bits of the secure-sudo CLI (secure-sudo.c + subcommands). */
#ifndef SECURE_SUDO_CLI_H
#define SECURE_SUDO_CLI_H

#include <stddef.h>

/* Overridable at build time for the tests only (tests/userspace/test-cli.sh). */
#ifndef SYSFS
#define SYSFS  "/sys/kernel/secure_sudo"
#endif
#ifndef SECFS
#define SECFS  "/sys/kernel/security/secure_sudo"
#endif
#ifndef CONFIG_DIR
#define CONFIG_DIR "/etc/secure_sudo"
#endif

#define SS_MAX_GIDS 16	/* SS_MAX_ADMIN_GIDS in the kernel */

/* Write @len bytes to a kernel file in one write(); 0 on success. */
int write_file(const char *path, const char *data, size_t len);
/* Same, silent; on failure returns -1 with the errno in *err. */
int write_file_err(const char *path, const char *data, size_t len, int *err);

/* policy.c: the settings and lists, the config parser, lint */
enum knob_type { K_BOOL, K_U32, K_ENUM, K_GIDS };
struct knob {
	const char *cfg_key;	/* key in secure-sudo.conf */
	const char *sysfs;	/* file under SYSFS */
	enum knob_type type;
	unsigned long lo, hi;	/* K_U32 range, as the kernel checks it */
};
enum list_kind { L_PATH, L_PREFIX, L_NAME, L_HOMEMAP };
struct listmap {
	const char *cfg_file;	/* file in CONFIG_DIR */
	const char *secfs;	/* file under SECFS */
	enum list_kind kind;
};
extern const struct knob ss_knobs[];
extern const size_t ss_nknobs;
extern const struct listmap ss_lists[];
extern const size_t ss_nlists;
const struct knob *find_knob(const char *key);
const struct listmap *find_list(const char *name);
int is_daemon_key(const char *key);
const char *check_value(const struct knob *k, const char *v, char *why, size_t n);

struct cfg_entry {
	int line;
	char key[64];
	char val[448];
	const char *bad;	/* non-NULL: malformed line, with the reason */
};
struct cfg_file {
	struct cfg_entry *e;
	int n;
};
int cfg_parse(const char *path, struct cfg_file *c);
void cfg_free(struct cfg_file *c);

struct lint_opts {
	const char *cfgdir, *pamdir, *otpdir, *sysfs, *secfs;
	int quiet;	/* only problems and the summary */
	int no_pam;	/* skip the PAM checks */
	int pam_soft;	/* report PAM errors as warnings (load's preflight) */
	int source_tree;	/* not installed: no owner/machine/kernel/PAM checks */
};
int policy_lint(const struct lint_opts *o);	/* returns the error count */
int cmd_lint(int argc, char **argv);

/* vault_allow.c */
int  cmd_vault_allow(int argc, char **argv);
void vault_allow_usage(void);

/* detect_admins.c */
int cmd_detect_admins(int argc, char **argv);

#endif
