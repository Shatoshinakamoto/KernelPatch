/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 Johnathan Edward Brown */
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

#ifndef SS_STATE_DIR
#define SS_STATE_DIR "/var/lib/secure_sudo"
#endif

#ifndef BOOT_ID_FILE
#define BOOT_ID_FILE "/proc/sys/kernel/random/boot_id"
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
const char *check_daemon_value(const char *key, const char *v, char *why,
			       size_t n);

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

/* node_scan.c: find SEA/pkg/renamed node runtimes for the Node guard (#11) */
int cmd_node_scan(int argc, char **argv);
/* Manual entries, then found ones, within the kernel's limits (256 / 64 KiB). */
int node_sea_merge(const char *manual, size_t mlen, const char *autol,
		   size_t alen, char **out, size_t *outlen, int *added,
		   int *dropped);
char *node_sea_read_file(const char *path, size_t *len);
const char *node_sea_auto_path(void);

/* policy_state.c: preview, snapshots, change history, restore (P1-6) */
struct ps_record {
	const char *action, *result, *detail, *rejected_keys;
	const char *snapshot, *snapshot_sums;	/* taken before the change */
	const char *restored_from;
	int lint_errors, changes;		/* -1: not measured */
	int accepted, rejected, skipped;
};
int knob_values_equal(const struct knob *k, const char *cfg, const char *live);
char *policy_list_payload(const struct listmap *m, size_t *len, int *have,
			  int *auto_added, int *auto_dropped);
int policy_locked(void);	/* 1, 0, or -1 when unknown */
int policy_live_digest(char out[65]);	/* P2-1 attestation */
int policy_diff(int print);	/* differences config vs kernel, -1: no LSM */
int policy_snapshot(const char *reason, char *id, size_t idlen, char *sums,
		    size_t sumslen);
int policy_history_append(const struct ps_record *r);
int cmd_diff(int argc, char **argv);
int cmd_snapshot(int argc, char **argv);
int cmd_history(int argc, char **argv);
int cmd_restore(int argc, char **argv);
/* secure-sudo.c: load, recorded as @action ("load" or "restore") */
int policy_load(int force, const char *action, const char *restored_from,
		const char *pre_snap, const char *pre_sums);

/* detect_admins.c */
int cmd_detect_admins(int argc, char **argv);

#endif
