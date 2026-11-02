// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * policy.c - the policy model shared by `load` and `lint` (TODO P0-6).
 *
 *   - every kernel setting, with the type and range its sysfs store handler
 *     accepts (kept in step with kernel/security/secure_sudo/; the kernel
 *     stays the authority, this lets mistakes be caught before anything is
 *     written);
 *   - the policy lists and the daemon-only keys;
 *   - the secure-sudo.conf parser;
 *   - `secure-sudo lint`: a read-only preflight of the configuration, the
 *     admin groups, the allowlists, setting combinations, the PAM stacks and
 *     what the one-way locks will do, before enforcement is engaged.
 *
 * `load` runs the same checks first and refuses to touch the kernel when they
 * find an error, so a typo cannot leave the machine on half a policy.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>

#include "cli.h"

static const char *const net_modes[] = {
	"monitor", "host", "lan-only", "public-only", NULL
};

const struct knob ss_knobs[] = {
	{ "admin_gid",             "admin_gid",             K_GIDS, 0, 0 },
	{ "block_setid",           "block_setid",           K_BOOL, 0, 1 },
	{ "block_userns",          "block_userns",          K_BOOL, 0, 1 },
	{ "block_setid_exec",      "block_setid_exec",      K_BOOL, 0, 1 },
	{ "block_flash",           "block_flash",           K_BOOL, 0, 1 },
	{ "ram_spike_enabled",     "ram_spike_enabled",     K_BOOL, 0, 1 },
	{ "max_ram_percent",       "max_ram_percent",       K_U32, 1, 100 },
	{ "check_interval_ms",     "check_interval_ms",     K_U32, 100, 3600UL * 1000 },
	{ "drop_cooldown_ms",      "drop_cooldown_ms",      K_U32, 1000, 24UL * 3600 * 1000 },
	{ "block_tmp_exec",        "block_tmp_exec",        K_BOOL, 0, 1 },
	{ "block_tmpfs_exec",      "block_tmpfs_exec",      K_BOOL, 0, 1 },
	{ "net_mode",              "net_mode",              K_ENUM, 0, 0 },
	{ "sudo_max_fails",        "sudo_max_fails",        K_U32, 1, 1000 },
	{ "sudo_window_sec",       "sudo_window_sec",       K_U32, 1, 86400 },
	{ "sudo_block_time_sec",   "sudo_block_time_sec",   K_U32, 1, 7UL * 86400 },
	{ "sudo_cooldown_enabled", "sudo_cooldown_enabled", K_BOOL, 0, 1 },
	{ "block_home_write",      "block_home_write",      K_BOOL, 0, 1 },
	{ "timevault_strict_mmap", "timevault_strict_mmap", K_BOOL, 0, 1 },
	{ "lock_modules",          "lock_modules",          K_BOOL, 0, 1 },
	{ "binaryvault",           "binaryvault",           K_BOOL, 0, 1 },
	{ "block_wifi",            "block_wifi",            K_BOOL, 0, 1 },
	{ "block_bluetooth",       "block_bluetooth",       K_BOOL, 0, 1 },
	{ "ethernet_only",         "ethernet_only",         K_BOOL, 0, 1 },
	{ "timevault_allow_autoupdate", "timevault_allow_autoupdate", K_BOOL, 0, 1 },
	{ "timevault_max_entries", "timevault_max_entries", K_U32, 1, 131072 },
	{ "prguard_enabled",       "prguard_enabled",       K_BOOL, 0, 1 },
	{ "prguard_observe",       "prguard_observe",       K_BOOL, 0, 1 },
	{ "bpf_guard",             "bpf_guard",             K_BOOL, 0, 1 },
	{ "bpf_lock_tracing",      "bpf_lock_tracing",      K_BOOL, 0, 1 },
	{ "perf_guard",            "perf_guard",            K_BOOL, 0, 1 },
	{ "sysctl_guard",          "sysctl_guard",          K_BOOL, 0, 1 },
	{ "audit_events",          "audit_events",          K_BOOL, 0, 1 },
	{ "lock_confidentiality",  "lock_confidentiality",  K_BOOL, 0, 1 },
};
const size_t ss_nknobs = sizeof(ss_knobs) / sizeof(ss_knobs[0]);

const struct listmap ss_lists[] = {
	{ "blacklist.conf",             "blacklist",             L_PATH },
	{ "setid_exec_allow.conf",      "setid_exec_allow",      L_PATH },
	{ "tmp_exec_allow.conf",        "tmp_exec_allow",        L_PREFIX },
	{ "node_allowed_children.conf", "node_allowed_children", L_NAME },
	{ "node_sea_binaries.conf",     "node_sea_binaries",     L_PATH },
	{ "driver_blacklist.conf",      "driver_blacklist",      L_NAME },
	{ "timevault_allow.conf",       "timevault_allow",       L_PATH },
	{ "home_map.conf",              "home_map",              L_HOMEMAP },
	{ "home_write_allow.conf",      "home_write_allow",      L_PREFIX },
	{ "binvault_allow.conf",        "binvault_allow",        L_PREFIX },
	{ "prguard_allow.conf",         "prguard_allow",         L_PATH },
	{ "tpm_openers.conf",           "tpm_openers",           L_PATH },
};
const size_t ss_nlists = sizeof(ss_lists) / sizeof(ss_lists[0]);

/* Keys read by secure-sudod, not the kernel. */
static const char *const daemon_keys[] = {
	"retain_days", "max_total_mb", "remote_syslog", "vault_action",
	"vault_watch", "remote_syslog_transport", "remote_syslog_ca_file",
	"remote_queue_max_mb", "node_sea_scan_dirs", "node_sea_scan_interval",
	"alert_cmd", "alert_min_severity", "alert_dedup_seconds",
	"alert_max_per_minute", "alert_timeout_seconds",
	NULL
};

const struct knob *find_knob(const char *key)
{
	size_t i;

	for (i = 0; i < ss_nknobs; i++)
		if (!strcmp(ss_knobs[i].cfg_key, key))
			return &ss_knobs[i];
	return NULL;
}

const struct listmap *find_list(const char *name)
{
	size_t i;

	for (i = 0; i < ss_nlists; i++)
		if (!strcmp(ss_lists[i].secfs, name) ||
		    !strcmp(ss_lists[i].cfg_file, name))
			return &ss_lists[i];
	return NULL;
}

int is_daemon_key(const char *key)
{
	int i;

	for (i = 0; daemon_keys[i]; i++)
		if (!strcmp(daemon_keys[i], key))
			return 1;
	return 0;
}

/* ------------------------------------------------------------ parsing */

static char *trim(char *s)
{
	char *e;

	while (isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = '\0';
	return s;
}

void cfg_free(struct cfg_file *c)
{
	free(c->e);
	c->e = NULL;
	c->n = 0;
}

/*
 * Parse secure-sudo.conf: "key = value" lines, '#' starts a comment line.
 * Malformed lines are kept as entries with bad != NULL so both load and lint
 * can report them by line number. Returns -1 (errno set) if the file cannot
 * be read.
 */
int cfg_parse(const char *path, struct cfg_file *c)
{
	char line[1024];
	FILE *f;
	int no = 0;

	memset(c, 0, sizeof(*c));
	f = fopen(path, "re");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		struct cfg_entry *e, *grown;
		char *p, *eq;
		size_t len = strlen(line);

		no++;
		if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
			int ch;

			while ((ch = fgetc(f)) != EOF && ch != '\n')
				;		/* drop the rest of the long line */
			line[0] = 'x';		/* force a "bad" entry below */
			line[1] = '\0';
		}
		p = trim(line);
		if (!*p || *p == '#')
			continue;
		grown = realloc(c->e, (c->n + 1) * sizeof(*c->e));
		if (!grown) {
			fclose(f);
			errno = ENOMEM;
			return -1;
		}
		c->e = grown;
		e = &c->e[c->n++];
		memset(e, 0, sizeof(*e));
		e->line = no;
		if (len == sizeof(line) - 1 && !strcmp(p, "x")) {
			e->bad = "line too long";
			continue;
		}
		eq = strchr(p, '=');
		if (!eq) {
			e->bad = "not a \"key = value\" line";
			snprintf(e->key, sizeof(e->key), "%.*s", (int)sizeof(e->key) - 1, p);
			continue;
		}
		*eq = '\0';
		snprintf(e->key, sizeof(e->key), "%s", trim(p));
		snprintf(e->val, sizeof(e->val), "%s", trim(eq + 1));
		if (!e->key[0])
			e->bad = "empty key";
	}
	fclose(f);
	return 0;
}

static int parse_bool(const char *v)
{
	static const char *const t[] = { "1", "yes", "on", "true", "y", NULL };
	static const char *const n[] = { "0", "no", "off", "false", "n", NULL };
	int i;

	for (i = 0; t[i]; i++)
		if (!strcasecmp(v, t[i]))
			return 1;
	for (i = 0; n[i]; i++)
		if (!strcasecmp(v, n[i]))
			return 0;
	return -1;
}

/* Truth value of a boolean setting in @c, or @dflt if absent/invalid. */
static int cfg_bool(const struct cfg_file *c, const char *key, int dflt)
{
	int i, v = dflt;

	for (i = 0; i < c->n; i++)
		if (!c->e[i].bad && !strcmp(c->e[i].key, key) &&
		    parse_bool(c->e[i].val) >= 0)
			v = parse_bool(c->e[i].val);
	return v;
}

static const char *cfg_get(const struct cfg_file *c, const char *key)
{
	const char *v = NULL;
	int i;

	for (i = 0; i < c->n; i++)
		if (!c->e[i].bad && !strcmp(c->e[i].key, key))
			v = c->e[i].val;
	return v;
}

/* Parse "unset" or "27,10 4" into @gids; returns count, -1 bad, -2 too many. */
static int parse_gids(const char *v, unsigned long *gids, int max)
{
	char buf[448], *p, *tok, *save = NULL;
	int n = 0;

	if (!strcmp(v, "unset"))
		return 0;
	snprintf(buf, sizeof(buf), "%s", v);
	for (p = buf; (tok = strtok_r(p, ", \t", &save)); p = NULL) {
		char *end;
		unsigned long g;

		errno = 0;
		g = strtoul(tok, &end, 10);
		if (*end || end == tok || errno || g > 0xffffffffUL || tok[0] == '-')
			return -1;
		if (n >= max)
			return -2;
		gids[n++] = g;
	}
	return n ? n : -1;
}

/* Check a value against a setting's type. NULL if fine, else a reason. */
const char *check_value(const struct knob *k, const char *v, char *why, size_t n)
{
	unsigned long g[SS_MAX_GIDS];
	int i;

	if (strchr(v, '#')) {
		snprintf(why, n, "'#' in a value: comments must be on their own line");
		return why;
	}
	switch (k->type) {
	case K_BOOL:
		if (parse_bool(v) < 0) {
			snprintf(why, n, "not a boolean (use 0 or 1)");
			return why;
		}
		return NULL;
	case K_U32: {
		char *end;
		unsigned long x;

		errno = 0;
		x = strtoul(v, &end, 10);
		if (!*v || *end || errno || v[0] == '-') {
			snprintf(why, n, "not a whole number");
			return why;
		}
		if (x < k->lo || x > k->hi) {
			snprintf(why, n, "out of range (%lu..%lu)", k->lo, k->hi);
			return why;
		}
		return NULL;
	}
	case K_ENUM:
		for (i = 0; net_modes[i]; i++)
			if (!strcmp(v, net_modes[i]))
				return NULL;
		snprintf(why, n, "not one of monitor, host, lan-only, public-only");
		return why;
	case K_GIDS:
		i = parse_gids(v, g, SS_MAX_GIDS);
		if (i == -1) {
			snprintf(why, n, "not \"unset\" or a list of numeric GIDs");
			return why;
		}
		if (i == -2) {
			snprintf(why, n, "more than %d GIDs", SS_MAX_GIDS);
			return why;
		}
		return NULL;
	}
	return NULL;
}

const char *check_daemon_value(const char *key, const char *v,
			       char *why, size_t n)
{
	if (!strcmp(key, "retain_days") || !strcmp(key, "max_total_mb")) {
		char *end;
		long x = strtol(v, &end, 10);

		if (!*v || *end || x < 1) {
			snprintf(why, n, "not a positive whole number");
			return why;
		}
	} else if (!strcmp(key, "vault_action")) {
		if (strcmp(v, "quarantine") && strcmp(v, "wipe")) {
			snprintf(why, n, "not quarantine or wipe");
			return why;
		}
	} else if (!strcmp(key, "remote_syslog")) {
		const char *colon = strrchr(v, ':');

		if (*v && (!colon || !colon[1] ||
			   strspn(colon + 1, "0123456789") != strlen(colon + 1) ||
			   (colon == v && v[0] != '[') ||
			   (v[0] == '[' && (!strchr(v, ']') ||
			    strchr(v, ']') != colon - 1 ||
			    strchr(v, ']') == v + 1)))) {
			snprintf(why, n, "not host:port");
			return why;
		}
		if (*v && colon) {
			char *end;
			long port = strtol(colon + 1, &end, 10);

			if (*end || port < 1 || port > 65535) {
				snprintf(why, n, "port is outside 1..65535");
				return why;
			}
		}
	} else if (!strcmp(key, "remote_syslog_transport")) {
		if (strcmp(v, "udp") && strcmp(v, "tls")) {
			snprintf(why, n, "not udp or tls");
			return why;
		}
	} else if (!strcmp(key, "remote_syslog_ca_file")) {
		if (!*v || *v != '/') {
			snprintf(why, n, "not an absolute path");
			return why;
		}
	} else if (!strcmp(key, "remote_queue_max_mb")) {
		char *end;
		long size = strtol(v, &end, 10);

		if (!*v || *end || size < 1 || size > 1024) {
			snprintf(why, n, "out of range (1..1024)");
			return why;
		}
	} else if (!strcmp(key, "alert_min_severity")) {
		if (strcmp(v, "info") && strcmp(v, "low") && strcmp(v, "medium") &&
		    strcmp(v, "high") && strcmp(v, "critical")) {
			snprintf(why, n, "not info, low, medium, high or critical");
			return why;
		}
	} else if (!strcmp(key, "alert_dedup_seconds") ||
		   !strcmp(key, "alert_max_per_minute") ||
		   !strcmp(key, "alert_timeout_seconds")) {
		char *end;
		long x = strtol(v, &end, 10);
		long lo = key[6] == 'd' ? 0 : 1;
		long hi = key[6] == 'd' ? 86400 : key[6] == 'm' ? 600 : 300;

		if (!*v || *end || x < lo || x > hi) {
			snprintf(why, n, "out of range (%ld..%ld)", lo, hi);
			return why;
		}
	} else if (!strcmp(key, "alert_cmd")) {
		/* the daemon runs it without a shell: quotes must balance and
		 * only its placeholders may appear (%s %t %d %r %o %u %m %j %h %n %%) */
		const char *q;
		char open = 0;

		for (q = v; *q; q++) {
			if (*q == '\\' && open != '\'' && q[1]) {
				q++;
				continue;
			}
			if (!open && (*q == '\'' || *q == '"'))
				open = *q;
			else if (open && *q == open)
				open = 0;
			else if (*q == '%' && (!q[1] || !strchr("stdromujhn%", q[1]))) {
				snprintf(why, n, "unknown placeholder %%%c", q[1] ? q[1] : ' ');
				return why;
			} else if (*q == '%')
				q++;
		}
		if (open) {
			snprintf(why, n, "unbalanced %c quote", open);
			return why;
		}
	} else if (!strcmp(key, "node_sea_scan_interval")) {
		char *end;
		long m = strtol(v, &end, 10);

		if (!*v || *end || m < 0 || m > 10080) {
			snprintf(why, n, "out of range (0 = off, else 1..10080 minutes)");
			return why;
		}
	} else if (!strcmp(key, "vault_watch") || !strcmp(key, "node_sea_scan_dirs")) {
		char buf[448], *p, *tok, *save = NULL;

		snprintf(buf, sizeof(buf), "%s", v);
		for (p = buf; (tok = strtok_r(p, ",", &save)); p = NULL) {
			tok = trim(tok);
			if (*tok && *tok != '/') {
				snprintf(why, n, "'%s' is not an absolute directory", tok);
				return why;
			}
		}
	}
	return NULL;
}

/* -------------------------------------------------------------- lint */

struct lint {
	int errors, warnings, notes, quiet, pam_errors_are_warnings, source_tree;
	const char *cfgdir, *pamdir, *otpdir, *sysfs, *secfs;
};

static void say(struct lint *l, int level, const char *where, const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));
static void say(struct lint *l, int level, const char *where, const char *fmt, ...)
{
	static const char *const tag[] = { "note ", "WARN ", "ERROR" };
	va_list ap;

	if (level == 2)
		l->errors++;
	else if (level == 1)
		l->warnings++;
	else
		l->notes++;
	if (l->quiet && level == 0)
		return;
	printf("  %s  %-26s ", tag[level], where);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
}
enum { NOTE, WARN, ERR };

/* Root-owned and not writable by anyone else (group root is tolerated). */
static void check_owner(struct lint *l, const char *path, const char *what)
{
	struct stat st;

	if (l->source_tree || stat(path, &st) != 0)
		return;
	if (st.st_uid != 0 || (st.st_mode & S_IWOTH) ||
	    ((st.st_mode & S_IWGRP) && st.st_gid != 0))
		say(l, ERR, what, "owned by uid %u, mode %04o: anyone who can write it "
		    "controls the policy at the next load (want root-owned, not "
		    "group/world-writable)", (unsigned)st.st_uid,
		    (unsigned)(st.st_mode & 07777));
}

/* Count entries in a list file and check their shape. -1 if missing. */
static int lint_list(struct lint *l, const struct listmap *m)
{
	char path[512], line[1024], where[96];
	FILE *f;
	int n = 0, no = 0;

	snprintf(path, sizeof(path), "%s/%s", l->cfgdir, m->cfg_file);
	f = fopen(path, "re");
	if (!f) {
		say(l, WARN, m->cfg_file, "missing: load will CLEAR the kernel's %s list",
		    m->secfs);
		return -1;
	}
	check_owner(l, path, m->cfg_file);
	while (fgets(line, sizeof(line), f)) {
		char *p = trim(line), *sp;
		struct stat st;

		no++;
		if (!*p || *p == '#')
			continue;
		n++;
		snprintf(where, sizeof(where), "%s:%d", m->cfg_file, no);
		switch (m->kind) {
		case L_PATH:
		case L_PREFIX:
			sp = strpbrk(p, " \t");
			if (sp)
				*sp = '\0';	/* timevault_allow: "path [sha256]" */
			if (*p != '/')
				say(l, ERR, where, "'%s' is not an absolute path", p);
			else if (m->kind == L_PATH && !l->source_tree && stat(p, &st) != 0)
				say(l, WARN, where, "%s does not exist on this machine", p);
			break;
		case L_HOMEMAP: {
			char *end;
			unsigned long uid = strtoul(p, &end, 10);

			if (end == p || !isspace((unsigned char)*end) ||
			    *trim(end) != '/')
				say(l, ERR, where, "want \"<uid> <absolute home>\"");
			else if (!l->source_tree && !getpwuid((uid_t)uid))
				say(l, WARN, where, "no user with uid %lu", uid);
			break;
		}
		case L_NAME:
			if (strchr(p, '/'))
				say(l, ERR, where, "'%s': a name, not a path, is expected", p);
			break;
		}
	}
	fclose(f);
	return n;
}

/* Is @uid in group @gid (as primary or supplementary member)? */
static int in_group(uid_t uid, gid_t gid)
{
	struct passwd *pw = getpwuid(uid);
	struct group *gr;
	char **m;

	if (!pw)
		return 0;
	if (pw->pw_gid == gid)
		return 1;
	gr = getgrgid(gid);
	for (m = gr ? gr->gr_mem : NULL; m && *m; m++)
		if (!strcmp(*m, pw->pw_name))
			return 1;
	return 0;
}

static int group_has_members(gid_t gid)
{
	struct group *gr = getgrgid(gid);
	struct passwd *pw;
	int found = 0;

	if (gr && gr->gr_mem && gr->gr_mem[0])
		return 1;
	setpwent();
	while (!found && (pw = getpwent()))
		if (pw->pw_gid == gid && pw->pw_uid != 0)
			found = 1;
	endpwent();
	return found;
}

static void lint_admins(struct lint *l, const struct cfg_file *c)
{
	unsigned long g[SS_MAX_GIDS];
	const char *v = cfg_get(c, "admin_gid");
	const char *su = getenv("SUDO_UID");
	int n, i, me_in = 0, setid_exec = cfg_bool(c, "block_setid_exec", 0);
	uid_t me = su ? (uid_t)strtoul(su, NULL, 10) : getuid();
	struct passwd *pw = getpwuid(me);

	if (!v)
		v = "unset";
	n = parse_gids(v, g, SS_MAX_GIDS);
	if (n < 0 || (n > 0 && l->source_tree))
		return;	/* bad value (reported already), or not this machine's */
	if (n == 0) {
		if (setid_exec)
			say(l, ERR, "admin_gid", "unset with block_setid_exec = 1: only root may "
			    "run sudo/su; every other admin is locked out (run "
			    "`secure-sudo detect-admins -n`)");
		else
			say(l, NOTE, "admin_gid", "unset: only root counts as a sudo user "
			    "(sudo still works because it runs as root)");
		return;
	}
	for (i = 0; i < n; i++) {
		struct group *gr = getgrgid((gid_t)g[i]);

		if (!gr)
			say(l, ERR, "admin_gid", "GID %lu does not exist on this machine", g[i]);
		else if (!group_has_members((gid_t)g[i]))
			say(l, WARN, "admin_gid", "group %s (%lu) has no members", gr->gr_name, g[i]);
		if (me != 0 && in_group(me, (gid_t)g[i]))
			me_in = 1;
	}
	if (me != 0 && !me_in)
		say(l, setid_exec ? ERR : WARN, "admin_gid",
		    "you (%s, uid %u) are in none of these groups: after load you count "
		    "as a non-sudo user%s", pw ? pw->pw_name : "?", (unsigned)me,
		    setid_exec ? " and can no longer run sudo" : "");
}

/* ------------------------------------------------------------- PAM */

static const char *const verifiers[] = {
	"pam_unix.so", "pam_sss.so", "pam_ldap.so", "pam_krb5.so",
	"pam_winbind.so", "pam_systemd_home.so", "pam_userdb.so", NULL
};

static int module_installed(const char *mod)
{
	static const char *const dirs[] = {
		"/lib/security", "/lib64/security", "/usr/lib/security",
		"/usr/lib64/security", "/lib/x86_64-linux-gnu/security",
		"/usr/lib/x86_64-linux-gnu/security",
		"/lib/aarch64-linux-gnu/security",
		"/usr/lib/aarch64-linux-gnu/security", NULL
	};
	char p[256];
	int i;

	if (mod[0] == '/')
		return access(mod, F_OK) == 0;
	for (i = 0; dirs[i]; i++) {
		snprintf(p, sizeof(p), "%s/%s", dirs[i], mod);
		if (access(p, F_OK) == 0)
			return 1;
	}
	return 0;
}

struct pamscan {
	int pos;		/* auth lines seen, includes expanded */
	int verifier;		/* position of first verifier (0 = none) */
	int ss, ss_explicit, otp, otp_first_pass, otp_sufficient;
	char otp_mod[256], ss_mod[256];
	int die_verifier;	/* "[default=die]" on a verifier */
};

static int basename_is(const char *path, const char *name)
{
	const char *b = strrchr(path, '/');

	return !strcmp(b ? b + 1 : path, name);
}

static void pam_scan(struct lint *l, const char *file, struct pamscan *s, int depth)
{
	char path[512], line[1024];
	FILE *f;

	if (depth > 4)
		return;
	snprintf(path, sizeof(path), "%s/%s", l->pamdir, file);
	f = fopen(path, "re");
	if (!f) {
		if (depth)
			say(l, WARN, file, "included PAM file %s is missing", path);
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		char *p = trim(line), *type, *ctl, *mod, *rest, *save = NULL;
		int i, is_verifier = 0;

		if (!*p || *p == '#')
			continue;
		if (!strncmp(p, "@include", 8) && isspace((unsigned char)p[8])) {
			pam_scan(l, trim(p + 8), s, depth + 1);
			continue;
		}
		if (*p == '-')
			p++;		/* "-auth": skip silently if module missing */
		type = strtok_r(p, " \t", &save);
		if (!type || strcmp(type, "auth"))
			continue;
		if (save && *save == '[') {	/* bracketed control may hold spaces */
			char *close = strchr(save, ']');

			if (!close)
				continue;
			ctl = save;
			*++close = '\0';
			save = close + 1;
		} else {
			ctl = strtok_r(NULL, " \t", &save);
		}
		mod = strtok_r(NULL, " \t", &save);
		rest = save ? save : (char *)"";
		if (!ctl || !mod)
			continue;
		if (!strcmp(ctl, "include") || !strcmp(ctl, "substack")) {
			pam_scan(l, mod, s, depth + 1);
			continue;
		}
		s->pos++;
		for (i = 0; verifiers[i]; i++)
			if (basename_is(mod, verifiers[i]))
				is_verifier = 1;
		if (is_verifier) {
			if (!s->verifier)
				s->verifier = s->pos;
			if (!strcmp(ctl, "[default=die]"))
				s->die_verifier = 1;
		}
		if (basename_is(mod, "pam_secure_sudo.so") && !s->ss) {
			s->ss = s->pos;
			snprintf(s->ss_mod, sizeof(s->ss_mod), "%s", mod);
			if (strstr(rest, "authfail") || strstr(rest, "authsucc"))
				s->ss_explicit = 1;
		}
		if (basename_is(mod, "pam_secure_otp.so") && !s->otp) {
			s->otp = s->pos;
			snprintf(s->otp_mod, sizeof(s->otp_mod), "%s", mod);
			s->otp_first_pass = strstr(rest, "use_first_pass") != NULL;
			s->otp_sufficient = !strcmp(ctl, "sufficient");
		}
	}
	fclose(f);
}

static void lint_pam(struct lint *l, const struct cfg_file *c)
{
	static const char *const services[] = { "sudo", "su", NULL };
	int level_err = l->pam_errors_are_warnings ? WARN : ERR;
	char otp_secret[512];
	int i;

	snprintf(otp_secret, sizeof(otp_secret), "%s/secret.enc", l->otpdir);
	for (i = 0; services[i]; i++) {
		struct pamscan s;
		char where[64], path[512];

		memset(&s, 0, sizeof(s));
		snprintf(where, sizeof(where), "pam.d/%s", services[i]);
		snprintf(path, sizeof(path), "%s/%s", l->pamdir, services[i]);
		if (access(path, F_OK) != 0)
			continue;
		pam_scan(l, services[i], &s, 0);

		if (s.die_verifier)
			say(l, level_err, where, "a password module with control "
			    "[default=die] fails every login, including the right "
			    "password (the old documented secure_sudo stack); use "
			    "\"auth optional pam_secure_sudo.so\" instead");
		if (s.ss && s.ss_explicit)
			say(l, WARN, where, "pam_secure_sudo.so authfail/authsucc only "
			    "reports correctly in a stack that branches on the "
			    "password result; the one-line form is recommended");
		else if (s.ss && s.verifier && s.ss > s.verifier)
			say(l, WARN, where, "pam_secure_sudo.so comes after the password "
			    "check: an attempt that stops the stack early is never "
			    "reported; move it to the first auth line");
		if (s.ss && !module_installed(s.ss_mod))
			say(l, WARN, where, "%s is not installed", s.ss_mod);
		if (!strcmp(services[i], "sudo") && !s.ss &&
		    cfg_bool(c, "sudo_cooldown_enabled", 1))
			say(l, WARN, where, "sudo_cooldown_enabled = 1 but pam_secure_sudo.so "
			    "is not in the sudo stack: no failure is ever reported, so "
			    "the cooldown never triggers");
		if (!s.otp)
			continue;
		if (!module_installed(s.otp_mod))
			say(l, level_err, where, "%s is not installed: every %s login "
			    "fails", s.otp_mod, services[i]);
		if (access(otp_secret, F_OK) != 0)
			say(l, level_err, where, "pam_secure_otp.so is wired but no OTP is "
			    "set up (%s missing): every %s login fails; run "
			    "`secure-sudo otp setup` first", otp_secret, services[i]);
		if (s.otp_first_pass && (!s.verifier || s.otp < s.verifier))
			say(l, level_err, where, "pam_secure_otp.so use_first_pass comes "
			    "before any password module: there is no password to take, "
			    "so every login fails");
		if (s.otp_sufficient && (!s.verifier || s.otp < s.verifier))
			say(l, NOTE, where, "pam_secure_otp.so is 'sufficient' before the "
			    "password check: a valid OTP alone grants %s", services[i]);
	}
}

/* -------------------------------------------------- combinations/locks */

static int list_entries(struct lint *l, const char *file)
{
	char path[512], line[1024];
	FILE *f;
	int n = 0;

	snprintf(path, sizeof(path), "%s/%s", l->cfgdir, file);
	f = fopen(path, "re");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		char *p = trim(line);

		if (*p && *p != '#')
			n++;
	}
	fclose(f);
	return n;
}

static void lint_combinations(struct lint *l, const struct cfg_file *c)
{
	const char *v;

	if (cfg_bool(c, "prguard_observe", 0) && !cfg_bool(c, "prguard_enabled", 0))
		say(l, WARN, "prguard_observe", "has no effect while prguard_enabled = 0");
	if (cfg_bool(c, "block_setid_exec", 0) && !list_entries(l, "setid_exec_allow.conf"))
		say(l, WARN, "block_setid_exec", "setid_exec_allow.conf is empty: non-sudo "
		    "users cannot run passwd, su, newgrp or any setuid program");
	if (cfg_bool(c, "block_home_write", 0) && !list_entries(l, "home_map.conf"))
		say(l, ERR, "block_home_write", "home_map.conf is empty: non-sudo users "
		    "could not even write to their own homes");
	if (cfg_bool(c, "timevault_strict_mmap", 0) &&
	    !list_entries(l, "timevault_allow.conf"))
		say(l, WARN, "timevault_strict_mmap", "timevault_allow.conf is empty: "
		    "with the vault engaged no shared library could be mapped");
	if (cfg_bool(c, "binaryvault", 0))
		say(l, NOTE, "binaryvault", "protected binaries cannot be updated until "
		    "a maintenance boot (docs/BINARYVAULT.md)");
	if (cfg_bool(c, "block_wifi", 0) || cfg_bool(c, "ethernet_only", 0))
		say(l, NOTE, "radio", "Wi-Fi is blocked once loaded: make sure this "
		    "machine has another way in");
	v = cfg_get(c, "net_mode");
	if (v && (!strcmp(v, "lan-only") || !strcmp(v, "public-only")))
		say(l, NOTE, "net_mode", "%s is applied by secure-sudod with nft; keep "
		    "a local console in case the rules cut your session", v);
	v = cfg_get(c, "vault_action");
	if (v && !strcmp(v, "wipe"))
		say(l, WARN, "vault_action", "wipe deletes flagged files instead of "
		    "quarantining them: the evidence is lost");
	if (cfg_get(c, "timevault_enabled"))
		say(l, NOTE, "timevault_enabled", "not applied by load: engaging TimeVault "
		    "also locks the configuration until reboot, so it is only ever "
		    "done by hand (`secure-sudo timevault on`)");

	/* What the one-way lock (`secure-sudo lock`, or engaging TimeVault)
	 * will do with this configuration. */
	say(l, NOTE, "lock (one-way)", "after `secure-sudo lock` no setting or list "
	    "can change until reboot; kexec%s%s are refused",
	    cfg_bool(c, "lock_modules", 0) ? ", ALL kernel module loads (load the "
	    "drivers you need first)" : "",
	    cfg_bool(c, "lock_confidentiality", 0) ? ", and reading kernel memory "
	    "(kprobes, perf, BPF tracing, /proc/kcore)" : "");
}

/* --------------------------------------------------------- the lint */

static void lint_kernel(struct lint *l, const struct cfg_file *c)
{
	char path[512], buf[16] = "";
	FILE *f;
	int i;

	if (access(l->sysfs, F_OK) != 0) {
		say(l, NOTE, "kernel", "secure_sudo LSM not active here: kernel support "
		    "for each setting not checked");
		return;
	}
	snprintf(path, sizeof(path), "%s/lock", l->sysfs);
	f = fopen(path, "re");
	if (f) {
		if (fgets(buf, sizeof(buf), f) && buf[0] == '1')
			say(l, ERR, "kernel", "the configuration is locked until reboot: "
			    "load cannot change anything");
		fclose(f);
	}
	for (i = 0; i < c->n; i++) {
		const struct knob *k = c->e[i].bad ? NULL : find_knob(c->e[i].key);

		if (!k)
			continue;
		snprintf(path, sizeof(path), "%s/%s", l->sysfs, k->sysfs);
		if (access(path, F_OK) != 0)
			say(l, ERR, k->cfg_key, "the running kernel has no %s (older "
			    "secure_sudo, or the feature is compiled out)", path);
	}
	for (i = 0; i < (int)ss_nlists; i++) {
		snprintf(path, sizeof(path), "%s/%s", l->secfs, ss_lists[i].secfs);
		if (access(path, F_OK) != 0)
			say(l, WARN, ss_lists[i].cfg_file, "the running kernel has no %s",
			    path);
	}
}

int policy_lint(const struct lint_opts *o)
{
	struct lint l = {
		.quiet = o->quiet, .pam_errors_are_warnings = o->pam_soft,
		.source_tree = o->source_tree,
		.cfgdir = o->cfgdir, .pamdir = o->pamdir, .otpdir = o->otpdir,
		.sysfs = o->sysfs, .secfs = o->secfs,
	};
	struct cfg_file c;
	char path[512], why[160], where[96];
	int i, j;
	size_t k;

	snprintf(path, sizeof(path), "%s/secure-sudo.conf", l.cfgdir);
	if (!l.quiet)
		printf("secure-sudo lint: %s\n", l.cfgdir);
	check_owner(&l, l.cfgdir, "config dir");
	if (cfg_parse(path, &c) != 0) {
		say(&l, ERR, "secure-sudo.conf", "cannot read %s: %s", path, strerror(errno));
		memset(&c, 0, sizeof(c));
	} else {
		check_owner(&l, path, "secure-sudo.conf");
	}

	for (i = 0; i < c.n; i++) {
		struct cfg_entry *e = &c.e[i];
		const struct knob *kn;

		snprintf(where, sizeof(where), "secure-sudo.conf:%d", e->line);
		if (e->bad) {
			say(&l, ERR, where, "%s", e->bad);
			continue;
		}
		for (j = 0; j < i; j++)
			if (!c.e[j].bad && !strcmp(c.e[j].key, e->key))
				say(&l, WARN, where, "%s is set again (first on line %d); "
				    "the last value wins", e->key, c.e[j].line);
		kn = find_knob(e->key);
		if (kn) {
			if (check_value(kn, e->val, why, sizeof(why)))
				say(&l, ERR, where, "%s = %s: %s", e->key, e->val, why);
		} else if (is_daemon_key(e->key)) {
			if (check_daemon_value(e->key, e->val, why, sizeof(why)))
				say(&l, ERR, where, "%s = %s: %s", e->key, e->val, why);
		} else if (strcmp(e->key, "timevault_enabled")) {
			say(&l, ERR, where, "unknown setting '%s' (typo?); "
			    "`secure-sudo settings` lists them", e->key);
		}
	}
	for (k = 0; k < ss_nlists; k++)
		lint_list(&l, &ss_lists[k]);
	lint_admins(&l, &c);
	lint_combinations(&l, &c);
	if (!o->source_tree)
		lint_kernel(&l, &c);
	if (!o->no_pam && !o->source_tree)
		lint_pam(&l, &c);
	cfg_free(&c);

	if (!l.quiet || l.errors || l.warnings)
		printf("lint: %d error(s), %d warning(s), %d note(s)\n",
		       l.errors, l.warnings, l.notes);
	return l.errors;
}

int cmd_lint(int argc, char **argv)
{
	struct lint_opts o = {
		.cfgdir = CONFIG_DIR, .pamdir = "/etc/pam.d",
		.otpdir = "/var/lib/secure_sudo/otp", .sysfs = SYSFS, .secfs = SECFS,
	};
	int i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--config-dir") && i + 1 < argc)
			o.cfgdir = argv[++i];
		else if (!strcmp(argv[i], "--pam-dir") && i + 1 < argc)
			o.pamdir = argv[++i];
		else if (!strcmp(argv[i], "--otp-dir") && i + 1 < argc)
			o.otpdir = argv[++i];
		else if (!strcmp(argv[i], "--no-kernel"))
			o.sysfs = o.secfs = "/nonexistent";
		else if (!strcmp(argv[i], "--no-pam"))
			o.no_pam = 1;
		else if (!strcmp(argv[i], "--source-tree"))
			o.source_tree = 1;
		else if (!strcmp(argv[i], "-q") || !strcmp(argv[i], "--quiet"))
			o.quiet = 1;
		else {
			fprintf(stderr, "usage: secure-sudo lint [--config-dir DIR] "
				"[--pam-dir DIR] [--otp-dir DIR] [--no-kernel] [--no-pam]\n"
				"                        [--source-tree] [-q]\n"
				"  --source-tree  check a config tree that is not installed "
				"(e.g. userspace/config):\n"
				"                 syntax, values and combinations only\n");
			return 2;
		}
	}
	return policy_lint(&o) ? 1 : 0;
}
