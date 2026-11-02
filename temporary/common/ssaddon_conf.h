/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ssaddon_conf - strict config parsing for the secure_sudo temporary/ add-ons
 * (TODO P2-2: config validation).
 *
 * Every add-on reads a small "key = value" file. A silent fallback is the
 * dangerous failure here: `mode = enforec` used to mean "monitor" without a
 * word, and a typo in a path meant the default path. So each add-on
 * describes its keys in a table and this parser checks every line:
 *
 *   - unknown keys, lines without '=', and keys set twice are errors;
 *   - enum values must be one of the listed choices, numbers must parse in
 *     full and lie in range, paths must be absolute with no "..";
 *   - a value too long for its buffer is an error (never truncated);
 *   - control characters are errors;
 *   - the file itself must be owned by root and not group/world writable,
 *     because it names commands (notify_cmd, sync_cmd) and paths that a root
 *     daemon acts on.
 *
 * A missing file is not an error: the built-in defaults apply. Each add-on
 * has a `check-config` command that prints every problem, and its acting
 * commands (daemon, scan, ...) refuse to run while the config has errors.
 */
#ifndef SSADDON_CONF_H
#define SSADDON_CONF_H

#include <stddef.h>
#include <stdio.h>

enum ssc_type {
	SSC_ENUM,	/* dst int*: index into choices */
	SSC_INT,	/* dst int*: min..max */
	SSC_PATH,	/* dst char[size]: absolute, no "..", empty if min == 0 */
	SSC_STR,	/* dst char[size]: printable text, empty if min == 0 */
	SSC_HOST,	/* dst char[size]: host name or address, empty if min == 0 */
	SSC_PORT,	/* dst char[size]: 1..65535 as text */
};

struct ssc_key {
	const char *name;
	enum ssc_type type;
	void *dst;
	size_t size;			/* string buffer size */
	long min, max;			/* SSC_INT range; strings: min 1 = required non-empty */
	const char *const *choices;	/* SSC_ENUM: NULL-terminated */
};

/* Ends a key table. */
#define SSC_END { NULL, SSC_ENUM, NULL, 0, 0, 0, NULL }

/* A line that is not "key = value" for a listed key goes here first.
 * Return 1 if it was handled, 0 if not (then it is an error), or -1 with a
 * message in @err if it is this hook's kind of line but wrong. */
typedef int (*ssc_line_fn)(char *line, char *err, size_t errlen, void *ctx);

/* Parse @path against @keys (terminated by a {NULL} entry). The caller sets
 * the defaults first; a key with an error keeps its default. Each problem is
 * printed to @report as "path:line: message" when @report is not NULL.
 * Returns the number of errors (0 = the file is valid or absent). */
int ssc_parse(const char *path, const struct ssc_key *keys, ssc_line_fn extra,
	      void *ctx, FILE *report);

/* Check a list file: every line that is not blank or a comment must be an
 * absolute path (same rules as SSC_PATH). @what names an entry ("allowlist
 * entry"). Same return and @report as ssc_parse. */
int ssc_check_list(const char *path, const char *what, FILE *report);

/* The checks ssc_parse applies to a path / an owner. Exposed for hooks. */
int ssc_path_ok(const char *v, char *err, size_t errlen);
int ssc_file_safe(const char *path, char *err, size_t errlen);

/* The exit status of an acting command refused for a bad config (EX_CONFIG).
 * systemd shows it as status=78/CONFIG and starts the OnFailure= handler. */
#define SSC_EXIT_CONFIG 78

/* For an acting command: @errors > 0 (already printed to stderr) is logged
 * and the command must stop: returns SSC_EXIT_CONFIG, else 0. */
int ssc_refuse(const char *what, int errors);

/* For `check-config`: prints the verdict, returns the exit status (0/1). */
int ssc_verdict(int errors);

#endif /* SSADDON_CONF_H */
