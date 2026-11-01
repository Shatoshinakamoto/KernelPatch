// SPDX-License-Identifier: GPL-2.0
/*
 * ssaddon_conf - strict config parsing for the temporary/ add-ons.
 * See ssaddon_conf.h for the rules.
 */
#define _GNU_SOURCE
#include "ssaddon_conf.h"
#include "ssaddon_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <sys/stat.h>

#define LINE_MAX_LEN	(PATH_MAX + 256)
#define MAX_KEYS	64

static void rtrim(char *s)
{
	size_t n = strlen(s);

	while (n && isspace((unsigned char)s[n - 1]))
		s[--n] = '\0';
}

static char *ltrim(char *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	return s;
}

static int has_ctrl(const char *s)
{
	for (; *s; s++)
		if (iscntrl((unsigned char)*s) && *s != '\t')
			return 1;
	return 0;
}

int ssc_path_ok(const char *v, char *err, size_t errlen)
{
	const char *p;

	if (v[0] != '/') {
		snprintf(err, errlen, "'%s' is not an absolute path", v);
		return 0;
	}
	for (p = v; (p = strstr(p, "/..")); p += 3) {
		if (p[3] == '/' || p[3] == '\0') {
			snprintf(err, errlen, "'%s' contains '..'", v);
			return 0;
		}
	}
	if (has_ctrl(v)) {
		snprintf(err, errlen, "path contains a control character");
		return 0;
	}
	return 1;
}

static int stat_safe(const struct stat *st, char *err, size_t errlen)
{
	if (st->st_uid != 0) {
		snprintf(err, errlen, "not owned by root (uid %u)", (unsigned)st->st_uid);
		return 0;
	}
	if (st->st_mode & 022) {
		snprintf(err, errlen, "writable by group or others (mode %04o)",
			 (unsigned)(st->st_mode & 07777));
		return 0;
	}
	return 1;
}

int ssc_file_safe(const char *path, char *err, size_t errlen)
{
	struct stat st;

	if (stat(path, &st) != 0) {
		snprintf(err, errlen, "%s", strerror(errno));
		return 0;
	}
	return stat_safe(&st, err, errlen);
}

static void say(FILE *r, const char *path, int ln, const char *msg)
{
	if (!r)
		return;
	if (ln)
		fprintf(r, "%s:%d: %s\n", path, ln, msg);
	else
		fprintf(r, "%s: %s\n", path, msg);
}

static int put_str(const struct ssc_key *k, const char *v, char *err, size_t errlen)
{
	if (strlen(v) >= k->size) {
		snprintf(err, errlen, "%s: value is too long (at most %zu characters)",
			 k->name, k->size - 1);
		return 0;
	}
	snprintf((char *)k->dst, k->size, "%s", v);
	return 1;
}

static int set_value(const struct ssc_key *k, const char *v, char *err, size_t errlen)
{
	char sub[256];
	long n;
	char *end;
	int i;

	if (has_ctrl(v)) {
		snprintf(err, errlen, "%s: value contains a control character", k->name);
		return 0;
	}
	switch (k->type) {
	case SSC_ENUM:
		for (i = 0; k->choices[i]; i++) {
			if (!strcmp(v, k->choices[i])) {
				*(int *)k->dst = i;
				return 1;
			}
		}
		{
			size_t o = 0;

			sub[0] = '\0';
			for (i = 0; k->choices[i] && o < sizeof(sub); i++)
				o += snprintf(sub + o, sizeof(sub) - o, "%s%s",
					      i ? ", " : "", k->choices[i]);
		}
		snprintf(err, errlen, "%s: '%s' is not one of: %s", k->name, v, sub);
		return 0;
	case SSC_INT:
		errno = 0;
		n = strtol(v, &end, 10);
		if (!*v || *end || errno) {
			snprintf(err, errlen, "%s: '%s' is not a whole number", k->name, v);
			return 0;
		}
		if (n < k->min || n > k->max) {
			snprintf(err, errlen, "%s: %ld is outside %ld..%ld", k->name, n,
				 k->min, k->max);
			return 0;
		}
		*(int *)k->dst = (int)n;
		return 1;
	case SSC_PORT:
		errno = 0;
		n = strtol(v, &end, 10);
		if (!*v || *end || errno || n < 1 || n > 65535) {
			snprintf(err, errlen, "%s: '%s' is not a port (1..65535)", k->name, v);
			return 0;
		}
		return put_str(k, v, err, errlen);
	case SSC_PATH:
		if (!*v && k->min == 0)
			return put_str(k, v, err, errlen);
		if (!ssc_path_ok(v, sub, sizeof(sub))) {
			snprintf(err, errlen, "%s: %s", k->name, sub);
			return 0;
		}
		return put_str(k, v, err, errlen);
	case SSC_HOST:
		for (i = 0; v[i]; i++) {
			unsigned char c = (unsigned char)v[i];

			if (!isalnum(c) && !strchr(".-_:[]%", c)) {
				snprintf(err, errlen, "%s: '%s' is not a host name or address",
					 k->name, v);
				return 0;
			}
		}
		__attribute__((fallthrough));
	case SSC_STR:
		if (!*v && k->min > 0) {
			snprintf(err, errlen, "%s: must not be empty", k->name);
			return 0;
		}
		return put_str(k, v, err, errlen);
	}
	snprintf(err, errlen, "%s: unknown setting type", k->name);
	return 0;
}

int ssc_parse(const char *path, const struct ssc_key *keys, ssc_line_fn extra,
	      void *ctx, FILE *report)
{
	FILE *f;
	struct stat st;
	char line[LINE_MAX_LEN], err[PATH_MAX + 128];
	int seen[MAX_KEYS] = { 0 };
	int errors = 0, ln = 0, nk;

	for (nk = 0; keys[nk].name; nk++)
		;
	if (nk > MAX_KEYS) {
		say(report, path, 0, "internal: too many settings");
		return 1;
	}
	f = fopen(path, "re");
	if (!f) {
		if (errno == ENOENT)
			return 0;		/* absent: the defaults apply */
		snprintf(err, sizeof(err), "cannot be read: %s", strerror(errno));
		say(report, path, 0, err);
		return 1;
	}
	if (fstat(fileno(f), &st) == 0 && !stat_safe(&st, err, sizeof(err))) {
		say(report, path, 0, err);
		errors++;
	}
	while (fgets(line, sizeof(line), f)) {
		char *k, *v, *eq;
		int i, r;

		ln++;
		if (!strchr(line, '\n') && !feof(f)) {
			int c;

			say(report, path, ln, "line is too long");
			errors++;
			while ((c = fgetc(f)) != EOF && c != '\n')
				;
			continue;
		}
		rtrim(line);
		k = ltrim(line);
		if (*k == '#' || *k == '\0')
			continue;
		if (extra) {
			err[0] = '\0';
			r = extra(k, err, sizeof(err), ctx);
			if (r > 0)
				continue;
			if (r < 0) {
				say(report, path, ln, err);
				errors++;
				continue;
			}
		}
		eq = strchr(k, '=');
		if (!eq) {
			say(report, path, ln, "not a 'key = value' line");
			errors++;
			continue;
		}
		*eq = '\0';
		v = ltrim(eq + 1);
		rtrim(k);
		for (i = 0; i < nk; i++)
			if (!strcmp(k, keys[i].name))
				break;
		if (i == nk) {
			snprintf(err, sizeof(err), "unknown setting '%.64s'", k);
			say(report, path, ln, err);
			errors++;
			continue;
		}
		if (seen[i]) {
			snprintf(err, sizeof(err), "%s is set twice (first on line %d)",
				 keys[i].name, seen[i]);
			say(report, path, ln, err);
			errors++;
			continue;
		}
		seen[i] = ln;
		if (!set_value(&keys[i], v, err, sizeof(err))) {
			say(report, path, ln, err);
			errors++;
		}
	}
	fclose(f);
	return errors;
}

int ssc_check_list(const char *path, const char *what, FILE *report)
{
	FILE *f;
	struct stat st;
	char line[LINE_MAX_LEN], err[PATH_MAX + 128], why[PATH_MAX + 64];
	int errors = 0, ln = 0;

	f = fopen(path, "re");
	if (!f) {
		if (errno == ENOENT)
			return 0;
		snprintf(err, sizeof(err), "cannot be read: %s", strerror(errno));
		say(report, path, 0, err);
		return 1;
	}
	if (fstat(fileno(f), &st) == 0 && !stat_safe(&st, err, sizeof(err))) {
		say(report, path, 0, err);
		errors++;
	}
	while (fgets(line, sizeof(line), f)) {
		char *p;

		ln++;
		rtrim(line);
		p = ltrim(line);
		if (*p == '#' || *p == '\0')
			continue;
		if (!ssc_path_ok(p, why, sizeof(why))) {
			snprintf(err, sizeof(err), "%s: %s", what, why);
			say(report, path, ln, err);
			errors++;
		}
	}
	fclose(f);
	return errors;
}

int ssc_refuse(const char *what, int errors)
{
	if (errors <= 0)
		return 0;
	ssl_err("refusing to %s: the configuration has %d error(s) "
		"(run check-config)", what, errors);
	fprintf(stderr, "refusing to %s: %d configuration error(s) above\n",
		what, errors);
	return SSC_EXIT_CONFIG;
}

int ssc_verdict(int errors)
{
	if (errors) {
		printf("%d configuration problem(s); the acting commands refuse to "
		       "run until they are fixed\n", errors);
		return 1;
	}
	printf("configuration OK\n");
	return 0;
}
