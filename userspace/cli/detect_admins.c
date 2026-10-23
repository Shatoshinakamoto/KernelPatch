// SPDX-License-Identifier: GPL-2.0
/*
 * detect_admins.c - `secure-sudo detect-admins [-n]`: find every admin group
 * on this box and make its members count as sudo users.
 *
 * Sources, in order:
 *   1. the well-known admin groups that exist here: sudo, wheel, admin
 *   2. every "%group" / "%#gid" rule in /etc/sudoers and /etc/sudoers.d/ files
 *
 * The result (e.g. "27,10") is written to admin_gid in secure-sudo.conf and
 * pushed to /sys/kernel/secure_sudo/admin_gid. -n prints it without saving.
 * install.sh runs the same detection (scripts/detect-admin-gids.sh) at
 * install time; this subcommand is for re-running it after a new admin group
 * is created.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "cli.h"

#define MAX_GIDS 16	/* SS_MAX_ADMIN_GIDS in the kernel */

static gid_t gids[MAX_GIDS];
static int ngids;

static void add_gid(gid_t g)
{
	int i;

	for (i = 0; i < ngids; i++)
		if (gids[i] == g)
			return;
	if (ngids < MAX_GIDS)
		gids[ngids++] = g;
	else
		fprintf(stderr, "secure-sudo: more than %d admin groups; ignoring GID %u\n",
			MAX_GIDS, (unsigned)g);
}

static void add_name(const char *name)
{
	struct group *gr;
	char *end;

	if (name[0] == '#') {		/* %#1600 form: numeric GID */
		unsigned long v = strtoul(name + 1, &end, 10);

		if (*end == '\0' && end != name + 1)
			add_gid((gid_t)v);
		return;
	}
	gr = getgrnam(name);
	if (gr)
		add_gid(gr->gr_gid);
}

/* Pull "%name" off the start of each rule line. */
static void scan_sudoers(const char *path)
{
	char line[1024];
	FILE *f = fopen(path, "re");

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char *p = line, *e;

		while (isspace((unsigned char)*p))
			p++;
		if (*p != '%')
			continue;
		e = ++p;
		while (*e && !isspace((unsigned char)*e))
			e++;
		*e = '\0';
		if (*p)
			add_name(p);
	}
	fclose(f);
}

static int render(char *buf, size_t len)
{
	size_t off = 0;
	int i;

	if (!ngids)
		return snprintf(buf, len, "unset");
	for (i = 0; i < ngids && off < len; i++)
		off += snprintf(buf + off, len - off, "%s%u", i ? "," : "",
				(unsigned)gids[i]);
	return (int)off;
}

/* Rewrite (or append) the admin_gid line in secure-sudo.conf. */
static int save_conf(const char *val)
{
	const char *conf = CONFIG_DIR "/secure-sudo.conf";
	char tmp[] = CONFIG_DIR "/.secure-sudo.conf.XXXXXX";
	char line[1024];
	FILE *in, *out;
	int fd, done = 0;

	in = fopen(conf, "re");
	fd = mkstemp(tmp);
	if (fd < 0 || !(out = fdopen(fd, "w"))) {
		fprintf(stderr, "secure-sudo: cannot write %s: %s\n", conf, strerror(errno));
		if (in)
			fclose(in);
		return -1;
	}
	while (in && fgets(line, sizeof(line), in)) {
		const char *p = line;

		while (isspace((unsigned char)*p))
			p++;
		if (!done && !strncmp(p, "admin_gid", 9) &&
		    (isspace((unsigned char)p[9]) || p[9] == '=')) {
			fprintf(out, "admin_gid = %s\n", val);
			done = 1;
		} else {
			fputs(line, out);
		}
	}
	if (!done)
		fprintf(out, "admin_gid = %s\n", val);
	if (in)
		fclose(in);
	fchmod(fd, 0644);
	if (fflush(out) || fsync(fd) || fclose(out) || rename(tmp, conf)) {
		fprintf(stderr, "secure-sudo: cannot save %s: %s\n", conf, strerror(errno));
		unlink(tmp);
		return -1;
	}
	return 0;
}

int cmd_detect_admins(int argc, char **argv)
{
	static const char *const known[] = { "sudo", "wheel", "admin" };
	char val[256];
	int dry = argc > 0 && (!strcmp(argv[0], "-n") || !strcmp(argv[0], "--dry-run"));
	struct dirent *de;
	DIR *d;
	size_t i;

	for (i = 0; i < sizeof(known) / sizeof(known[0]); i++)
		add_name(known[i]);

	scan_sudoers("/etc/sudoers");
	d = opendir("/etc/sudoers.d");
	if (d) {
		while ((de = readdir(d))) {
			char path[512];

			/* sudo itself skips names with '.' or ending in '~'. */
			if (strchr(de->d_name, '.') ||
			    de->d_name[strlen(de->d_name) - 1] == '~')
				continue;
			snprintf(path, sizeof(path), "/etc/sudoers.d/%s", de->d_name);
			scan_sudoers(path);
		}
		closedir(d);
	}

	render(val, sizeof(val));
	printf("detected admin GIDs: %s\n", val);
	if (dry)
		return 0;
	if (!ngids)
		fprintf(stderr, "secure-sudo: warning: no admin groups found; only root "
			"will count as a sudo user\n");

	if (save_conf(val) != 0)
		return 1;
	if (access(SYSFS "/admin_gid", F_OK) == 0) {
		if (write_file(SYSFS "/admin_gid", val, strlen(val)) != 0) {
			fprintf(stderr, "secure-sudo: saved to secure-sudo.conf; kernel "
				"refused it now (config locked?), applies at next boot\n");
			return 1;
		}
		printf("secure-sudo: admin_gid set to %s (kernel + secure-sudo.conf)\n", val);
	} else {
		printf("secure-sudo: admin_gid = %s saved; kernel will load it at boot\n", val);
	}
	return 0;
}
