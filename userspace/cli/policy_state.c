// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * policy_state.c - policy preview, snapshots and change history (TODO P1-6).
 *
 *   secure-sudo diff            what `load` would change: every setting and
 *   (= load --dry-run)          list entry where /etc/secure_sudo differs
 *                               from the running kernel. Writes nothing.
 *   secure-sudo snapshot ...    a versioned copy of the configuration files
 *                               AND the live kernel state, with SHA256SUMS
 *                               and a link to the previous snapshot's sums.
 *                               `load`, `restore`, `set`, `lock` and
 *                               `timevault on` take one before they change
 *                               anything.
 *   secure-sudo history         who changed policy, what changed, the lint
 *                               result and what the kernel accepted, one
 *                               JSON line per change, each line carrying the
 *                               SHA-256 of the line before (and sent to
 *                               syslog, so a forwarded copy exists off-box).
 *   secure-sudo restore ID      put a snapshot's configuration files back and
 *                               load them (refused while locked unless
 *                               --no-load), after showing what it changes and
 *                               taking a snapshot of what it replaces.
 *
 * Integrity here means: a snapshot that was damaged or edited after it was
 * taken fails `snapshot verify`, and so does a history line that was edited,
 * removed or reordered (`history --verify`). Root on the box can rewrite the
 * whole chain consistently; the syslog copy (forwarded off-box by the
 * collector, see CONFIGURATION.md) is what that cannot rewrite.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/utsname.h>
#include <openssl/evp.h>

#include "cli.h"

#define PS_DIR      SS_STATE_DIR "/policy"
#define PS_SNAPDIR  PS_DIR "/snapshots"
#define PS_HISTORY  PS_DIR "/history.jsonl"
#define PS_FORMAT   "secure_sudo policy snapshot v1"
#ifndef PS_KEEP
#define PS_KEEP     100		/* snapshots kept; the oldest go first */
#endif
#define PS_MAX_FILE (16u << 20)	/* no config or kernel list is near this */
#define PS_SHOW_MAX 20		/* list entries shown per list in a diff */

static const char zero_hash[] =
	"0000000000000000000000000000000000000000000000000000000000000000";

/* ------------------------------------------------------------- helpers */

/* Whole file, NUL-terminated; NULL with errno set on failure. */
static char *slurp(const char *path, size_t *len)
{
	char *buf = NULL, *grown;
	size_t cap = 0, n = 0;
	ssize_t r;
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

	if (fd < 0)
		return NULL;
	for (;;) {
		if (n + 4097 > cap) {
			if (cap >= PS_MAX_FILE) {
				free(buf);
				close(fd);
				errno = EFBIG;
				return NULL;
			}
			cap = cap ? cap * 2 : 8192;
			grown = realloc(buf, cap);
			if (!grown) {
				free(buf);
				close(fd);
				errno = ENOMEM;
				return NULL;
			}
			buf = grown;
		}
		r = read(fd, buf + n, cap - n - 1);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			int e = errno;

			free(buf);
			close(fd);
			errno = e;
			return NULL;
		}
		if (r == 0)
			break;
		n += (size_t)r;
	}
	close(fd);
	buf[n] = '\0';
	if (len)
		*len = n;
	return buf;
}

static void sha256_hex(const void *data, size_t len, char out[65])
{
	unsigned char md[32];
	unsigned int mdlen = 0;
	int i;

	if (EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL) != 1 ||
	    mdlen != 32) {
		snprintf(out, 65, "%s", zero_hash);
		return;
	}
	for (i = 0; i < 32; i++)
		sprintf(out + 2 * i, "%02x", md[i]);
}

static int file_sha256(const char *path, char out[65])
{
	size_t len;
	char *b = slurp(path, &len);

	if (!b)
		return -1;
	sha256_hex(b, len, out);
	free(b);
	return 0;
}

/* Create @path with exactly @data (no following links, no overwrite). */
static int write_new(const char *path, const void *data, size_t len,
		     mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
		      mode);
	const char *p = data;
	size_t off = 0;

	if (fd < 0)
		return -1;
	while (off < len) {
		ssize_t w = write(fd, p + off, len - off);

		if (w < 0 && errno == EINTR)
			continue;
		if (w <= 0) {
			close(fd);
			unlink(path);
			return -1;
		}
		off += (size_t)w;
	}
	if (fsync(fd) != 0 || close(fd) != 0) {
		unlink(path);
		return -1;
	}
	return 0;
}

/* Replace @path atomically with @data, mode @mode. */
static int write_replace(const char *path, const void *data, size_t len,
			 mode_t mode)
{
	char tmp[512];

	if ((size_t)snprintf(tmp, sizeof(tmp), "%s.restore-tmp", path) >=
	    sizeof(tmp)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	unlink(tmp);
	if (write_new(tmp, data, len, mode) != 0)
		return -1;
	if (chmod(tmp, mode) != 0 || rename(tmp, path) != 0) {
		int e = errno;

		unlink(tmp);
		errno = e;
		return -1;
	}
	return 0;
}

/* A directory we own, not group/world-writable, not a link: made if absent. */
static int ensure_dir(const char *path)
{
	struct stat st;

	if (mkdir(path, 0700) != 0 && errno != EEXIST)
		return -1;
	if (lstat(path, &st) != 0)
		return -1;
	if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
	    (st.st_mode & 0022)) {
		errno = EPERM;
		return -1;
	}
	return 0;
}

static int ensure_state_dirs(void)
{
	if (ensure_dir(SS_STATE_DIR) != 0 || ensure_dir(PS_DIR) != 0 ||
	    ensure_dir(PS_SNAPDIR) != 0) {
		fprintf(stderr, "secure-sudo: %s: %s\n", PS_DIR, strerror(errno));
		return -1;
	}
	return 0;
}

static void read_trimmed(const char *path, char *buf, size_t size)
{
	size_t len;
	char *b = slurp(path, &len);

	buf[0] = '\0';
	if (!b)
		return;
	while (len && isspace((unsigned char)b[len - 1]))
		b[--len] = '\0';
	snprintf(buf, size, "%s", b);
	free(b);
}

int policy_locked(void)
{
	char v[16];

	read_trimmed(SYSFS "/lock", v, sizeof(v));
	if (!v[0])
		return -1;
	return strcmp(v, "0") != 0;
}

/* Snapshot ids are made here; anything else is refused before use. */
static int valid_id(const char *id)
{
	size_t i, n = strlen(id);

	if (n < 17 || n > 40)
		return 0;
	for (i = 0; i < n; i++)
		if (!isdigit((unsigned char)id[i]) && id[i] != 'T' &&
		    id[i] != 'Z' && id[i] != '-')
			return 0;
	return 1;
}

/* ------------------------------------------------------- list entries */

struct ents {
	char **v;
	size_t n;
};

static int str_cmp(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The meaningful lines of a list: trimmed, no blanks or comments, sorted and
 * de-duplicated; home_map's "uid dir" with its spacing normalised. */
static void ents_parse(const char *text, enum list_kind kind, struct ents *e)
{
	char *copy = strdup(text ? text : ""), *save = NULL, *line;
	size_t cap = 0, i, j;

	e->v = NULL;
	e->n = 0;
	if (!copy)
		return;
	for (line = strtok_r(copy, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *p = line, *end, *s, *d;

		while (isspace((unsigned char)*p))
			p++;
		end = p + strlen(p);
		while (end > p && isspace((unsigned char)end[-1]))
			*--end = '\0';
		if (!*p || *p == '#')
			continue;
		if (kind == L_HOMEMAP) {
			for (s = d = p; *s; s++) {
				if (isspace((unsigned char)*s)) {
					if (d > p && d[-1] != ' ')
						*d++ = ' ';
				} else {
					*d++ = *s;
				}
			}
			*d = '\0';
		}
		if (e->n == cap) {
			char **g = realloc(e->v, (cap = cap ? cap * 2 : 64) *
					   sizeof(*e->v));
			if (!g)
				break;
			e->v = g;
		}
		e->v[e->n] = strdup(p);
		if (e->v[e->n])
			e->n++;
	}
	free(copy);
	if (!e->n)
		return;
	qsort(e->v, e->n, sizeof(*e->v), str_cmp);
	for (i = 1, j = 1; i < e->n; i++) {
		if (strcmp(e->v[i], e->v[j - 1]))
			e->v[j++] = e->v[i];
		else
			free(e->v[i]);
	}
	e->n = j;
}

static void ents_free(struct ents *e)
{
	size_t i;

	for (i = 0; i < e->n; i++)
		free(e->v[i]);
	free(e->v);
	e->v = NULL;
	e->n = 0;
}

/*
 * Compare list @want (what would be loaded / restored) with @have (what is
 * there now). Prints "+ entry" for an entry that would be added and "- entry"
 * for one that would go, at most PS_SHOW_MAX of each. Returns the number of
 * differing entries.
 */
static size_t ents_diff(const char *label, const char *want, const char *have,
			enum list_kind kind, int print)
{
	struct ents w, h;
	size_t i = 0, j = 0, add = 0, del = 0, shown = 0;

	ents_parse(want, kind, &w);
	ents_parse(have, kind, &h);
	while (i < w.n || j < h.n) {
		int c = i >= w.n ? 1 : j >= h.n ? -1 : strcmp(w.v[i], h.v[j]);

		if (c == 0) {
			i++;
			j++;
			continue;
		}
		if (c < 0)
			add++;
		else
			del++;
		if (print && shown < 2 * PS_SHOW_MAX) {
			if (!shown)
				printf("  change    %s\n", label);
			printf("              %c %s\n", c < 0 ? '+' : '-',
			       c < 0 ? w.v[i] : h.v[j]);
			shown++;
		}
		if (c < 0)
			i++;
		else
			j++;
	}
	if (print && add + del > shown)
		printf("              ... %zu more\n", add + del - shown);
	if (print && add + del)
		printf("              (%zu to add, %zu to remove)\n", add, del);
	ents_free(&w);
	ents_free(&h);
	return add + del;
}

/* ------------------------------------------------------ setting values */

static int truthy(const char *v)
{
	return !strcasecmp(v, "1") || !strcasecmp(v, "yes") ||
	       !strcasecmp(v, "on") || !strcasecmp(v, "true") ||
	       !strcasecmp(v, "y");
}

static int ul_cmp(const void *a, const void *b)
{
	unsigned long x = *(const unsigned long *)a, y = *(const unsigned long *)b;

	return x < y ? -1 : x > y;
}

/* GIDs as a sorted set; "unset" is the empty set. -1 if not numbers. */
static int gid_set(const char *v, unsigned long *g, int max)
{
	char *copy = strdup(v), *save = NULL, *tok, *end;
	int n = 0;

	if (!copy)
		return -1;
	if (!strcmp(v, "unset")) {
		free(copy);
		return 0;
	}
	for (tok = strtok_r(copy, ", \t", &save); tok;
	     tok = strtok_r(NULL, ", \t", &save)) {
		errno = 0;
		if (n == max || (g[n] = strtoul(tok, &end, 10), errno || *end)) {
			free(copy);
			return -1;
		}
		n++;
	}
	free(copy);
	qsort(g, (size_t)n, sizeof(*g), ul_cmp);
	return n;
}

int knob_values_equal(const struct knob *k, const char *cfg, const char *live)
{
	unsigned long a[SS_MAX_GIDS + 1], b[SS_MAX_GIDS + 1], x, y;
	char *e1, *e2;
	int na, nb;

	switch (k->type) {
	case K_BOOL:
		return truthy(cfg) == truthy(live);
	case K_U32:
		errno = 0;
		x = strtoul(cfg, &e1, 10);
		if (errno || e1 == cfg || *e1)
			return 0;
		y = strtoul(live, &e2, 10);
		return !errno && e2 != live && !*e2 && x == y;
	case K_GIDS:
		na = gid_set(cfg, a, SS_MAX_GIDS + 1);
		nb = gid_set(live, b, SS_MAX_GIDS + 1);
		return na >= 0 && na == nb &&
		       !memcmp(a, b, (size_t)na * sizeof(*a));
	default:
		return !strcmp(cfg, live);
	}
}

/* The value secure-sudo.conf gives @key (the last one wins, as in load). */
static const char *cfg_value(const struct cfg_file *c, const char *key)
{
	const char *v = NULL;
	int i;

	for (i = 0; c && i < c->n; i++)
		if (!c->e[i].bad && !strcmp(c->e[i].key, key))
			v = c->e[i].val;
	return v;
}

/* ------------------------------------------------- list payload (load) */

char *policy_list_payload(const struct listmap *m, size_t *len, int *have,
			  int *auto_added, int *auto_dropped)
{
	char cfg[256], *buf;
	size_t n = 0;

	*have = 0;
	*auto_added = *auto_dropped = 0;
	snprintf(cfg, sizeof(cfg), CONFIG_DIR "/%s", m->cfg_file);
	buf = slurp(cfg, &n);
	if (buf)
		*have = 1;
	if (!strcmp(m->secfs, "node_sea_binaries")) {
		/* hand-written entries first, then what node-scan found */
		size_t alen = 0, glen = 0;
		char *autol = node_sea_read_file(node_sea_auto_path(), &alen);
		char *merged = NULL;

		if (autol && node_sea_merge(buf, n, autol, alen, &merged, &glen,
					    auto_added, auto_dropped) == 0) {
			free(buf);
			buf = merged;
			n = glen;
			*have = 1;
		}
		free(autol);
	}
	*len = buf ? n : 0;
	return buf;
}

/* ----------------------------------------------------------- the diff */

/*
 * What `load` would change. @print: report each difference. Returns the
 * number of differences (settings + list entries), or -1 if the kernel
 * cannot be read at all.
 */
int policy_diff(int print)
{
	struct cfg_file c;
	int have_cfg = cfg_parse(CONFIG_DIR "/secure-sudo.conf", &c) == 0;
	size_t i, changes = 0, unreadable = 0;
	char path[256], live[512];

	if (access(SYSFS, F_OK) != 0) {
		if (print)
			fprintf(stderr, "secure-sudo: LSM not active (no %s)\n",
				SYSFS);
		if (have_cfg)
			cfg_free(&c);
		return -1;
	}
	for (i = 0; i < ss_nlists; i++) {
		const struct listmap *m = &ss_lists[i];
		int have, added, dropped;
		size_t wl = 0;
		char *want = policy_list_payload(m, &wl, &have, &added, &dropped);
		char *cur;

		snprintf(path, sizeof(path), SECFS "/%s", m->secfs);
		cur = slurp(path, NULL);
		if (!cur) {
			if (print)
				printf("  unknown   %-34s live list unreadable: %s\n",
				       m->secfs, strerror(errno));
			unreadable++;
		} else {
			changes += ents_diff(m->secfs, want ? want : "", cur,
					     m->kind, print);
		}
		free(want);
		free(cur);
	}
	for (i = 0; i < ss_nknobs; i++) {
		const struct knob *k = &ss_knobs[i];
		const char *want = have_cfg ? cfg_value(&c, k->cfg_key) : NULL;
		char why[160];

		if (!want)
			continue;	/* not configured: load leaves it alone */
		snprintf(path, sizeof(path), SYSFS "/%s", k->sysfs);
		read_trimmed(path, live, sizeof(live));
		if (!live[0]) {
			if (print)
				printf("  unknown   %-34s live value unreadable\n",
				       k->cfg_key);
			unreadable++;
			continue;
		}
		if (knob_values_equal(k, want, live))
			continue;
		changes++;
		if (print)
			printf("  change    %-34s live %s -> config %s%s\n",
			       k->cfg_key, live, want,
			       check_value(k, want, why, sizeof(why)) ?
			       "  (invalid: load rejects it)" : "");
	}
	if (have_cfg)
		cfg_free(&c);
	if (print) {
		int locked = policy_locked();

		printf("diff: %zu change(s)", changes);
		if (unreadable)
			printf(", %zu unreadable", unreadable);
		printf("%s\n", changes ? "" : ": the kernel runs the configuration");
		if (locked == 1 && changes)
			printf("diff: the config is LOCKED until reboot: load "
			       "would be refused; these apply at the next boot\n");
	}
	return (int)changes;
}

int cmd_diff(int argc, char **argv)
{
	struct lint_opts o = {
		.cfgdir = CONFIG_DIR, .pamdir = "/etc/pam.d",
		.otpdir = "/var/lib/secure_sudo/otp", .sysfs = SYSFS,
		.secfs = SECFS, .quiet = 1, .pam_soft = 1,
	};
	int errs, n;

	(void)argv;
	if (argc > 0) {
		fprintf(stderr, "usage: secure-sudo diff\n");
		return 2;
	}
	printf("secure-sudo diff: %s against the running kernel (nothing is "
	       "changed)\n", CONFIG_DIR);
	errs = policy_lint(&o);
	if (errs > 0)
		printf("diff: lint found %d error(s): load would REFUSE this "
		       "configuration (shown anyway)\n", errs);
	n = policy_diff(1);
	return n < 0 || errs > 0 ? 1 : 0;
}

/* ---------------------------------------------------------- snapshots */

static int name_cmp(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Snapshot ids, oldest first. Caller frees. */
static char **snap_ids(size_t *n)
{
	DIR *d = opendir(PS_SNAPDIR);
	struct dirent *de;
	char **v = NULL, **g;
	size_t cap = 0;

	*n = 0;
	if (!d)
		return NULL;
	while ((de = readdir(d))) {
		if (!valid_id(de->d_name))
			continue;
		if (*n == cap) {
			g = realloc(v, (cap = cap ? cap * 2 : 32) * sizeof(*v));
			if (!g)
				break;
			v = g;
		}
		v[*n] = strdup(de->d_name);
		if (v[*n])
			(*n)++;
	}
	closedir(d);
	if (*n)
		qsort(v, *n, sizeof(*v), name_cmp);
	return v;
}

static void ids_free(char **v, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(v[i]);
	free(v);
}

static int snap_sums_hash(const char *id, char out[65])
{
	char p[512];

	snprintf(p, sizeof(p), PS_SNAPDIR "/%s/SHA256SUMS", id);
	return file_sha256(p, out);
}

/* Remove a snapshot directory: its files, disk/, live/. */
static void snap_remove(const char *id)
{
	static const char *const sub[] = { "disk", "live", "" };
	char p[512];
	size_t i;

	for (i = 0; i < 3; i++) {
		DIR *d;
		struct dirent *de;

		snprintf(p, sizeof(p), PS_SNAPDIR "/%s%s%s", id,
			 sub[i][0] ? "/" : "", sub[i]);
		d = opendir(p);
		if (!d)
			continue;
		while ((de = readdir(d)))
			if (de->d_name[0] != '.')
				unlinkat(dirfd(d), de->d_name, 0);
		closedir(d);
		if (sub[i][0])
			rmdir(p);
	}
	snprintf(p, sizeof(p), PS_SNAPDIR "/%s", id);
	rmdir(p);
}

static void snap_prune(void)
{
	size_t n, i;
	char **v = snap_ids(&n);

	for (i = 0; n > PS_KEEP && i < n - PS_KEEP; i++)
		snap_remove(v[i]);
	ids_free(v, n);
}

struct sums {
	char *text;
	size_t len, cap;
};

static int sums_add(struct sums *s, const char *rel, const void *data,
		    size_t len)
{
	char h[65], line[400];
	int n;

	sha256_hex(data, len, h);
	n = snprintf(line, sizeof(line), "%s  %s\n", h, rel);
	if (n < 0 || (size_t)n >= sizeof(line))
		return -1;
	if (s->len + (size_t)n + 1 > s->cap) {
		char *g = realloc(s->text, s->cap = (s->len + (size_t)n + 1) * 2);

		if (!g)
			return -1;
		s->text = g;
	}
	memcpy(s->text + s->len, line, (size_t)n + 1);
	s->len += (size_t)n;
	return 0;
}

/* Write @rel inside snapshot @dir and record its hash. */
static int snap_put(const char *dir, const char *rel, const void *data,
		    size_t len, struct sums *s)
{
	char p[1024];

	snprintf(p, sizeof(p), "%s/%s", dir, rel);
	if (write_new(p, data, len, 0600) != 0)
		return -1;
	return sums_add(s, rel, data, len);
}

static void who(char *user, size_t n, unsigned long *loginuid)
{
	const char *su = getenv("SUDO_USER");
	char lu[32];
	size_t i, j = 0;

	read_trimmed("/proc/self/loginuid", lu, sizeof(lu));
	*loginuid = lu[0] ? strtoul(lu, NULL, 10) : 4294967295UL;
	for (i = 0; su && su[i] && j + 1 < n && j < 32; i++)
		if (isalnum((unsigned char)su[i]) || strchr("._-", su[i]))
			user[j++] = su[i];
	user[j] = '\0';
}

/*
 * Take a snapshot of /etc/secure_sudo and the live kernel state. Writes the
 * new id (and the SHA-256 of its SHA256SUMS) to @id/@sums. 0 or -1.
 */
/*
 * P2-1: one digest of the policy the kernel is enforcing now: every
 * setting and every list, read back from the kernel (not from disk), in a
 * fixed order and framing, so two machines with the same live policy get
 * the same digest. Used in the attestation report.
 */
int policy_live_digest(char out[65])
{
	char *k = NULL, p[1024], val[512];
	size_t klen = 0, i, len;
	FILE *mf = open_memstream(&k, &klen);

	if (!mf)
		return -1;
	fprintf(mf, "secure_sudo-policy-v1\nsettings\n");
	for (i = 0; i < ss_nknobs; i++) {
		snprintf(p, sizeof(p), SYSFS "/%s", ss_knobs[i].sysfs);
		read_trimmed(p, val, sizeof(val));
		fprintf(mf, "%s = %s\n", ss_knobs[i].cfg_key, val[0] ? val : "?unreadable");
	}
	for (i = 0; i < ss_nlists; i++) {
		char *b;

		snprintf(p, sizeof(p), SECFS "/%s", ss_lists[i].secfs);
		b = slurp(p, &len);
		fprintf(mf, "list %s %zu\n", ss_lists[i].secfs, b ? len : (size_t)0);
		if (b) {
			fwrite(b, 1, len, mf);
			free(b);
		}
	}
	if (fclose(mf) != 0 || !k) {
		free(k);
		return -1;
	}
	sha256_hex(k, klen, out);
	free(k);
	return 0;
}

int policy_snapshot(const char *reason, char *id, size_t idlen, char *sums,
		    size_t sumslen)
{
	char dir[512] = "", p[1024], stamp[32], user[40], prev_sums[65], ts[40];
	char *meta = NULL, **ids;
	struct sums s = { 0 };
	struct utsname u;
	struct tm tm;
	time_t now = time(NULL);
	unsigned long luid;
	size_t i, nids, len;
	struct timespec tsp;
	int seq, rc = -1, locked;

	id[0] = '\0';
	if (ensure_state_dirs() != 0)
		return -1;
	ids = snap_ids(&nids);
	if (nids && snap_sums_hash(ids[nids - 1], prev_sums) != 0)
		snprintf(prev_sums, sizeof(prev_sums), "%s", zero_hash);
	gmtime_r(&now, &tm);
	strftime(stamp, sizeof(stamp), "%Y%m%dT%H%M%SZ", &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
	/* Time-ordered and never reused, even after an older one is removed:
	 * the history refers to snapshots by id. */
	clock_gettime(CLOCK_REALTIME, &tsp);
	for (seq = 0; seq < 1000; seq++) {
		snprintf(id, idlen, "%s-%09ld", stamp,
			 (tsp.tv_nsec + seq) % 1000000000L);
		snprintf(dir, sizeof(dir), PS_SNAPDIR "/%s", id);
		if (mkdir(dir, 0700) == 0)
			break;
		if (errno != EEXIST)
			goto out;
	}
	if (seq == 1000)
		goto out;
	snprintf(p, sizeof(p), "%s/disk", dir);
	if (mkdir(p, 0700) != 0)
		goto out;
	snprintf(p, sizeof(p), "%s/live", dir);
	if (mkdir(p, 0700) != 0)
		goto out;

	/* disk: every file load reads */
	for (i = 0; i <= ss_nlists; i++) {
		const char *f = i < ss_nlists ? ss_lists[i].cfg_file :
						"secure-sudo.conf";
		char rel[300], *b;

		snprintf(p, sizeof(p), CONFIG_DIR "/%s", f);
		b = slurp(p, &len);
		if (!b)
			continue;	/* absent: load clears that list */
		snprintf(rel, sizeof(rel), "disk/%s", f);
		if (snap_put(dir, rel, b, len, &s) != 0) {
			free(b);
			goto out;
		}
		free(b);
	}
	/* live: every setting, every list, the lock */
	{
		char *k = NULL, val[512];
		size_t klen = 0;
		FILE *mf = open_memstream(&k, &klen);

		if (!mf)
			goto out;
		for (i = 0; i < ss_nknobs; i++) {
			snprintf(p, sizeof(p), SYSFS "/%s", ss_knobs[i].sysfs);
			read_trimmed(p, val, sizeof(val));
			if (val[0])
				fprintf(mf, "%s = %s\n", ss_knobs[i].cfg_key, val);
			else
				fprintf(mf, "# %s: unreadable\n", ss_knobs[i].cfg_key);
		}
		fclose(mf);
		if (!k || snap_put(dir, "live/settings", k, klen, &s) != 0) {
			free(k);
			goto out;
		}
		free(k);
	}
	for (i = 0; i < ss_nlists; i++) {
		char rel[300], *b;

		snprintf(p, sizeof(p), SECFS "/%s", ss_lists[i].secfs);
		b = slurp(p, &len);
		if (!b)
			continue;
		snprintf(rel, sizeof(rel), "live/%s", ss_lists[i].secfs);
		if (snap_put(dir, rel, b, len, &s) != 0) {
			free(b);
			goto out;
		}
		free(b);
	}
	locked = policy_locked();
	who(user, sizeof(user), &luid);
	if (uname(&u) != 0)
		snprintf(u.release, sizeof(u.release), "unknown");
	{
		char boot[64];
		FILE *mf;

		read_trimmed(BOOT_ID_FILE, boot, sizeof(boot));
		mf = open_memstream(&meta, &len);
		if (!mf)
			goto out;
		fprintf(mf, "format = %s\nid = %s\ncreated = %lld\n"
			"created_utc = %s\nreason = %s\nuid = %u\n"
			"loginuid = %lu\nsudo_user = %s\nkernel = %s\n"
			"boot_id = %s\nlocked = %s\nprev = %s\nprev_sums = %s\n",
			PS_FORMAT, id, (long long)now, ts, reason,
			(unsigned)getuid(), luid, user[0] ? user : "-",
			u.release, boot[0] ? boot : "-",
			locked < 0 ? "unknown" : locked ? "1" : "0",
			nids ? ids[nids - 1] : "-",
			nids ? prev_sums : zero_hash);
		fclose(mf);
	}
	if (!meta || snap_put(dir, "meta", meta, len, &s) != 0)
		goto out;
	snprintf(p, sizeof(p), "%s/SHA256SUMS", dir);
	if (write_new(p, s.text, s.len, 0400) != 0)
		goto out;
	sha256_hex(s.text, s.len, sums);
	(void)sumslen;
	rc = 0;
out:
	if (rc != 0) {
		int e = errno;

		if (dir[0] && id[0])
			snap_remove(id);
		errno = e;
	}
	free(meta);
	free(s.text);
	ids_free(ids, nids);
	if (rc == 0)
		snap_prune();
	return rc;
}

/* A field of a snapshot's meta file. */
static void meta_get(const char *id, const char *key, char *out, size_t n)
{
	char p[512], *m, *line, *save = NULL;
	size_t kl = strlen(key);

	out[0] = '\0';
	snprintf(p, sizeof(p), PS_SNAPDIR "/%s/meta", id);
	m = slurp(p, NULL);
	for (line = m ? strtok_r(m, "\n", &save) : NULL; line;
	     line = strtok_r(NULL, "\n", &save))
		if (!strncmp(line, key, kl) && !strncmp(line + kl, " = ", 3)) {
			snprintf(out, n, "%s", line + kl + 3);
			break;
		}
	free(m);
}

/*
 * Check snapshot @id: every file listed in SHA256SUMS has that hash, no file
 * is missing or extra, the meta names this id, and the previous snapshot (if
 * still kept) has the SHA256SUMS this one recorded. Prints the problems
 * unless @quiet. Returns the number of problems.
 */
static int snap_verify(const char *id, int quiet)
{
	char dir[512], p[1024], *sums, *line, *save = NULL, h[65];
	char prev[64], prev_sums[65], mid[64], fmt[64];
	int bad = 0, listed = 0, found = 0;
	static const char *const sub[] = { "disk", "live" };
	size_t i;

#define PROBLEM(...) do { bad++; if (!quiet) { \
	printf("  BAD  %s: ", id); printf(__VA_ARGS__); printf("\n"); } } while (0)

	snprintf(dir, sizeof(dir), PS_SNAPDIR "/%s", id);
	snprintf(p, sizeof(p), "%s/SHA256SUMS", dir);
	sums = slurp(p, NULL);
	if (!sums) {
		PROBLEM("no SHA256SUMS (%s)", strerror(errno));
		return bad;
	}
	for (line = strtok_r(sums, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		const char *rel = line + 66;

		if (strlen(line) < 67 || line[64] != ' ' || line[65] != ' ' ||
		    strstr(rel, "..") || rel[0] == '/') {
			PROBLEM("malformed SHA256SUMS line");
			continue;
		}
		listed++;
		snprintf(p, sizeof(p), "%s/%s", dir, rel);
		if (file_sha256(p, h) != 0)
			PROBLEM("%s missing (%s)", rel, strerror(errno));
		else if (strncmp(h, line, 64))
			PROBLEM("%s changed since the snapshot was taken", rel);
	}
	free(sums);
	/* every file present must be listed */
	for (i = 0; i < 2; i++) {
		DIR *d;
		struct dirent *de;

		snprintf(p, sizeof(p), "%s/%s", dir, sub[i]);
		d = opendir(p);
		if (!d)
			continue;
		while ((de = readdir(d)))
			if (de->d_name[0] != '.')
				found++;
		closedir(d);
	}
	found++;		/* meta */
	if (found != listed)
		PROBLEM("%d file(s) present, %d listed in SHA256SUMS", found,
			listed);
	meta_get(id, "format", fmt, sizeof(fmt));
	meta_get(id, "id", mid, sizeof(mid));
	if (strcmp(fmt, PS_FORMAT))
		PROBLEM("unknown format '%s'", fmt);
	if (strcmp(mid, id))
		PROBLEM("meta names '%s', not this snapshot", mid);
	meta_get(id, "prev", prev, sizeof(prev));
	meta_get(id, "prev_sums", prev_sums, sizeof(prev_sums));
	if (strcmp(prev, "-") && valid_id(prev)) {
		snprintf(p, sizeof(p), PS_SNAPDIR "/%s", prev);
		if (access(p, F_OK) == 0) {
			if (snap_sums_hash(prev, h) != 0 || strcmp(h, prev_sums))
				PROBLEM("previous snapshot %s changed after this "
					"one was taken", prev);
		} else if (!quiet) {
			printf("  note %s: previous snapshot %s no longer kept\n",
			       id, prev);
		}
	}
#undef PROBLEM
	return bad;
}

static void snap_line(const char *id)
{
	char reason[64], user[40], locked[16];

	meta_get(id, "reason", reason, sizeof(reason));
	meta_get(id, "sudo_user", user, sizeof(user));
	meta_get(id, "locked", locked, sizeof(locked));
	printf("%-24s %-16s by %-12s locked=%s\n", id, reason, user, locked);
}

static void snapshot_usage(void)
{
	fprintf(stderr,
		"usage: secure-sudo snapshot [create] [-m REASON]\n"
		"       secure-sudo snapshot list\n"
		"       secure-sudo snapshot show ID\n"
		"       secure-sudo snapshot verify [ID]\n");
}

int cmd_snapshot(int argc, char **argv)
{
	char id[64], sums[65];
	size_t n, i;
	char **ids;
	int bad = 0;

	if (argc == 0 || !strcmp(argv[0], "create") || !strcmp(argv[0], "-m")) {
		char reason[64] = "manual";
		int a = argc && !strcmp(argv[0], "create") ? 1 : 0;

		if (argc - a == 2 && !strcmp(argv[a], "-m")) {
			size_t j, k = 0;

			for (j = 0; argv[a + 1][j] && k + 1 < sizeof(reason); j++)
				if (isalnum((unsigned char)argv[a + 1][j]) ||
				    strchr("._-", argv[a + 1][j]))
					reason[k++] = argv[a + 1][j];
			reason[k] = '\0';
			if (!k)
				snprintf(reason, sizeof(reason), "manual");
		} else if (argc - a != 0) {
			snapshot_usage();
			return 2;
		}
		if (policy_snapshot(reason, id, sizeof(id), sums, sizeof(sums))) {
			fprintf(stderr, "secure-sudo: snapshot failed: %s\n",
				strerror(errno));
			return 1;
		}
		printf("snapshot %s\n", id);
		{
			struct ps_record r = { .action = "snapshot",
				.result = "complete", .detail = reason,
				.snapshot = id, .snapshot_sums = sums,
				.lint_errors = -1, .changes = -1 };

			policy_history_append(&r);
		}
		return 0;
	}
	if (!strcmp(argv[0], "list") && argc == 1) {
		ids = snap_ids(&n);
		for (i = 0; i < n; i++)
			snap_line(ids[i]);
		if (!n)
			printf("no snapshots in %s\n", PS_SNAPDIR);
		ids_free(ids, n);
		return 0;
	}
	if (!strcmp(argv[0], "show") && argc == 2) {
		char p[512], *m, *s;

		if (!valid_id(argv[1])) {
			fprintf(stderr, "secure-sudo: not a snapshot id: %s\n", argv[1]);
			return 2;
		}
		snprintf(p, sizeof(p), PS_SNAPDIR "/%s/meta", argv[1]);
		m = slurp(p, NULL);
		if (!m) {
			fprintf(stderr, "secure-sudo: no snapshot %s\n", argv[1]);
			return 1;
		}
		fputs(m, stdout);
		free(m);
		snprintf(p, sizeof(p), PS_SNAPDIR "/%s/SHA256SUMS", argv[1]);
		s = slurp(p, NULL);
		printf("files:\n%s", s ? s : "  (no SHA256SUMS)\n");
		free(s);
		bad = snap_verify(argv[1], 0);
		printf("integrity: %s\n", bad ? "FAILED" : "ok");
		return bad ? 1 : 0;
	}
	if (!strcmp(argv[0], "verify") && argc <= 2) {
		if (argc == 2) {
			if (!valid_id(argv[1])) {
				fprintf(stderr, "secure-sudo: not a snapshot id: %s\n",
					argv[1]);
				return 2;
			}
			bad = snap_verify(argv[1], 0);
			printf("snapshot %s: %s\n", argv[1], bad ? "FAILED" : "ok");
			return bad ? 1 : 0;
		}
		ids = snap_ids(&n);
		for (i = 0; i < n; i++)
			bad += snap_verify(ids[i], 0) ? 1 : 0;
		printf("snapshot verify: %zu snapshot(s), %d failed\n", n, bad);
		ids_free(ids, n);
		return bad ? 1 : 0;
	}
	snapshot_usage();
	return 2;
}

/* ------------------------------------------------------------ history */

static void json_str(FILE *f, const char *s)
{
	fputc('"', f);
	for (; s && *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\')
			fprintf(f, "\\%c", c);
		else if (c < 0x20 || c == 0x7f)
			fprintf(f, "\\u%04x", c);
		else
			fputc(c, f);
	}
	fputc('"', f);
}

/* The last line of @text (without its newline) into a new string. */
static char *last_line(const char *text, size_t len)
{
	size_t end = len, start;

	while (end && text[end - 1] == '\n')
		end--;
	if (!end)
		return NULL;
	start = end;
	while (start && text[start - 1] != '\n')
		start--;
	return strndup(text + start, end - start);
}

int policy_history_append(const struct ps_record *r)
{
	char prev[65], ts[40], user[40], *line = NULL, *all, *last;
	size_t len = 0, alen;
	unsigned long luid;
	struct tm tm;
	time_t now = time(NULL);
	FILE *mf;
	int fd, rc = -1;

	if (ensure_state_dirs() != 0)
		return -1;
	fd = open(PS_HISTORY, O_RDWR | O_CREAT | O_APPEND | O_NOFOLLOW |
		  O_CLOEXEC, 0600);
	if (fd < 0 || flock(fd, LOCK_EX) != 0) {
		fprintf(stderr, "secure-sudo: %s: %s\n", PS_HISTORY,
			strerror(errno));
		if (fd >= 0)
			close(fd);
		return -1;
	}
	all = slurp(PS_HISTORY, &alen);
	last = all ? last_line(all, alen) : NULL;
	if (last)
		sha256_hex(last, strlen(last), prev);
	else
		snprintf(prev, sizeof(prev), "%s", zero_hash);
	free(last);
	free(all);
	gmtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
	who(user, sizeof(user), &luid);
	mf = open_memstream(&line, &len);
	if (!mf)
		goto out;
	fprintf(mf, "{\"v\":1,\"time\":\"%s\",\"ts\":%lld,\"action\":", ts,
		(long long)now);
	json_str(mf, r->action);
	fprintf(mf, ",\"uid\":%u,\"loginuid\":%lu,\"sudo_user\":",
		(unsigned)getuid(), luid);
	json_str(mf, user);
	fprintf(mf, ",\"result\":");
	json_str(mf, r->result);
	if (r->lint_errors >= 0)
		fprintf(mf, ",\"lint_errors\":%d", r->lint_errors);
	if (r->changes >= 0)
		fprintf(mf, ",\"changes\":%d", r->changes);
	if (r->accepted || r->rejected || r->skipped)
		fprintf(mf, ",\"accepted\":%d,\"rejected\":%d,\"skipped\":%d",
			r->accepted, r->rejected, r->skipped);
	if (r->rejected_keys && r->rejected_keys[0]) {
		fprintf(mf, ",\"rejected_keys\":");
		json_str(mf, r->rejected_keys);
	}
	if (r->detail && r->detail[0]) {
		fprintf(mf, ",\"detail\":");
		json_str(mf, r->detail);
	}
	if (r->snapshot && r->snapshot[0]) {
		fprintf(mf, ",\"snapshot\":");
		json_str(mf, r->snapshot);
		fprintf(mf, ",\"snapshot_sums\":");
		json_str(mf, r->snapshot_sums);
	}
	if (r->restored_from && r->restored_from[0]) {
		fprintf(mf, ",\"restored_from\":");
		json_str(mf, r->restored_from);
	}
	fprintf(mf, ",\"prev\":\"%s\"}", prev);
	if (fclose(mf) != 0 || !line)
		goto out;
	{
		char *out = malloc(len + 2);
		ssize_t w;

		if (!out)
			goto out;
		memcpy(out, line, len);
		out[len] = '\n';
		w = write(fd, out, len + 1);
		free(out);
		if (w != (ssize_t)(len + 1) || fsync(fd) != 0)
			goto out;
	}
	openlog("secure-sudo", LOG_PID, LOG_AUTHPRIV);
	syslog(LOG_NOTICE, "policy_change %s", line);
	closelog();
	rc = 0;
out:
	if (rc != 0)
		fprintf(stderr, "secure-sudo: could not record the change in %s: "
			"%s\n", PS_HISTORY, strerror(errno));
	free(line);
	flock(fd, LOCK_UN);
	close(fd);
	return rc;
}

/* A field of one of our JSON lines (flat, written by the code above). */
static int jget(const char *line, const char *key, char *out, size_t n)
{
	char pat[64];
	const char *p;
	size_t j = 0;

	out[0] = '\0';
	snprintf(pat, sizeof(pat), "\"%s\":", key);
	p = strstr(line, pat);
	if (!p)
		return -1;
	p += strlen(pat);
	if (*p == '"') {
		for (p++; *p && *p != '"' && j + 1 < n; p++) {
			if (*p == '\\' && p[1])
				p++;
			out[j++] = *p;
		}
	} else {
		while (*p && *p != ',' && *p != '}' && j + 1 < n)
			out[j++] = *p++;
	}
	out[j] = '\0';
	return 0;
}

static void history_usage(void)
{
	fprintf(stderr, "usage: secure-sudo history [-n N] [--json] [--verify]\n");
}

int cmd_history(int argc, char **argv)
{
	int i, json = 0, verify = 0, bad = 0;
	long want = 20, total = 0, idx = 0;
	char *all, *line, *save = NULL, prev[65], h[65];
	size_t len;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--json"))
			json = 1;
		else if (!strcmp(argv[i], "--verify"))
			verify = 1;
		else if (!strcmp(argv[i], "-n") && i + 1 < argc)
			want = strtol(argv[++i], NULL, 10);
		else {
			history_usage();
			return 2;
		}
	}
	all = slurp(PS_HISTORY, &len);
	if (!all) {
		printf("no policy history yet (%s)\n", PS_HISTORY);
		return verify ? 1 : 0;
	}
	for (i = 0; (size_t)i < len; i++)
		if (all[i] == '\n')
			total++;
	snprintf(prev, sizeof(prev), "%s", zero_hash);
	for (line = strtok_r(all, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save), idx++) {
		char f[10][96];

		if (verify) {
			char rp[80], snap[64], ss[80], p[512];

			if (jget(line, "prev", rp, sizeof(rp)) != 0 ||
			    strcmp(rp, prev)) {
				printf("  BAD  line %ld: does not follow line %ld "
				       "(edited, removed or reordered)\n", idx + 1, idx);
				bad++;
			}
			if (jget(line, "snapshot", snap, sizeof(snap)) == 0 &&
			    valid_id(snap) &&
			    jget(line, "snapshot_sums", ss, sizeof(ss)) == 0) {
				snprintf(p, sizeof(p), PS_SNAPDIR "/%s", snap);
				if (access(p, F_OK) == 0 &&
				    (snap_sums_hash(snap, h) != 0 || strcmp(h, ss))) {
					printf("  BAD  line %ld: snapshot %s is not the "
					       "one recorded\n", idx + 1, snap);
					bad++;
				}
			}
			sha256_hex(line, strlen(line), prev);
			continue;
		}
		if (want >= 0 && idx < total - want)
			continue;
		if (json) {
			puts(line);
			continue;
		}
		jget(line, "time", f[0], sizeof(f[0]));
		jget(line, "action", f[1], sizeof(f[1]));
		jget(line, "sudo_user", f[2], sizeof(f[2]));
		jget(line, "result", f[3], sizeof(f[3]));
		jget(line, "changes", f[4], sizeof(f[4]));
		jget(line, "accepted", f[5], sizeof(f[5]));
		jget(line, "rejected", f[6], sizeof(f[6]));
		jget(line, "snapshot", f[7], sizeof(f[7]));
		jget(line, "rejected_keys", f[8], sizeof(f[8]));
		jget(line, "detail", f[9], sizeof(f[9]));
		printf("%s  %-9s %-10s %-9s", f[0], f[1], f[2][0] ? f[2] : "-",
		       f[3]);
		if (f[4][0])
			printf(" changes=%s", f[4]);
		if (f[5][0])
			printf(" accepted=%s rejected=%s", f[5], f[6]);
		if (f[8][0])
			printf(" rejected_keys=%s", f[8]);
		if (f[9][0])
			printf(" (%s)", f[9]);
		if (f[7][0])
			printf(" before=%s", f[7]);
		printf("\n");
	}
	free(all);
	if (verify) {
		printf("history verify: %ld record(s), %d problem(s)\n", idx, bad);
		return bad ? 1 : 0;
	}
	return 0;
}

/* ------------------------------------------------------------ restore */

/* Show what restoring @id changes in /etc/secure_sudo; returns #changes. */
static int restore_preview(const char *id)
{
	char sp[512], cp[512];
	int changes = 0;
	size_t i;

	for (i = 0; i <= ss_nlists; i++) {
		const char *f = i < ss_nlists ? ss_lists[i].cfg_file :
						"secure-sudo.conf";
		char *want, *have;
		size_t wl = 0, hl = 0;

		snprintf(sp, sizeof(sp), PS_SNAPDIR "/%s/disk/%s", id, f);
		snprintf(cp, sizeof(cp), CONFIG_DIR "/%s", f);
		want = slurp(sp, &wl);
		have = slurp(cp, &hl);
		if (!want && !have) {
			continue;
		} else if (!want) {
			printf("  remove    %s (not in the snapshot: load clears "
			       "its list)\n", f);
			changes++;
		} else if (!have) {
			printf("  create    %s\n", f);
			changes++;
		} else if (wl != hl || memcmp(want, have, wl)) {
			changes++;
			if (i < ss_nlists) {
				if (!ents_diff(f, want, have, ss_lists[i].kind, 1))
					printf("  rewrite   %s (comments/order "
					       "only)\n", f);
			} else {
				struct cfg_file a, b;
				size_t k;
				int shown = 0;

				if (cfg_parse(sp, &a) == 0) {
					if (cfg_parse(cp, &b) != 0)
						memset(&b, 0, sizeof(b));
					for (k = 0; k < ss_nknobs; k++) {
						const char *x = cfg_value(&a, ss_knobs[k].cfg_key);
						const char *y = cfg_value(&b, ss_knobs[k].cfg_key);

						if ((x || y) && (!x || !y || strcmp(x, y))) {
							printf("  change    %-34s now %s -> "
							       "snapshot %s\n",
							       ss_knobs[k].cfg_key,
							       y ? y : "(unset)",
							       x ? x : "(unset)");
							shown++;
						}
					}
					cfg_free(&a);
					cfg_free(&b);
				}
				if (!shown)
					printf("  rewrite   %s (other keys, comments "
					       "or order)\n", f);
			}
		}
		free(want);
		free(have);
	}
	return changes;
}

static int restore_files(const char *id)
{
	char sp[512], cp[512];
	size_t i;
	int bad = 0;

	for (i = 0; i <= ss_nlists; i++) {
		const char *f = i < ss_nlists ? ss_lists[i].cfg_file :
						"secure-sudo.conf";
		char *want;
		size_t wl = 0;

		snprintf(sp, sizeof(sp), PS_SNAPDIR "/%s/disk/%s", id, f);
		snprintf(cp, sizeof(cp), CONFIG_DIR "/%s", f);
		want = slurp(sp, &wl);
		if (!want) {
			if (unlink(cp) != 0 && errno != ENOENT) {
				fprintf(stderr, "secure-sudo: remove %s: %s\n", cp,
					strerror(errno));
				bad++;
			}
			continue;
		}
		if (write_replace(cp, want, wl, 0644) != 0) {
			fprintf(stderr, "secure-sudo: write %s: %s\n", cp,
				strerror(errno));
			bad++;
		}
		free(want);
	}
	return bad;
}

static void restore_usage(void)
{
	fprintf(stderr, "usage: secure-sudo restore ID [--no-load] [-y]\n"
		"       (secure-sudo snapshot list shows the ids)\n");
}

int cmd_restore(int argc, char **argv)
{
	const char *id = NULL;
	int i, no_load = 0, yes = 0, n, locked, rc;
	char pre[64] = "", pre_sums[65] = "";
	struct ps_record r = { .action = "restore", .lint_errors = -1,
			       .changes = -1 };

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--no-load"))
			no_load = 1;
		else if (!strcmp(argv[i], "-y"))
			yes = 1;
		else if (!id)
			id = argv[i];
		else {
			restore_usage();
			return 2;
		}
	}
	if (!id || !valid_id(id)) {
		restore_usage();
		return 2;
	}
	locked = policy_locked();
	if (locked == 1 && !no_load) {
		fprintf(stderr, "secure-sudo: restore refused: the config is locked "
			"until reboot. `restore %s --no-load` puts the files back "
			"for the next boot.\n", id);
		return 1;
	}
	if (snap_verify(id, 0) != 0) {
		fprintf(stderr, "secure-sudo: restore refused: snapshot %s failed "
			"its integrity check\n", id);
		r.result = "refused";
		r.detail = "snapshot failed verification";
		r.restored_from = id;
		policy_history_append(&r);
		return 1;
	}
	printf("secure-sudo restore %s into %s:\n", id, CONFIG_DIR);
	n = restore_preview(id);
	if (!n)
		printf("  (the files already match the snapshot)\n");
	if (!yes) {
		char ans[8] = "";

		fprintf(stderr, "Restore these files%s? Type 'yes': ",
			no_load ? "" : " and load them");
		if (!fgets(ans, sizeof(ans), stdin) || strcmp(ans, "yes\n")) {
			fprintf(stderr, "aborted\n");
			return 1;
		}
	}
	if (policy_snapshot("pre-restore", pre, sizeof(pre), pre_sums,
			    sizeof(pre_sums)) != 0) {
		fprintf(stderr, "secure-sudo: restore refused: could not snapshot "
			"the current state first: %s\n", strerror(errno));
		return 1;
	}
	printf("restore: current state saved as snapshot %s\n", pre);
	if (restore_files(id) != 0) {
		fprintf(stderr, "secure-sudo: restore INCOMPLETE: some files were "
			"not written; `secure-sudo restore %s` puts back what was "
			"there\n", pre);
		r.result = "partial";
		r.detail = "files not all written";
		r.snapshot = pre;
		r.snapshot_sums = pre_sums;
		r.restored_from = id;
		policy_history_append(&r);
		return 1;
	}
	if (no_load) {
		printf("restore: files restored; not loaded (%s)\n",
		       locked == 1 ? "locked: they apply at the next boot" :
		       "run `secure-sudo load` to apply them");
		r.result = "complete";
		r.detail = "files only (--no-load)";
		r.snapshot = pre;
		r.snapshot_sums = pre_sums;
		r.restored_from = id;
		policy_history_append(&r);
		return 0;
	}
	rc = policy_load(0, "restore", id, pre, pre_sums);
	return rc == 0 ? 0 : 1;
}
