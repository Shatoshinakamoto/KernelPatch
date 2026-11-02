// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * node_scan.c - `secure-sudo node-scan`: find Node.js runtimes that are not
 * at a standard path and register them for the Node child guard (#11).
 *
 * The kernel treats an exec of /usr/bin/node, /usr/bin/nodejs,
 * /usr/local/bin/node, or of any path on node_sea_binaries, as "node": that
 * process and its forks may only exec programs on node_allowed_children.
 * Single-executable applications (SEA) and pkg-built programs are node
 * runtimes under another name, so they need listing. Listing them by hand is
 * easy to forget; this finds them (THREAT_MODEL.md gap G1).
 *
 * What counts as a node runtime: a regular, executable ELF file that holds
 * - Node's SEA fuse, "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2". Every
 *   Node build since 18.16 carries it; ":1" after it means a SEA blob was
 *   injected (an SEA), ":0" a plain node binary, e.g. a renamed copy; or
 * - pkg's markers, "PKG_EXECPATH" or "// PAYLOAD_POSITION //" (Vercel pkg
 *   and its forks patch these into their node base binaries);
 * and is not an Electron app (see scan_fd).
 *
 * Registering a file only ever adds restriction: a task that execs it is
 * marked, and a marked task that execs it stays marked. Nothing here can
 * lift the guard from anything. So a non-root user who plants a file with
 * the marker gains nothing but a guard on that file; to keep such files from
 * crowding legitimate ones out of the kernel's 256 entries, root-owned files
 * that only root can write are listed first, and manual entries always come
 * before any found ones.
 *
 * Results go to SS_STATE_DIR/node_sea_auto.list (kept apart from the
 * hand-written node_sea_binaries.conf); `load` sends both to the kernel.
 * A cache keyed by device, inode, size and mtime means an unchanged file is
 * not read again. secure-sudod runs this at start and every
 * node_sea_scan_interval minutes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cli.h"

#define NS_AUTO		SS_STATE_DIR "/node_sea_auto.list"
#define NS_CACHE	SS_STATE_DIR "/node_sea_scan.cache"
#define NS_DEFAULT_DIRS	"/opt,/usr/local/bin,/usr/local/sbin,/usr/local/lib,/srv"
#define NS_MAX_SIZE	(1024LL * 1024 * 1024)	/* larger files are skipped */
#define NS_MAX_FOUND	1024
#define NS_MAX_VISIT	500000
#define NS_KERNEL_ITEMS	256		/* SL_MAX_ITEMS in ss_node.c */
#define NS_KERNEL_TEXT	(64 * 1024)	/* SL_MAX_TEXT in ss_node.c */

static const char SEA_FUSE[] = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";
static const char *const PKG_MARKS[] = { "PKG_EXECPATH", "// PAYLOAD_POSITION //" };
/* @electron/fuses' sentinel, and the switch every Electron build reads */
static const char *const ELECTRON_MARKS[] = {
	"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", "ELECTRON_RUN_AS_NODE"
};
#define NMARKS(a) (sizeof(a) / sizeof((a)[0]))

enum verdict { V_NONE = 0, V_SEA, V_NODE, V_PKG, V_ELECTRON };
static const char *const vname[] = { "none", "sea", "node", "pkg", "electron" };

struct found {
	char path[PATH_MAX];
	enum verdict kind;
	int trusted;		/* owned by root, writable by root only */
};

struct cache_ent {
	unsigned long long dev, ino, size, mtime;
	int verdict;
};

static struct {
	struct found *found;
	int nfound, overflow;
	struct cache_ent *old, *new_;
	int nold, nnew, capnew;
	long visited, read, cached, unrepresentable, too_big, unreadable, electron;
	int quiet, partial;
} S;

/* ---------------------------------------------------------------- cache */

static int cmp_ent(const void *a, const void *b)
{
	const struct cache_ent *x = a, *y = b;

	if (x->dev != y->dev)
		return x->dev < y->dev ? -1 : 1;
	if (x->ino != y->ino)
		return x->ino < y->ino ? -1 : 1;
	return 0;
}

static void cache_load(void)
{
	FILE *f = fopen(NS_CACHE, "re");
	struct cache_ent e;
	int cap = 0;

	if (!f)
		return;
	while (fscanf(f, "%llu %llu %llu %llu %d\n", &e.dev, &e.ino, &e.size,
		      &e.mtime, &e.verdict) == 5) {
		if (e.verdict < V_NONE || e.verdict > V_ELECTRON)
			continue;
		if (S.nold == cap) {
			struct cache_ent *g;

			cap = cap ? cap * 2 : 256;
			g = realloc(S.old, (size_t)cap * sizeof(*g));
			if (!g)
				break;
			S.old = g;
		}
		S.old[S.nold++] = e;
	}
	fclose(f);
	if (S.nold)
		qsort(S.old, (size_t)S.nold, sizeof(*S.old), cmp_ent);
}

/* The old cache is sorted by device and inode once; each lookup bisects. */
static int cache_find(const struct cache_ent *k)
{
	const struct cache_ent *e = S.nold ?
		bsearch(k, S.old, (size_t)S.nold, sizeof(*S.old), cmp_ent) : NULL;

	if (e && e->size == k->size && e->mtime == k->mtime)
		return e->verdict;
	return -1;
}


static void cache_add(const struct cache_ent *e)
{
	if (S.nnew == S.capnew) {
		struct cache_ent *g;
		int cap = S.capnew ? S.capnew * 2 : 256;

		g = realloc(S.new_, (size_t)cap * sizeof(*g));
		if (!g)
			return;
		S.new_ = g;
		S.capnew = cap;
	}
	S.new_[S.nnew++] = *e;
}

/*
 * A scan of a few directories keeps what the cache knows about the rest, so
 * the next full scan does not read them all again.
 */
static void cache_keep_unvisited(void)
{
	int i, n = S.nnew;

	if (n)
		qsort(S.new_, (size_t)n, sizeof(*S.new_), cmp_ent);
	for (i = 0; i < S.nold; i++)
		if (!n || !bsearch(&S.old[i], S.new_, (size_t)n, sizeof(*S.new_), cmp_ent))
			cache_add(&S.old[i]);
}

/* ------------------------------------------------------------- matching */

/*
 * Read the whole file and note which markers it holds; a marker may span two
 * reads, so each read is searched together with the tail of the last one.
 * Electron apps embed Node as well, but registering one would confine its
 * whole UI (a code editor's terminal could no longer start a shell), so they
 * are reported, not registered: list one by hand to confine it.
 */
static enum verdict scan_fd(int fd)
{
	static char buf[(1 << 20) + 256];
	size_t keep = 0, have = 0, i, flen = sizeof(SEA_FUSE) - 1;
	int fuse = 0, sea = 0, pkg = 0, electron = 0;
	unsigned char magic[4];
	ssize_t n;

	if (pread(fd, magic, 4, 0) != 4 || memcmp(magic, "\177ELF", 4))
		return V_NONE;
	for (i = 0; i < NMARKS(PKG_MARKS); i++)
		if (strlen(PKG_MARKS[i]) > keep)
			keep = strlen(PKG_MARKS[i]);
	for (i = 0; i < NMARKS(ELECTRON_MARKS); i++)
		if (strlen(ELECTRON_MARKS[i]) > keep)
			keep = strlen(ELECTRON_MARKS[i]);
	if (flen + 2 > keep)
		keep = flen + 2;		/* the fuse and its ":0"/":1" */
	while ((n = read(fd, buf + have, sizeof(buf) - 256 - have)) > 0) {
		size_t len = have + (size_t)n;
		const char *p = buf, *end = buf + len, *hit;

		/* every fuse whose flag is in this window; one cut short is
		 * kept in the tail and seen again whole next time */
		while ((hit = memmem(p, (size_t)(end - p), SEA_FUSE, flen))) {
			if (hit + flen + 2 <= end) {
				fuse = 1;
				if (hit[flen] == ':' && hit[flen + 1] == '1')
					sea = 1;	/* postject flipped it: an SEA */
			}
			p = hit + 1;
		}
		for (i = 0; !pkg && i < NMARKS(PKG_MARKS); i++)
			pkg = memmem(buf, len, PKG_MARKS[i], strlen(PKG_MARKS[i])) != NULL;
		for (i = 0; !electron && i < NMARKS(ELECTRON_MARKS); i++)
			electron = memmem(buf, len, ELECTRON_MARKS[i],
					  strlen(ELECTRON_MARKS[i])) != NULL;
		have = len < keep ? len : keep;
		memmove(buf, buf + len - have, have);
	}
	/* a fuse that ends the file without its flag is still a fuse */
	if (memmem(buf, have, SEA_FUSE, flen))
		fuse = 1;
	if (electron && (fuse || pkg))
		return V_ELECTRON;
	if (fuse)
		return sea ? V_SEA : V_NODE;
	return pkg ? V_PKG : V_NONE;
}

/* The kernel list is one entry per line, trimmed: such paths can't be listed. */
static int representable(const char *p)
{
	size_t n = strlen(p);

	if (!n || p[0] != '/' || p[n - 1] == ' ' || p[n - 1] == '\t')
		return 0;
	for (; *p; p++)
		if ((unsigned char)*p < 0x20 || *p == 0x7f)
			return 0;
	return 1;
}

static void add_found(const char *path, enum verdict v)
{
	char real[PATH_MAX];
	struct stat st;
	int i;

	if (!realpath(path, real) || !representable(real)) {
		S.unrepresentable++;
		if (!S.quiet)
			fprintf(stderr, "node-scan: skipped a runtime whose path cannot "
				"be listed: %s\n", path);
		return;
	}
	for (i = 0; i < S.nfound; i++)
		if (!strcmp(S.found[i].path, real))
			return;
	if (S.nfound == NS_MAX_FOUND) {
		S.overflow++;
		return;
	}
	if (stat(real, &st) != 0)
		return;
	snprintf(S.found[S.nfound].path, PATH_MAX, "%s", real);
	S.found[S.nfound].kind = v;
	S.found[S.nfound].trusted = st.st_uid == 0 && !(st.st_mode & 022);
	S.nfound++;
}

static int visit(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
	struct cache_ent k;
	struct stat fst;
	int fd, v;

	(void)ftw;
	if (++S.visited > NS_MAX_VISIT)
		return 1;	/* stop the walk: reported as truncated */
	if (type != FTW_F || !S_ISREG(st->st_mode) || !(st->st_mode & 0111))
		return 0;
	if (st->st_size < 64)
		return 0;
	if (st->st_size > NS_MAX_SIZE) {
		S.too_big++;
		return 0;
	}
	k.dev = st->st_dev;
	k.ino = st->st_ino;
	k.size = (unsigned long long)st->st_size;
	k.mtime = (unsigned long long)st->st_mtim.tv_sec * 1000000000ULL +
		  (unsigned long long)st->st_mtim.tv_nsec;
	v = cache_find(&k);
	if (v >= 0) {
		S.cached++;
	} else {
		fd = open(path, O_RDONLY | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0) {
			S.unreadable++;
			return 0;
		}
		/* the same file nftw saw, not one swapped in since */
		if (fstat(fd, &fst) != 0 || fst.st_ino != st->st_ino ||
		    fst.st_dev != st->st_dev || !S_ISREG(fst.st_mode)) {
			close(fd);
			return 0;
		}
		v = scan_fd(fd);
		close(fd);
		S.read++;
	}
	k.verdict = v;
	cache_add(&k);
	if (v == V_ELECTRON) {
		S.electron++;
		if (!S.quiet)
			fprintf(stderr, "node-scan: not registered (an Electron app; list it "
				"by hand to confine it): %s\n", path);
	} else if (v != V_NONE) {
		add_found(path, (enum verdict)v);
	}
	return 0;
}

/* --------------------------------------------------------------- merging */

static int cmp_found(const void *a, const void *b)
{
	const struct found *x = a, *y = b;

	if (x->trusted != y->trusted)
		return y->trusted - x->trusted;	/* trusted first */
	return strcmp(x->path, y->path);
}

/* Append one line; returns 0, or -1 when the kernel's limits are reached. */
static int append_line(char **buf, size_t *len, size_t *cap, int *items,
		       const char *line, size_t n)
{
	if (*items >= NS_KERNEL_ITEMS || *len + n + 1 > NS_KERNEL_TEXT)
		return -1;
	if (*len + n + 2 > *cap) {
		size_t c = (*len + n + 2) * 2;
		char *g = realloc(*buf, c);

		if (!g)
			return -1;
		*buf = g;
		*cap = c;
	}
	memcpy(*buf + *len, line, n);
	(*buf)[*len + n] = '\n';
	*len += n + 1;
	(*buf)[*len] = '\0';
	(*items)++;
	return 0;
}

static int has_line(const char *buf, size_t len, const char *line, size_t n)
{
	const char *p = buf, *end = buf + len;

	while (p < end) {
		const char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t l = nl ? (size_t)(nl - p) : (size_t)(end - p);

		if (l == n && !memcmp(p, line, n))
			return 1;
		p += l + 1;
	}
	return 0;
}

/* Each non-comment line of @text, trimmed, to @fn. */
static void each_line(const char *text, size_t len,
		      void (*fn)(const char *s, size_t n, void *arg), void *arg)
{
	const char *p = text, *end = text + len;

	while (p < end) {
		const char *nl = memchr(p, '\n', (size_t)(end - p));
		const char *e = nl ? nl : end, *s = p;

		while (s < e && (*s == ' ' || *s == '\t' || *s == '\r'))
			s++;
		while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'))
			e--;
		if (e > s && *s != '#')
			fn(s, (size_t)(e - s), arg);
		p = nl ? nl + 1 : end;
	}
}

struct merge {
	char *buf;
	size_t len, cap;
	int items, manual, added, dropped;
	int adding_auto;
};

static void merge_one(const char *s, size_t n, void *arg)
{
	struct merge *m = arg;

	if (m->buf && has_line(m->buf, m->len, s, n))
		return;
	if (append_line(&m->buf, &m->len, &m->cap, &m->items, s, n) != 0) {
		m->dropped++;
		return;
	}
	if (m->adding_auto)
		m->added++;
	else
		m->manual++;
}

int node_sea_merge(const char *manual, size_t mlen, const char *autol,
		   size_t alen, char **out, size_t *outlen, int *added,
		   int *dropped)
{
	struct merge m = { 0 };

	if (manual)
		each_line(manual, mlen, merge_one, &m);
	m.adding_auto = 1;
	if (autol)
		each_line(autol, alen, merge_one, &m);
	if (!m.buf) {
		m.buf = strdup("\n");
		m.len = 1;
		if (!m.buf)
			return -1;
	}
	*out = m.buf;
	*outlen = m.len;
	if (added)
		*added = m.added;
	if (dropped)
		*dropped = m.dropped;
	return 0;
}

char *node_sea_read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "re");
	char *buf = NULL;
	size_t cap = 0, n;
	char chunk[4096];

	*len = 0;
	if (!f)
		return NULL;
	while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) {
		if (*len + n + 1 > cap) {
			char *g;

			cap = (*len + n + 1) * 2;
			g = realloc(buf, cap);
			if (!g) {
				free(buf);
				fclose(f);
				*len = 0;
				return NULL;
			}
			buf = g;
		}
		memcpy(buf + *len, chunk, n);
		*len += n;
	}
	fclose(f);
	if (buf)
		buf[*len] = '\0';
	return buf;
}

const char *node_sea_auto_path(void)
{
	return NS_AUTO;
}

/* --------------------------------------------------------------- output */

static int write_atomic(const char *path, const char *data, size_t len)
{
	char tmp[PATH_MAX];
	int fd, ok;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof(tmp))
		return -1;
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	ok = write(fd, data, len) == (ssize_t)len && fsync(fd) == 0;
	if (close(fd) != 0)
		ok = 0;
	if (!ok || rename(tmp, path) != 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

static int write_state(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	char line[PATH_MAX + 64];
	int i, rc = 0, n;

	if (mkdir(SS_STATE_DIR, 0700) != 0 && errno != EEXIST)
		return -1;

	/* cache */
	if (S.partial)
		cache_keep_unvisited();
	for (i = 0; i < S.nnew; i++) {
		n = snprintf(line, sizeof(line), "%llu %llu %llu %llu %d\n",
			     S.new_[i].dev, S.new_[i].ino, S.new_[i].size,
			     S.new_[i].mtime, S.new_[i].verdict);
		if (len + (size_t)n + 1 > cap) {
			char *g;

			cap = (len + (size_t)n + 1) * 2;
			g = realloc(buf, cap);
			if (!g) {
				free(buf);
				return -1;
			}
			buf = g;
		}
		memcpy(buf + len, line, (size_t)n);
		len += (size_t)n;
	}
	if (write_atomic(NS_CACHE, buf ? buf : "", len) != 0)
		rc = -1;
	free(buf);

	/* found list */
	buf = NULL; len = 0; cap = 0;
	n = snprintf(line, sizeof(line),
		     "# Written by `secure-sudo node-scan`; do not edit (list paths by hand in\n"
		     "# " CONFIG_DIR "/node_sea_binaries.conf). One path per line.\n");
	buf = malloc((size_t)n + 1);
	if (!buf)
		return -1;
	memcpy(buf, line, (size_t)n + 1);
	len = (size_t)n;
	cap = (size_t)n + 1;
	for (i = 0; i < S.nfound; i++) {
		size_t l = strlen(S.found[i].path);

		if (len + l + 2 > cap) {
			char *g;

			cap = (len + l + 2) * 2;
			g = realloc(buf, cap);
			if (!g) {
				free(buf);
				return -1;
			}
			buf = g;
		}
		memcpy(buf + len, S.found[i].path, l);
		buf[len + l] = '\n';
		len += l + 1;
	}
	if (write_atomic(NS_AUTO, buf, len) != 0)
		rc = -1;
	free(buf);
	return rc;
}

static void print_changes(const char *prev, size_t plen)
{
	int i;

	for (i = 0; i < S.nfound; i++)
		if (!prev || !has_line(prev, plen, S.found[i].path, strlen(S.found[i].path)))
			printf("node-scan: + %s (%s%s)\n", S.found[i].path,
			       vname[S.found[i].kind],
			       S.found[i].trusted ? "" : ", not root-owned");
	if (prev) {
		const char *p = prev, *end = prev + plen;

		while (p < end) {
			const char *nl = memchr(p, '\n', (size_t)(end - p));
			size_t l = nl ? (size_t)(nl - p) : (size_t)(end - p);
			int still = 0;

			if (l && *p == '/') {
				for (i = 0; i < S.nfound; i++)
					if (strlen(S.found[i].path) == l &&
					    !memcmp(S.found[i].path, p, l))
						still = 1;
				if (!still)
					printf("node-scan: - %.*s (gone)\n", (int)l, p);
			}
			p += l + 1;
		}
	}
}

/* ----------------------------------------------------------------- main */

static void ns_usage(void)
{
	fprintf(stderr,
"Usage: secure-sudo node-scan [--dry-run] [--quiet] [DIR|FILE...]\n"
"  Find Node.js runtimes (SEA, pkg, renamed node) under DIR (default: the\n"
"  node_sea_scan_dirs setting, else " NS_DEFAULT_DIRS ")\n"
"  and register them for the Node child guard (#11). --dry-run only lists,\n"
"  one \"PATH<TAB>KIND\" line per runtime (KIND: sea, node, pkg).\n");
}

static void scan_dirs_from_config(char *out, size_t n)
{
	struct cfg_file c;
	int i;

	snprintf(out, n, "%s", NS_DEFAULT_DIRS);
	if (cfg_parse(CONFIG_DIR "/secure-sudo.conf", &c) != 0)
		return;
	for (i = 0; i < c.n; i++)
		if (!c.e[i].bad && !strcmp(c.e[i].key, "node_sea_scan_dirs"))
			snprintf(out, n, "%s", c.e[i].val);
	cfg_free(&c);
}

static void walk(const char *dir)
{
	struct stat st;

	if (dir[0] != '/') {
		fprintf(stderr, "node-scan: '%s' is not an absolute path; skipped\n", dir);
		return;
	}
	if (lstat(dir, &st) != 0)
		return;		/* absent default dirs are normal */
	if (S_ISREG(st.st_mode))
		visit(dir, &st, FTW_F, NULL);	/* one file named on the command line */
	else if (S_ISDIR(st.st_mode))
		nftw(dir, visit, 32, FTW_PHYS);
}

/* Is @path @dir itself or inside it? Both are compared as real paths. */
static int under(const char *path, const char *dir)
{
	char rd[PATH_MAX];
	size_t n;

	if (!realpath(dir, rd))
		snprintf(rd, sizeof(rd), "%s", dir);	/* gone: compare as given */
	n = strlen(rd);
	while (n > 1 && rd[n - 1] == '/')
		rd[--n] = '\0';
	return !strncmp(path, rd, n) && (path[n] == '\0' || path[n] == '/' || n == 1);
}

/*
 * `node-scan DIR` re-scans DIR only: what an earlier scan found elsewhere is
 * checked again file by file (from the cache when unchanged) and kept, so a
 * scan of one directory never unregisters runtimes in the others.
 */
static void keep_found_elsewhere(int argc, char **argv)
{
	size_t plen;
	char *prev = node_sea_read_file(NS_AUTO, &plen), *line, *save = NULL;
	int i, inside;

	if (!prev)
		return;
	for (line = strtok_r(prev, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (line[0] != '/')
			continue;
		for (inside = 0, i = 0; !inside && i < argc; i++)
			inside = argv[i][0] != '-' && under(line, argv[i]);
		if (!inside)
			walk(line);
	}
	free(prev);
}

int cmd_node_scan(int argc, char **argv)
{
	char dirs[448], *p, *tok, *save = NULL;
	char *prev, *manual, *merged = NULL;
	size_t plen, mlen, alen, glen;
	char *autol;
	int dry = 0, ndirs = 0, i, added = 0, dropped = 0, err = 0, rc = 0;
	long nsea = 0, nnode = 0, npkg = 0;
	FILE *info;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--dry-run"))
			dry = 1;
		else if (!strcmp(argv[i], "--quiet"))
			S.quiet = 1;
		else if (argv[i][0] == '-') {
			ns_usage();
			return 2;
		} else
			ndirs++;
	}
	S.partial = ndirs > 0;
	/* a dry run's stdout is only the list, one runtime per line */
	info = dry ? stderr : stdout;
	S.found = calloc(NS_MAX_FOUND, sizeof(*S.found));
	if (!S.found)
		return 1;
	cache_load();

	if (ndirs) {
		for (i = 0; i < argc; i++)
			if (argv[i][0] != '-')
				walk(argv[i]);
		keep_found_elsewhere(argc, argv);
	} else {
		scan_dirs_from_config(dirs, sizeof(dirs));
		for (p = dirs; (tok = strtok_r(p, ",", &save)); p = NULL) {
			while (*tok == ' ' || *tok == '\t')
				tok++;
			tok[strcspn(tok, " \t")] = '\0';
			if (*tok)
				walk(tok);
		}
	}
	qsort(S.found, (size_t)S.nfound, sizeof(*S.found), cmp_found);
	for (i = 0; i < S.nfound; i++) {
		nsea += S.found[i].kind == V_SEA;
		nnode += S.found[i].kind == V_NODE;
		npkg += S.found[i].kind == V_PKG;
	}

	prev = node_sea_read_file(NS_AUTO, &plen);
	if (dry) {
		for (i = 0; i < S.nfound; i++)
			printf("%s\t%s%s\n", S.found[i].path, vname[S.found[i].kind],
			       S.found[i].trusted ? "" : "\tnot-root-owned");
	} else {
		print_changes(prev, plen);
		if (write_state() != 0) {
			fprintf(stderr, "node-scan: cannot write %s: %s\n", SS_STATE_DIR,
				strerror(errno));
			rc = 1;
		}
	}

	if (!dry && !rc) {
		manual = node_sea_read_file(CONFIG_DIR "/node_sea_binaries.conf", &mlen);
		autol = node_sea_read_file(NS_AUTO, &alen);
		if (node_sea_merge(manual, mlen, autol, alen, &merged, &glen,
				   &added, &dropped) != 0) {
			rc = 1;
		} else if (write_file_err(SECFS "/node_sea_binaries", merged, glen, &err) != 0) {
			if (err == EPERM && access(SYSFS "/lock", F_OK) == 0) {
				char lk[4] = "";
				FILE *f = fopen(SYSFS "/lock", "re");

				if (f) {
					if (!fgets(lk, sizeof(lk), f))
						lk[0] = '\0';
					fclose(f);
				}
				if (lk[0] == '1')
					fprintf(stderr, "node-scan: the config is locked: the "
						"kernel list is unchanged until the next boot's "
						"`load`\n");
				else
					fprintf(stderr, "node-scan: kernel refused node_sea_binaries: %s\n",
						strerror(err));
			} else {
				fprintf(stderr, "node-scan: kernel refused node_sea_binaries: %s\n",
					strerror(err));
			}
			rc = 1;
		}
		free(manual);
		free(autol);
		free(merged);
	}

	if (!S.quiet || rc || dropped || S.overflow || S.visited > NS_MAX_VISIT)
		fprintf(info, "node-scan: %ld files seen, %ld read, %ld unchanged; %d runtime%s "
		       "found (%ld sea, %ld node, %ld pkg)%s\n",
		       S.visited > NS_MAX_VISIT ? NS_MAX_VISIT : S.visited, S.read,
		       S.cached, S.nfound, S.nfound == 1 ? "" : "s", nsea, nnode,
		       npkg, dry ? "; dry run, nothing written" :
		       rc ? "" : "; registered");
	if (S.visited > NS_MAX_VISIT) {
		fprintf(stderr, "node-scan: stopped after %d files: narrow node_sea_scan_dirs\n",
			NS_MAX_VISIT);
		rc = 1;
	}
	if (S.overflow) {
		fprintf(stderr, "node-scan: more than %d runtimes found; %d not recorded\n",
			NS_MAX_FOUND, S.overflow);
		rc = 1;
	}
	if (dropped) {
		fprintf(stderr, "node-scan: the kernel list is full (%d entries or 64 KiB): "
			"%d found runtime%s NOT registered\n", NS_KERNEL_ITEMS, dropped,
			dropped == 1 ? "" : "s");
		rc = 1;
	}
	if (!S.quiet && (S.too_big || S.unreadable || S.unrepresentable || S.electron))
		fprintf(info, "node-scan: skipped %ld over 1 GiB, %ld unreadable, "
			"%ld unlistable, %ld Electron\n", S.too_big, S.unreadable,
			S.unrepresentable, S.electron);
	free(prev);
	free(S.found);
	free(S.old);
	free(S.new_);
	return rc;
}
