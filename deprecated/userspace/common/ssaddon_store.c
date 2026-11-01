// SPDX-License-Identifier: GPL-2.0
/*
 * ssaddon_store - hourly-rotating compressed storage + Locus client.
 * See ssaddon_store.h for the interface and design notes.
 */
#define _GNU_SOURCE
#include "ssaddon_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <zlib.h>

/* Locus client target: read from /etc/secure_sudo/addons/locus-client.conf,
 * one "host = ..." / "port = ..." pair. Absent => no allocator, use defaults. */
#define LOCUS_CLIENT_CONF "/etc/secure_sudo/addons/locus-client.conf"

/* ---- directory bucket (hourly rotation) ---- */

/* mkdir -p for an absolute path, each component 0700. */
static int mkpath(const char *path)
{
	char tmp[PATH_MAX];
	size_t i, len;

	len = strlen(path);
	if (len == 0 || len >= sizeof(tmp))
		return -1;
	snprintf(tmp, sizeof(tmp), "%s", path);
	for (i = 1; i < len; i++) {
		if (tmp[i] == '/') {
			tmp[i] = '\0';
			if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
				return -1;
			tmp[i] = '/';
		}
	}
	if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

int store_current_bucket(const char *root, char *out, size_t n)
{
	time_t now = time(NULL);
	struct tm tm;
	char stamp[16];

	localtime_r(&now, &tm);
	strftime(stamp, sizeof(stamp), "%Y%m%d%H", &tm);	/* hour granularity */
	if (snprintf(out, n, "%s/%s", root, stamp) >= (int)n)
		return -1;
	return mkpath(out);
}

/* ---- compressed store ---- */

static int sha256_first8(const char *s, char out[9])
{
	unsigned char d[EVP_MAX_MD_SIZE];
	unsigned int dn = 0;
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	int ok = 0, i;

	if (c && EVP_DigestInit_ex(c, EVP_sha256(), NULL) &&
	    EVP_DigestUpdate(c, s, strlen(s)) && EVP_DigestFinal_ex(c, d, &dn))
		ok = 1;
	EVP_MD_CTX_free(c);
	if (!ok)
		return -1;
	for (i = 0; i < 4; i++)
		sprintf(out + 2 * i, "%02x", d[i]);
	out[8] = '\0';
	return 0;
}

int store_put_compressed(const char *srcpath, const char *bucketdir,
			 const char *label, char *outpath, size_t n)
{
	struct stat st;
	unsigned char *buf = NULL, *cbuf = NULL;
	uLongf clen;
	uint64_t hdr;
	char sha8[9];
	FILE *in, *out;
	size_t got;
	int rc = -1;

	if (stat(srcpath, &st) != 0 || !S_ISREG(st.st_mode))
		return -1;
	if ((unsigned long)st.st_size > STORE_MAX_FILE)
		return -1;
	buf = malloc(st.st_size ? (size_t)st.st_size : 1);
	if (!buf)
		return -1;
	in = fopen(srcpath, "rbe");
	if (!in) {
		free(buf);
		return -1;
	}
	got = fread(buf, 1, (size_t)st.st_size, in);
	fclose(in);
	if (got != (size_t)st.st_size)
		goto out;

	clen = compressBound(got);
	cbuf = malloc(clen ? clen : 1);
	if (!cbuf)
		goto out;
	if (compress2(cbuf, &clen, buf, got, Z_BEST_COMPRESSION) != Z_OK)
		goto out;

	if (sha256_first8(srcpath, sha8) != 0)
		snprintf(sha8, sizeof(sha8), "00000000");
	if (snprintf(outpath, n, "%s/%s.%s.z", bucketdir, label, sha8) >= (int)n)
		goto out;

	out = fopen(outpath, "wbe");
	if (!out)
		goto out;
	hdr = got;			/* 8-byte LE original length header */
	if (fwrite(&hdr, 1, 8, out) == 8 && fwrite(cbuf, 1, clen, out) == clen)
		rc = 0;
	fclose(out);
	if (rc == 0)
		chmod(outpath, 0600);
out:
	free(cbuf);
	free(buf);
	return rc;
}

int store_restore_compressed(const char *blobpath, const char *dstpath)
{
	FILE *f;
	uint64_t orig = 0;
	long csz;
	unsigned char *cbuf = NULL, *obuf = NULL;
	uLongf olen;
	int fd, rc = -1;

	f = fopen(blobpath, "rbe");
	if (!f)
		return -1;
	if (fread(&orig, 1, 8, f) != 8 || orig > STORE_MAX_FILE) {
		fclose(f);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	csz = ftell(f) - 8;
	fseek(f, 8, SEEK_SET);
	if (csz <= 0) {
		fclose(f);
		return -1;
	}
	cbuf = malloc((size_t)csz);
	obuf = malloc(orig ? (size_t)orig : 1);
	if (!cbuf || !obuf || fread(cbuf, 1, (size_t)csz, f) != (size_t)csz) {
		fclose(f);
		free(cbuf);
		free(obuf);
		return -1;
	}
	fclose(f);
	olen = orig;
	if (uncompress(obuf, &olen, cbuf, (uLong)csz) != Z_OK || olen != orig)
		goto out;
	fd = open(dstpath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		goto out;
	if (write(fd, obuf, (size_t)orig) == (ssize_t)orig) {
		fsync(fd);
		rc = 0;
	}
	close(fd);
out:
	free(cbuf);
	free(obuf);
	return rc;
}

int store_find_latest(const char *root, const char *label, const char *srcpath,
		      char *out, size_t n)
{
	DIR *d = opendir(root);
	struct dirent *de;
	char sha8[9], want[PATH_MAX];
	char best_bucket[32] = "";
	int found = 0;

	if (!d)
		return -1;
	if (sha256_first8(srcpath, sha8) != 0)
		snprintf(sha8, sizeof(sha8), "00000000");
	snprintf(want, sizeof(want), "%s.%s.z", label, sha8);

	/* Buckets are named by the hour (YYYYMMDDHH); the lexically greatest
	 * name that actually contains the wanted blob is the most recent. */
	while ((de = readdir(d))) {
		char cand[PATH_MAX];
		struct stat st;

		if (!isdigit((unsigned char)de->d_name[0]))
			continue;
		if (strlen(de->d_name) >= sizeof(best_bucket))
			continue;		/* not an hourly bucket name */
		if (snprintf(cand, sizeof(cand), "%s/%s/%s", root, de->d_name,
			     want) >= (int)sizeof(cand))
			continue;
		if (stat(cand, &st) != 0 || !S_ISREG(st.st_mode))
			continue;
		if (!found || strcmp(de->d_name, best_bucket) > 0) {
			snprintf(best_bucket, sizeof(best_bucket), "%s", de->d_name);
			found = 1;
		}
	}
	closedir(d);
	if (!found)
		return -1;
	if (snprintf(out, n, "%s/%s/%s", root, best_bucket, want) >= (int)n)
		return -1;
	return 0;
}

/* ---- Locus client ---- */

static void trim(char *s)
{
	size_t n = strlen(s);

	while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' ||
		     s[n - 1] == '\t'))
		s[--n] = '\0';
}

static int read_locus_target(char *host, size_t hn, char *port, size_t pn)
{
	FILE *f = fopen(LOCUS_CLIENT_CONF, "re");
	char line[256];
	int have_host = 0;

	host[0] = port[0] = '\0';
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *eq, *k, *v;

		trim(line);
		if (line[0] == '#' || line[0] == '\0')
			continue;
		eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = '\0';
		k = line; v = eq + 1;
		while (*k == ' ' || *k == '\t') k++;
		trim(k);
		while (*v == ' ' || *v == '\t') v++;
		if (!strcmp(k, "host")) { snprintf(host, hn, "%s", v); have_host = 1; }
		else if (!strcmp(k, "port")) snprintf(port, pn, "%s", v);
	}
	fclose(f);
	if (!have_host || !host[0] || !port[0])
		return -1;
	return 0;
}

/* Validate the allocator's reply path: absolute, no "..", no control chars, so
 * a rogue or spoofed allocator cannot steer a guard into writing somewhere
 * dangerous. The allocator is trusted only to *name a location*, nothing more. */
static int safe_abs_path(const char *p)
{
	if (p[0] != '/')
		return 0;
	if (strstr(p, ".."))
		return 0;
	for (; *p; p++)
		if ((unsigned char)*p < 0x20)
			return 0;
	return 1;
}

int locus_request_root(const char *purpose, char *out, size_t n)
{
	char host[256], port[16], req[256], resp[PATH_MAX + 16];
	struct addrinfo hints, *res, *rp;
	int fd = -1;
	ssize_t r;

	if (read_locus_target(host, sizeof(host), port, sizeof(port)) != 0)
		return -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, port, &hints, &res) != 0)
		return -1;
	for (rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC,
			    rp->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0)
		return -1;

	snprintf(req, sizeof(req), "ALLOC %s\n", purpose);
	if (send(fd, req, strlen(req), MSG_NOSIGNAL) < 0) {
		close(fd);
		return -1;
	}
	r = recv(fd, resp, sizeof(resp) - 1, 0);
	close(fd);
	if (r <= 0)
		return -1;
	resp[r] = '\0';
	trim(resp);
	/* Expect "OK <absolute-path>". */
	if (strncmp(resp, "OK ", 3) != 0)
		return -1;
	if (!safe_abs_path(resp + 3))
		return -1;
	snprintf(out, n, "%s", resp + 3);
	return 0;
}
