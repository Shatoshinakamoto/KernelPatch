// SPDX-License-Identifier: GPL-2.0
/*
 * ssaddon_trust - baseline trust and evidence for the temporary/ add-ons.
 * See ssaddon_trust.h.
 */
#define _GNU_SOURCE
#include "ssaddon_trust.h"
#include "ssaddon_conf.h"
#include "ssaddon_log.h"
#include "ssaddon_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define MANIFEST_MAX	(64UL * 1024 * 1024)

const char *const sst_modes[] = { "local", "signed", NULL };

static void hex(const unsigned char *d, size_t n, char *out)
{
	size_t i;

	for (i = 0; i < n; i++)
		sprintf(out + 2 * i, "%02x", d[i]);
	out[2 * n] = '\0';
}

static int sha256_buf(const unsigned char *b, size_t n, char out[65])
{
	unsigned char d[EVP_MAX_MD_SIZE];
	unsigned int dn = 0;

	if (!EVP_Digest(b, n, d, &dn, EVP_sha256(), NULL) || dn != 32)
		return -1;
	hex(d, 32, out);
	return 0;
}

int sst_sha256_file(const char *path, char out[65])
{
	unsigned char buf[65536], d[EVP_MAX_MD_SIZE];
	unsigned int dn = 0;
	EVP_MD_CTX *c;
	FILE *f;
	size_t r;
	int ok = 0;

	f = fopen(path, "rbe");
	if (!f)
		return -1;
	c = EVP_MD_CTX_new();
	if (c && EVP_DigestInit_ex(c, EVP_sha256(), NULL)) {
		ok = 1;
		while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
			if (!EVP_DigestUpdate(c, buf, r))
				ok = 0;
		if (ferror(f) || !EVP_DigestFinal_ex(c, d, &dn) || dn != 32)
			ok = 0;
	}
	EVP_MD_CTX_free(c);
	fclose(f);
	if (!ok)
		return -1;
	hex(d, 32, out);
	return 0;
}

/* Read a whole (small) file. */
static unsigned char *slurp(const char *path, size_t max, size_t *len)
{
	FILE *f = fopen(path, "rbe");
	unsigned char *b = NULL;
	struct stat st;

	*len = 0;
	if (!f)
		return NULL;
	if (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    (size_t)st.st_size <= max) {
		b = malloc(st.st_size ? (size_t)st.st_size : 1);
		if (b && fread(b, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
			free(b);
			b = NULL;
		} else if (b) {
			*len = (size_t)st.st_size;
		}
	}
	fclose(f);
	return b;
}

static EVP_PKEY *load_key(char *why, size_t n)
{
	char err[256];
	EVP_PKEY *k;
	FILE *f;

	if (!ssc_file_safe(SSADDON_SIGNING_KEY, err, sizeof(err))) {
		snprintf(why, n, "signing key %s: %s", SSADDON_SIGNING_KEY, err);
		return NULL;
	}
	f = fopen(SSADDON_SIGNING_KEY, "re");
	if (!f) {
		snprintf(why, n, "signing key %s: %s", SSADDON_SIGNING_KEY, strerror(errno));
		return NULL;
	}
	k = PEM_read_PUBKEY(f, NULL, NULL, NULL);
	fclose(f);
	if (!k || EVP_PKEY_id(k) != EVP_PKEY_ED25519) {
		snprintf(why, n, "signing key %s is not an Ed25519 public key (PEM)",
			 SSADDON_SIGNING_KEY);
		EVP_PKEY_free(k);
		return NULL;
	}
	return k;
}

/* First 16 hex of the SHA-256 of the key's SubjectPublicKeyInfo. */
static void key_fpr(EVP_PKEY *k, char out[17])
{
	unsigned char *der = NULL;
	char full[65];
	int n = i2d_PUBKEY(k, &der);

	snprintf(out, 17, "unknown");
	if (n > 0 && sha256_buf(der, (size_t)n, full) == 0)
		snprintf(out, 17, "%.16s", full);
	OPENSSL_free(der);
}

int sst_manifest_trusted(const char *manifest, int mode, char *why, size_t n)
{
	char sigp[PATH_MAX];
	unsigned char *m = NULL, *sig = NULL;
	size_t ml, sl;
	EVP_PKEY *k;
	EVP_MD_CTX *c;
	int ok = 0;

	why[0] = '\0';
	if (access(manifest, F_OK) != 0) {
		snprintf(why, n, "no baseline");
		return 0;
	}
	if (mode != SST_SIGNED)
		return 1;
	if (snprintf(sigp, sizeof(sigp), "%s.sig", manifest) >= (int)sizeof(sigp)) {
		snprintf(why, n, "path too long");
		return 0;
	}
	k = load_key(why, n);
	if (!k)
		return 0;
	m = slurp(manifest, MANIFEST_MAX, &ml);
	sig = slurp(sigp, 1024, &sl);
	if (!m) {
		snprintf(why, n, "the baseline cannot be read");
	} else if (!sig) {
		snprintf(why, n, "the baseline is not signed (no %s)", sigp);
	} else {
		c = EVP_MD_CTX_new();
		ok = c && EVP_DigestVerifyInit(c, NULL, NULL, NULL, k) == 1 &&
		     EVP_DigestVerify(c, sig, sl, m, ml) == 1;
		EVP_MD_CTX_free(c);
		if (!ok)
			snprintf(why, n, "the baseline's signature does not verify with %s",
				 SSADDON_SIGNING_KEY);
	}
	free(m);
	free(sig);
	EVP_PKEY_free(k);
	return ok;
}

void sst_announce(const char *feature, const char *manifest, const char *reason,
		  int mode)
{
	char sigp[PATH_MAX], sha[65], fpr[17] = "none", why[256];
	EVP_PKEY *k;
	FILE *f;
	size_t lines = 0;
	int ch;

	if (snprintf(sigp, sizeof(sigp), "%s.sig", manifest) < (int)sizeof(sigp))
		unlink(sigp);		/* it signed the previous baseline */
	if (sst_sha256_file(manifest, sha) != 0)
		snprintf(sha, sizeof(sha), "unreadable");
	f = fopen(manifest, "re");
	if (f) {
		while ((ch = fgetc(f)) != EOF)
			lines += ch == '\n';
		fclose(f);
	}
	k = mode == SST_SIGNED ? load_key(why, sizeof(why)) : NULL;
	if (k)
		key_fpr(k, fpr);
	EVP_PKEY_free(k);
	ssl_crit("BASELINE %s (%s): %s sha256=%s, %zu entries; trust=%s%s%s",
		 feature, reason, manifest, sha, lines, sst_modes[mode ? 1 : 0],
		 mode == SST_SIGNED ? ", sign it with the key " : "",
		 mode == SST_SIGNED ? fpr : "");
}

void sst_describe(const char *manifest, int mode, char *out, size_t n)
{
	char why[512];

	if (mode != SST_SIGNED) {
		snprintf(out, n, "local (the host's own copy; not independently verified)");
		return;
	}
	if (sst_manifest_trusted(manifest, mode, why, sizeof(why)))
		snprintf(out, n, "signed - signature valid");
	else
		snprintf(out, n, "signed - NOT TRUSTED: %s", why);
}

int sst_restore_verified(const char *blob, const char *dst, const char *expect_sha,
			 char *why, size_t n)
{
	unsigned char *b;
	size_t len;
	char got[65], tmp[PATH_MAX], dir[PATH_MAX];
	struct stat st;
	uid_t uid = 0;
	gid_t gid = 0;
	mode_t mode = 0644;
	int fd, dfd, rc = -1;

	if (store_load_compressed(blob, &b, &len) != 0) {
		snprintf(why, n, "backup %s cannot be read or decompressed", blob);
		return -1;
	}
	if (sha256_buf(b, len, got) != 0 || strcmp(got, expect_sha) != 0) {
		snprintf(why, n, "backup %s does not match the baseline (sha256 %.12s, "
			 "expected %.12s)", blob, got, expect_sha);
		free(b);
		return -1;
	}
	if (lstat(dst, &st) == 0 && S_ISREG(st.st_mode)) {
		uid = st.st_uid;
		gid = st.st_gid;
		mode = st.st_mode & 07777;
	}
	if (snprintf(tmp, sizeof(tmp), "%s.ss-restore", dst) >= (int)sizeof(tmp)) {
		snprintf(why, n, "path too long");
		free(b);
		return -1;
	}
	unlink(tmp);			/* a stale one, or something planted */
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		snprintf(why, n, "cannot create %s: %s", tmp, strerror(errno));
		free(b);
		return -1;
	}
	if (write(fd, b, len) == (ssize_t)len && fchown(fd, uid, gid) == 0 &&
	    fchmod(fd, mode) == 0 && fsync(fd) == 0)
		rc = 0;
	else
		snprintf(why, n, "writing %s: %s", tmp, strerror(errno));
	close(fd);
	free(b);
	if (rc == 0 && rename(tmp, dst) != 0) {
		snprintf(why, n, "rename onto %s: %s", dst, strerror(errno));
		rc = -1;
	}
	if (rc != 0) {
		unlink(tmp);
		return -1;
	}
	snprintf(dir, sizeof(dir), "%s", dst);
	dfd = open(dirname(dir), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd >= 0) {
		fsync(dfd);
		close(dfd);
	}
	return 0;
}

int sst_restore_from_backups(const char *root, const char *label, const char *dst,
			     const char *expect_sha, char *used, size_t un,
			     char *why, size_t n)
{
	char blob[PATH_MAX], bucket[32] = "", prev[32];
	int tries = 0, bad = 0;

	snprintf(why, n, "no backup of %s under %s", dst, root);
	while (tries++ < 10000) {
		snprintf(prev, sizeof(prev), "%s", bucket);
		if (store_find_before(root, label, dst, tries == 1 ? NULL : prev, blob,
				      sizeof(blob), bucket, sizeof(bucket)) != 0)
			break;
		if (sst_restore_verified(blob, dst, expect_sha, why, n) == 0) {
			snprintf(used, un, "%s", blob);
			if (bad)
				ssl_warn("restored %s from an older backup: %d newer one(s) "
					 "did not match the baseline", dst, bad);
			return 0;
		}
		ssl_warn("backup refused for %s: %s", dst, why);
		bad++;
	}
	return -1;
}

/* JSON string body for a path (escapes ", \ and control characters). */
static void jstr(const char *s, char *out, size_t n)
{
	size_t o = 0;

	for (; *s && o + 7 < n; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\') {
			out[o++] = '\\';
			out[o++] = (char)c;
		} else if (c < 0x20) {
			o += snprintf(out + o, n - o, "\\u%04x", c);
		} else {
			out[o++] = (char)c;
		}
	}
	out[o] = '\0';
}

static int mkdirs(const char *p)
{
	char t[PATH_MAX];
	size_t i;

	snprintf(t, sizeof(t), "%s", p);
	for (i = 1; t[i]; i++) {
		if (t[i] == '/') {
			t[i] = '\0';
			if (mkdir(t, 0700) != 0 && errno != EEXIST)
				return -1;
			t[i] = '/';
		}
	}
	return mkdir(t, 0700) != 0 && errno != EEXIST ? -1 : 0;
}

int sst_evidence(const char *feature, const char *path, const char *action,
		 const char *expect_sha, const char *sample)
{
	char root[PATH_MAX], bucket[PATH_MAX], stored[PATH_MAX], rec[PATH_MAX];
	char jp[3 * PATH_MAX], js[3 * PATH_MAX], sha[65] = "", ts[32];
	struct stat st;
	struct tm tm;
	time_t now = time(NULL);
	int have, fd, n;
	char line[8 * PATH_MAX];

	snprintf(root, sizeof(root), "%s/%s", SSADDON_EVIDENCE_ROOT, feature);
	if (mkdirs(root) != 0) {
		ssl_err("EVIDENCE: cannot create %s: %s", root, strerror(errno));
		return -1;
	}
	have = lstat(path, &st) == 0;
	stored[0] = '\0';
	if (have && S_ISREG(st.st_mode)) {
		if (sst_sha256_file(path, sha) != 0)
			sha[0] = '\0';
		if (sample && *sample) {
			snprintf(stored, sizeof(stored), "%s", sample);
		} else if (store_bucket(root, 1, bucket, sizeof(bucket)) != 0 ||
			   store_put_compressed(path, bucket, "evidence", stored,
						sizeof(stored)) != 0) {
			ssl_err("EVIDENCE: could not keep a copy of %s", path);
			stored[0] = '\0';
		}
	}
	gmtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
	jstr(path, jp, sizeof(jp));
	jstr(stored, js, sizeof(js));
	if (!have)
		n = snprintf(line, sizeof(line),
			"{\"time\":\"%s\",\"feature\":\"%s\",\"action\":\"%s\",\"path\":\"%s\","
			"\"state\":\"missing\",\"expected_sha256\":\"%s\"}\n",
			ts, feature, action, jp, expect_sha ? expect_sha : "");
	else
		n = snprintf(line, sizeof(line),
			"{\"time\":\"%s\",\"feature\":\"%s\",\"action\":\"%s\",\"path\":\"%s\","
			"\"state\":\"%s\",\"sha256\":\"%s\",\"expected_sha256\":\"%s\","
			"\"size\":%lld,\"mode\":\"%04o\",\"uid\":%u,\"gid\":%u,"
			"\"mtime\":%lld,\"ctime\":%lld,\"inode\":%llu,\"sample\":\"%s\"}\n",
			ts, feature, action, jp,
			S_ISREG(st.st_mode) ? "file" : S_ISLNK(st.st_mode) ? "symlink" : "other",
			sha, expect_sha ? expect_sha : "", (long long)st.st_size,
			(unsigned)(st.st_mode & 07777), (unsigned)st.st_uid, (unsigned)st.st_gid,
			(long long)st.st_mtime, (long long)st.st_ctime,
			(unsigned long long)st.st_ino, js);
	if (n < 0 || n >= (int)sizeof(line)) {
		ssl_err("EVIDENCE: record too long for %s", path);
		return -1;
	}
	snprintf(rec, sizeof(rec), "%s/%s.jsonl", SSADDON_EVIDENCE_ROOT, feature);
	fd = open(rec, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0 || write(fd, line, (size_t)n) != n) {
		ssl_err("EVIDENCE: cannot append to %s: %s", rec, strerror(errno));
		if (fd >= 0)
			close(fd);
		return -1;
	}
	fsync(fd);
	close(fd);
	ssl_crit("EVIDENCE %s before %s: %s sha256=%s expected=%s%s%s", feature, action,
		 path, have ? (*sha ? sha : "unreadable") : "missing",
		 expect_sha ? expect_sha : "-", *stored ? " copy=" : "", stored);
	return 0;
}
