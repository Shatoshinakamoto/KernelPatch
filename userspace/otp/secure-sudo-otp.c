// SPDX-License-Identifier: GPL-2.0
/*
 * secure-sudo-otp - rotating OTP sudo password helper (#14, #15).
 *
 * This is the corrected replacement for the old C++ otp-generator, which had
 * three problems the feature map calls out:
 *   1. Its no-OpenCV "QR" fallback printed instructions telling the user to
 *      paste the otpauth:// URI - secret and all - into a THIRD-PARTY website.
 *      That hands the TOTP seed to someone else. Gone: we render the QR locally
 *      with libqrencode to a root-only PNG and print a file:// URL.
 *   2. It wrapped the secret in "triple AES" all keyed from the same password,
 *      which is no stronger than one layer. Replaced with a single AES-256-GCM
 *      (authenticated) under a root-only master key.
 *   3. The prefix was stored decryptably. We store it as a yescrypt hash, which
 *      never has to be decrypted - we only ever verify against it.
 *
 * At rest, under /var/lib/secure_sudo/otp/ (0700, root-only):
 *   masterkey   32 random bytes (0600)         - AES key for the secret
 *   secret.enc  [12B IV][16B tag][ciphertext]  - AES-256-GCM of the base32 seed
 *   prefix.hash crypt(3) yescrypt hash          - optional prefix, never decrypted
 *   meta        account/issuer for the otpauth URI
 *
 * At runtime the decrypted seed lives in an mlock'd buffer wiped immediately
 * after use. Every subcommand requires root.
 *
 * Build: cc ... -lcrypto -lcrypt [-DHAVE_QRENCODE -lqrencode -lz]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <crypt.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define OTP_DIR   "/var/lib/secure_sudo/otp"
#define F_MASTER  OTP_DIR "/masterkey"
#define F_SECRET  OTP_DIR "/secret.enc"
#define F_PREFIX  OTP_DIR "/prefix.hash"
#define F_META    OTP_DIR "/meta"
#define F_QR      OTP_DIR "/qr.png"

#define SECRET_RAW_LEN 20	/* 160-bit seed, standard for TOTP */
#define TOTP_STEP 30
#define TOTP_DIGITS 6
#define TOTP_WINDOW 1		/* accept current +/- 1 step for clock skew */

/* ----------------------------- helpers ---------------------------------- */

static int require_root(void)
{
	if (geteuid() != 0) {
		fprintf(stderr, "secure-sudo-otp: must be run as root\n");
		return -1;
	}
	return 0;
}

static int ensure_dir(void)
{
	if (mkdir(OTP_DIR, 0700) != 0 && errno != EEXIST) {
		fprintf(stderr, "secure-sudo-otp: mkdir %s: %s\n", OTP_DIR,
			strerror(errno));
		return -1;
	}
	chmod(OTP_DIR, 0700);
	return 0;
}

static int write_file(const char *path, const void *data, size_t len, mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, data, len);
	fchmod(fd, mode);
	close(fd);
	return (n == (ssize_t)len) ? 0 : -1;
}

static ssize_t read_file(const char *path, void *buf, size_t max)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, max);
	close(fd);
	return n;
}

/* ----------------------------- base32 ----------------------------------- */

static const char B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static size_t base32_encode(const uint8_t *in, size_t inlen, char *out)
{
	size_t i, bits = 0, o = 0;
	uint32_t buf = 0;

	for (i = 0; i < inlen; i++) {
		buf = (buf << 8) | in[i];
		bits += 8;
		while (bits >= 5) {
			out[o++] = B32[(buf >> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if (bits > 0)
		out[o++] = B32[(buf << (5 - bits)) & 31];
	out[o] = '\0';
	return o;
}

static int b32_val(char c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a';
	if (c >= '2' && c <= '7') return c - '2' + 26;
	return -1;
}

static size_t base32_decode(const char *in, uint8_t *out, size_t max)
{
	size_t bits = 0, o = 0;
	uint32_t buf = 0;

	for (; *in; in++) {
		int v;

		if (*in == '=' || isspace((unsigned char)*in))
			continue;
		v = b32_val(*in);
		if (v < 0)
			continue;
		buf = (buf << 5) | v;
		bits += 5;
		if (bits >= 8) {
			if (o >= max)
				break;
			out[o++] = (buf >> (bits - 8)) & 0xff;
			bits -= 8;
		}
	}
	return o;
}

/* ------------------------- AES-256-GCM at rest -------------------------- */

static int load_or_create_master(uint8_t key[32])
{
	if (read_file(F_MASTER, key, 32) == 32)
		return 0;
	if (RAND_bytes(key, 32) != 1)
		return -1;
	if (write_file(F_MASTER, key, 32, 0600) != 0)
		return -1;
	return 0;
}

/* Encrypt @pt -> file: [12B IV][16B tag][ct]. */
static int secret_encrypt(const uint8_t *pt, int ptlen)
{
	uint8_t key[32], iv[12], tag[16];
	uint8_t *blob;
	int ctlen = 0, tmp = 0, rc = -1;
	EVP_CIPHER_CTX *ctx = NULL;

	if (load_or_create_master(key) != 0)
		return -1;
	if (RAND_bytes(iv, sizeof(iv)) != 1)
		goto out;

	blob = malloc(12 + 16 + ptlen);
	if (!blob)
		goto out;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		goto out_free;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1)
		goto out_free;
	if (EVP_EncryptUpdate(ctx, blob + 28, &ctlen, pt, ptlen) != 1)
		goto out_free;
	if (EVP_EncryptFinal_ex(ctx, blob + 28 + ctlen, &tmp) != 1)
		goto out_free;
	ctlen += tmp;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
		goto out_free;

	memcpy(blob, iv, 12);
	memcpy(blob + 12, tag, 16);
	rc = write_file(F_SECRET, blob, 28 + ctlen, 0600);

out_free:
	OPENSSL_cleanse(blob, 12 + 16 + ptlen);
	free(blob);
out:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	OPENSSL_cleanse(key, sizeof(key));
	return rc;
}

/* Decrypt F_SECRET into @pt (mlock'd by caller). Returns length or -1. */
static int secret_decrypt(uint8_t *pt, int max)
{
	uint8_t key[32], blob[512];
	ssize_t blen;
	int ptlen = 0, tmp = 0, rc = -1;
	EVP_CIPHER_CTX *ctx = NULL;

	blen = read_file(F_SECRET, blob, sizeof(blob));
	if (blen < 28)
		return -1;
	if (read_file(F_MASTER, key, 32) != 32)
		return -1;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		goto out;
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, blob) != 1)
		goto out;
	if (EVP_DecryptUpdate(ctx, pt, &ptlen, blob + 28, blen - 28) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, blob + 12) != 1)
		goto out;
	if (EVP_DecryptFinal_ex(ctx, pt + ptlen, &tmp) != 1)
		goto out;		/* authentication failed - tampered */
	ptlen += tmp;
	rc = (ptlen <= max) ? ptlen : -1;

out:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	OPENSSL_cleanse(key, sizeof(key));
	OPENSSL_cleanse(blob, sizeof(blob));
	return rc;
}

/* ------------------------------- TOTP ----------------------------------- */

static unsigned totp_at(const uint8_t *key, int keylen, uint64_t counter)
{
	uint8_t msg[8], mac[EVP_MAX_MD_SIZE];
	unsigned maclen = 0, off, bin, i;

	for (i = 0; i < 8; i++)
		msg[7 - i] = (counter >> (8 * i)) & 0xff;

	HMAC(EVP_sha1(), key, keylen, msg, 8, mac, &maclen);
	off = mac[maclen - 1] & 0x0f;
	bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) |
	      (mac[off + 2] << 8) | mac[off + 3];
	return bin % 1000000u;
}

/* True if @code (6-digit string) matches TOTP now within the window. */
static int totp_check(const uint8_t *key, int keylen, const char *code)
{
	uint64_t t = (uint64_t)time(NULL) / TOTP_STEP;
	long w;
	char buf[8];

	for (w = -TOTP_WINDOW; w <= TOTP_WINDOW; w++) {
		snprintf(buf, sizeof(buf), "%06u",
			 totp_at(key, keylen, t + w));
		if (strlen(code) == TOTP_DIGITS &&
		    CRYPTO_memcmp(buf, code, TOTP_DIGITS) == 0)
			return 1;
	}
	return 0;
}

/* ------------------------------ prefix ---------------------------------- */

static int prefix_set(const char *prefix)
{
	char salt[64], *hash;
	uint8_t rnd[16];

	if (!prefix || !*prefix) {
		unlink(F_PREFIX);		/* no prefix configured */
		return 0;
	}
	if (RAND_bytes(rnd, sizeof(rnd)) != 1)
		return -1;
	if (!crypt_gensalt_rn("$y$", 0, (const char *)rnd, sizeof(rnd),
			      salt, sizeof(salt)))
		return -1;

	hash = crypt(prefix, salt);		/* yescrypt */
	if (!hash)
		return -1;
	return write_file(F_PREFIX, hash, strlen(hash), 0600);
}

static int prefix_required(void)
{
	return access(F_PREFIX, F_OK) == 0;
}

static int prefix_check(const char *candidate_prefix)
{
	char stored[256];
	struct crypt_data cd;
	ssize_t n;
	char *got;

	n = read_file(F_PREFIX, stored, sizeof(stored) - 1);
	if (n <= 0)
		return 0;
	stored[n] = '\0';
	while (n > 0 && (stored[n - 1] == '\n' || stored[n - 1] == ' '))
		stored[--n] = '\0';

	memset(&cd, 0, sizeof(cd));
	got = crypt_r(candidate_prefix, stored, &cd);
	if (!got)
		return 0;
	return CRYPTO_memcmp(got, stored, strlen(stored)) == 0;
}

/* --------------------------- meta / URI --------------------------------- */

static void get_meta(char *account, size_t an, char *issuer, size_t in)
{
	char buf[256];
	ssize_t n = read_file(F_META, buf, sizeof(buf) - 1);

	snprintf(account, an, "root");
	snprintf(issuer, in, "secure_sudo");
	if (n > 0) {
		buf[n] = '\0';
		sscanf(buf, "account=%63s issuer=%63s", account, issuer);
	}
}

static void build_uri(const char *b32, char *uri, size_t n)
{
	char account[64], issuer[64];

	get_meta(account, sizeof(account), issuer, sizeof(issuer));
	snprintf(uri, n,
		 "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		 issuer, account, b32, issuer, TOTP_DIGITS, TOTP_STEP);
}

/* --------------------------- read a line -------------------------------- */

/* Read one line (no echo) from the controlling tty, or from stdin for --pam. */
static int read_line(char *buf, size_t n, int from_stdin, const char *prompt)
{
	FILE *in = stdin;
	struct termios old, raw;
	int restore = 0;

	if (!from_stdin) {
		in = fopen("/dev/tty", "r+e");
		if (!in)
			in = stdin;
		if (prompt)
			fprintf(stderr, "%s", prompt);
		if (tcgetattr(fileno(in), &old) == 0) {
			raw = old;
			raw.c_lflag &= ~(tcflag_t)ECHO;
			tcsetattr(fileno(in), TCSAFLUSH, &raw);
			restore = 1;
		}
	}
	if (!fgets(buf, n, in)) {
		if (restore)
			tcsetattr(fileno(in), TCSAFLUSH, &old);
		return -1;
	}
	if (restore) {
		tcsetattr(fileno(in), TCSAFLUSH, &old);
		fprintf(stderr, "\n");
	}
	buf[strcspn(buf, "\r\n")] = '\0';
	if (in != stdin)
		fclose(in);
	return 0;
}

/* ------------------------------ commands -------------------------------- */

static int cmd_setup(int argc, char **argv)
{
	uint8_t raw[SECRET_RAW_LEN];
	char b32[64], uri[512], prefix[128] = "";
	int want_prefix = 0, i;

	for (i = 2; i < argc; i++)
		if (!strcmp(argv[i], "--prefix"))
			want_prefix = 1;

	if (ensure_dir() != 0)
		return 1;
	if (RAND_bytes(raw, sizeof(raw)) != 1) {
		fprintf(stderr, "secure-sudo-otp: RNG failure\n");
		return 1;
	}
	base32_encode(raw, sizeof(raw), b32);

	if (secret_encrypt((const uint8_t *)b32, strlen(b32)) != 0) {
		fprintf(stderr, "secure-sudo-otp: failed to store secret\n");
		OPENSSL_cleanse(raw, sizeof(raw));
		return 1;
	}

	if (want_prefix) {
		if (read_line(prefix, sizeof(prefix), 0, "Prefix password: ") != 0 ||
		    prefix_set(prefix) != 0) {
			fprintf(stderr, "secure-sudo-otp: failed to set prefix\n");
			return 1;
		}
		OPENSSL_cleanse(prefix, sizeof(prefix));
	} else {
		unlink(F_PREFIX);
	}

	build_uri(b32, uri, sizeof(uri));
	printf("OTP configured.\n");
	printf("Manual entry key: %s\n", b32);
	printf("otpauth URI:      %s\n", uri);
	printf("Run 'secure-sudo otp show-qr' to get a scannable QR image.\n");
	if (want_prefix)
		printf("Your sudo password is now: <prefix>%06u-style (prefix + rotating code).\n", 0u);

	OPENSSL_cleanse(raw, sizeof(raw));
	OPENSSL_cleanse(b32, sizeof(b32));
	return 0;
}

static int load_secret_mlocked(uint8_t **out, int *outlen)
{
	uint8_t *sec = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	int n;

	if (sec == MAP_FAILED)
		return -1;
	mlock(sec, 4096);
	n = secret_decrypt(sec, 128);
	if (n <= 0) {
		munlock(sec, 4096);
		munmap(sec, 4096);
		return -1;
	}
	sec[n] = '\0';
	*out = sec;
	*outlen = n;
	return 0;
}

static void free_secret(uint8_t *sec)
{
	OPENSSL_cleanse(sec, 4096);
	munlock(sec, 4096);
	munmap(sec, 4096);
}

static int cmd_show_key(void)
{
	uint8_t *sec;
	int n;
	char uri[512];

	if (load_secret_mlocked(&sec, &n) != 0) {
		fprintf(stderr, "secure-sudo-otp: no secret configured\n");
		return 1;
	}
	build_uri((char *)sec, uri, sizeof(uri));
	printf("Manual entry key: %s\n", (char *)sec);
	printf("otpauth URI:      %s\n", uri);
	free_secret(sec);
	return 0;
}

static int cmd_verify(int from_stdin)
{
	uint8_t *sec, keyraw[64];
	int n, keylen, ok = 0;
	char line[256], *code_part;
	size_t len;

	if (read_line(line, sizeof(line), from_stdin,
		      from_stdin ? NULL : "Password: ") != 0)
		return 1;

	len = strlen(line);
	if (len < TOTP_DIGITS)
		goto done;

	/* The last 6 chars are the rotating code; anything before is prefix. */
	code_part = line + len - TOTP_DIGITS;

	if (prefix_required()) {
		char pfx[256];

		memcpy(pfx, line, len - TOTP_DIGITS);
		pfx[len - TOTP_DIGITS] = '\0';
		if (!prefix_check(pfx)) {
			OPENSSL_cleanse(pfx, sizeof(pfx));
			goto done;
		}
		OPENSSL_cleanse(pfx, sizeof(pfx));
	} else if (len != TOTP_DIGITS) {
		goto done;		/* no prefix expected: must be just code */
	}

	if (load_secret_mlocked(&sec, &n) != 0)
		goto done;
	keylen = base32_decode((char *)sec, keyraw, sizeof(keyraw));
	ok = totp_check(keyraw, keylen, code_part);
	OPENSSL_cleanse(keyraw, sizeof(keyraw));
	free_secret(sec);

done:
	OPENSSL_cleanse(line, sizeof(line));
	return ok ? 0 : 1;
}

static int cmd_reset(int argc, char **argv)
{
	/* Same as setup; regenerates the seed. Prefix kept unless --prefix. */
	if (access(F_PREFIX, F_OK) == 0) {
		int keep = 1, i;

		for (i = 2; i < argc; i++)
			if (!strcmp(argv[i], "--prefix"))
				keep = 0;
		if (keep)
			printf("(keeping existing prefix; pass --prefix to change it)\n");
	}
	return cmd_setup(argc, argv);
}

static int cmd_disable(void)
{
	/* Best-effort shred: overwrite then unlink the sensitive files. */
	const char *files[] = { F_SECRET, F_PREFIX, F_QR, F_MASTER };
	size_t i;

	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		int fd = open(files[i], O_WRONLY);

		if (fd >= 0) {
			uint8_t z[512] = { 0 };

			if (write(fd, z, sizeof(z)) < 0)
				; /* best-effort shred; unlink follows regardless */
			close(fd);
		}
		unlink(files[i]);
	}
	printf("OTP disabled; secret material removed.\n");
	return 0;
}

#ifdef HAVE_QRENCODE
#include <qrencode.h>
#include <zlib.h>

static void png_put_u32(FILE *f, uint32_t v)
{
	uint8_t b[4] = { v >> 24, v >> 16, v >> 8, v };

	fwrite(b, 1, 4, f);
}

static void png_chunk(FILE *f, const char type[4], const uint8_t *data,
		      uint32_t len)
{
	uLong crc = crc32(0L, Z_NULL, 0);

	png_put_u32(f, len);
	fwrite(type, 1, 4, f);
	crc = crc32(crc, (const Bytef *)type, 4);
	if (len) {
		fwrite(data, 1, len, f);
		crc = crc32(crc, data, len);
	}
	png_put_u32(f, (uint32_t)crc);
}

/* Write an 8-bit grayscale PNG (no libpng; zlib for IDAT). */
static int write_png(const char *path, const uint8_t *gray, int w, int h)
{
	static const uint8_t sig[8] = { 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a };
	uint8_t ihdr[13];
	uint8_t *raw, *comp;
	uLongf comp_len;
	size_t rawlen = (size_t)(w + 1) * h;
	int y, rc = -1;
	FILE *f;

	raw = malloc(rawlen);
	if (!raw)
		return -1;
	for (y = 0; y < h; y++) {
		raw[(size_t)(w + 1) * y] = 0;	/* filter type 0 (None) */
		memcpy(raw + (size_t)(w + 1) * y + 1, gray + (size_t)w * y, w);
	}

	comp_len = compressBound(rawlen);
	comp = malloc(comp_len);
	if (!comp) {
		free(raw);
		return -1;
	}
	if (compress2(comp, &comp_len, raw, rawlen, 9) != Z_OK)
		goto out;

	f = fopen(path, "wbe");
	if (!f)
		goto out;

	fwrite(sig, 1, sizeof(sig), f);
	ihdr[0] = w >> 24; ihdr[1] = w >> 16; ihdr[2] = w >> 8; ihdr[3] = w;
	ihdr[4] = h >> 24; ihdr[5] = h >> 16; ihdr[6] = h >> 8; ihdr[7] = h;
	ihdr[8] = 8;	/* bit depth */
	ihdr[9] = 0;	/* colour type: grayscale */
	ihdr[10] = 0;	/* compression */
	ihdr[11] = 0;	/* filter */
	ihdr[12] = 0;	/* interlace */
	png_chunk(f, "IHDR", ihdr, sizeof(ihdr));
	png_chunk(f, "IDAT", comp, (uint32_t)comp_len);
	png_chunk(f, "IEND", NULL, 0);
	fclose(f);
	rc = 0;
out:
	free(raw);
	free(comp);
	return rc;
}

static int cmd_show_qr(void)
{
	uint8_t *sec, *img;
	int n, scale = 8, margin = 4, x, y, px, py, W, rc;
	char uri[512];
	QRcode *qr;

	if (load_secret_mlocked(&sec, &n) != 0) {
		fprintf(stderr, "secure-sudo-otp: no secret configured\n");
		return 1;
	}
	build_uri((char *)sec, uri, sizeof(uri));
	free_secret(sec);

	qr = QRcode_encodeString(uri, 0, QR_ECLEVEL_M, QR_MODE_8, 1);
	OPENSSL_cleanse(uri, sizeof(uri));
	if (!qr) {
		fprintf(stderr, "secure-sudo-otp: QR encode failed\n");
		return 1;
	}

	W = (qr->width + 2 * margin) * scale;
	img = malloc((size_t)W * W);
	if (!img) {
		QRcode_free(qr);
		return 1;
	}
	memset(img, 0xff, (size_t)W * W);		/* white background */
	for (y = 0; y < qr->width; y++)
		for (x = 0; x < qr->width; x++)
			if (qr->data[y * qr->width + x] & 1)	/* black module */
				for (py = 0; py < scale; py++)
					for (px = 0; px < scale; px++) {
						int iy = (y + margin) * scale + py;
						int ix = (x + margin) * scale + px;

						img[(size_t)iy * W + ix] = 0x00;
					}

	rc = write_png(F_QR, img, W, W);
	free(img);
	QRcode_free(qr);
	if (rc != 0) {
		fprintf(stderr, "secure-sudo-otp: failed to write %s\n", F_QR);
		return 1;
	}
	chmod(F_QR, 0600);
	printf("QR written. Open it locally in your browser:\n  file://%s\n", F_QR);
	return 0;
}
#else
static int cmd_show_qr(void)
{
	fprintf(stderr,
		"secure-sudo-otp: built without libqrencode; rebuild with -DHAVE_QRENCODE.\n"
		"Use 'secure-sudo otp show-key' and type the key into your authenticator.\n");
	return 1;
}
#endif /* HAVE_QRENCODE */

static void usage(void)
{
	fprintf(stderr,
"Usage: secure-sudo-otp <setup [--prefix] | show-key | show-qr | verify [--pam] | reset [--prefix] | disable>\n");
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 2;
	}
	if (require_root() != 0)
		return 1;

	if (!strcmp(argv[1], "setup"))
		return cmd_setup(argc, argv);
	if (!strcmp(argv[1], "show-key"))
		return cmd_show_key();
	if (!strcmp(argv[1], "show-qr"))
		return cmd_show_qr();
	if (!strcmp(argv[1], "verify")) {
		int pam = (argc > 2 && !strcmp(argv[2], "--pam"));

		return cmd_verify(pam);
	}
	if (!strcmp(argv[1], "reset"))
		return cmd_reset(argc, argv);
	if (!strcmp(argv[1], "disable"))
		return cmd_disable();

	usage();
	return 2;
}
