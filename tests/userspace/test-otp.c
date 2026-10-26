// SPDX-License-Identifier: GPL-2.0
/*
 * test-otp.c - tests for the OTP helper (userspace/otp/secure-sudo-otp.c),
 * TODO P0-2: RFC 4226/6238 vectors, base32, the clock-skew window, replay
 * refusal, the prefix, and the secret at rest. Built and run by test-otp.sh,
 * which sets OTP_DIR to a throwaway directory; the helper's own main() is
 * renamed so this file can call its functions directly. Needs no root.
 */
#include <time.h>
static time_t test_now;
#define OTP_NOW() test_now
#define main otp_main
#include "../../userspace/otp/secure-sudo-otp.c"
#undef main

#include <sys/wait.h>

static int tap_n, tap_fail;

static void tap(int cond, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
static void tap(int cond, const char *fmt, ...)
{
	va_list ap;

	tap_n++;
	if (!cond)
		tap_fail++;
	printf("%s %d - ", cond ? "ok" : "not ok", tap_n);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
}

/* RFC 6238 appendix B uses this 20-byte ASCII seed for SHA-1. */
static const uint8_t SEED[] = "12345678901234567890";
#define SEED_LEN 20
#define SEED_B32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

static void code_at(time_t t, char out[8])
{
	snprintf(out, 8, "%06u", totp_at(SEED, SEED_LEN, (uint64_t)t / TOTP_STEP));
}

/* Run cmd_verify(--pam) with @input on stdin, as the PAM module does. */
static int verify(const char *input)
{
	char path[] = OTP_DIR "/../stdin";
	FILE *f = fopen(path, "w");

	if (!f)
		return -1;
	fputs(input, f);
	fclose(f);
	if (!freopen(path, "r", stdin))
		return -1;
	return cmd_verify(1);
}

/* Run a helper command in a child with its stdout discarded. */
static int quiet(int (*fn)(int, char **, int), int argc, char **argv, int k)
{
	pid_t pid = fork();
	int st;

	if (pid == 0) {
		if (!freopen("/dev/null", "w", stdout))
			_exit(99);
		_exit(fn(argc, argv, k));
	}
	if (pid < 0 || waitpid(pid, &st, 0) < 0 || !WIFEXITED(st))
		return -1;
	return WEXITSTATUS(st);
}

static int disable_cmd(int argc, char **argv, int k)
{
	(void)argc; (void)argv; (void)k;
	return cmd_disable();
}

static int file_contains(const char *path, const void *needle, size_t nlen)
{
	uint8_t buf[4096];
	ssize_t n = read_file(path, buf, sizeof(buf));

	return n > 0 && memmem(buf, n, needle, nlen) != NULL;
}

static int mode_is(const char *path, mode_t want)
{
	struct stat st;

	return stat(path, &st) == 0 && (st.st_mode & 07777) == want;
}

static void flip_byte(const char *path, off_t off)
{
	int fd = open(path, O_RDWR);
	uint8_t b;

	if (fd < 0)
		return;
	if (pread(fd, &b, 1, off) == 1) {
		b ^= 0x01;
		if (pwrite(fd, &b, 1, off) != 1)
			perror("pwrite");
	}
	close(fd);
}

int main(void)
{
	/* RFC 4226 appendix D: HOTP for counters 0..9. */
	static const unsigned hotp[10] = {
		755224, 287082, 359152, 969429, 338314,
		254676, 287922, 162583, 399871, 520489,
	};
	/* RFC 6238 appendix B, SHA-1 column; the helper uses 6 digits, which
	 * are the low 6 digits of the 8-digit reference values. */
	static const struct { uint64_t t; unsigned code8; } totp[] = {
		{ 59ULL, 94287082 }, { 1111111109ULL, 7081804 },
		{ 1111111111ULL, 14050471 }, { 1234567890ULL, 89005924 },
		{ 2000000000ULL, 69279037 }, { 20000000000ULL, 65353130 },
	};
	/* RFC 4648 section 10 (the helper writes no '=' padding). */
	static const struct { const char *in, *out; } b32[] = {
		{ "", "" }, { "f", "MY" }, { "fo", "MZXQ" }, { "foo", "MZXW6" },
		{ "foob", "MZXW6YQ" }, { "fooba", "MZXW6YTB" },
		{ "foobar", "MZXW6YTBOI" },
	};
	char c[8], c2[8], in[512], enc[64];
	uint8_t dec[64];
	size_t i, n;

	for (i = 0; i < 10; i++)
		tap(totp_at(SEED, SEED_LEN, i) == hotp[i],
		    "RFC 4226 HOTP counter %zu = %06u (got %06u)", i, hotp[i],
		    totp_at(SEED, SEED_LEN, i));
	for (i = 0; i < sizeof(totp) / sizeof(totp[0]); i++) {
		unsigned want = totp[i].code8 % 1000000u;
		unsigned got = totp_at(SEED, SEED_LEN, totp[i].t / TOTP_STEP);

		tap(got == want, "RFC 6238 SHA-1 T=%llu = %06u (got %06u)",
		    (unsigned long long)totp[i].t, want, got);
	}

	for (i = 0; i < sizeof(b32) / sizeof(b32[0]); i++) {
		n = base32_encode((const uint8_t *)b32[i].in, strlen(b32[i].in), enc);
		tap(n == strlen(b32[i].out) && !strcmp(enc, b32[i].out),
		    "RFC 4648 base32 \"%s\" -> \"%s\" (got \"%s\")",
		    b32[i].in, b32[i].out, enc);
		n = base32_decode(b32[i].out, dec, sizeof(dec));
		tap(n == strlen(b32[i].in) && !memcmp(dec, b32[i].in, n),
		    "base32 decode \"%s\"", b32[i].out);
	}
	n = base32_decode("gezd gnbv-gy3t====", dec, sizeof(dec));
	tap(n == 7 && !memcmp(dec, "1234567", 7),
	    "base32 decode ignores case, spaces, padding and stray characters");
	n = base32_encode(SEED, SEED_LEN, enc);
	tap(!strcmp(enc, SEED_B32), "seed encodes to the RFC key %s", SEED_B32);

	/* --- the secret at rest: setup stores the test seed --- */
	tap(ensure_dir() == 0 && mode_is(OTP_DIR, 0700), "OTP dir created 0700");
	tap(secret_encrypt((const uint8_t *)SEED_B32, strlen(SEED_B32)) == 0,
	    "secret stored");
	tap(mode_is(F_SECRET, 0600) && mode_is(F_MASTER, 0600),
	    "secret and master key are 0600");
	tap(!file_contains(F_SECRET, SEED_B32, 8) &&
	    !file_contains(F_SECRET, SEED, 8),
	    "secret file holds no plaintext seed (encoded or raw)");

	/* --- verify, no prefix --- */
	test_now = 1234567890;
	code_at(test_now, c);
	snprintf(in, sizeof(in), "%s\n", c);
	tap(verify(in) == 0, "current code accepted");
	tap(verify(in) == 1, "the same code is refused a second time (RFC 6238 5.2)");
	test_now += TOTP_STEP;
	code_at(test_now - TOTP_STEP, c);
	snprintf(in, sizeof(in), "%s\n", c);
	tap(verify(in) == 1, "an older code is refused once a newer one was used");
	code_at(test_now + TOTP_STEP, c);
	snprintf(in, sizeof(in), "%s\n", c);
	tap(verify(in) == 0, "code one step ahead accepted (clock skew window)");
	test_now += 10 * TOTP_STEP;
	code_at(test_now - TOTP_STEP, c);
	snprintf(in, sizeof(in), "%s\n", c);
	tap(verify(in) == 0, "code one step behind accepted (clock skew window)");
	test_now += 10 * TOTP_STEP;
	code_at(test_now - 2 * TOTP_STEP, c);
	code_at(test_now + 2 * TOTP_STEP, c2);
	snprintf(in, sizeof(in), "%s\n", c);
	tap(verify(in) == 1, "code two steps behind refused");
	snprintf(in, sizeof(in), "%s\n", c2);
	tap(verify(in) == 1, "code two steps ahead refused");
	code_at(test_now, c);
	snprintf(in, sizeof(in), "%06u\n", (unsigned)((strtoul(c, NULL, 10) + 1) % 1000000));
	tap(verify(in) == 1, "wrong code refused");
	snprintf(in, sizeof(in), "%.5s\n", c);
	tap(verify(in) == 1, "5-digit input refused");
	snprintf(in, sizeof(in), "x%s\n", c);
	tap(verify(in) == 1, "extra characters refused when no prefix is set");
	tap(verify("") == 1, "empty input (EOF) refused");
	snprintf(in, sizeof(in), "%s\n", c);
	tap(verify(in) == 0, "valid code still accepted after the failures");

	/* --- prefix --- */
	test_now += 10 * TOTP_STEP;
	tap(prefix_set("hunter2") == 0 && mode_is(F_PREFIX, 0600),
	    "prefix stored 0600");
	tap(file_contains(F_PREFIX, "$y$", 3) &&
	    !file_contains(F_PREFIX, "hunter2", 7),
	    "prefix stored as a yescrypt hash, not plaintext");
	code_at(test_now, c);
	snprintf(in, sizeof(in), "%s\n", c);
	tap(verify(in) == 1, "code alone refused once a prefix is set");
	snprintf(in, sizeof(in), "hunter3%s\n", c);
	tap(verify(in) == 1, "wrong prefix + right code refused");
	snprintf(in, sizeof(in), "hunter2%06u\n",
		 (unsigned)((strtoul(c, NULL, 10) + 1) % 1000000));
	tap(verify(in) == 1, "right prefix + wrong code refused");
	snprintf(in, sizeof(in), "hunter2%s\n", c);
	tap(verify(in) == 0, "right prefix + right code accepted");
	memset(in, 'A', 300);
	memcpy(in + 300, c, 6);
	strcpy(in + 306, "\n");
	tap(verify(in) == 1, "over-long input refused");

	/* reset without --prefix must keep the prefix (it used to drop it,
	 * silently turning the password into the bare 6-digit code) */
	{
		char *av[] = { "secure-sudo-otp", "reset", NULL };

		tap(quiet(cmd_setup, 2, av, 1) == 0 &&
		    access(F_PREFIX, F_OK) == 0,
		    "reset without --prefix keeps the prefix");
		tap(quiet(cmd_setup, 2, av, 0) == 0 &&
		    access(F_PREFIX, F_OK) != 0,
		    "setup without --prefix removes it");
	}

	/* --- tampering: reset changed the seed, so store the test one again --- */
	test_now += 10 * TOTP_STEP;
	tap(secret_encrypt((const uint8_t *)SEED_B32, strlen(SEED_B32)) == 0,
	    "test seed stored again");
	code_at(test_now, c);
	snprintf(in, sizeof(in), "%s\n", c);
	flip_byte(F_SECRET, 30);
	tap(verify(in) == 1, "tampered ciphertext refused (GCM tag)");
	flip_byte(F_SECRET, 30);
	flip_byte(F_SECRET, 14);
	tap(verify(in) == 1, "tampered tag refused");
	flip_byte(F_SECRET, 14);
	flip_byte(F_MASTER, 0);
	tap(verify(in) == 1, "wrong master key refused");
	flip_byte(F_MASTER, 0);
	tap(verify(in) == 0, "restored files verify again");

	/* --- fail closed --- */
	test_now += 10 * TOTP_STEP;
	code_at(test_now, c);
	snprintf(in, sizeof(in), "%s\n", c);
	unlink(F_LAST);
	tap(mkdir(F_LAST, 0700) == 0 && verify(in) == 1,
	    "replay record not writable: code refused (fails closed)");
	rmdir(F_LAST);
	tap(verify(in) == 0, "record writable again: code accepted");

	/* disable shreds and removes everything */
	tap(quiet(disable_cmd, 0, NULL, 0) == 0 && access(F_SECRET, F_OK) != 0 &&
	    access(F_MASTER, F_OK) != 0 && access(F_LAST, F_OK) != 0,
	    "disable removes secret, master key and replay record");
	test_now += 10 * TOTP_STEP;
	code_at(test_now, c);
	snprintf(in, sizeof(in), "%s\n", c);
	tap(verify(in) == 1, "nothing verifies after disable");

	printf("1..%d\n", tap_n);
	return tap_fail ? 1 : 0;
}
