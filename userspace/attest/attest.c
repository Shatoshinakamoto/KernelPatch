// SPDX-License-Identifier: GPL-2.0
/*
 * secure-sudo-attest - the TPM side of remote attestation (TODO P2-1).
 *
 *   secure-sudo-attest ak
 *       Print the attestation key's public part (base64 TPM2B_PUBLIC) and
 *       TPM name as JSON. The verifier enrolls these once.
 *   secure-sudo-attest quote --nonce HEX --report FILE [--pcrs 0,1,...]
 *       Have the TPM sign the listed SHA-256 PCRs (default 0,1,2,3,4,5,7,8,9)
 *       together with sha256(nonce || report): the verifier's fresh nonce
 *       proves the quote is not a replay, and the report (kernel, boot id,
 *       policy digest, lock state) is bound to it. Prints JSON.
 *
 * The attestation key (AK) is a restricted ECC P-256 signing key: it can only
 * sign data the TPM itself produced (quotes), never an arbitrary digest, so
 * nobody - root included - can make it sign a forged quote. It is a PRIMARY
 * key in the owner hierarchy created from a fixed template, which makes it
 * the same key every time from the same TPM until the owner seed changes
 * (TPM2_Clear, which G4 blocks): nothing is stored on disk.
 *
 * This program deliberately does nothing else (no extend, no clear, no NV):
 * it is the one attestation binary on the kernel's tpm_openers list (G4), so
 * once the policy is locked a root shell still cannot drive the TPM through
 * it.
 *
 * Environment: SS_ATTEST_TCTI (e.g. "swtpm:host=127.0.0.1,port=2321") picks
 * the TPM; default is the system one (/dev/tpmrm0). SS_ATTEST_OWNER_AUTH_FILE
 * names a file holding the owner hierarchy password when one is set (most
 * machines have none).
 */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define DEFAULT_PCRS "0,1,2,3,4,5,7,8,9"
#define REPORT_MAX (8u << 20)	/* the policy log can be a few MiB */

static ESYS_CONTEXT *ctx;
static TSS2_TCTI_CONTEXT *tcti;

static void die_rc(const char *what, TSS2_RC rc)
{
	fprintf(stderr, "secure-sudo-attest: %s: %s\n", what, Tss2_RC_Decode(rc));
	exit(1);
}

static void die(const char *msg)
{
	fprintf(stderr, "secure-sudo-attest: %s\n", msg);
	exit(2);
}

static void tpm_open(void)
{
	TSS2_RC rc;

	rc = Tss2_TctiLdr_Initialize(getenv("SS_ATTEST_TCTI"), &tcti);
	if (rc != TSS2_RC_SUCCESS)
		die_rc("cannot reach the TPM", rc);
	rc = Esys_Initialize(&ctx, tcti, NULL);
	if (rc != TSS2_RC_SUCCESS)
		die_rc("Esys_Initialize", rc);
}

static void tpm_close(void)
{
	Esys_Finalize(&ctx);
	Tss2_TctiLdr_Finalize(&tcti);
}

static void owner_auth(void)
{
	const char *f = getenv("SS_ATTEST_OWNER_AUTH_FILE");
	TPM2B_AUTH a = { 0 };
	FILE *fp;
	size_t n;

	if (!f || !*f)
		return;
	fp = fopen(f, "re");
	if (!fp)
		die("cannot read SS_ATTEST_OWNER_AUTH_FILE");
	n = fread(a.buffer, 1, sizeof(a.buffer), fp);
	fclose(fp);
	while (n && (a.buffer[n - 1] == '\n' || a.buffer[n - 1] == '\r'))
		n--;
	a.size = (UINT16)n;
	Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &a);
}

/* The AK: same template, same TPM -> same key. The unique field carries a
 * label so it never collides with another primary from the same template. */
static ESYS_TR make_ak(TPM2B_PUBLIC **pub)
{
	static const char label[] = "secure_sudo attestation key v1";
	TPM2B_SENSITIVE_CREATE in = { 0 };
	TPM2B_PUBLIC t = { 0 };
	TPM2B_DATA outside = { 0 };
	TPML_PCR_SELECTION none = { 0 };
	ESYS_TR key;
	TSS2_RC rc;

	t.publicArea.type = TPM2_ALG_ECC;
	t.publicArea.nameAlg = TPM2_ALG_SHA256;
	t.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
		TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
		TPMA_OBJECT_SIGN_ENCRYPT;
	t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
	t.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
	t.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
	t.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
	t.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
	t.publicArea.unique.ecc.x.size = sizeof(label) - 1;
	memcpy(t.publicArea.unique.ecc.x.buffer, label, sizeof(label) - 1);

	owner_auth();
	rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
				ESYS_TR_NONE, ESYS_TR_NONE, &in, &t, &outside,
				&none, &key, pub, NULL, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS)
		die_rc("creating the attestation key (owner hierarchy)", rc);
	return key;
}

static void hex(const unsigned char *b, size_t n, char *out)
{
	static const char d[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		out[2 * i] = d[b[i] >> 4];
		out[2 * i + 1] = d[b[i] & 15];
	}
	out[2 * n] = '\0';
}

static char *b64(const unsigned char *b, size_t n)
{
	char *o = malloc(4 * ((n + 2) / 3) + 1);

	if (!o)
		die("out of memory");
	EVP_EncodeBlock((unsigned char *)o, b, (int)n);
	return o;
}

static void print_ak(ESYS_TR key, const TPM2B_PUBLIC *pub)
{
	unsigned char buf[sizeof(TPM2B_PUBLIC)];
	size_t off = 0;
	TPM2B_NAME *name = NULL;
	char nh[2 * sizeof(name->name) + 1], *p;
	TSS2_RC rc;

	rc = Tss2_MU_TPM2B_PUBLIC_Marshal(pub, buf, sizeof(buf), &off);
	if (rc != TSS2_RC_SUCCESS)
		die_rc("marshal AK public", rc);
	rc = Esys_TR_GetName(ctx, key, &name);
	if (rc != TSS2_RC_SUCCESS)
		die_rc("AK name", rc);
	hex(name->name, name->size, nh);
	p = b64(buf, off);
	printf("\"ak_public\":\"%s\",\"ak_name\":\"%s\"", p, nh);
	free(p);
	Esys_Free(name);
}

static int parse_pcrs(const char *s, TPML_PCR_SELECTION *sel, int *list, int *n)
{
	const char *p = s;

	memset(sel, 0, sizeof(*sel));
	sel->count = 1;
	sel->pcrSelections[0].hash = TPM2_ALG_SHA256;
	sel->pcrSelections[0].sizeofSelect = 3;
	*n = 0;
	while (*p) {
		char *e;
		long v = strtol(p, &e, 10);

		if (e == p || v < 0 || v > 23 || *n >= 24)
			return -1;
		if (!(sel->pcrSelections[0].pcrSelect[v / 8] & (1 << (v % 8))))
			list[(*n)++] = (int)v;
		sel->pcrSelections[0].pcrSelect[v / 8] |= (BYTE)(1 << (v % 8));
		p = e;
		if (*p == ',')
			p++;
		else if (*p)
			return -1;
	}
	return *n ? 0 : -1;
}

static int cmp_int(const void *a, const void *b)
{
	return *(const int *)a - *(const int *)b;
}

/* Read the selected PCRs (in index order, as the quote digests them). */
static void read_pcrs(const int *list, int n, unsigned char vals[][32])
{
	int i;

	for (i = 0; i < n; i++) {
		TPML_PCR_SELECTION one = { 0 }, *outsel = NULL;
		TPML_DIGEST *d = NULL;
		UINT32 upd;
		TSS2_RC rc;

		one.count = 1;
		one.pcrSelections[0].hash = TPM2_ALG_SHA256;
		one.pcrSelections[0].sizeofSelect = 3;
		one.pcrSelections[0].pcrSelect[list[i] / 8] = (BYTE)(1 << (list[i] % 8));
		rc = Esys_PCR_Read(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				   &one, &upd, &outsel, &d);
		if (rc != TSS2_RC_SUCCESS)
			die_rc("PCR_Read", rc);
		if (!d || d->count != 1 || d->digests[0].size != 32)
			die("the TPM has no SHA-256 PCR bank");
		memcpy(vals[i], d->digests[0].buffer, 32);
		Esys_Free(outsel);
		Esys_Free(d);
	}
}

static int unhex(const char *s, unsigned char *out, size_t max, size_t *n)
{
	size_t l = strlen(s), i;

	if (l % 2 || l / 2 > max || l == 0)
		return -1;
	for (i = 0; i < l; i += 2) {
		if (!isxdigit((unsigned char)s[i]) || !isxdigit((unsigned char)s[i + 1]))
			return -1;
		sscanf(s + i, "%2hhx", &out[i / 2]);
	}
	*n = l / 2;
	return 0;
}

static int cmd_quote(const char *nonce_hex, const char *report, const char *pcrs)
{
	unsigned char nonce[64], vals[24][32], again[24][32], qd[32];
	int list[24], n, i, tries;
	size_t nlen, rlen;
	char *rbuf, h[65], rh[2 * sizeof(((TPM2B_ECC_PARAMETER *)0)->buffer) + 1];
	char sh[sizeof(rh)], *ab;
	TPML_PCR_SELECTION sel;
	TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_ECDSA };
	TPM2B_DATA q = { .size = 32 };
	TPM2B_ATTEST *att = NULL;
	TPMT_SIGNATURE *sig = NULL;
	TPM2B_PUBLIC *pub = NULL;
	EVP_MD_CTX *md;
	ESYS_TR key;
	FILE *f;

	if (unhex(nonce_hex, nonce, sizeof(nonce), &nlen) != 0 || nlen < 16)
		die("--nonce must be at least 16 bytes of hex (from the verifier)");
	if (parse_pcrs(pcrs, &sel, list, &n) != 0)
		die("--pcrs must be a comma-separated list of PCR numbers 0-23");
	qsort(list, (size_t)n, sizeof(int), cmp_int);
	f = fopen(report, "re");
	if (!f)
		die("cannot read --report");
	rbuf = malloc(REPORT_MAX);
	if (!rbuf)
		die("out of memory");
	rlen = fread(rbuf, 1, REPORT_MAX, f);
	if (!feof(f)) {
		fclose(f);
		die("--report is larger than 8 MiB");
	}
	fclose(f);

	/* qualifying data = sha256(nonce || report) */
	md = EVP_MD_CTX_new();
	if (!md || EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(md, nonce, nlen) != 1 ||
	    EVP_DigestUpdate(md, rbuf, rlen) != 1 ||
	    EVP_DigestFinal_ex(md, qd, NULL) != 1)
		die("sha256");
	EVP_MD_CTX_free(md);
	free(rbuf);
	memcpy(q.buffer, qd, 32);
	scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;

	tpm_open();
	key = make_ak(&pub);
	/* The PCR values reported must be the ones quoted: read, quote, read
	 * again, and retry if something extended a PCR in between. */
	for (tries = 0; tries < 5; tries++) {
		TSS2_RC rc;

		read_pcrs(list, n, vals);
		rc = Esys_Quote(ctx, key, ESYS_TR_PASSWORD, ESYS_TR_NONE,
				ESYS_TR_NONE, &q, &scheme, &sel, &att, &sig);
		if (rc != TSS2_RC_SUCCESS)
			die_rc("Quote", rc);
		read_pcrs(list, n, again);
		if (!memcmp(vals, again, sizeof(vals[0]) * (size_t)n))
			break;
		Esys_Free(att);
		Esys_Free(sig);
		att = NULL;
		sig = NULL;
	}
	if (!att)
		die("the PCRs kept changing during the quote; try again");

	printf("{\"tool\":\"secure-sudo-attest\",\"version\":1,");
	print_ak(key, pub);
	hex(qd, 32, h);
	ab = b64(att->attestationData, att->size);
	hex(sig->signature.ecdsa.signatureR.buffer, sig->signature.ecdsa.signatureR.size, rh);
	hex(sig->signature.ecdsa.signatureS.buffer, sig->signature.ecdsa.signatureS.size, sh);
	printf(",\"qualifying_data\":\"%s\",\"quote\":\"%s\","
	       "\"signature\":{\"alg\":\"ecdsa-p256-sha256\",\"r\":\"%s\",\"s\":\"%s\"},"
	       "\"pcrs\":{", h, ab, rh, sh);
	for (i = 0; i < n; i++) {
		hex(vals[i], 32, h);
		printf("%s\"%d\":\"%s\"", i ? "," : "", list[i], h);
	}
	printf("}}\n");
	free(ab);
	Esys_Free(att);
	Esys_Free(sig);
	Esys_Free(pub);
	Esys_FlushContext(ctx, key);
	tpm_close();
	return 0;
}

static int cmd_ak(void)
{
	TPM2B_PUBLIC *pub = NULL;
	ESYS_TR key;

	tpm_open();
	key = make_ak(&pub);
	printf("{");
	print_ak(key, pub);
	printf("}\n");
	Esys_Free(pub);
	Esys_FlushContext(ctx, key);
	tpm_close();
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"usage: secure-sudo-attest ak\n"
		"       secure-sudo-attest quote --nonce HEX --report FILE [--pcrs " DEFAULT_PCRS "]\n");
	exit(2);
}

int main(int argc, char **argv)
{
	const char *nonce = NULL, *report = NULL, *pcrs = DEFAULT_PCRS;
	int i;

	if (argc < 2)
		usage();
	if (!strcmp(argv[1], "ak") && argc == 2)
		return cmd_ak();
	if (strcmp(argv[1], "quote"))
		usage();
	for (i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "--nonce") && i + 1 < argc)
			nonce = argv[++i];
		else if (!strcmp(argv[i], "--report") && i + 1 < argc)
			report = argv[++i];
		else if (!strcmp(argv[i], "--pcrs") && i + 1 < argc)
			pcrs = argv[++i];
		else
			usage();
	}
	if (!nonce || !report)
		usage();
	return cmd_quote(nonce, report, pcrs);
}
