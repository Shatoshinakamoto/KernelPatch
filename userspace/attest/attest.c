// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * secure-sudo-attest - the TPM side of remote attestation (TODO P2-1).
 *
 *   secure-sudo-attest ak
 *       Print the attestation key's public part (base64 TPM2B_PUBLIC) and
 *       TPM name as JSON. The verifier enrolls these once.
 *   secure-sudo-attest ek
 *       Print the TPM's endorsement keys (EKs) under the TCG EK Credential
 *       Profile templates L-1 (RSA 2048), L-2 (ECC P-256) and H-3 (ECC
 *       P-384), each with the manufacturer's EK certificate from NV when
 *       the TPM has one. The verifier checks a certificate against the
 *       manufacturer's CA.
 *   secure-sudo-attest activate [--ek TEMPLATE] --credential B64 --secret B64
 *       TPM2_ActivateCredential: recover the verifier's secret from a
 *       challenge made for this EK and this AK. The TPM releases it only
 *       if the AK named in the challenge is loaded in the same TPM as that
 *       EK, which binds the AK to the certified TPM (no trust on first use).
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
 * This program deliberately does nothing else (no extend, no clear, no NV
 * write; it only reads the EK certificate indices):
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
/* Transient objects and sessions, flushed on every exit: without a resource
 * manager (a raw /dev/tpm0 or a software TPM) a failed run would otherwise
 * leave them taking the TPM's few object slots. */
static ESYS_TR live[4];
static int nlive;

static ESYS_TR track(ESYS_TR h)
{
	if (nlive < (int)(sizeof(live) / sizeof(live[0])))
		live[nlive++] = h;
	return h;
}

static void flush_live(void)
{
	while (ctx && nlive > 0)
		Esys_FlushContext(ctx, live[--nlive]);
}

static void die_rc(const char *what, TSS2_RC rc)
{
	fprintf(stderr, "secure-sudo-attest: %s: %s\n", what, Tss2_RC_Decode(rc));
	flush_live();
	exit(1);
}

static void die(const char *msg)
{
	fprintf(stderr, "secure-sudo-attest: %s\n", msg);
	flush_live();
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
	return track(key);
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

/*
 * The EK templates of the TCG EK Credential Profile that this tool knows:
 * each is the key a manufacturer's EK certificate in that NV index
 * certifies. L-1 and L-2 ("low range") need PolicySecret(TPM_RH_ENDORSEMENT)
 * to use; H-3 ("high range", ECC P-384) has userWithAuth and an empty auth.
 */
struct ek_tmpl {
	const char *id;
	TPM2_HANDLE cert_index;
	TPMI_ALG_PUBLIC type;
	TPMI_ALG_HASH name_alg;
	TPMA_OBJECT attrs;
	const BYTE *policy;
	UINT16 policy_len;
	UINT16 aes_bits;
	TPMI_ECC_CURVE curve;	/* ECC only */
	UINT16 unique_len;	/* RSA modulus or each ECC coordinate; 0 = empty */
	int user_with_auth;
};

static const BYTE policy_a_sha256[32] = {
	0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc,
	0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52,
	0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
};
static const BYTE policy_b_sha384[48] = {
	0xb2, 0x6e, 0x7d, 0x28, 0xd1, 0x1a, 0x50, 0xbc, 0x53, 0xd8, 0x82, 0xbc,
	0xf5, 0xfd, 0x3a, 0x1a, 0x07, 0x41, 0x48, 0xbb, 0x35, 0xd3, 0xb4, 0xe4,
	0xcb, 0x1c, 0x0a, 0xd9, 0xbd, 0xe4, 0x19, 0xca, 0xcb, 0x47, 0xba, 0x09,
	0x69, 0x96, 0x46, 0x15, 0x0f, 0x9f, 0xc0, 0x00, 0xf3, 0xf8, 0x0e, 0x12,
};
#define EK_LOW (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | \
		TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_ADMINWITHPOLICY | \
		TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT)

static const struct ek_tmpl ek_tmpls[] = {
	{ "rsa2048", 0x01C00002, TPM2_ALG_RSA, TPM2_ALG_SHA256, EK_LOW,
	  policy_a_sha256, 32, 128, 0, 256, 0 },
	{ "ecc-p256", 0x01C0000A, TPM2_ALG_ECC, TPM2_ALG_SHA256, EK_LOW,
	  policy_a_sha256, 32, 128, TPM2_ECC_NIST_P256, 32, 0 },
	{ "ecc-p384", 0x01C00016, TPM2_ALG_ECC, TPM2_ALG_SHA384,
	  EK_LOW | TPMA_OBJECT_USERWITHAUTH, policy_b_sha384, 48, 256,
	  TPM2_ECC_NIST_P384, 0, 1 },
};

static const struct ek_tmpl *ek_find(const char *id)
{
	size_t i;

	for (i = 0; i < sizeof(ek_tmpls) / sizeof(ek_tmpls[0]); i++)
		if (!strcmp(ek_tmpls[i].id, id))
			return &ek_tmpls[i];
	return NULL;
}

/* Create the EK from a template; ESYS_TR_NONE if the TPM cannot (and !must). */
static ESYS_TR make_ek(const struct ek_tmpl *k, TPM2B_PUBLIC **pub, int must)
{
	TPM2B_SENSITIVE_CREATE in = { 0 };
	TPM2B_PUBLIC t = { 0 };
	TPM2B_DATA outside = { 0 };
	TPML_PCR_SELECTION none = { 0 };
	TPMT_SYM_DEF_OBJECT *sym;
	ESYS_TR key;
	TSS2_RC rc;

	t.publicArea.type = k->type;
	t.publicArea.nameAlg = k->name_alg;
	t.publicArea.objectAttributes = k->attrs;
	t.publicArea.authPolicy.size = k->policy_len;
	memcpy(t.publicArea.authPolicy.buffer, k->policy, k->policy_len);
	if (k->type == TPM2_ALG_RSA) {
		sym = &t.publicArea.parameters.rsaDetail.symmetric;
		t.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
		t.publicArea.parameters.rsaDetail.keyBits = 2048;
		t.publicArea.parameters.rsaDetail.exponent = 0;
		t.publicArea.unique.rsa.size = k->unique_len;	/* zero bytes */
	} else {
		sym = &t.publicArea.parameters.eccDetail.symmetric;
		t.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
		t.publicArea.parameters.eccDetail.curveID = k->curve;
		t.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
		t.publicArea.unique.ecc.x.size = k->unique_len;
		t.publicArea.unique.ecc.y.size = k->unique_len;
	}
	sym->algorithm = TPM2_ALG_AES;
	sym->keyBits.aes = k->aes_bits;
	sym->mode.aes = TPM2_ALG_CFB;

	rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD,
				ESYS_TR_NONE, ESYS_TR_NONE, &in, &t, &outside,
				&none, &key, pub, NULL, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		if (must)
			die_rc("creating the endorsement key (endorsement hierarchy)", rc);
		return ESYS_TR_NONE;
	}
	return track(key);
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
	flush_live();
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
	flush_live();
	tpm_close();
	return 0;
}

/* Read an NV index (an EK certificate) whole; NULL when it is not there. */
static unsigned char *nv_read_all(TPM2_HANDLE index, size_t *len)
{
	TPM2B_NV_PUBLIC *np = NULL;
	unsigned char *out;
	ESYS_TR nv;
	UINT16 size, off = 0;
	TSS2_RC rc;

	rc = Esys_TR_FromTPMPublic(ctx, index, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, &nv);
	if (rc != TSS2_RC_SUCCESS)
		return NULL;
	rc = Esys_NV_ReadPublic(ctx, nv, ESYS_TR_NONE, ESYS_TR_NONE,
				ESYS_TR_NONE, &np, NULL);
	if (rc != TSS2_RC_SUCCESS)
		return NULL;
	size = np->nvPublic.dataSize;
	Esys_Free(np);
	out = malloc(size ? size : 1);
	if (!out)
		die("out of memory");
	while (off < size) {
		TPM2B_MAX_NV_BUFFER *d = NULL;
		UINT16 n = (UINT16)(size - off > 512 ? 512 : size - off);

		rc = Esys_NV_Read(ctx, nv, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE,
				  ESYS_TR_NONE, n, off, &d);
		if (rc != TSS2_RC_SUCCESS || d->size != n)
			die_rc("reading the EK certificate from NV", rc);
		memcpy(out + off, d->buffer, n);
		off = (UINT16)(off + n);
		Esys_Free(d);
	}
	Esys_TR_Close(ctx, &nv);
	*len = size;
	return out;
}

/* Every EK this TPM has under a known template, with its certificate. */
static int cmd_ek(void)
{
	unsigned char buf[sizeof(TPM2B_PUBLIC)], *cert;
	size_t i, n = 0;
	char *p;

	tpm_open();
	printf("{\"eks\":[");
	for (i = 0; i < sizeof(ek_tmpls) / sizeof(ek_tmpls[0]); i++) {
		const struct ek_tmpl *k = &ek_tmpls[i];
		TPM2B_PUBLIC *pub = NULL;
		size_t off = 0, clen = 0;
		ESYS_TR key;

		cert = nv_read_all(k->cert_index, &clen);
		/* the low-range RSA EK always (for --ek-no-cert); the
		 * others only when the manufacturer certified them */
		if (strcmp(k->id, "rsa2048") && !(cert && clen)) {
			free(cert);
			continue;
		}
		key = make_ek(k, &pub, 0);
		if (key == ESYS_TR_NONE) {
			free(cert);
			continue;
		}
		if (Tss2_MU_TPM2B_PUBLIC_Marshal(pub, buf, sizeof(buf), &off) != TSS2_RC_SUCCESS)
			die("marshal EK public");
		p = b64(buf, off);
		printf("%s{\"template\":\"%s\",\"public\":\"%s\",\"cert\":",
		       n++ ? "," : "", k->id, p);
		free(p);
		if (cert && clen) {
			p = b64(cert, clen);
			printf("\"%s\"}", p);
			free(p);
		} else {
			printf("null}");
		}
		free(cert);
		Esys_Free(pub);
		Esys_FlushContext(ctx, key);
		nlive--;
	}
	printf("]}\n");
	tpm_close();
	return n ? 0 : 1;
}

static size_t unb64(const char *s, unsigned char *out, size_t max)
{
	size_t l = strlen(s);
	int n;

	if (!l || l % 4 || l / 4 * 3 > max)
		die("bad base64 in the challenge");
	n = EVP_DecodeBlock(out, (const unsigned char *)s, (int)l);
	if (n < 0)
		die("bad base64 in the challenge");
	if (l >= 1 && s[l - 1] == '=')
		n--;
	if (l >= 2 && s[l - 2] == '=')
		n--;
	return (size_t)n;
}

static int cmd_activate(const char *tmpl, const char *cred_b64, const char *secret_b64)
{
	const struct ek_tmpl *k = ek_find(tmpl);
	unsigned char cb[sizeof(TPM2B_ID_OBJECT)], sb[sizeof(TPM2B_ENCRYPTED_SECRET)];
	char h[2 * sizeof(((TPM2B_DIGEST *)0)->buffer) + 1];
	TPM2B_ID_OBJECT cred = { 0 };
	TPM2B_ENCRYPTED_SECRET sec = { 0 };
	TPM2B_DIGEST *out = NULL;
	TPM2B_PUBLIC *akp = NULL, *ekp = NULL;
	TPMT_SYM_DEF sym = { .algorithm = TPM2_ALG_NULL };
	TPM2B_NONCE empty = { 0 };
	ESYS_TR ak, ek, sess = ESYS_TR_PASSWORD;
	size_t cl, sl, off = 0;
	TSS2_RC rc;

	if (!k)
		die("unknown EK template in the challenge");
	cl = unb64(cred_b64, cb, sizeof(cb));
	sl = unb64(secret_b64, sb, sizeof(sb));
	if (Tss2_MU_TPM2B_ID_OBJECT_Unmarshal(cb, cl, &off, &cred) != TSS2_RC_SUCCESS || off != cl)
		die("the challenge's credential is not a TPM2B_ID_OBJECT");
	off = 0;
	if (Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(sb, sl, &off, &sec) != TSS2_RC_SUCCESS || off != sl)
		die("the challenge's secret is not a TPM2B_ENCRYPTED_SECRET");

	tpm_open();
	ak = make_ak(&akp);
	ek = make_ek(k, &ekp, 1);
	if (!k->user_with_auth) {
		/* low range: the EK's policy is PolicySecret(TPM_RH_ENDORSEMENT) */
		rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
					   ESYS_TR_NONE, ESYS_TR_NONE, NULL,
					   TPM2_SE_POLICY, &sym, k->name_alg, &sess);
		if (rc != TSS2_RC_SUCCESS)
			die_rc("StartAuthSession", rc);
		track(sess);
		rc = Esys_PolicySecret(ctx, ESYS_TR_RH_ENDORSEMENT, sess, ESYS_TR_PASSWORD,
				       ESYS_TR_NONE, ESYS_TR_NONE, &empty, NULL, NULL, 0,
				       NULL, NULL);
		if (rc != TSS2_RC_SUCCESS)
			die_rc("PolicySecret(endorsement)", rc);
	}
	rc = Esys_ActivateCredential(ctx, ak, ek, ESYS_TR_PASSWORD, sess,
				     ESYS_TR_NONE, &cred, &sec, &out);
	if (rc != TSS2_RC_SUCCESS)
		die_rc("ActivateCredential (the challenge is not for this TPM's EK and AK)", rc);
	hex(out->buffer, out->size, h);
	printf("{\"tool\":\"secure-sudo-attest\",\"activated_secret\":\"%s\"}\n", h);
	Esys_Free(out);
	Esys_Free(akp);
	Esys_Free(ekp);
	flush_live();
	tpm_close();
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"usage: secure-sudo-attest ak | ek\n"
		"       secure-sudo-attest activate --ek TEMPLATE --credential B64 --secret B64\n"
		"       secure-sudo-attest quote --nonce HEX --report FILE [--pcrs " DEFAULT_PCRS "]\n");
	exit(2);
}

int main(int argc, char **argv)
{
	const char *nonce = NULL, *report = NULL, *pcrs = DEFAULT_PCRS;
	int i;

	/* errors are decoded and reported here; keep tss2's own log quiet
	 * (a missing EK certificate index is not an error) unless asked */
	setenv("TSS2_LOG", "all+NONE", 0);

	if (argc < 2)
		usage();
	if (!strcmp(argv[1], "ak") && argc == 2)
		return cmd_ak();
	if (!strcmp(argv[1], "ek") && argc == 2)
		return cmd_ek();
	if (!strcmp(argv[1], "activate") && argc == 6 &&
	    !strcmp(argv[2], "--credential") && !strcmp(argv[4], "--secret"))
		return cmd_activate("rsa2048", argv[3], argv[5]);
	if (!strcmp(argv[1], "activate") && argc == 8 && !strcmp(argv[2], "--ek") &&
	    !strcmp(argv[4], "--credential") && !strcmp(argv[6], "--secret"))
		return cmd_activate(argv[3], argv[5], argv[7]);
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
