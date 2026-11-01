// SPDX-License-Identifier: GPL-2.0
/*
 * secure_sudo policy measurement (TODO P2-1 part 2).
 *
 * Every successful policy change - a knob written under
 * /sys/kernel/secure_sudo/, a list written under
 * /sys/kernel/security/secure_sudo/, and the lock latching - is appended to
 * an in-kernel event log and extended into one TPM PCR
 * (CONFIG_SECURITY_SECURE_SUDO_MEASURE_PCR, default 13):
 *
 *	event  = "knob NAME VALUE" | "list NAME SHA256-OF-TEXT" | "lock WHY"
 *	PCR    = SHA256(PCR || SHA256(event))	(the SHA-256 bank)
 *
 * Other banks get the same SHA-256 digest cut or zero-padded to their size;
 * the verifier reads only the SHA-256 bank. The log is
 * /sys/kernel/security/secure_sudo/policy_log (root, read-only):
 *
 *	secure_sudo-policy-log v1 pcr=13 count=N extended=E overflow=0|1
 *	<index> <0|1 extended> <sha256(event)> <event>
 *
 * A remote verifier replays the extended entries, compares the result with
 * the PCR in a TPM quote, and so learns the policy the kernel actually
 * applied - not what root says it applied. Root cannot remove an event from
 * the PCR, only add one, and an added one makes the replay fail.
 *
 * The record is taken where the kernel swaps in its own copy of the new
 * text, under that list's lock, so the order of the log is the order the
 * changes took effect. Extending happens on a work item because a TPM
 * command sleeps and the TPM may not be up yet early in boot; entries wait
 * as "not extended" until it is. The log holds at most SS_MEASURE_MAX
 * entries; past that, measuring stops and the header says overflow=1, which
 * the verifier treats as a failure (fail closed).
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/tpm.h>
#include <linux/workqueue.h>
#include <crypto/sha2.h>

#include "secure_sudo.h"

#ifndef CONFIG_SECURITY_SECURE_SUDO_MEASURE_PCR
#define CONFIG_SECURITY_SECURE_SUDO_MEASURE_PCR 13
#endif
#define SS_MEASURE_PCR	CONFIG_SECURITY_SECURE_SUDO_MEASURE_PCR
#define SS_MEASURE_MAX	8192
#define SS_MEASURE_TEXT	160

struct ss_mentry {
	u8 digest[SHA256_DIGEST_SIZE];		/* sha256(text) */
	char text[SS_MEASURE_TEXT];
	/* set by the worker when the PCR held something else before this event */
	u8 foreign;
	u8 seen[SHA256_DIGEST_SIZE];		/* the PCR value found */
	u8 fdigest[SHA256_DIGEST_SIZE];		/* sha256("foreign pcr <seen>") */
};

static struct ss_mentry *m_log[SS_MEASURE_MAX];
static DEFINE_MUTEX(m_lock);		/* appends, and m_count */
static unsigned int m_count;		/* entries in m_log */
static unsigned int m_done;		/* entries extended (only the worker writes) */
static bool m_overflow;
static int m_last_rc;			/* last extend result, for the log header */
static unsigned int m_backoff = 1;	/* seconds until the next retry */
static u8 m_expect[SHA256_DIGEST_SIZE];	/* the PCR as our extends leave it */

static void ss_measure_work(struct work_struct *w);
static DECLARE_DELAYED_WORK(m_work, ss_measure_work);

/* Keep an event on one log line: printable ASCII, no spaces in NAME/VALUE. */
static void m_clean(char *s)
{
	for (; *s; s++)
		if (*s < 0x21 || *s > 0x7e)
			*s = '_';
}

static void m_append(const char *kind, const char *name, const char *value)
{
	struct ss_mentry *e;
	char n[48], v[SHA256_DIGEST_SIZE * 2 + 1];
	unsigned int i;
	size_t klen;

	strscpy(n, name ? name : "-", sizeof(n));
	strscpy(v, value ? value : "-", sizeof(v));
	m_clean(n);
	m_clean(v);
	if (!*v)
		strscpy(v, "-", sizeof(v));

	/* Small and must not be lost: a lost record would make the log lie. */
	e = kzalloc(sizeof(*e), GFP_KERNEL | __GFP_NOFAIL);
	snprintf(e->text, sizeof(e->text), "%s %s %s", kind, n, v);
	sha256((const u8 *)e->text, strlen(e->text), e->digest);

	mutex_lock(&m_lock);
	/* The same value written again changes nothing: keep the log short
	 * (load rewrites every list) without changing what it proves. */
	klen = strlen(kind) + strlen(n) + 2;
	for (i = m_count; i-- > 0;) {
		if (strncmp(m_log[i]->text, e->text, klen))
			continue;
		if (!strcmp(m_log[i]->text, e->text)) {
			mutex_unlock(&m_lock);
			kfree(e);
			return;
		}
		break;
	}
	if (m_count >= SS_MEASURE_MAX) {
		if (!m_overflow)
			pr_warn("measure: policy log full; measuring stopped\n");
		m_overflow = true;
		mutex_unlock(&m_lock);
		kfree(e);
		return;
	}
	m_log[m_count] = e;
	smp_store_release(&m_count, m_count + 1);
	mutex_unlock(&m_lock);
	mod_delayed_work(system_wq, &m_work, 0);
}

void ss_measure_knob(const char *name, const char *buf, size_t len)
{
	char v[SHA256_DIGEST_SIZE * 2 + 1];
	size_t n = min(len, sizeof(v) - 1);

	memcpy(v, buf, n);
	v[n] = '\0';
	m_append("knob", name, strim(v));
}

void ss_measure_list(const char *name, const void *text, size_t len)
{
	char hex[SHA256_DIGEST_SIZE * 2 + 1];

	ss_sha256_buf(text, len, hex);
	m_append("list", name, hex);
}

void ss_measure_lock(const char *why)
{
	m_append("lock", why, "1");
}

static void m_fill(struct tpm_chip *chip, struct tpm_digest *d, const u8 *dg)
{
	unsigned int i;

	for (i = 0; i < chip->nr_allocated_banks; i++) {
		u16 sz = chip->allocated_banks[i].digest_size;

		d[i].alg_id = chip->allocated_banks[i].alg_id;
		memset(d[i].digest, 0, sizeof(d[i].digest));
		memcpy(d[i].digest, dg, min_t(u16, sz, SHA256_DIGEST_SIZE));
	}
}

static void m_chain(const u8 *dg)
{
	u8 buf[2 * SHA256_DIGEST_SIZE];

	memcpy(buf, m_expect, SHA256_DIGEST_SIZE);
	memcpy(buf + SHA256_DIGEST_SIZE, dg, SHA256_DIGEST_SIZE);
	sha256(buf, sizeof(buf), m_expect);
}

/*
 * Before each extend, check the PCR still holds what our own events give.
 * If not, something else extended it (root through /dev/tpm*, before the
 * lock or through an allowed opener): record a "foreign" marker - extended
 * like any event, so it cannot be dropped from the log without breaking the
 * replay - and carry on from the value seen. The verifier fails on it.
 */
static int m_check_foreign(struct tpm_chip *chip, struct tpm_digest *d,
			   struct ss_mentry *e)
{
	struct tpm_digest cur = { .alg_id = TPM_ALG_SHA256 };
	char text[SS_MEASURE_TEXT];
	int rc;

	if (e->foreign)		/* already marked on an earlier try */
		return 0;
	rc = tpm_pcr_read(chip, SS_MEASURE_PCR, &cur);
	if (rc)
		return rc;
	if (!memcmp(cur.digest, m_expect, SHA256_DIGEST_SIZE))
		return 0;
	memcpy(e->seen, cur.digest, SHA256_DIGEST_SIZE);
	snprintf(text, sizeof(text), "foreign pcr %*phN", SHA256_DIGEST_SIZE,
		 e->seen);
	sha256((const u8 *)text, strlen(text), e->fdigest);
	m_fill(chip, d, e->fdigest);
	rc = tpm_pcr_extend(chip, SS_MEASURE_PCR, d);
	if (rc)
		return rc;
	memcpy(m_expect, e->seen, SHA256_DIGEST_SIZE);
	m_chain(e->fdigest);
	smp_store_release(&e->foreign, 1);
	pr_warn("measure: PCR %d was extended outside secure_sudo (before event %u)\n",
		SS_MEASURE_PCR, m_done);
	ss_event_typed("policy_measurement", "tpm_pcr", "check_pcr",
		       "policy_measurement_pcr", "alert", "foreign_extend",
		       "measure: PCR %d extended outside secure_sudo",
		       SS_MEASURE_PCR);
	return 0;
}

/* Extend each pending entry in order; retry later when the TPM is not up. */
static void ss_measure_work(struct work_struct *w)
{
	struct tpm_digest *d;
	struct tpm_chip *chip;
	unsigned int count;
	int rc = 0;

	count = smp_load_acquire(&m_count);
	if (m_done >= count)
		return;
	/* A built-in LSM cannot call into a modular TPM driver: with
	 * CONFIG_TCG_TPM=m nothing is extended (the header says tpm=-19) and
	 * the compiler drops the rest of this function. */
	if (!IS_BUILTIN(CONFIG_TCG_TPM)) {
		m_last_rc = -ENODEV;
		return;
	}
	chip = tpm_default_chip();
	if (!chip) {
		/* No TPM (yet): retry, backing off to once a minute. */
		m_last_rc = -ENODEV;
		mod_delayed_work(system_wq, &m_work, m_backoff * HZ);
		m_backoff = min(m_backoff * 2, 60U);
		return;
	}
	d = kcalloc(chip->nr_allocated_banks, sizeof(*d), GFP_KERNEL);
	if (!d) {
		put_device(&chip->dev);
		mod_delayed_work(system_wq, &m_work, HZ);
		return;
	}
	while (m_done < count) {
		struct ss_mentry *e = m_log[m_done];

		rc = m_check_foreign(chip, d, e);
		if (rc)
			break;
		m_fill(chip, d, e->digest);
		rc = tpm_pcr_extend(chip, SS_MEASURE_PCR, d);
		if (rc)
			break;
		m_chain(e->digest);
		smp_store_release(&m_done, m_done + 1);
		count = smp_load_acquire(&m_count);
	}
	m_last_rc = rc;
	kfree(d);
	put_device(&chip->dev);
	if (rc) {
		pr_warn_ratelimited("measure: PCR %d extend failed (%d); retrying\n",
				    SS_MEASURE_PCR, rc);
		mod_delayed_work(system_wq, &m_work, m_backoff * HZ);
		m_backoff = min(m_backoff * 2, 60U);
	} else {
		m_backoff = 1;
	}
}

/* ------------------------------ policy_log ------------------------------- */

static void *pl_start(struct seq_file *m, loff_t *pos)
{
	unsigned int count = smp_load_acquire(&m_count);

	if (*pos == 0)
		return SEQ_START_TOKEN;
	/* entry *pos - 1, as *pos + 1: never SEQ_START_TOKEN ((void *)1) */
	return (*pos - 1 < count) ? (void *)(uintptr_t)(*pos + 1) : NULL;
}

static void *pl_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return pl_start(m, pos);
}

static void pl_stop(struct seq_file *m, void *v) { }

static int pl_show(struct seq_file *m, void *v)
{
	unsigned int i;

	if (v == SEQ_START_TOKEN) {
		seq_printf(m, "secure_sudo-policy-log v1 pcr=%d count=%u extended=%u overflow=%d tpm=%d\n",
			   SS_MEASURE_PCR, smp_load_acquire(&m_count),
			   smp_load_acquire(&m_done), READ_ONCE(m_overflow) ? 1 : 0,
			   READ_ONCE(m_last_rc));
		return 0;
	}
	i = (unsigned int)(uintptr_t)v - 2;
	if (smp_load_acquire(&m_log[i]->foreign))
		seq_printf(m, "%uF 1 %*phN foreign pcr %*phN\n", i,
			   SHA256_DIGEST_SIZE, m_log[i]->fdigest,
			   SHA256_DIGEST_SIZE, m_log[i]->seen);
	seq_printf(m, "%u %d %*phN %s\n", i, i < smp_load_acquire(&m_done) ? 1 : 0,
		   SHA256_DIGEST_SIZE, m_log[i]->digest, m_log[i]->text);
	return 0;
}

static const struct seq_operations pl_sops = {
	.start = pl_start, .next = pl_next, .stop = pl_stop, .show = pl_show,
};

static int pl_open(struct inode *inode, struct file *file)
{
	if (!ss_may_admin(file))
		return -EPERM;
	return seq_open(file, &pl_sops);
}

static const struct file_operations pl_fops = {
	.open = pl_open, .read = seq_read, .llseek = seq_lseek,
	.release = seq_release,
};

int ss_measure_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("policy_log", 0400, dir, NULL, &pl_fops);
	return IS_ERR(d) ? PTR_ERR(d) : 0;
}
