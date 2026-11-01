// SPDX-License-Identifier: GPL-2.0
/*
 * ss_tpm.c - Protection #5: block clearing the TPM.
 *
 * The attack is a one-liner:
 *     echo 5 | sudo tee /sys/class/tpm/tpm0/ppi/request
 * which schedules a Physical Presence Interface "clear TPM" at the next boot,
 * wiping TPM-sealed keys (disk-encryption keys, measured-boot state).
 * (secure_sudo's own OTP master key is TPM-sealed when there is a TPM, see
 * userspace/otp/secure-sudo-otp.c.) Because it is
 * destructive even for a legitimate admin who fat-fingers it, this block
 * applies to *everyone, root included* - it is not gated on sudo. The only
 * way to allow it is to boot with
 *
 *     secure_sudo.tpm_maint=1
 *
 * i.e. you must deliberately reboot into a maintenance window to clear the TPM.
 *
 * Matching is on the resolved file: the write target's path ends in
 * "/ppi/request" and sits under a TPM device. /sys/class/tpm/tpm0 is a symlink
 * into /sys/devices, so we match on the resolved d_path rather than the class
 * path.
 *
 * The other route (gap G4) is TPM2_Clear sent straight to the chip through
 * /dev/tpm0 or /dev/tpmrm0. An LSM cannot see the command bytes, so once the
 * config lock (#16) is engaged only the programs on tpm_openers may open a
 * TPM character device at all: systemd-creds, the systemd TPM helpers,
 * cryptsetup and tpm2-abrmd by default. root running tpm2_clear (or any
 * other program) is refused. The device is matched by its device number,
 * not its name, so a node made elsewhere with mknod is caught too; that
 * needs CONFIG_TCG_TPM=y (install.sh builds it in) to know the TPM major,
 * otherwise only /dev/tpm0 (misc 10:224) is guarded. The second half of G4
 * lives in the installer: it sets a TPM lockout password, so TPM2_Clear
 * with lockout authorization needs a secret root does not hold. The same
 * tpm_maint boot lifts this guard.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/magic.h>
#include <linux/moduleparam.h>
#include <linux/lsm_hooks.h>
#include <linux/kdev_t.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/sched/mm.h>
#include <linux/sort.h>
#include <linux/bsearch.h>
#include <linux/security.h>
#include <linux/uaccess.h>

#include "secure_sudo.h"

#if IS_BUILTIN(CONFIG_TCG_TPM)
/* drivers/char/tpm/tpm-chip.c: the region tpm1.. and every tpmrmN live in */
extern dev_t tpm_devt;
#endif
#define SS_TPM_MINOR	224		/* /dev/tpm0 is misc 10:224 (TPM_MINOR) */

/* Read-only boot parameter: secure_sudo.tpm_maint=1 permits TPM clear. */
static bool tpm_maint;
module_param(tpm_maint, bool, 0444);
MODULE_PARM_DESC(tpm_maint,
		 "secure_sudo: allow writes to TPM ppi/request (TPM clear). Boot-time only.");

static bool is_tpm_ppi_request(const char *p)
{
	size_t len = strlen(p);
	static const char suffix[] = "/ppi/request";
	size_t slen = sizeof(suffix) - 1;

	if (len < slen || strcmp(p + len - slen, suffix) != 0)
		return false;
	/* Must actually be a TPM node, not some unrelated ppi/request. */
	return strstr(p, "/tpm") != NULL;
}

/* ------------------- G4: who may open /dev/tpm* when locked -------------- */

#define TO_MAX_ITEMS	64
#define TO_MAX_TEXT	(16 * 1024)

static const char to_default[] =
	"/usr/bin/systemd-creds\n"
	"/usr/bin/systemd-cryptenroll\n"
	"/usr/lib/systemd/systemd-cryptsetup\n"
	"/usr/lib/systemd/systemd-pcrextend\n"
	"/usr/lib/systemd/systemd-pcrlock\n"
	"/usr/lib/systemd/systemd-tpm2-setup\n"
	"/usr/lib/systemd/systemd-measure\n"
	"/usr/sbin/tpm2-abrmd\n"
	"/usr/libexec/secure-sudo/secure-sudo-attest\n";

static DEFINE_MUTEX(to_lock);
static char **to_list;
static int to_count;
static char *to_text;
static size_t to_text_len;

static int to_cmp(const void *a, const void *b)
{
	return strcmp(*(const char * const *)a, *(const char * const *)b);
}

static int to_key_cmp(const void *key, const void *elt)
{
	return strcmp(key, *(const char * const *)elt);
}

static void to_free(char **list, int count)
{
	int i;

	if (!list)
		return;
	for (i = 0; i < count; i++)
		kfree(list[i]);
	kfree(list);
}

static char **to_parse(char *text, int *out_count)
{
	char **list, *p = text, *line;
	int n = 0;

	list = kcalloc(TO_MAX_ITEMS, sizeof(*list), GFP_KERNEL);
	if (!list)
		return NULL;
	while ((line = strsep(&p, "\n")) && n < TO_MAX_ITEMS) {
		line = strim(line);
		if (*line != '/')
			continue;		/* comments, blanks: absolute paths only */
		list[n] = kstrdup(line, GFP_KERNEL);
		if (!list[n]) {
			to_free(list, n);
			return NULL;
		}
		n++;
	}
	sort(list, n, sizeof(*list), to_cmp, NULL);
	*out_count = n;
	return list;
}

/* Install @text (count bytes, NUL-terminated, now owned here) as the list. */
static int to_set(char *text, size_t count)
{
	char *scratch, **new_list, **old_list, *old_text;
	int new_count, old_count;

	scratch = kmemdup(text, count + 1, GFP_KERNEL);
	if (!scratch) {
		kfree(text);
		return -ENOMEM;
	}
	new_list = to_parse(scratch, &new_count);
	kfree(scratch);
	if (!new_list) {
		kfree(text);
		return -ENOMEM;
	}
	mutex_lock(&to_lock);
	old_list = to_list;
	old_count = to_count;
	old_text = to_text;
	to_list = new_list;
	to_count = new_count;
	to_text = text;
	to_text_len = count;
	mutex_unlock(&to_lock);
	to_free(old_list, old_count);
	kfree(old_text);
	return 0;
}

static bool is_tpm_chardev(const struct inode *inode)
{
	dev_t d = inode->i_rdev;

	if (!S_ISCHR(inode->i_mode))
		return false;
	if (MAJOR(d) == MISC_MAJOR && MINOR(d) == SS_TPM_MINOR)
		return true;
#if IS_BUILTIN(CONFIG_TCG_TPM)
	if (tpm_devt && MAJOR(d) == MAJOR(tpm_devt))
		return true;
#endif
	return false;
}

/*
 * May the current process open a TPM device? Its main executable must be on
 * tpm_openers, owned by root and not group/world-writable (a listed path
 * someone could overwrite is no allowlist). Fails closed.
 */
static bool tpm_opener_allowed(char *buf, char **who)
{
	struct mm_struct *mm = current->mm;
	struct file *exe;
	struct inode *inode;
	char *p;
	bool hit = false;

	*who = "?";
	if (!mm)
		return true;		/* kernel threads (in-kernel TPM users) */
	exe = get_mm_exe_file(mm);
	if (!exe)
		return false;
	p = ss_file_path(&exe->f_path, buf, PATH_MAX);
	inode = file_inode(exe);
	if (!IS_ERR(p)) {
		*who = p;
		mutex_lock(&to_lock);
		hit = to_count && bsearch(p, to_list, to_count, sizeof(*to_list),
					  to_key_cmp);
		mutex_unlock(&to_lock);
		if (hit && (!uid_eq(inode->i_uid, GLOBAL_ROOT_UID) ||
			    (inode->i_mode & (S_IWGRP | S_IWOTH))))
			hit = false;
	}
	fput(exe);
	return hit;
}

static int tpm_dev_open(struct file *file)
{
	char *buf, *who;
	int ret = 0;

	if (!ss_locked())
		return 0;		/* unlocked: root can change everything anyway */
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;		/* fail closed */
	if (!tpm_opener_allowed(buf, &who)) {
		pr_warn_ratelimited("blocked TPM device open by %s (UID %u): not on tpm_openers\n",
				    who, from_kuid(&init_user_ns, current_uid()));
		ss_event_typed_self("tpm_guard", "current_process", "open",
				    "tpm_device", "deny", "tpm_opener_not_allowed",
				    "tpm: denied TPM device open by %s (UID %u)", who,
				    from_kuid(&init_user_ns, current_uid()));
		ret = -EPERM;
	}
	kfree(buf);
	return ret;
}

int ss_tpm_file_open(struct file *file)
{
	unsigned long magic = file_inode(file)->i_sb->s_magic;
	char *buf, *p;
	int ret = 0;

	if (tpm_maint)
		return 0;			/* maintenance boot: allow */
	if (is_tpm_chardev(file_inode(file)))
		return tpm_dev_open(file);
	if (!(file->f_mode & FMODE_WRITE))
		return 0;			/* only writes clear the TPM */
	if (magic != SYSFS_MAGIC)
		return 0;			/* ppi/request lives in sysfs */

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return 0;

	p = ss_file_path(&file->f_path, buf, PATH_MAX);
	if (!IS_ERR(p) && is_tpm_ppi_request(p)) {
		pr_warn_ratelimited("blocked TPM ppi/request write %s (boot with secure_sudo.tpm_maint=1 to allow)\n",
				    p);
		ss_event_typed_self("tpm_guard", "current_process", "write", p,
				    "deny", "tpm_clear_request",
				    "tpm: denied ppi/request write %s by UID %u", p,
				    from_kuid(&init_user_ns, current_uid()));
		ret = -EPERM;
	}

	kfree(buf);
	return ret;
}

/* ---------------------- securityfs: tpm_openers -------------------------- */

static ssize_t to_read(struct file *file, char __user *ubuf, size_t count,
		       loff_t *ppos)
{
	ssize_t ret;

	mutex_lock(&to_lock);
	ret = simple_read_from_buffer(ubuf, count, ppos, to_text ? to_text : "",
				      to_text_len);
	mutex_unlock(&to_lock);
	return ret;
}

static ssize_t to_write(struct file *file, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	char *text;
	int rc;

	if (!ss_may_admin(file))
		return -EPERM;
	if (ss_locked())
		return -EPERM;		/* the list is what the lock relies on */
	if (*ppos != 0)
		return -EINVAL;
	if (count == 0)
		return 0;
	if (count > TO_MAX_TEXT)
		return -EFBIG;
	text = kmalloc(count + 1, GFP_KERNEL);
	if (!text)
		return -ENOMEM;
	if (copy_from_user(text, ubuf, count)) {
		kfree(text);
		return -EFAULT;
	}
	text[count] = '\0';
	rc = to_set(text, count);
	if (rc)
		return rc;
	*ppos = count;
	return count;
}

static const struct file_operations to_fops = {
	.read   = to_read,
	.write  = to_write,
	.llseek = default_llseek,
};

int ss_tpm_secfs(struct dentry *dir)
{
	struct dentry *d;
	char *text = kmemdup(to_default, sizeof(to_default), GFP_KERNEL);
	int rc;

	if (!text)
		return -ENOMEM;
	rc = to_set(text, sizeof(to_default) - 1);	/* the defaults until load */
	if (rc)
		return rc;
#if !IS_BUILTIN(CONFIG_TCG_TPM)
	pr_info("tpm_openers guards /dev/tpm0 only: build CONFIG_TCG_TPM=y to guard every TPM device\n");
#endif
	d = securityfs_create_file("tpm_openers", 0600, dir, NULL, &to_fops);
	return IS_ERR(d) ? PTR_ERR(d) : 0;
}
