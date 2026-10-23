// SPDX-License-Identifier: GPL-2.0
/*
 * ss_tmpexec.c - Protection #12: stop non-sudo users executing code out of the
 * world-writable scratch trees.
 *
 * Dropper malware (and the "unbundle a binary into /tmp and run it" trick that
 * single-file Node/pkg apps use) stages payloads in /tmp, /var/tmp or
 * /dev/shm. This denies, for non-sudo users:
 *
 *   - execve of any file under those trees            (bprm_check_security)
 *   - PROT_EXEC mmap of any file under those trees     (mmap_file)
 *
 * mmap coverage matters: without it an interpreter could mmap+jump into a
 * payload it never execve'd. Specific paths can be exempted by writing them to
 * /sys/kernel/security/secure_sudo/tmp_exec_allow (prefix match, so a single
 * trusted directory or file is enough).
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

#define SS_TMP_MAX_ALLOW	256
#define SS_TMP_MAX_TEXT		(64 * 1024)

/* The world-writable trees we police. Trailing slash so "/tmpfoo" is not a
 * false positive but everything genuinely inside /tmp/ is caught. */
static const char *const tmp_trees[] = {
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
};

static bool under_tmp_tree(const char *p)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(tmp_trees); i++)
		if (str_has_prefix(p, tmp_trees[i]))
			return true;
	return false;
}

/* ---- allowlist (prefix match) ---- */
static DEFINE_MUTEX(allow_lock);
static char **allow_list;
static int allow_count;
static char *allow_text;
static size_t allow_text_len;

static bool path_allowed(const char *p)
{
	int i;
	bool ok = false;

	mutex_lock(&allow_lock);
	for (i = 0; i < allow_count; i++) {
		if (str_has_prefix(p, allow_list[i])) {
			ok = true;
			break;
		}
	}
	mutex_unlock(&allow_lock);
	return ok;
}

/* Resolve @path to a buffer the caller must kfree(); returns NULL on error. */
static char *resolve(const struct path *path, char **out_free)
{
	char *buf, *p;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return NULL;
	p = d_path(path, buf, PATH_MAX);
	if (IS_ERR(p)) {
		kfree(buf);
		return NULL;
	}
	*out_free = buf;
	return p;
}

/* Common decision for both hooks. */
static int tmp_check(const struct path *path, const char *what)
{
	char *buf = NULL, *p;
	int ret = 0;

	if (!READ_ONCE(ss_cfg.block_tmp_exec))
		return 0;
	if (ss_is_sudo_user())
		return 0;

	p = resolve(path, &buf);
	if (!p)
		return 0;		/* fail open on resolution failure */

	if (under_tmp_tree(p) && !path_allowed(p)) {
		pr_warn_ratelimited("non-sudo UID %u denied %s from scratch tree: %s\n",
				    from_kuid(&init_user_ns, current_uid()),
				    what, p);
		ret = -EPERM;
	}

	kfree(buf);
	return ret;
}

static int ss_tmp_bprm(struct linux_binprm *bprm)
{
	return tmp_check(&bprm->file->f_path, "exec");
}

static int ss_tmp_mmap(struct file *file, unsigned long reqprot,
		       unsigned long prot, unsigned long flags)
{
	if (!file)
		return 0;		/* anonymous mapping */
	if (!(prot & PROT_EXEC))
		return 0;
	return tmp_check(&file->f_path, "PROT_EXEC mmap");
}

static struct security_hook_list ss_tmp_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, ss_tmp_bprm),
	LSM_HOOK_INIT(mmap_file,           ss_tmp_mmap),
};

void __init ss_tmpexec_init(void)
{
	security_add_hooks(ss_tmp_hooks, ARRAY_SIZE(ss_tmp_hooks), &ss_lsmid);
}

/* ---------------------------- sysfs knob --------------------------------- */

static ssize_t block_tmp_exec_show(struct kobject *k, struct kobj_attribute *a,
				   char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.block_tmp_exec));
}
static ssize_t block_tmp_exec_store(struct kobject *k, struct kobj_attribute *a,
				    const char *buf, size_t count)
{
	bool v;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	WRITE_ONCE(ss_cfg.block_tmp_exec, v);
	return count;
}
static struct kobj_attribute block_tmp_exec_attr =
	__ATTR(block_tmp_exec, 0644, block_tmp_exec_show, block_tmp_exec_store);

static struct attribute *ss_tmp_attrs[] = {
	&block_tmp_exec_attr.attr,
	NULL,
};
static const struct attribute_group ss_tmp_group = {
	.attrs = ss_tmp_attrs,
};

int ss_tmpexec_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_tmp_group);
}

/* ------------------------ securityfs: allowlist -------------------------- */

static void free_allow(char **list, int count)
{
	int i;

	if (!list)
		return;
	for (i = 0; i < count; i++)
		kfree(list[i]);
	kfree(list);
}

static char **parse_allow(char *text, int *out_count)
{
	char **list;
	char *p = text, *line;
	int n = 0;

	list = kcalloc(SS_TMP_MAX_ALLOW, sizeof(*list), GFP_KERNEL);
	if (!list)
		return NULL;

	while ((line = strsep(&p, "\n")) && n < SS_TMP_MAX_ALLOW) {
		line = strim(line);
		if (*line == '\0' || *line == '#' || *line != '/')
			continue;
		list[n] = kstrdup(line, GFP_KERNEL);
		if (!list[n]) {
			free_allow(list, n);
			return NULL;
		}
		n++;
	}
	*out_count = n;
	return list;
}

static ssize_t allow_read(struct file *file, char __user *ubuf, size_t count,
			  loff_t *ppos)
{
	ssize_t ret;

	mutex_lock(&allow_lock);
	ret = simple_read_from_buffer(ubuf, count, ppos,
				      allow_text ? allow_text : "",
				      allow_text_len);
	mutex_unlock(&allow_lock);
	return ret;
}

static ssize_t allow_write(struct file *file, const char __user *ubuf,
			   size_t count, loff_t *ppos)
{
	char *text, *scratch, **new_list, **old_list, *old_text;
	int new_count, old_count;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (*ppos != 0)
		return -EINVAL;
	if (count == 0)
		return 0;
	if (count > SS_TMP_MAX_TEXT)
		return -EFBIG;

	text = kmalloc(count + 1, GFP_KERNEL);
	if (!text)
		return -ENOMEM;
	if (copy_from_user(text, ubuf, count)) {
		kfree(text);
		return -EFAULT;
	}
	text[count] = '\0';

	scratch = kmemdup(text, count + 1, GFP_KERNEL);
	if (!scratch) {
		kfree(text);
		return -ENOMEM;
	}
	new_list = parse_allow(scratch, &new_count);
	kfree(scratch);
	if (!new_list) {
		kfree(text);
		return -ENOMEM;
	}

	mutex_lock(&allow_lock);
	old_list = allow_list;
	old_count = allow_count;
	old_text = allow_text;
	allow_list = new_list;
	allow_count = new_count;
	allow_text = text;
	allow_text_len = count;
	mutex_unlock(&allow_lock);

	free_allow(old_list, old_count);
	kfree(old_text);

	*ppos = count;
	return count;
}

static const struct file_operations allow_fops = {
	.read   = allow_read,
	.write  = allow_write,
	.llseek = default_llseek,
};

int ss_tmpexec_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("tmp_exec_allow", 0600, dir, NULL,
				   &allow_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
	return 0;
}
