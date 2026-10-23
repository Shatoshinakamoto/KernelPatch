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
 *   - mprotect(PROT_EXEC) of a file mapping under them (file_mprotect)
 *
 * mmap coverage matters: without it an interpreter (or "ld.so /tmp/x") could
 * mmap+jump into a payload it never execve'd, and without the mprotect hook a
 * PROT_READ mapping could simply be flipped to PROT_EXEC afterwards.
 *
 * With block_tmpfs_exec the same rule extends to every tmpfs/ramfs mount
 * (/run/user/<uid>, ad-hoc tmpfs mounts) and to memfd files, which closes the
 * "fileless" memfd_create()+fexecve() technique. PROT_EXEC *mmap* of a memfd
 * stays allowed so JITs that double-map a memfd keep working; exec'ing one
 * does not.
 *
 * Decisions fail closed: a path that cannot be resolved (for example one made
 * longer than PATH_MAX on purpose) is denied, not waved through.
 *
 * Specific paths can be exempted via
 * /sys/kernel/security/secure_sudo/tmp_exec_allow. Entries match on a path
 * component boundary: "/tmp/build" covers /tmp/build and /tmp/build/..., but
 * not /tmp/buildevil.
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
#include <linux/magic.h>
#include <linux/mm.h>
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

static bool on_tmpfs(const struct path *path)
{
	unsigned long m = path->dentry->d_sb->s_magic;

	return m == TMPFS_MAGIC || m == RAMFS_MAGIC;
}

/* memfd_create() files: unlinked shmem/hugetlbfs dentries named "memfd:..." */
static bool is_memfd(const struct path *path)
{
	unsigned long m = path->dentry->d_sb->s_magic;

	return (m == TMPFS_MAGIC || m == HUGETLBFS_MAGIC) &&
	       !strncmp(path->dentry->d_name.name, "memfd:", 6);
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
		if (ss_path_under(p, allow_list[i])) {
			ok = true;
			break;
		}
	}
	mutex_unlock(&allow_lock);
	return ok;
}

/* Common decision for every hook. @is_mmap relaxes the memfd case only. */
static int tmp_check(const struct path *path, const char *what, bool is_mmap)
{
	bool tmpfs_rule = READ_ONCE(ss_cfg.block_tmpfs_exec);
	char *buf, *p;
	int ret = 0;

	/* Step 1: feature off -> allow. */
	if (!READ_ONCE(ss_cfg.block_tmp_exec))
		return 0;
	/* Step 2: sudo users are unrestricted. */
	if (ss_is_sudo_user())
		return 0;
	/* Step 3: a PROT_EXEC *mapping* of a memfd is how legitimate JITs run
	 * generated code, so exempt it - but only for mmap/mprotect, never for an
	 * actual exec() of a memfd (is_mmap is false there, so a fileless
	 * memfd-exec still falls through to the checks below and is blocked). */
	if (is_mmap && is_memfd(path))
		return 0;

	/* Step 4: resolve the target path (chroot-safe). */
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;			/* fail closed: no memory -> deny */
	p = ss_file_path(path, buf, PATH_MAX);
	if (IS_ERR(p)) {
		ret = -EPERM;			/* fail closed: unresolvable -> deny */
		p = "(unresolvable path)";
	} else if ((under_tmp_tree(p) ||		/* in /tmp,/var/tmp,/dev/shm */
		    (tmpfs_rule && on_tmpfs(path))) &&	/* or any tmpfs, if strict */
		   !path_allowed(p)) {			/* and not on the allowlist */
		ret = -EPERM;			/* deny exec from a scratch tree */
	}

	if (ret)
		pr_warn_ratelimited("non-sudo UID %u denied %s from scratch tree: %s\n",
				    from_kuid(&init_user_ns, current_uid()),
				    what, p);
	kfree(buf);
	return ret;
}

static int ss_tmp_bprm(struct linux_binprm *bprm)
{
	return tmp_check(&bprm->file->f_path, "exec", false);
}

static int ss_tmp_mmap(struct file *file, unsigned long reqprot,
		       unsigned long prot, unsigned long flags)
{
	if (!file)
		return 0;		/* anonymous mapping */
	if (!(prot & PROT_EXEC))
		return 0;
	return tmp_check(&file->f_path, "PROT_EXEC mmap", true);
}

static int ss_tmp_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
			   unsigned long prot)
{
	if (!vma->vm_file || !(prot & PROT_EXEC) || (vma->vm_flags & VM_EXEC))
		return 0;
	return tmp_check(&vma->vm_file->f_path, "mprotect(PROT_EXEC)", true);
}

static struct security_hook_list ss_tmp_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, ss_tmp_bprm),
	LSM_HOOK_INIT(mmap_file,           ss_tmp_mmap),
	LSM_HOOK_INIT(file_mprotect,       ss_tmp_mprotect),
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

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	WRITE_ONCE(ss_cfg.block_tmp_exec, v);
	return count;
}
static struct kobj_attribute block_tmp_exec_attr =
	__ATTR(block_tmp_exec, 0600, block_tmp_exec_show, block_tmp_exec_store);

static ssize_t block_tmpfs_exec_show(struct kobject *k, struct kobj_attribute *a,
				     char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.block_tmpfs_exec));
}
static ssize_t block_tmpfs_exec_store(struct kobject *k,
				      struct kobj_attribute *a,
				      const char *buf, size_t count)
{
	bool v;

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	WRITE_ONCE(ss_cfg.block_tmpfs_exec, v);
	return count;
}
static struct kobj_attribute block_tmpfs_exec_attr =
	__ATTR(block_tmpfs_exec, 0600, block_tmpfs_exec_show,
	       block_tmpfs_exec_store);

static struct attribute *ss_tmp_attrs[] = {
	&block_tmp_exec_attr.attr,
	&block_tmpfs_exec_attr.attr,
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

	if (!ss_may_admin(file))
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
