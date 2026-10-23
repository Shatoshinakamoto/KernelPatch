// SPDX-License-Identifier: GPL-2.0
/*
 * ss_exec.c - Protection #2: command blacklist for non-sudo users.
 *
 * v1 parsed /etc/secure_sudo/blacklist.conf inside the kernel and matched by
 * basename, with a read loop that truncated the file at one page. v2's exec
 * hook left the blacklist loop body empty. This merge keeps the kernel as the
 * enforcement point but moves the policy in from userspace through securityfs,
 * and matches by (device, inode) and canonical path instead of basename:
 *
 *   - inode match  catches renaming the blacklisted binary (same inode).
 *   - path  match  catches dropping a different binary at the blacklisted path.
 *
 * (A copy to a fresh path is a new inode at a new name and is out of scope
 * here - that is what the hash-based driver blacklist and TimeVault are for.)
 *
 * The root-only CLI writes the resolved absolute paths, newline-separated, to
 * /sys/kernel/security/secure_sudo/blacklist. Each write replaces the list.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/namei.h>
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

#define SS_BL_MAX_ENTRIES   1024
#define SS_BL_MAX_TEXT      (256 * 1024)	/* 256 KiB of policy text */

struct bl_entry {
	dev_t		dev;	/* 0 if the path did not resolve at load time */
	unsigned long	ino;	/* 0 if the path did not resolve at load time */
	u32		gen;	/* i_generation: guards against inode reuse */
	char		*path;	/* canonical path string as configured */
};

/* Protects bl_list/bl_count and bl_text/bl_text_len below. */
static DEFINE_MUTEX(bl_lock);
static struct bl_entry *bl_list;
static int bl_count;
/* Normalised text, kept verbatim so reads of the securityfs file echo policy. */
static char *bl_text;
static size_t bl_text_len;

static void bl_free_list(struct bl_entry *list, int count)
{
	int i;

	if (!list)
		return;
	for (i = 0; i < count; i++)
		kfree(list[i].path);
	kfree(list);
}

/*
 * Parse newline-separated absolute paths into a fresh bl_entry array,
 * resolving each to (dev, ino) where possible. Returns the array (caller owns
 * it) and sets *out_count, or NULL on allocation failure.
 */
static struct bl_entry *bl_parse(char *text, int *out_count)
{
	struct bl_entry *list;
	char *p = text, *line;
	int n = 0;

	list = kcalloc(SS_BL_MAX_ENTRIES, sizeof(*list), GFP_KERNEL);
	if (!list)
		return NULL;

	while ((line = strsep(&p, "\n")) && n < SS_BL_MAX_ENTRIES) {
		struct path path;

		line = strim(line);
		if (*line == '\0' || *line == '#')
			continue;
		if (*line != '/') {
			pr_warn_ratelimited("blacklist: ignoring non-absolute entry \"%s\"\n",
					    line);
			continue;
		}

		list[n].path = kstrdup(line, GFP_KERNEL);
		if (!list[n].path) {
			bl_free_list(list, n);
			return NULL;
		}

		/* Resolve to dev/ino so a later rename is still caught. A path
		 * that does not exist yet is kept path-only (dev/ino stay 0). */
		if (kern_path(line, LOOKUP_FOLLOW, &path) == 0) {
			struct inode *inode = d_backing_inode(path.dentry);

			if (inode) {
				list[n].dev = inode->i_sb->s_dev;
				list[n].ino = inode->i_ino;
				list[n].gen = inode->i_generation;
			}
			path_put(&path);
		}
		n++;
	}

	*out_count = n;
	return list;
}

/* ---------------------------- enforcement -------------------------------- */

static int ss_bprm_check_security(struct linux_binprm *bprm)
{
	struct inode *inode;
	dev_t dev;
	unsigned long ino;
	u32 gen;
	char *buf, *exec_path;
	int i, ret = 0;

	/* Sudo users may run anything. */
	if (ss_is_sudo_user())
		return 0;

	/* Fast path: nothing configured. */
	if (!READ_ONCE(bl_count))
		return 0;

	inode = file_inode(bprm->file);
	dev = inode->i_sb->s_dev;
	ino = inode->i_ino;

	/*
	 * Fail closed: if the path cannot be built (OOM, or a deliberately
	 * over-long path, which d_path rejects with -ENAMETOOLONG) a non-sudo
	 * exec is refused rather than slipping past the path match.
	 */
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	exec_path = ss_file_path(&bprm->file->f_path, buf, PATH_MAX);
	if (IS_ERR(exec_path)) {
		kfree(buf);
		pr_warn_ratelimited("non-sudo UID %u exec denied: path unresolvable\n",
				    from_kuid(&init_user_ns, current_uid()));
		return -EPERM;
	}
	/* An unlinked file has no path any more; only the inode match applies. */
	if (d_unlinked(bprm->file->f_path.dentry))
		exec_path = NULL;

	mutex_lock(&bl_lock);
	for (i = 0; i < bl_count; i++) {
		bool inode_hit = bl_list[i].ino &&
				 bl_list[i].dev == dev &&
				 bl_list[i].ino == ino &&
				 bl_list[i].gen == gen;
		bool path_hit = exec_path &&
				!strcmp(exec_path, bl_list[i].path);

		if (inode_hit || path_hit) {
			pr_warn_ratelimited("non-sudo UID %u denied blacklisted exec %s\n",
					    from_kuid(&init_user_ns,
						      current_uid()),
					    bl_list[i].path);
			ret = -EPERM;
			break;
		}
	}
	mutex_unlock(&bl_lock);

	kfree(buf);
	return ret;
}

static struct security_hook_list ss_exec_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, ss_bprm_check_security),
};

void __init ss_exec_init(void)
{
	security_add_hooks(ss_exec_hooks, ARRAY_SIZE(ss_exec_hooks),
			   &ss_lsmid);
}

/* ------------------------- securityfs: blacklist ------------------------- */

static ssize_t bl_file_read(struct file *file, char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	ssize_t ret;

	mutex_lock(&bl_lock);
	ret = simple_read_from_buffer(ubuf, count, ppos,
				      bl_text ? bl_text : "", bl_text_len);
	mutex_unlock(&bl_lock);
	return ret;
}

static ssize_t bl_file_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	char *text;
	struct bl_entry *new_list, *old_list;
	int new_count, old_count;
	size_t old_text_len;
	char *old_text;

	if (!ss_may_admin(file))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (*ppos != 0)			/* whole-file replacement only */
		return -EINVAL;
	if (count == 0)
		return 0;
	if (count > SS_BL_MAX_TEXT)
		return -EFBIG;

	text = kmalloc(count + 1, GFP_KERNEL);
	if (!text)
		return -ENOMEM;
	if (copy_from_user(text, ubuf, count)) {
		kfree(text);
		return -EFAULT;
	}
	text[count] = '\0';

	/* bl_parse() consumes a mutable copy; keep the verbatim text for reads. */
	{
		char *scratch = kmemdup(text, count + 1, GFP_KERNEL);

		if (!scratch) {
			kfree(text);
			return -ENOMEM;
		}
		new_list = bl_parse(scratch, &new_count);
		kfree(scratch);
	}
	if (!new_list) {
		kfree(text);
		return -ENOMEM;
	}

	mutex_lock(&bl_lock);
	old_list = bl_list;
	old_count = bl_count;
	old_text = bl_text;
	old_text_len = bl_text_len;

	bl_list = new_list;
	WRITE_ONCE(bl_count, new_count);
	bl_text = text;
	bl_text_len = count;
	mutex_unlock(&bl_lock);

	bl_free_list(old_list, old_count);
	kfree(old_text);
	(void)old_text_len;

	pr_info("blacklist: loaded %d entries\n", new_count);
	*ppos = count;
	return count;
}

static const struct file_operations bl_fops = {
	.read  = bl_file_read,
	.write = bl_file_write,
	.llseek = default_llseek,
};

int ss_exec_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("blacklist", 0600, dir, NULL, &bl_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
	return 0;
}
