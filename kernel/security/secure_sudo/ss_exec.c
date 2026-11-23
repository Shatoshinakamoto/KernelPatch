// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * ss_exec.c - Protection #2: command blacklist for non-sudo users.
 *
 * v1 parsed /etc/secure_sudo/blacklist.conf inside the kernel and matched by
 * basename, with a read loop that truncated the file at one page. v2's exec
 * hook left the blacklist loop body empty. This merge keeps the kernel as the
 * enforcement point but moves the policy in from userspace through securityfs,
 * and matches by (device, inode) and canonical path instead of basename:
 *
 *   - inode match    catches renaming the blacklisted binary (same inode).
 *   - path  match    catches dropping a different binary at the blacklisted
 *                    path.
 *   - content match  catches a copy at a new path (a new inode at a new
 *                    name): each entry's SHA-256 and size are taken when the
 *                    list is loaded, and an exec whose file has the same size
 *                    is hashed and compared. Only same-size files are hashed,
 *                    so ordinary execs pay nothing. A copy that was changed
 *                    (even by one byte) is a different program and is not
 *                    matched; TimeVault (#13) is the allowlist for that.
 *
 * The root-only CLI writes the resolved absolute paths, newline-separated, to
 * /sys/kernel/security/secure_sudo/blacklist. Each write replaces the list.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/file.h>
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
#define SS_BL_HEX           64		/* SHA-256 as lowercase hex */
#define SS_BL_MAX_TEXT      (256 * 1024)	/* 256 KiB of policy text */

struct bl_entry {
	dev_t		dev;	/* 0 if the path did not resolve at load time */
	unsigned long	ino;	/* 0 if the path did not resolve at load time */
	u32		gen;	/* i_generation: guards against inode reuse */
	char		*path;	/* canonical path string as configured */
	loff_t		size;	/* content match: file size at load time */
	bool		hashed;	/* content match: hash below is valid */
	char		hash[SS_BL_HEX + 1];
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
			/* Content match: fingerprint the program as it is now,
			 * so a copy at another path is caught too. */
			if (inode && S_ISREG(inode->i_mode)) {
				struct file *f = dentry_open(&path, O_RDONLY,
							     current_cred());

				if (!IS_ERR(f)) {
					list[n].size = i_size_read(file_inode(f));
					list[n].hashed =
						ss_sha256_file(f, list[n].hash) == 0;
					fput(f);
				}
			}
			path_put(&path);
		}
		n++;
	}

	*out_count = n;
	return list;
}

/* ---------------------------- enforcement -------------------------------- */

int ss_exec_bprm(struct linux_binprm *bprm)
{
	struct inode *inode;
	dev_t dev;
	unsigned long ino;
	u32 gen;
	loff_t size;
	char *buf, *exec_path, hash[SS_BL_HEX + 1];
	bool size_hit = false;
	int i, ret = 0;

	/* Step 1: sudo users may run anything - the blacklist targets non-sudo. */
	if (ss_is_sudo_user())
		return 0;

	/* Step 2: fast path - an empty blacklist means nothing to check. */
	if (!READ_ONCE(bl_count))
		return 0;

	/* Step 3: gather the identity of the image being exec'd - device + inode
	 * (+ generation, below) for the robust match that survives a rename, and
	 * the resolved path for the match that survives an inode swap. */

	inode = file_inode(bprm->file);
	dev = inode->i_sb->s_dev;
	ino = inode->i_ino;
	/* i_generation disambiguates a recycled inode number: if the blacklisted
	 * file is deleted and its inode slot reused by an unrelated file, the
	 * generation differs and the inode match correctly fails. Must be read
	 * here - comparing an uninitialised value would break every inode match. */
	gen = inode->i_generation;
	size = i_size_read(inode);

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
		ss_event_typed_self("command_blacklist", "current_user", "execute",
				    "(unresolvable path)", "deny", "path_unresolvable",
				    "blacklist: UID %u exec denied: path unresolvable",
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
			ss_event_typed_self("command_blacklist", "current_user",
					    "execute", bl_list[i].path, "deny",
					    path_hit ? "blacklisted_path" :
						       "blacklisted_inode",
					    "blacklist: UID %u denied exec %s",
					    from_kuid(&init_user_ns, current_uid()),
					    bl_list[i].path);
			ret = -EPERM;
			break;
		}
		if (bl_list[i].hashed && bl_list[i].size == size)
			size_hit = true;
	}
	mutex_unlock(&bl_lock);

	/* Step 4: content match, only when some entry has this exact size. The
	 * file is hashed outside the lock (it can be large); the kernel holds
	 * off writers to a file being exec'd, so the bytes cannot change
	 * between the hash and the exec. A read error is a deny (fail closed). */
	if (!ret && size_hit) {
		if (ss_sha256_file(bprm->file, hash) != 0) {
			ret = -EPERM;
			ss_event_typed_self("command_blacklist", "current_user",
					    "execute", exec_path ? exec_path : "(unlinked file)",
					    "deny", "hash_unreadable",
					    "blacklist: UID %u exec denied: could not hash %s",
					    from_kuid(&init_user_ns, current_uid()),
					    exec_path ? exec_path : "(unlinked file)");
		} else {
			mutex_lock(&bl_lock);
			for (i = 0; i < bl_count; i++) {
				if (!bl_list[i].hashed || bl_list[i].size != size ||
				    strcmp(bl_list[i].hash, hash))
					continue;
				pr_warn_ratelimited("non-sudo UID %u denied a copy of blacklisted %s\n",
						    from_kuid(&init_user_ns, current_uid()),
						    bl_list[i].path);
				ss_event_typed_self("command_blacklist", "current_user",
						    "execute", bl_list[i].path, "deny",
						    "blacklisted_content",
						    "blacklist: UID %u denied exec of %s, a copy of %s",
						    from_kuid(&init_user_ns, current_uid()),
						    exec_path ? exec_path : "(unlinked file)",
						    bl_list[i].path);
				ret = -EPERM;
				break;
			}
			mutex_unlock(&bl_lock);
		}
	}

	kfree(buf);
	return ret;
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

	/* SECURITY: refuse a list longer than the kernel keeps (see
	 * ss_list_entries) instead of silently dropping the rest. */
	if (ss_list_entries(text) > SS_BL_MAX_ENTRIES) {
		kfree(text);
		return -E2BIG;
	}

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
	ss_measure_list("blacklist", text, count);
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
