// SPDX-License-Identifier: GPL-2.0
/*
 * ss_home.c - Protection #4: confine a non-sudo user's *writes* to their home
 * directory (plus the normally-writable scratch/device trees and a configured
 * allowlist). Reads are untouched, and execution control is #12's job, not
 * this file's.
 *
 * Both source versions implemented this on a "path_permission" LSM hook that
 * does not exist, and v2's fallback denied writes outside /home/<numeric-uid>,
 * which matches no real home and broke everything. The right tools are:
 *
 *   - file_open  : deny a write-mode open (incl. O_CREAT/O_TRUNC) whose target
 *                  resolves outside the allowed set. Covers content writes.
 *   - path_*     : deny namespace mutations (mkdir/rmdir/unlink/rename/symlink/
 *                  link/mknod/truncate) whose target directory is outside the
 *                  allowed set. Covers "write" that isn't an open.
 *
 * The kernel has no /etc/passwd, so the daemon/CLI supplies a uid->home map via
 * securityfs (home_map); extra writable prefixes go in home_write_allow. The
 * usual always-writable trees (/tmp, /var/tmp, /dev, /dev/shm, /run, /proc,
 * /sys) are permitted unconditionally so normal programs keep working - the
 * dangerous bits of /dev and /sys are already gated by #3. OFF by default.
 *
 * Every decision fails closed once the feature is on: an unresolvable or
 * over-long target (a classic way to dodge path-based checks) is a deny.
 * chmod/chown of files outside the allowed set are covered too.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <linux/err.h>
#include <linux/security.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

#define HM_MAX_ENTRIES	4096
#define HM_MAX_TEXT	(256 * 1024)

/* Trees every unprivileged process must be able to write to for normal use. */
static const char *const safe_prefixes[] = {
	"/tmp/", "/var/tmp/", "/dev/shm/", "/dev/", "/run/", "/var/run/",
	"/proc/", "/sys/", "/var/lock/",
};

/* uid -> home directory, from securityfs "home_map" ("<uid> <path>"). */
struct home_ent {
	uid_t uid;
	char *home;
};

static DEFINE_MUTEX(hm_lock);
static struct home_ent *hm_list;
static int hm_count;
static char *hm_text;
static size_t hm_text_len;

/* Extra always-writable path prefixes, from securityfs "home_write_allow". */
static char **allow_list;
static int allow_count;
static char *allow_text;
static size_t allow_text_len;

/* Is a non-sudo write to @path by @uid permitted? */
static bool write_allowed(const char *path, uid_t uid)
{
	size_t i;
	bool ok = false;

	for (i = 0; i < ARRAY_SIZE(safe_prefixes); i++)
		if (str_has_prefix(path, safe_prefixes[i]))
			return true;

	mutex_lock(&hm_lock);
	for (i = 0; i < (size_t)hm_count; i++) {
		if (hm_list[i].uid == uid &&
		    ss_path_under(path, hm_list[i].home)) {
			ok = true;
			goto out;
		}
	}
	for (i = 0; i < (size_t)allow_count; i++) {
		if (ss_path_under(path, allow_list[i])) {
			ok = true;
			goto out;
		}
	}
out:
	mutex_unlock(&hm_lock);
	return ok;
}

/* Common decision given an already-resolved target path string. */
static int home_check(const char *path, const char *what)
{
	uid_t uid;

	/* Step 1: feature off -> allow. */
	if (!READ_ONCE(ss_cfg.block_home_write))
		return 0;
	/* Step 2: sudo users write anywhere. */
	if (ss_is_sudo_user())
		return 0;

	/* Step 3: permit only if the target is inside this uid's own home, one of
	 * the always-writable scratch/device trees, or the admin allowlist
	 * (write_allowed covers all three). Any other write by a non-sudo user is
	 * denied - this is the confinement. */
	uid = from_kuid(&init_user_ns, current_uid());
	if (write_allowed(path, uid))
		return 0;

	pr_warn_ratelimited("home: non-sudo UID %u denied %s outside home: %s\n",
			    uid, what, path);
	ss_event("home: UID %u denied %s outside home: %s", uid, what, path);
	return -EPERM;
}

/* ------------------------------ file_open -------------------------------- */

static int ss_home_file_open(struct file *file)
{
	char *buf, *p;
	int ret = 0;

	if (!READ_ONCE(ss_cfg.block_home_write))
		return 0;
	if (!(file->f_mode & FMODE_WRITE))
		return 0;
	if (ss_is_sudo_user())
		return 0;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	p = ss_file_path(&file->f_path, buf, PATH_MAX);
	/* Pseudo files (pipes, sockets, memfd) have no real path: not ours. */
	if (IS_ERR(p))
		ret = -EPERM;
	else if (*p == '/')
		ret = home_check(p, "write");
	kfree(buf);
	return ret;
}

/* --------------------------- path_* mutations ---------------------------- */
#ifdef CONFIG_SECURITY_PATH

/* Build "<dir>/<dentry>" into @out (size PATH_MAX); @scratch is PATH_MAX too. */
static const char *target_path(const struct path *dir, struct dentry *dentry,
			       char *out, char *scratch)
{
	char *dp = ss_file_path(dir, scratch, PATH_MAX);

	if (IS_ERR(dp))
		return NULL;
	if (snprintf(out, PATH_MAX, "%s/%s", dp, dentry->d_name.name) >= PATH_MAX)
		return NULL;			/* truncated: refuse */
	return out;
}

/* Check a (dir, dentry) target; allocates and frees its own buffers. */
static int check_dir_dentry(const struct path *dir, struct dentry *dentry,
			    const char *what)
{
	char *out, *scratch;
	const char *p;
	int ret = 0;

	if (!READ_ONCE(ss_cfg.block_home_write) || ss_is_sudo_user())
		return 0;

	out = kmalloc(PATH_MAX, GFP_KERNEL);
	scratch = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!out || !scratch) {
		ret = -ENOMEM;
		goto out;
	}
	p = target_path(dir, dentry, out, scratch);
	ret = p ? home_check(p, what) : -EPERM;
out:
	kfree(out);
	kfree(scratch);
	return ret;
}

static int ss_path_mkdir(const struct path *dir, struct dentry *d, umode_t m)
{
	return check_dir_dentry(dir, d, "mkdir");
}
static int ss_path_rmdir(const struct path *dir, struct dentry *d)
{
	return check_dir_dentry(dir, d, "rmdir");
}
static int ss_path_unlink(const struct path *dir, struct dentry *d)
{
	return check_dir_dentry(dir, d, "unlink");
}
static int ss_path_symlink(const struct path *dir, struct dentry *d,
			   const char *old)
{
	return check_dir_dentry(dir, d, "symlink");
}
static int ss_path_link(struct dentry *old, const struct path *ndir,
			struct dentry *nd)
{
	return check_dir_dentry(ndir, nd, "link");
}
static int ss_path_mknod(const struct path *dir, struct dentry *d, umode_t m,
			 unsigned int dev)
{
	return check_dir_dentry(dir, d, "mknod");
}
static int ss_path_rename(const struct path *odir, struct dentry *od,
			  const struct path *ndir, struct dentry *nd,
			  unsigned int flags)
{
	int ret = check_dir_dentry(odir, od, "rename-from");

	return ret ? ret : check_dir_dentry(ndir, nd, "rename-to");
}
static int check_path(const struct path *path, const char *what)
{
	char *buf, *p;
	int ret;

	if (!READ_ONCE(ss_cfg.block_home_write) || ss_is_sudo_user())
		return 0;
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	p = ss_file_path(path, buf, PATH_MAX);
	ret = IS_ERR(p) ? -EPERM : home_check(p, what);
	kfree(buf);
	return ret;
}

static int ss_path_truncate(const struct path *path)
{
	return check_path(path, "truncate");
}
static int ss_path_chmod(const struct path *path, umode_t mode)
{
	return check_path(path, "chmod");
}
static int ss_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	return check_path(path, "chown");
}
#endif /* CONFIG_SECURITY_PATH */

static struct security_hook_list ss_home_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_open, ss_home_file_open),
#ifdef CONFIG_SECURITY_PATH
	LSM_HOOK_INIT(path_mkdir,    ss_path_mkdir),
	LSM_HOOK_INIT(path_rmdir,    ss_path_rmdir),
	LSM_HOOK_INIT(path_unlink,   ss_path_unlink),
	LSM_HOOK_INIT(path_symlink,  ss_path_symlink),
	LSM_HOOK_INIT(path_link,     ss_path_link),
	LSM_HOOK_INIT(path_mknod,    ss_path_mknod),
	LSM_HOOK_INIT(path_rename,   ss_path_rename),
	LSM_HOOK_INIT(path_truncate, ss_path_truncate),
	LSM_HOOK_INIT(path_chmod,    ss_path_chmod),
	LSM_HOOK_INIT(path_chown,    ss_path_chown),
#endif
};

void __init ss_home_init(void)
{
	security_add_hooks(ss_home_hooks, ARRAY_SIZE(ss_home_hooks), &ss_lsmid);
}

/* ---------------------------- sysfs knob --------------------------------- */

static ssize_t block_home_write_show(struct kobject *k, struct kobj_attribute *a,
				     char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.block_home_write));
}
static ssize_t block_home_write_store(struct kobject *k, struct kobj_attribute *a,
				      const char *buf, size_t count)
{
	bool v;

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	WRITE_ONCE(ss_cfg.block_home_write, v);
	return count;
}
static struct kobj_attribute block_home_write_attr =
	__ATTR(block_home_write, 0600, block_home_write_show, block_home_write_store);

static struct attribute *ss_home_attrs[] = {
	&block_home_write_attr.attr,
	NULL,
};
static const struct attribute_group ss_home_group = {
	.attrs = ss_home_attrs,
};

int ss_home_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_home_group);
}

/* ------------------------- securityfs: home_map -------------------------- */

static void hm_free(struct home_ent *list, int count)
{
	int i;

	if (!list)
		return;
	for (i = 0; i < count; i++)
		kfree(list[i].home);
	kfree(list);
}

static struct home_ent *hm_parse(char *text, int *out_count)
{
	struct home_ent *list;
	char *p = text, *line;
	int n = 0;

	list = kcalloc(HM_MAX_ENTRIES, sizeof(*list), GFP_KERNEL);
	if (!list)
		return NULL;
	while ((line = strsep(&p, "\n")) && n < HM_MAX_ENTRIES) {
		char *sp;
		unsigned int uid;

		line = strim(line);
		if (*line == '\0' || *line == '#')
			continue;
		sp = strchr(line, ' ');
		if (!sp)
			continue;
		*sp = '\0';
		if (kstrtouint(line, 10, &uid))
			continue;
		sp = strim(sp + 1);
		if (*sp != '/')
			continue;
		list[n].uid = uid;
		list[n].home = kstrdup(sp, GFP_KERNEL);
		if (!list[n].home) {
			hm_free(list, n);
			return NULL;
		}
		n++;
	}
	*out_count = n;
	return list;
}

static void sl_free(char **list, int count)
{
	int i;

	if (!list)
		return;
	for (i = 0; i < count; i++)
		kfree(list[i]);
	kfree(list);
}

static char **allow_parse(char *text, int *out_count)
{
	char **list;
	char *p = text, *line;
	int n = 0;

	list = kcalloc(HM_MAX_ENTRIES, sizeof(*list), GFP_KERNEL);
	if (!list)
		return NULL;
	while ((line = strsep(&p, "\n")) && n < HM_MAX_ENTRIES) {
		line = strim(line);
		if (*line == '\0' || *line == '#' || *line != '/')
			continue;
		list[n] = kstrdup(line, GFP_KERNEL);
		if (!list[n]) {
			sl_free(list, n);
			return NULL;
		}
		n++;
	}
	*out_count = n;
	return list;
}

/* Slurp a whole-file write into a kmalloc'd NUL-terminated buffer. */
static char *slurp_write(struct file *file, const char __user *ubuf,
			 size_t count, loff_t *ppos)
{
	char *text;

	if (!ss_may_admin(file))
		return ERR_PTR(-EPERM);
	if (ss_locked())
		return ERR_PTR(-EPERM);
	if (*ppos != 0)
		return ERR_PTR(-EINVAL);
	if (count == 0)
		return ERR_PTR(-EINVAL);
	if (count > HM_MAX_TEXT)
		return ERR_PTR(-EFBIG);
	text = kmalloc(count + 1, GFP_KERNEL);
	if (!text)
		return ERR_PTR(-ENOMEM);
	if (copy_from_user(text, ubuf, count)) {
		kfree(text);
		return ERR_PTR(-EFAULT);
	}
	text[count] = '\0';
	return text;
}

static ssize_t home_map_read(struct file *f, char __user *u, size_t c, loff_t *p)
{
	ssize_t ret;

	mutex_lock(&hm_lock);
	ret = simple_read_from_buffer(u, c, p, hm_text ? hm_text : "",
				      hm_text_len);
	mutex_unlock(&hm_lock);
	return ret;
}

static ssize_t home_map_write(struct file *f, const char __user *u, size_t c,
			      loff_t *p)
{
	char *text, *scratch, *old_text;
	struct home_ent *new_list, *old_list;
	int new_count, old_count;

	text = slurp_write(f, u, c, p);
	if (IS_ERR(text))
		return PTR_ERR(text);
	scratch = kmemdup(text, c + 1, GFP_KERNEL);
	if (!scratch) {
		kfree(text);
		return -ENOMEM;
	}
	new_list = hm_parse(scratch, &new_count);
	kfree(scratch);
	if (!new_list) {
		kfree(text);
		return -ENOMEM;
	}
	mutex_lock(&hm_lock);
	old_list = hm_list; old_count = hm_count; old_text = hm_text;
	hm_list = new_list; hm_count = new_count;
	hm_text = text; hm_text_len = c;
	mutex_unlock(&hm_lock);
	hm_free(old_list, old_count);
	kfree(old_text);
	*p = c;
	return c;
}

static ssize_t allow_read(struct file *f, char __user *u, size_t c, loff_t *p)
{
	ssize_t ret;

	mutex_lock(&hm_lock);
	ret = simple_read_from_buffer(u, c, p, allow_text ? allow_text : "",
				      allow_text_len);
	mutex_unlock(&hm_lock);
	return ret;
}

static ssize_t allow_write(struct file *f, const char __user *u, size_t c,
			   loff_t *p)
{
	char *text, *scratch, *old_text, **new_list, **old_list;
	int new_count, old_count;

	text = slurp_write(f, u, c, p);
	if (IS_ERR(text))
		return PTR_ERR(text);
	scratch = kmemdup(text, c + 1, GFP_KERNEL);
	if (!scratch) {
		kfree(text);
		return -ENOMEM;
	}
	new_list = allow_parse(scratch, &new_count);
	kfree(scratch);
	if (!new_list) {
		kfree(text);
		return -ENOMEM;
	}
	mutex_lock(&hm_lock);
	old_list = allow_list; old_count = allow_count; old_text = allow_text;
	allow_list = new_list; allow_count = new_count;
	allow_text = text; allow_text_len = c;
	mutex_unlock(&hm_lock);
	sl_free(old_list, old_count);
	kfree(old_text);
	*p = c;
	return c;
}

static const struct file_operations home_map_fops = {
	.read = home_map_read, .write = home_map_write, .llseek = default_llseek,
};
static const struct file_operations allow_fops = {
	.read = allow_read, .write = allow_write, .llseek = default_llseek,
};

int ss_home_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("home_map", 0600, dir, NULL, &home_map_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
	d = securityfs_create_file("home_write_allow", 0600, dir, NULL,
				   &allow_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
	return 0;
}
