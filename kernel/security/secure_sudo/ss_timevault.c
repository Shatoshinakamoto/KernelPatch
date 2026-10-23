// SPDX-License-Identifier: GPL-2.0
/*
 * ss_timevault.c - Protection #13: TimeVault lockdown (kernel half).
 *
 * When the vault is engaged the system runs only an explicit allowlist of
 * programs; everything else is denied at exec, and the attempt is counted so
 * the daemon can quarantine and investigate the binary. Package managers are
 * refused unconditionally - even if someone allowlists them - because
 * installing software is exactly what a vault is meant to stop.
 *
 * Kernel vs userspace split (per the feature map): the kernel owns the exec
 * allowlist and the denied-attempt counter; the daemon owns the manifest over
 * watched trees, moving new/changed files into /var/lib/secure_sudo/quarantine
 * and shipping logs off-box (so a locked-down host cannot have its logs wiped).
 * The TODO said "wipe" new files; we quarantine instead - a wipe is
 * irreversible and destroys the evidence - and the daemon keeps
 * vault_action=wipe available as an opt-in.
 *
 * Allowlist lines are "<path> <sha256hex>". Every entry must pin a hash: a
 * path alone could be satisfied by a different file in another mount
 * namespace or chroot, or by a binary swapped in place. A write containing a
 * malformed line is rejected as a whole, so a typo can never silently shrink
 * the list.
 *
 * Engaging the vault latches the one-way config lock (#16). From then on the
 * vault cannot be disengaged and the allowlist cannot change until reboot -
 * that is the point of a vault. Engaging with an empty allowlist is refused,
 * since it would leave nothing runnable.
 *
 * Exec checks while engaged, in order:
 *   1. package managers and the dynamic loader (ld-linux*, ld.so, ld-musl*)
 *      are always denied - "ld.so /any/binary" would otherwise run a program
 *      that is not on the list;
 *   2. the resolved path (namespace-absolute, see ss_file_path) must be on
 *      the list and the file must still be linked;
 *   3. the file must be root-owned and not group/world-writable, and nobody
 *      may currently have it open for writing;
 *   4. its contents must hash to the pinned SHA-256.
 * While engaged, write-opens and truncation of allowlisted files are denied,
 * so a verified binary cannot be changed underneath a running exec.
 *
 * timevault_strict_mmap additionally requires any file mapped PROT_EXEC
 * (shared libraries, plugins) to be on the list by path. Off by default:
 * turning it on without allowlisting /usr/lib* stops every dynamic program.
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
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <linux/sort.h>
#include <linux/bsearch.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

/* Sized for whole-directory scans (e.g. /usr/bin + /usr/sbin + /usr/lib*):
 * ~100 bytes a line, so 16k entries fit comfortably in 4 MiB. */
#define TV_MAX_ITEMS	16384
#define TV_MAX_TEXT	(4 * 1024 * 1024)
#define SHA256_HEX	64

/* Package managers denied unconditionally while the vault is engaged. */
static const char *const pkg_managers[] = {
	"apt", "apt-get", "aptitude", "dpkg",
	"dnf", "yum", "rpm",
	"zypper", "pacman",
	"snap", "snapd", "flatpak",
};

struct tv_entry {
	char *path;
	char hash[SHA256_HEX + 1];
};

/* (dev, ino) of each entry that resolved at load time, for the write guard. */
struct tv_ino {
	dev_t dev;
	unsigned long ino;
};

static DEFINE_MUTEX(tv_lock);
static struct tv_entry *tv_list;	/* sorted by path */
static int tv_count;
static struct tv_ino *tv_inos;		/* sorted by (dev, ino) */
static int tv_ninos;
static char *tv_text;
static size_t tv_text_len;
static atomic_long_t tv_denied = ATOMIC_LONG_INIT(0);

static bool is_pkg_manager(const char *base)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(pkg_managers); i++)
		if (!strcmp(base, pkg_managers[i]))
			return true;
	return false;
}

static bool is_dynamic_loader(const char *base)
{
	return str_has_prefix(base, "ld-linux") ||
	       str_has_prefix(base, "ld.so") ||
	       str_has_prefix(base, "ld-musl") ||
	       str_has_prefix(base, "ld64.so");
}

static int tv_entry_cmp(const void *a, const void *b)
{
	return strcmp(((const struct tv_entry *)a)->path,
		      ((const struct tv_entry *)b)->path);
}

static int tv_key_cmp(const void *key, const void *elt)
{
	return strcmp(key, ((const struct tv_entry *)elt)->path);
}

static int tv_ino_cmp(const void *a, const void *b)
{
	const struct tv_ino *x = a, *y = b;

	if (x->dev != y->dev)
		return x->dev < y->dev ? -1 : 1;
	if (x->ino != y->ino)
		return x->ino < y->ino ? -1 : 1;
	return 0;
}

/* Look up @path; caller holds tv_lock. */
static struct tv_entry *tv_find_locked(const char *path)
{
	if (!tv_count)
		return NULL;
	return bsearch(path, tv_list, tv_count, sizeof(*tv_list), tv_key_cmp);
}

static bool tv_inode_listed(const struct inode *inode)
{
	struct tv_ino key = { inode->i_sb->s_dev, inode->i_ino };
	bool hit;

	mutex_lock(&tv_lock);
	hit = tv_ninos && bsearch(&key, tv_inos, tv_ninos, sizeof(*tv_inos),
				  tv_ino_cmp);
	mutex_unlock(&tv_lock);
	return hit;
}

static void tv_deny(const char *what, const char *why)
{
	atomic_long_inc(&tv_denied);
	pr_warn_ratelimited("timevault: denied %s (%s)\n", what, why);
	ss_event("timevault: denied exec %s (%s)", what, why);
}

static int ss_timevault_bprm(struct linux_binprm *bprm)
{
	struct file *file = bprm->file;
	struct inode *inode = file_inode(file);
	char want_hash[SHA256_HEX + 1], got[SHA256_HEX + 1];
	const char *base;
	struct tv_entry *e;
	char *buf, *resolved;
	int ret = -EPERM;		/* default DENY: the vault is deny-by-default */

	/* Step 0: vault not engaged -> no restriction. */
	if (!READ_ONCE(ss_cfg.timevault_enabled))
		return 0;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -EPERM;		/* fail CLOSED: vault is a deny-all state */

	/* Step 1: resolve the binary's path; an unresolvable one is denied. */
	resolved = ss_file_path(&file->f_path, buf, PATH_MAX);
	if (IS_ERR(resolved)) {
		tv_deny("(unresolvable path)", "no path");
		goto out;
	}
	base = kbasename(resolved);

	/* Step 2: hard denials that apply no matter what the allowlist says -
	 * package managers (they would install new code) and running the dynamic
	 * loader directly (ld.so /path/to/x sidesteps a per-binary check). */
	if (is_pkg_manager(base)) {
		tv_deny(resolved, "package manager");
		goto out;
	}
	if (is_dynamic_loader(base)) {
		tv_deny(resolved, "direct dynamic-loader exec");
		goto out;
	}
	/* Step 3: refuse an unlinked file - its name no longer pins its inode. */
	if (d_unlinked(file->f_path.dentry)) {
		tv_deny(resolved, "file unlinked");
		goto out;
	}

	/* Step 4: the binary must be on the allowlist. Copy its pinned hash out
	 * under the lock so we can release it before the expensive hashing. */
	mutex_lock(&tv_lock);
	e = tv_find_locked(resolved);
	if (e)
		memcpy(want_hash, e->hash, sizeof(want_hash));
	mutex_unlock(&tv_lock);
	if (!e) {
		tv_deny(resolved, "not on allowlist");
		goto out;
	}

	/* Step 5: integrity preconditions before we even hash - the file must be
	 * root-owned and not group/world-writable (else a non-root user could
	 * have altered it), and not currently open for writing (a writer could
	 * change the bytes after we hash them: a TOCTOU guard). */
	if (!uid_eq(inode->i_uid, GLOBAL_ROOT_UID) || (inode->i_mode & 0022)) {
		tv_deny(resolved, "not root-owned or group/world-writable");
		goto out;
	}
	if (inode_is_open_for_write(inode)) {
		tv_deny(resolved, "open for writing");
		goto out;
	}
	/* Step 6: the decisive check - the file's actual SHA-256 must equal the
	 * hash pinned in the allowlist. Only then permit the exec. */
	if (ss_sha256_file(file, got) != 0 || strcasecmp(got, want_hash) != 0) {
		tv_deny(resolved, "hash mismatch");
		goto out;
	}
	ret = 0;			/* all checks passed -> permit */
out:
	kfree(buf);
	return ret;
}

/* While engaged, a verified binary must not change: refuse write-opens. */
static int ss_timevault_file_open(struct file *file)
{
	if (!READ_ONCE(ss_cfg.timevault_enabled))
		return 0;
	if (!(file->f_mode & FMODE_WRITE))
		return 0;
	if (!S_ISREG(file_inode(file)->i_mode))
		return 0;
	if (tv_inode_listed(file_inode(file))) {
		pr_warn_ratelimited("timevault: denied write-open of allowlisted file\n");
		ss_event("timevault: denied write to allowlisted inode %lu",
			 file_inode(file)->i_ino);
		return -EPERM;
	}
	return 0;
}

#ifdef CONFIG_SECURITY_PATH
static int ss_timevault_truncate(const struct path *path)
{
	if (!READ_ONCE(ss_cfg.timevault_enabled))
		return 0;
	if (d_backing_inode(path->dentry) &&
	    tv_inode_listed(d_backing_inode(path->dentry)))
		return -EPERM;
	return 0;
}
#endif

/* Optional: every PROT_EXEC file mapping must be on the list (by path). */
static int tv_check_exec_map(struct file *file)
{
	struct tv_entry *e;
	char *buf, *p;

	if (!READ_ONCE(ss_cfg.timevault_enabled) ||
	    !READ_ONCE(ss_cfg.timevault_strict_mmap) || !file)
		return 0;
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -EPERM;
	p = ss_file_path(&file->f_path, buf, PATH_MAX);
	if (IS_ERR(p) || d_unlinked(file->f_path.dentry)) {
		e = NULL;
	} else {
		mutex_lock(&tv_lock);
		e = tv_find_locked(p);
		mutex_unlock(&tv_lock);
	}
	if (!e)
		tv_deny(IS_ERR(p) ? "(unresolvable path)" : p,
			"PROT_EXEC map not on allowlist");
	kfree(buf);
	return e ? 0 : -EPERM;
}

static int ss_timevault_mmap(struct file *file, unsigned long reqprot,
			     unsigned long prot, unsigned long flags)
{
	if (!(prot & PROT_EXEC))
		return 0;
	return tv_check_exec_map(file);
}

static int ss_timevault_mprotect(struct vm_area_struct *vma,
				 unsigned long reqprot, unsigned long prot)
{
	if (!(prot & PROT_EXEC) || (vma->vm_flags & VM_EXEC))
		return 0;
	return tv_check_exec_map(vma->vm_file);
}

static struct security_hook_list ss_tv_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, ss_timevault_bprm),
	LSM_HOOK_INIT(file_open,           ss_timevault_file_open),
#ifdef CONFIG_SECURITY_PATH
	LSM_HOOK_INIT(path_truncate,       ss_timevault_truncate),
#endif
	LSM_HOOK_INIT(mmap_file,           ss_timevault_mmap),
	LSM_HOOK_INIT(file_mprotect,       ss_timevault_mprotect),
};

void __init ss_timevault_init(void)
{
	security_add_hooks(ss_tv_hooks, ARRAY_SIZE(ss_tv_hooks), &ss_lsmid);
}

/* ---------------------------- sysfs knobs -------------------------------- */

static ssize_t timevault_show(struct kobject *k, struct kobj_attribute *a,
			      char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.timevault_enabled));
}

/*
 * Engage: refused with an empty allowlist; otherwise turns the vault on and
 * latches the config lock. Disengage: only possible while unlocked - and
 * since engaging locks, an engaged vault stays engaged until reboot.
 */
static ssize_t timevault_store(struct kobject *k, struct kobj_attribute *a,
			       const char *buf, size_t count)
{
	bool v;

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;

	if (v) {
		if (!READ_ONCE(tv_count)) {
			pr_warn("timevault: refusing to engage with an empty allowlist\n");
			return -ENOENT;
		}
		WRITE_ONCE(ss_cfg.timevault_enabled, true);
		pr_warn("timevault: ENGAGED - exec restricted to allowlist\n");
		ss_event("timevault: engaged");
		ss_lock_engage("timevault");
	} else {
		if (ss_locked()) {
			ss_event("timevault: refused disengage while locked (UID %u)",
				 from_kuid(&init_user_ns, current_uid()));
			return -EPERM;
		}
		WRITE_ONCE(ss_cfg.timevault_enabled, false);
	}
	return count;
}

static ssize_t timevault_strict_mmap_show(struct kobject *k,
					  struct kobj_attribute *a, char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.timevault_strict_mmap));
}

static ssize_t timevault_strict_mmap_store(struct kobject *k,
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
	WRITE_ONCE(ss_cfg.timevault_strict_mmap, v);
	return count;
}

static struct kobj_attribute timevault_attr =
	__ATTR(timevault, 0600, timevault_show, timevault_store);
static struct kobj_attribute timevault_strict_mmap_attr =
	__ATTR(timevault_strict_mmap, 0600, timevault_strict_mmap_show,
	       timevault_strict_mmap_store);

static ssize_t timevault_denied_show(struct kobject *k,
				     struct kobj_attribute *a, char *buf)
{
	return sysfs_emit(buf, "%ld\n", atomic_long_read(&tv_denied));
}
static struct kobj_attribute timevault_denied_attr =
	__ATTR(timevault_denied, 0400, timevault_denied_show, NULL);

static struct attribute *ss_tv_attrs[] = {
	&timevault_attr.attr,
	&timevault_strict_mmap_attr.attr,
	&timevault_denied_attr.attr,
	NULL,
};
static const struct attribute_group ss_tv_group = {
	.attrs = ss_tv_attrs,
};

int ss_timevault_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_tv_group);
}

/* ------------------------ securityfs: allowlist -------------------------- */

static void tv_free(struct tv_entry *list, int count)
{
	int i;

	if (!list)
		return;
	for (i = 0; i < count; i++)
		kfree(list[i].path);
	kvfree(list);
}

static bool is_sha256_hex(const char *s)
{
	int i;

	if (strlen(s) != SHA256_HEX)
		return false;
	for (i = 0; i < SHA256_HEX; i++)
		if (!isxdigit(s[i]))
			return false;
	return true;
}

/* Parse into a sorted list + inode index. Returns 0 or -errno. */
static int tv_parse(char *text, struct tv_entry **out_list, int *out_count,
		    struct tv_ino **out_inos, int *out_ninos)
{
	struct tv_entry *list;
	struct tv_ino *inos;
	char *p = text, *line;
	int n = 0, ni = 0, i, ret = -EINVAL;

	list = kvcalloc(TV_MAX_ITEMS, sizeof(*list), GFP_KERNEL);
	inos = kvcalloc(TV_MAX_ITEMS, sizeof(*inos), GFP_KERNEL);
	if (!list || !inos) {
		ret = -ENOMEM;
		goto err;
	}

	while ((line = strsep(&p, "\n"))) {
		char *sp;

		line = strim(line);
		if (*line == '\0' || *line == '#')
			continue;
		if (n >= TV_MAX_ITEMS) {
			ret = -E2BIG;
			goto err;
		}
		sp = strchr(line, ' ');
		if (*line != '/' || !sp)
			goto err;		/* -EINVAL: path + hash required */
		*sp = '\0';
		sp = strim(sp + 1);
		if (!is_sha256_hex(sp))
			goto err;

		list[n].path = kstrdup(line, GFP_KERNEL);
		if (!list[n].path) {
			ret = -ENOMEM;
			goto err;
		}
		for (i = 0; i < SHA256_HEX; i++)
			list[n].hash[i] = tolower(sp[i]);
		list[n].hash[SHA256_HEX] = '\0';
		n++;
	}

	sort(list, n, sizeof(*list), tv_entry_cmp, NULL);
	for (i = 1; i < n; i++)
		if (!strcmp(list[i - 1].path, list[i].path))
			goto err;		/* duplicate path: ambiguous */

	for (i = 0; i < n; i++) {
		struct path path;

		if (kern_path(list[i].path, LOOKUP_FOLLOW, &path) == 0) {
			struct inode *inode = d_backing_inode(path.dentry);

			if (inode) {
				inos[ni].dev = inode->i_sb->s_dev;
				inos[ni].ino = inode->i_ino;
				ni++;
			}
			path_put(&path);
		}
	}
	sort(inos, ni, sizeof(*inos), tv_ino_cmp, NULL);

	*out_list = list;
	*out_count = n;
	*out_inos = inos;
	*out_ninos = ni;
	return 0;
err:
	tv_free(list, n);
	kvfree(inos);
	return ret;
}

static ssize_t tv_read(struct file *file, char __user *ubuf, size_t count,
		       loff_t *ppos)
{
	ssize_t ret;

	mutex_lock(&tv_lock);
	ret = simple_read_from_buffer(ubuf, count, ppos,
				      tv_text ? tv_text : "", tv_text_len);
	mutex_unlock(&tv_lock);
	return ret;
}

static ssize_t tv_write(struct file *file, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	struct tv_entry *new_list, *old_list;
	struct tv_ino *new_inos, *old_inos;
	int new_count, old_count, new_ninos, ret;
	char *text, *scratch, *old_text;

	if (!ss_may_admin(file))
		return -EPERM;
	/* Once locked, the allowlist is frozen like every other knob. */
	if (ss_locked())
		return -EPERM;
	if (*ppos != 0)
		return -EINVAL;
	if (count == 0)
		return 0;
	if (count > TV_MAX_TEXT)
		return -EFBIG;

	text = kvmalloc(count + 1, GFP_KERNEL);
	if (!text)
		return -ENOMEM;
	if (copy_from_user(text, ubuf, count)) {
		kvfree(text);
		return -EFAULT;
	}
	text[count] = '\0';

	scratch = kvmemdup(text, count + 1, GFP_KERNEL);
	if (!scratch) {
		kvfree(text);
		return -ENOMEM;
	}
	ret = tv_parse(scratch, &new_list, &new_count, &new_inos, &new_ninos);
	kvfree(scratch);
	if (ret) {
		kvfree(text);
		return ret;
	}

	mutex_lock(&tv_lock);
	old_list = tv_list;
	old_count = tv_count;
	old_inos = tv_inos;
	old_text = tv_text;
	tv_list = new_list;
	WRITE_ONCE(tv_count, new_count);
	tv_inos = new_inos;
	tv_ninos = new_ninos;
	tv_text = text;
	tv_text_len = count;
	mutex_unlock(&tv_lock);

	tv_free(old_list, old_count);
	kvfree(old_inos);
	kvfree(old_text);

	*ppos = count;
	return count;
}

static const struct file_operations tv_fops = {
	.read   = tv_read,
	.write  = tv_write,
	.llseek = default_llseek,
};

int ss_timevault_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("timevault_allow", 0600, dir, NULL,
				   &tv_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
	return 0;
}
