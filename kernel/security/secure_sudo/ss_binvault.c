// SPDX-License-Identifier: GPL-2.0
/*
 * ss_binvault.c - Protection #17: BinaryVault.
 *
 * ============================ WHAT IT DOES ===============================
 * BinaryVault makes every *binary* on the machine immutable while the system
 * is running. Once engaged (which, in practice, is at boot - see "WHEN IT
 * ENGAGES" below) nothing can modify, truncate, delete, rename over, chmod or
 * re-label an executable or a shared library - not a user, not a service, and
 * not root. The on-disk code that the kernel will execute is frozen exactly as
 * it was when the box booted.
 *
 * The point is anti-tamper / anti-persistence. The single most common thing a
 * successful intruder does after landing code execution is to make the change
 * survive a reboot: overwrite /usr/bin/sshd, swap a shared library under
 * /usr/lib, drop a trojaned helper into /usr/sbin, or flip a file capability
 * with setcap. BinaryVault removes that entire class of persistence: the
 * attacker may still run in RAM, but the moment the box reboots their changes
 * are gone, because they were never allowed to touch disk.
 *
 * ========================= WHY IT COVERS ROOT ============================
 * Unlike the "non-sudo" protections (#1, #4, #12 ...), BinaryVault applies to
 * *everyone, root included*. That is deliberate and it is the whole value: a
 * protection that an attacker can switch off the instant they get root is not
 * a protection. The same reasoning is already used for #5 (TPM-clear). The
 * only way to legitimately write a system binary is to deliberately reboot
 * into a maintenance window (see below); at normal runtime the answer is "no"
 * for every caller.
 *
 * =========================== THE LOGIC GATE ==============================
 * Every write-type operation is decided by ONE gate, ss_binvault_denies().
 * A write is denied when, and only when, ALL of these are true:
 *
 *      (1) the feature is turned on          - READ_ONCE(ss_cfg.binaryvault)
 *      (2) we are NOT in a maintenance boot  - !binvault_maint
 *      (3) the target is a protected binary  - is_protected_binary()
 *      (4) the target is not allowlisted     - !vault_allowlisted()
 *
 * If any one of them is false, the operation is allowed through untouched.
 * This is the "logic gate" the feature is dictated by: the config toggle, the
 * boot-time maintenance override, the binary classifier, and the allowlist,
 * AND-ed together. It is evaluated identically from every hook, so there is
 * exactly one place to reason about (and one place a bug could hide).
 *
 * ========================== WHEN IT ENGAGES ==============================
 * The config knob `binaryvault` defaults OFF in the kernel and is turned on by
 * `secure-sudo load` at every boot (the systemd unit runs it in ExecStartPre,
 * before any multi-user service starts). So on a configured box the vault is
 * effectively engaged "at boot", as asked - there is no window between the
 * root filesystem mounting and the vault closing in which a service could
 * rewrite a binary. The knob is a normal secure_sudo knob: root-only (0600)
 * and frozen once the #16 config lock latches, so once a box is locked the
 * vault cannot even be toggled off until reboot.
 *
 * ========================= HOW YOU UPDATE ================================
 * Chosen mechanism: a MAINTENANCE REBOOT, gated by a read-only boot parameter
 *
 *      secure_sudo.binvault_maint=1
 *
 * modelled exactly on #5's secure_sudo.tpm_maint. Rationale for choosing this
 * over a "let the package manager write" carve-out:
 *
 *   - A package-manager carve-out (e.g. "allow writes whose parent process is
 *     dpkg/rpm") is trivially forgeable - an attacker just names their process
 *     dpkg, or injects into the real one - so it would reduce the guarantee to
 *     theatre. There is no tamper-proof way for the kernel to know "this write
 *     is a legitimate upgrade".
 *   - A boot parameter cannot be set from a running, locked system. Flipping
 *     it requires editing the boot loader and rebooting, which is itself a
 *     physically/administratively privileged act and is loud (it is logged and
 *     it drops the machine out of service briefly).
 *
 * So the update procedure is: reboot with secure_sudo.binvault_maint=1 (a
 * GRUB one-shot is ideal), run your `apt/dnf/pacman/zypper upgrade`, then
 * reboot normally. During the maintenance boot gate condition (2) is false, so
 * the vault allows all writes; on the next normal boot it closes again over
 * the new binaries. The installer documents this and `secure-sudo status`
 * shows whether the current boot is a maintenance boot.
 *
 * ======================= WHAT COUNTS AS A BINARY =========================
 * is_protected_binary() treats a target as a binary when it is a *regular
 * file* and either:
 *   - it has any execute bit set (S_IXUGO)      -> ELF programs and +x scripts
 *   - it is a shared library: its name ends in ".so" or contains ".so."
 *     (versioned, e.g. libc.so.6) AND it lives under a known library tree
 *     -> shared objects, which are mmap()ed executable but often are not +x.
 * Directories, devices, fifos, sockets and plain data files are never touched,
 * so normal writes (logs, databases, config, user files) are unaffected.
 *
 * ============================== THE HOOKS ================================
 * Every path by which an existing binary's bytes, identity or labels could
 * change is covered, and each FAILS CLOSED (an unresolvable path is a deny):
 *   - file_open (FMODE_WRITE) : opening a binary for writing (covers O_TRUNC,
 *                               O_APPEND, O_CREAT-over-existing).
 *   - file_truncate           : ftruncate() on an already-open fd.
 *   - path_truncate           : truncate() by path.
 *   - path_unlink             : deleting a binary (so it can be replaced).
 *   - path_rename             : renaming a binary away, OR renaming something
 *                               else *over* a binary (the classic dpkg/rpm
 *                               "write new file, rename into place" swap).
 *   - path_chmod              : changing a binary's mode (e.g. stripping +x to
 *                               dodge the classifier, or adding setuid).
 *   - inode_setxattr /
 *     inode_removexattr       : changing a binary's extended attributes
 *                               (file capabilities live in security.capability;
 *                               IMA/EVM labels in security.ima/evm).
 *
 * Creating brand-new files is never blocked here - only mutation of existing
 * binaries - so a maintenance boot, or writing a new program into an
 * allowlisted self-updating directory, works normally.
 *
 * ========================= KNOWN LIMITATIONS ============================
 * These are deliberate scope boundaries, documented honestly rather than
 * papered over (see docs/SECURITY_REVIEW.md #17 for the full second-pass):
 *
 *   - BinaryVault freezes EXISTING binaries. It does not decide whether a
 *     *new* program may run - that is the job of #2 (blacklist), #1b (setid
 *     exec), #12 (no-exec-from-tmp) and #13 (TimeVault's hash allowlist).
 *     Freezing and exec-control are complementary layers.
 *   - A pre-existing second hard link to a no-exec-bit library (created before
 *     the vault engaged) is a second path to the same inode. We block creating
 *     new links (path_link) so none can be added while engaged; links that
 *     predate boot are out of scope - use #13 TimeVault, which pins each
 *     allowed file by SHA-256, to detect a library whose bytes changed.
 *   - Mounting a fresh filesystem *over* a system directory (e.g. tmpfs over
 *     /usr/bin) does not modify the frozen files, so BinaryVault ignores it;
 *     #13 TimeVault defeats it instead, because a binary served from the
 *     overlay will not match its pinned hash and is refused execution.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/limits.h>
#include <linux/err.h>
#include <linux/moduleparam.h>
#include <linux/security.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

/* Bounds for the allowlist securityfs file (same scale as the other lists). */
#define BV_MAX_ALLOW	1024
#define BV_MAX_TEXT	(128 * 1024)

/*
 * Read-only boot parameter: secure_sudo.binvault_maint=1 opens the vault for
 * this boot so a maintenance window can apply package upgrades. 0444 means it
 * can be read from sysfs but never written at runtime - the only way to set it
 * is on the kernel command line, i.e. at boot. This is condition (2) of the
 * gate, and it is read locklessly because it never changes after boot.
 */
static bool binvault_maint;
module_param(binvault_maint, bool, 0444);
MODULE_PARM_DESC(binvault_maint,
	"secure_sudo: open BinaryVault for this boot so binaries can be updated. Boot-time only.");

/*
 * Library trees. A shared object (.so) is "protected" when it is a regular
 * file whose name looks like a library AND it lives under one of these. We do
 * NOT key libraries purely on name, so a data file called foo.sofa somewhere
 * random is not frozen; and we do NOT freeze every regular file under these
 * trees, so a package's data/cache file that happens to live under /usr/lib
 * can still be written. The intersection (looks like a lib AND under a lib
 * tree) is what a real shared object always satisfies.
 */
static const char *const lib_prefixes[] = {
	"/usr/lib/", "/usr/lib32/", "/usr/lib64/", "/usr/libx32/",
	"/lib/", "/lib32/", "/lib64/", "/libx32/",
	"/usr/local/lib/", "/usr/local/lib64/",
};

/* Allowlist: directory prefixes exempt from the vault (self-updating apps).
 * Managed via securityfs "binvault_allow"; protected by bv_lock (RCU would be
 * overkill - writes are rare admin actions, reads take a short mutex). */
static DEFINE_MUTEX(bv_lock);
static char **allow_list;
static int    allow_count;
static char  *allow_text;
static size_t allow_text_len;

/* True if @name is a shared-object name: ends ".so" or contains ".so." */
static bool has_so_name(const char *name)
{
	const char *dot = strstr(name, ".so");

	if (!dot)
		return false;
	/* the character after ".so" must be end-of-string or '.' (version) */
	return dot[3] == '\0' || dot[3] == '.';
}

/* True if @path sits under one of the library trees. */
static bool under_lib_tree(const char *path)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(lib_prefixes); i++)
		if (str_has_prefix(path, lib_prefixes[i]))
			return true;
	return false;
}

/*
 * Classifier (condition 3). @mode is the target's i_mode, @path its resolved
 * absolute path. Returns true for an executable or a shared library.
 */
static bool is_protected_binary(umode_t mode, const char *path)
{
	const char *base;

	if (!S_ISREG(mode))		/* only real files hold code */
		return false;
	if (mode & 0111)		/* any execute bit => a program/script */
		return true;

	/* Otherwise, a shared library: name looks like a .so and it is under a
	 * recognised library tree. basename = after the last '/'. */
	base = strrchr(path, '/');
	base = base ? base + 1 : path;
	return has_so_name(base) && under_lib_tree(path);
}

/* Condition (4): is @path under an admin-configured exempt prefix? */
static bool vault_allowlisted(const char *path)
{
	int i;
	bool hit = false;

	mutex_lock(&bv_lock);
	for (i = 0; i < allow_count; i++) {
		if (ss_path_under(path, allow_list[i])) {
			hit = true;
			break;
		}
	}
	mutex_unlock(&bv_lock);
	return hit;
}

/*
 * THE GATE. Returns true when a write-type operation on (@mode, @path) must be
 * denied. @what is a short verb for the log line. Conditions are checked
 * cheapest-first so the common "feature off" case costs a single READ_ONCE.
 */
static bool ss_binvault_denies(umode_t mode, const char *path, const char *what)
{
	if (!READ_ONCE(ss_cfg.binaryvault))	/* (1) feature off */
		return false;
	if (binvault_maint)			/* (2) maintenance boot */
		return false;
	if (!is_protected_binary(mode, path))	/* (3) not a binary */
		return false;
	if (vault_allowlisted(path))		/* (4) explicitly exempt */
		return false;

	pr_warn_ratelimited("binvault: denied %s of binary %s\n", what, path);
	ss_event("binvault: denied %s of %s", what, path);
	return true;
}

/*
 * Shared back-end for the two file-based hooks. Resolves the file's path and
 * runs the gate against the file's inode mode. Fails closed: if the path can't
 * be resolved while the feature is on, deny.
 */
static int file_guard(struct file *file, const char *what)
{
	char *buf, *p;
	int ret = 0;

	if (!READ_ONCE(ss_cfg.binaryvault) || binvault_maint)
		return 0;			/* fast path: gate open */

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;			/* no memory => fail closed */
	p = ss_file_path(&file->f_path, buf, PATH_MAX);
	if (IS_ERR(p)) {
		/* A writable binary we cannot name is exactly the case an
		 * attacker would engineer; deny rather than guess. */
		ret = -EPERM;
	} else if (*p == '/' &&
		   ss_binvault_denies(file_inode(file)->i_mode, p, what)) {
		ret = -EPERM;
	}
	kfree(buf);
	return ret;
}

/* ------------------------------ file hooks ------------------------------- */

/* Opening a binary for writing (covers O_TRUNC/O_APPEND and creating over an
 * existing binary). Non-write opens are irrelevant - reading/executing a
 * binary is exactly what we want to keep working. */
static int ss_binvault_file_open(struct file *file)
{
	if (!(file->f_mode & FMODE_WRITE))
		return 0;
	return file_guard(file, "write-open");
}

/* ftruncate() on an fd that is already open (so it bypasses file_open's
 * FMODE_WRITE test on this call). */
static int ss_binvault_file_truncate(struct file *file)
{
	return file_guard(file, "truncate");
}

/* --------------------------- path_* mutations ---------------------------- */
#ifdef CONFIG_SECURITY_PATH

/*
 * Resolve a (dir, dentry) pair - the form path hooks hand us for operations on
 * a name within a directory - into an absolute path string and the target's
 * inode mode, then run the gate. The inode is the backing inode of @dentry (it
 * exists for unlink/rename-source/rename-target-overwrite; when @dentry is
 * negative there is nothing to protect and we allow).
 */
static int dir_dentry_guard(const struct path *dir, struct dentry *dentry,
			    const char *what)
{
	struct inode *inode;
	char *out, *scratch, *dp;
	int ret = 0;

	if (!READ_ONCE(ss_cfg.binaryvault) || binvault_maint)
		return 0;

	inode = d_backing_inode(dentry);
	if (!inode)			/* negative dentry: nothing exists yet */
		return 0;

	out     = kmalloc(PATH_MAX, GFP_KERNEL);
	scratch = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!out || !scratch) {
		ret = -ENOMEM;
		goto out;
	}
	dp = ss_file_path(dir, scratch, PATH_MAX);
	if (IS_ERR(dp)) {
		ret = -EPERM;		/* fail closed */
		goto out;
	}
	if (snprintf(out, PATH_MAX, "%s/%s", dp, dentry->d_name.name) >= PATH_MAX) {
		ret = -EPERM;		/* truncated path => fail closed */
		goto out;
	}
	if (ss_binvault_denies(inode->i_mode, out, what))
		ret = -EPERM;
out:
	kfree(out);
	kfree(scratch);
	return ret;
}

/* Deleting a binary (first half of a delete-then-recreate swap). */
static int ss_binvault_path_unlink(const struct path *dir, struct dentry *d)
{
	return dir_dentry_guard(dir, d, "unlink");
}

/*
 * Rename. Two targets to guard:
 *   - the SOURCE (od): moving a binary out of the way.
 *   - the DESTINATION (nd): renaming some freshly-written file *over* an
 *     existing binary - the standard atomic "replace a binary" trick, and the
 *     one dpkg/rpm themselves use. If nd names an existing binary, block it.
 */
static int ss_binvault_path_rename(const struct path *odir, struct dentry *od,
				   const struct path *ndir, struct dentry *nd,
				   unsigned int flags)
{
	int ret = dir_dentry_guard(odir, od, "rename-from");

	return ret ? ret : dir_dentry_guard(ndir, nd, "rename-over");
}

/*
 * Hard link. Second-pass-review fix: a protected file is classified partly by
 * its *location* (a .so under a library tree that has no execute bit). A
 * privileged attacker could otherwise hardlink such a library into a writable
 * directory - the new name is NOT under a library tree, so the location test
 * would miss it - and then write through that alias to mutate the real inode's
 * bytes. We refuse to create a new hard link whose SOURCE is a protected
 * binary, so no second, unprotected name to a frozen inode can ever be made.
 * (Executables carry the execute bit on the inode itself, so they are caught
 * by is_protected_binary() through any name regardless; this hook closes the
 * no-exec-bit library case.)
 */
static int ss_binvault_path_link(struct dentry *old_dentry,
				 const struct path *new_dir,
				 struct dentry *new_dentry)
{
	struct inode *inode;
	char *buf, *p;
	int ret = 0;

	if (!READ_ONCE(ss_cfg.binaryvault) || binvault_maint)
		return 0;

	inode = d_backing_inode(old_dentry);
	if (!inode || !S_ISREG(inode->i_mode))
		return 0;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	p = dentry_path_raw(old_dentry, buf, PATH_MAX);
	if (IS_ERR(p))
		ret = -EPERM;			/* fail closed */
	else if (ss_binvault_denies(inode->i_mode, p, "hardlink-source"))
		ret = -EPERM;
	kfree(buf);
	return ret;
}

/*
 * chmod. Changing a binary's mode is a write to its metadata: it can strip the
 * execute bit (to slip a later rewrite past the classifier) or add setuid/
 * setgid. The path hook gives us the live path; resolve and gate it.
 */
static int ss_binvault_path_chmod(const struct path *path, umode_t mode)
{
	char *buf, *p;
	int ret = 0;

	if (!READ_ONCE(ss_cfg.binaryvault) || binvault_maint)
		return 0;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	p = ss_file_path(path, buf, PATH_MAX);
	if (IS_ERR(p))
		ret = -EPERM;
	else if (*p == '/' &&
		 ss_binvault_denies(d_backing_inode(path->dentry)->i_mode,
				    p, "chmod"))
		ret = -EPERM;
	kfree(buf);
	return ret;
}
#endif /* CONFIG_SECURITY_PATH */

/* --------------------------- xattr mutations ----------------------------- */
/*
 * Extended-attribute writes. File capabilities (security.capability) and
 * IMA/EVM labels (security.ima, security.evm) are stored as xattrs, so writing
 * them is another way to change what a binary *is* without changing a byte of
 * its code - e.g. granting a binary CAP_SETUID via setcap. These hooks take an
 * (idmap, dentry, name) triple; we resolve the dentry's path with a temporary
 * struct path built from the dentry and gate it like any other write.
 *
 * We only care about regular-file targets that the classifier calls a binary;
 * xattr writes on directories, configs and data files are none of our
 * business and pass straight through.
 */
static int xattr_guard(struct dentry *dentry, const char *what)
{
	struct inode *inode = d_backing_inode(dentry);
	char *buf, *p;
	int ret = 0;

	if (!READ_ONCE(ss_cfg.binaryvault) || binvault_maint)
		return 0;
	if (!inode || !S_ISREG(inode->i_mode))
		return 0;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	/* dentry_path_raw gives a mount-namespace-independent path; good enough
	 * for the classifier, which only needs the location and basename. */
	p = dentry_path_raw(dentry, buf, PATH_MAX);
	if (IS_ERR(p))
		ret = -EPERM;			/* fail closed */
	else if (ss_binvault_denies(inode->i_mode, p, what))
		ret = -EPERM;
	kfree(buf);
	return ret;
}

static int ss_binvault_inode_setxattr(struct mnt_idmap *idmap,
				      struct dentry *dentry, const char *name,
				      const void *value, size_t size, int flags)
{
	return xattr_guard(dentry, "setxattr");
}

static int ss_binvault_inode_removexattr(struct mnt_idmap *idmap,
					 struct dentry *dentry, const char *name)
{
	return xattr_guard(dentry, "removexattr");
}

/* ------------------------------ hook table ------------------------------- */

static struct security_hook_list ss_binvault_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_open,         ss_binvault_file_open),
	LSM_HOOK_INIT(file_truncate,     ss_binvault_file_truncate),
#ifdef CONFIG_SECURITY_PATH
	LSM_HOOK_INIT(path_unlink,       ss_binvault_path_unlink),
	LSM_HOOK_INIT(path_rename,       ss_binvault_path_rename),
	LSM_HOOK_INIT(path_link,         ss_binvault_path_link),
	LSM_HOOK_INIT(path_chmod,        ss_binvault_path_chmod),
#endif
	LSM_HOOK_INIT(inode_setxattr,    ss_binvault_inode_setxattr),
	LSM_HOOK_INIT(inode_removexattr, ss_binvault_inode_removexattr),
};

void __init ss_binvault_init(void)
{
	security_add_hooks(ss_binvault_hooks, ARRAY_SIZE(ss_binvault_hooks),
			   &ss_lsmid);
}

/* ---------------------------- sysfs knob --------------------------------- */
/*
 * The single scalar toggle, `binaryvault`. Read returns the live value; write
 * is root-only (ss_may_admin), refused once the config lock is latched
 * (ss_locked), and only accepts a boolean. 0600 so no non-root reader even
 * learns the state. This is condition (1) of the gate.
 */
static ssize_t binaryvault_show(struct kobject *k, struct kobj_attribute *a,
				char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.binaryvault));
}
static ssize_t binaryvault_store(struct kobject *k, struct kobj_attribute *a,
				 const char *buf, size_t count)
{
	bool v;

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	WRITE_ONCE(ss_cfg.binaryvault, v);
	return count;
}
static struct kobj_attribute binaryvault_attr =
	__ATTR(binaryvault, 0600, binaryvault_show, binaryvault_store);

/*
 * Read-only mirror of the maintenance boot parameter so `secure-sudo status`
 * can show whether this boot has the vault open. Also 0600.
 */
static ssize_t binvault_maint_show(struct kobject *k, struct kobj_attribute *a,
				   char *buf)
{
	return sysfs_emit(buf, "%d\n", binvault_maint);
}
static struct kobj_attribute binvault_maint_attr =
	__ATTR(binvault_maint, 0400, binvault_maint_show, NULL);

static struct attribute *ss_binvault_attrs[] = {
	&binaryvault_attr.attr,
	&binvault_maint_attr.attr,
	NULL,
};
static const struct attribute_group ss_binvault_group = {
	.attrs = ss_binvault_attrs,
};

int ss_binvault_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_binvault_group);
}

/* ---------------------- securityfs: binvault_allow ----------------------- */
/*
 * Allowlist of directory prefixes exempt from the vault, for genuinely
 * self-updating software (a browser that patches itself under /opt, say). One
 * absolute path per line; '#' comments and blanks ignored. Written as a whole
 * replacement, root-only, and frozen when locked - identical handling to the
 * other secure_sudo policy lists.
 */
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

	list = kcalloc(BV_MAX_ALLOW, sizeof(*list), GFP_KERNEL);
	if (!list)
		return NULL;

	while ((line = strsep(&p, "\n")) && n < BV_MAX_ALLOW) {
		line = strim(line);
		if (*line == '\0' || *line == '#' || *line != '/')
			continue;		/* only absolute paths count */
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

	mutex_lock(&bv_lock);
	ret = simple_read_from_buffer(ubuf, count, ppos,
				      allow_text ? allow_text : "",
				      allow_text_len);
	mutex_unlock(&bv_lock);
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
	if (count > BV_MAX_TEXT)
		return -EFBIG;

	text = kmalloc(count + 1, GFP_KERNEL);
	if (!text)
		return -ENOMEM;
	if (copy_from_user(text, ubuf, count)) {
		kfree(text);
		return -EFAULT;
	}
	text[count] = '\0';

	/* parse_allow tokenises in place, so hand it a throwaway copy and keep
	 * the pristine text for read-back. */
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

	mutex_lock(&bv_lock);
	old_list = allow_list;
	old_count = allow_count;
	old_text = allow_text;
	allow_list = new_list;
	allow_count = new_count;
	allow_text = text;
	allow_text_len = count;
	mutex_unlock(&bv_lock);

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

int ss_binvault_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("binvault_allow", 0600, dir, NULL,
				   &allow_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
	return 0;
}
