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
 * allowlist and the denied-attempt counter; the daemon owns the Merkle tree
 * over watched trees, moving new/changed files into
 * /var/lib/secure_sudo/quarantine/*.zip, and shipping logs off-box (so a
 * locked-down host cannot have its logs wiped). The TODO said "wipe" new files;
 * we quarantine instead - a wipe is irreversible and destroys the evidence -
 * and the daemon keeps vault_action=wipe available as an opt-in.
 *
 * Allowlist entries are "path" or "path <sha256hex>"; when a hash is given the
 * file's contents must match it, so a tampered binary at an allowed path is
 * still denied.
 *
 * Engaging the vault latches the one-way config lock (#16). Disengaging is
 * permitted even while locked, so an admin at the console is never stranded.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/limits.h>
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
	char hash[SHA256_HEX + 1];	/* empty string = no hash required */
};

static DEFINE_MUTEX(tv_lock);
static struct tv_entry *tv_list;
static int tv_count;
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

/* Look up @path; return the entry (still under tv_lock) or NULL. */
static struct tv_entry *tv_find_locked(const char *path)
{
	int i;

	for (i = 0; i < tv_count; i++)
		if (!strcmp(path, tv_list[i].path))
			return &tv_list[i];
	return NULL;
}

static void tv_deny(const char *base, const char *why)
{
	atomic_long_inc(&tv_denied);
	pr_warn_ratelimited("timevault: denied %s (%s)\n", base, why);
	ss_event("timevault: denied exec %s (%s)", base, why);
}

static int ss_timevault_bprm(struct linux_binprm *bprm)
{
	char *buf, *resolved;
	const char *base;
	struct tv_entry *e;
	char want_hash[SHA256_HEX + 1] = "";
	bool need_hash = false;
	int ret = 0;

	if (!READ_ONCE(ss_cfg.timevault_enabled))
		return 0;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -EPERM;		/* fail CLOSED: vault is a deny-all state */

	resolved = d_path(&bprm->file->f_path, buf, PATH_MAX);
	if (IS_ERR(resolved)) {
		kfree(buf);
		return -EPERM;
	}
	base = kbasename(resolved);

	/* Package managers: never, even if allowlisted. */
	if (is_pkg_manager(base)) {
		tv_deny(base, "package manager");
		kfree(buf);
		return -EPERM;
	}

	mutex_lock(&tv_lock);
	e = tv_find_locked(resolved);
	if (!e) {
		mutex_unlock(&tv_lock);
		tv_deny(base, "not on allowlist");
		kfree(buf);
		return -EPERM;
	}
	if (e->hash[0]) {
		need_hash = true;
		memcpy(want_hash, e->hash, sizeof(want_hash));
	}
	mutex_unlock(&tv_lock);

	/* Verify contents if the entry pins a hash. */
	if (need_hash) {
		char got[SHA256_HEX + 1];

		if (ss_sha256_file(bprm->file, got) != 0 ||
		    strcasecmp(got, want_hash) != 0) {
			tv_deny(base, "hash mismatch");
			ret = -EPERM;
		}
	}

	kfree(buf);
	return ret;
}

static struct security_hook_list ss_tv_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, ss_timevault_bprm),
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

static ssize_t timevault_store(struct kobject *k, struct kobj_attribute *a,
			       const char *buf, size_t count)
{
	bool v;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;

	/*
	 * Deliberately NOT gated on ss_locked(): the vault must be
	 * disengageable by a console admin even after it latched the lock.
	 * Engaging it latches the config lock so no other knob can be changed.
	 */
	if (v) {
		WRITE_ONCE(ss_cfg.timevault_enabled, true);
		WRITE_ONCE(ss_cfg.locked, true);
		pr_warn("timevault: ENGAGED - exec restricted to allowlist, config locked\n");
		ss_event("timevault: engaged");
	} else {
		WRITE_ONCE(ss_cfg.timevault_enabled, false);
		pr_warn("timevault: disengaged (config stays locked until reboot)\n");
		ss_event("timevault: disengaged");
	}
	return count;
}

static struct kobj_attribute timevault_attr =
	__ATTR(timevault, 0644, timevault_show, timevault_store);

static ssize_t timevault_denied_show(struct kobject *k,
				     struct kobj_attribute *a, char *buf)
{
	return sysfs_emit(buf, "%ld\n", atomic_long_read(&tv_denied));
}
static struct kobj_attribute timevault_denied_attr =
	__ATTR(timevault_denied, 0444, timevault_denied_show, NULL);

static struct attribute *ss_tv_attrs[] = {
	&timevault_attr.attr,
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

static struct tv_entry *tv_parse(char *text, int *out_count)
{
	struct tv_entry *list;
	char *p = text, *line;
	int n = 0;

	list = kvcalloc(TV_MAX_ITEMS, sizeof(*list), GFP_KERNEL);
	if (!list)
		return NULL;

	while ((line = strsep(&p, "\n")) && n < TV_MAX_ITEMS) {
		char *sp;

		line = strim(line);
		if (*line == '\0' || *line == '#' || *line != '/')
			continue;

		/* Optional "<path> <sha256hex>" - split on first space. */
		sp = strchr(line, ' ');
		if (sp) {
			*sp = '\0';
			sp = strim(sp + 1);
		}

		list[n].path = kstrdup(line, GFP_KERNEL);
		if (!list[n].path) {
			tv_free(list, n);
			return NULL;
		}
		if (sp && strlen(sp) == SHA256_HEX) {
			memcpy(list[n].hash, sp, SHA256_HEX);
			list[n].hash[SHA256_HEX] = '\0';
		} else {
			list[n].hash[0] = '\0';
		}
		n++;
	}
	*out_count = n;
	return list;
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
	char *text, *scratch;
	struct tv_entry *new_list, *old_list;
	int new_count, old_count;
	char *old_text;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	/* Once locked, the allowlist is frozen like every other knob; the
	 * recovery path is to disengage the vault, not to edit it in place. */
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
	new_list = tv_parse(scratch, &new_count);
	kvfree(scratch);
	if (!new_list) {
		kvfree(text);
		return -ENOMEM;
	}

	mutex_lock(&tv_lock);
	old_list = tv_list;
	old_count = tv_count;
	old_text = tv_text;
	tv_list = new_list;
	tv_count = new_count;
	tv_text = text;
	tv_text_len = count;
	mutex_unlock(&tv_lock);

	tv_free(old_list, old_count);
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
