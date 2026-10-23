// SPDX-License-Identifier: GPL-2.0
/*
 * ss_core.c - secure_sudo LSM core: registration, config, shared helpers.
 *
 * The LSM .init callback runs during security_init(), very early in boot and
 * well before sysfs is usable, so it only sets defaults and registers hooks.
 * A separate late_initcall builds the /sys/kernel/secure_sudo tree once the
 * driver model is up.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/security.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/string.h>
#include <linux/kernel_read_file.h>
#include <linux/sizes.h>
#include <linux/lsm_hooks.h>
#include <crypto/sha2.h>

#include "secure_sudo.h"

struct ss_cfg ss_cfg;
DEFINE_MUTEX(ss_cfg_lock);

/* #16 one-way lock. 0 = unlocked, 1 = locked. Only ss_lock_engage() writes it
 * and it only ever writes 1; there is no unlock path anywhere in the kernel. */
atomic_t ss_lock_state = ATOMIC_INIT(0);

const struct lsm_id ss_lsmid = {
	.name = SS_NAME,
	.id   = LSM_ID_SECURE_SUDO,
};

/* /sys/kernel/secure_sudo - root of the scalar knobs. */
static struct kobject *ss_kobj;
/* /sys/kernel/security/secure_sudo - root of the securityfs policy files. */
static struct dentry *ss_secfs_dir;

struct ss_admin_gids {
	struct rcu_head rcu;
	unsigned int n;
	u32 gid[SS_MAX_ADMIN_GIDS];
};

/* Admin-GID list. NULL = none configured (root-only). Readers use RCU so the
 * credential hooks never see a half-updated list; writers hold ss_cfg_lock. */
static struct ss_admin_gids __rcu *ss_admin;

static bool kgid_in_list(kgid_t g, const struct ss_admin_gids *a)
{
	u32 v = from_kgid(&init_user_ns, g);
	unsigned int i;

	for (i = 0; i < a->n; i++)
		if (a->gid[i] == v)
			return true;
	return false;
}

bool ss_cred_is_sudo(const struct cred *cred)
{
	const struct ss_admin_gids *a;
	const struct group_info *gi;
	unsigned int i;
	bool ok = false;

	if (!cred)
		return false;

	/* Root by real or effective UID is always privileged. */
	if (uid_eq(cred->uid, GLOBAL_ROOT_UID) ||
	    uid_eq(cred->euid, GLOBAL_ROOT_UID))
		return true;

	rcu_read_lock();
	a = rcu_dereference(ss_admin);
	if (!a || !a->n)
		goto out;

	/* Real, effective or fs GID in the admin list. */
	if (kgid_in_list(cred->gid, a) || kgid_in_list(cred->egid, a) ||
	    kgid_in_list(cred->fsgid, a)) {
		ok = true;
		goto out;
	}

	/* Supplementary groups. */
	gi = cred->group_info;
	if (gi) {
		for (i = 0; i < gi->ngroups; i++) {
			if (kgid_in_list(gi->gid[i], a)) {
				ok = true;
				break;
			}
		}
	}
out:
	rcu_read_unlock();
	return ok;
}

int ss_set_admin_gids(const u32 *gids, unsigned int n)
{
	struct ss_admin_gids *new = NULL, *old;

	/* Step 1: bound the list to the fixed-size array; refuse an oversize set
	 * rather than truncating silently. */
	if (n > SS_MAX_ADMIN_GIDS)
		return -E2BIG;
	/* Step 2: build the replacement list off to the side. n == 0 is valid and
	 * means "root only" - we install a NULL pointer for that. */
	if (n) {
		new = kzalloc(sizeof(*new), GFP_KERNEL);
		if (!new)
			return -ENOMEM;
		new->n = n;
		memcpy(new->gid, gids, n * sizeof(u32));
	}

	/* Step 3: swap it in under the config mutex. rcu_assign_pointer() publishes
	 * the fully-built list with the right barrier, so a concurrent lockless
	 * reader in ss_cred_is_sudo() sees either the whole old or the whole new
	 * list, never a half-written one. */
	mutex_lock(&ss_cfg_lock);
	old = rcu_dereference_protected(ss_admin, lockdep_is_held(&ss_cfg_lock));
	rcu_assign_pointer(ss_admin, new);
	mutex_unlock(&ss_cfg_lock);

	/* Step 4: free the old list only after a grace period, once no reader can
	 * still hold a reference to it. */
	if (old)
		kfree_rcu(old, rcu);
	return 0;
}

ssize_t ss_show_admin_gids(char *buf)
{
	const struct ss_admin_gids *a;
	ssize_t len = 0;
	unsigned int i;

	rcu_read_lock();
	a = rcu_dereference(ss_admin);
	if (!a || !a->n) {
		len = sysfs_emit(buf, "unset\n");
	} else {
		for (i = 0; i < a->n; i++)
			len += sysfs_emit_at(buf, len, "%s%u", i ? "," : "",
					     a->gid[i]);
		len += sysfs_emit_at(buf, len, "\n");
	}
	rcu_read_unlock();
	return len;
}

/* ----------------------------- shared helpers ----------------------------- */

bool ss_may_admin(const struct file *file)
{
	/* Step 1: the *acting* task must hold CAP_SYS_ADMIN in the initial user
	 * namespace. capable() checks the current task against init_user_ns, so
	 * a token forged inside an unprivileged user namespace does not count. */
	if (!capable(CAP_SYS_ADMIN))
		return false;
	/* Step 2: for a securityfs/sysfs write, also require that the credentials
	 * the *file was opened with* hold the capability. This defeats the
	 * confused-deputy where a low-priv process opens the control file and
	 * hands the fd to a privileged one (or the reverse). A NULL file means a
	 * direct sysfs store with no separate opener to check. */
	return !file || file_ns_capable(file, &init_user_ns, CAP_SYS_ADMIN);
}

char *ss_file_path(const struct path *path, char *buf, int buflen)
{
	/* Step 1: prefer d_absolute_path() - it renders the path relative to the
	 * mount-namespace root, so a chrooted task cannot make /jail/usr/bin/x
	 * read as /usr/bin/x and slip past a path check. */
	char *p = d_absolute_path(path, buf, buflen);

	/* Step 2: pseudo files (memfd, pipes, anon inodes) have no absolute path;
	 * fall back to d_path() so callers at least get a stable "anon_inode:..."
	 * style string rather than an error they would have to special-case. */
	if (IS_ERR(p))
		p = d_path(path, buf, buflen);
	return p;
}

bool ss_path_under(const char *path, const char *prefix)
{
	size_t pl = strlen(prefix);

	/* Step 1: the prefix must be a leading substring of the path at all. */
	if (!pl || strncmp(path, prefix, pl) != 0)
		return false;
	/* Step 2: guard against a partial component match: "/tmp/build" must
	 * cover "/tmp/build" and "/tmp/build/x" but NOT "/tmp/buildx". The byte
	 * just past the prefix therefore has to be end-of-string or '/', unless
	 * the prefix itself already ended in '/' (then any child matches). */
	return path[pl] == '\0' || path[pl] == '/' || prefix[pl - 1] == '/';
}

void ss_sha256_buf(const void *data, size_t len, char *hex)
{
	struct sha256_state st;
	u8 digest[SHA256_DIGEST_SIZE];
	const u8 *p = data;

	sha256_init(&st);
	while (len) {
		unsigned int n = min_t(size_t, len, SZ_1M);

		sha256_update(&st, p, n);
		p += n;
		len -= n;
	}
	sha256_final(&st, digest);
	bin2hex(hex, digest, sizeof(digest));
	hex[2 * SHA256_DIGEST_SIZE] = '\0';
	memzero_explicit(&st, sizeof(st));
}

/* --------------------------- #16 config lock ----------------------------- */

void ss_lock_engage(const char *why)
{
	if (atomic_cmpxchg(&ss_lock_state, 0, 1) == 0) {
		pr_warn("configuration LOCKED until reboot (%s)\n", why);
		ss_event("lock: engaged by %s; config frozen until reboot", why);
	}
}

static ssize_t lock_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	return sysfs_emit(buf, "%d\n", ss_locked());
}

/*
 * One-way switch. Writing a true value latches the lock; it can only be
 * cleared by rebooting. Any attempt to write a false value is refused (with
 * -EPERM once locked, so the caller learns it is locked, -EINVAL before) and
 * logged - there is deliberately no code path that unlocks.
 */
static ssize_t lock_store(struct kobject *kobj, struct kobj_attribute *attr,
			  const char *buf, size_t count)
{
	bool v;

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	if (!v) {
		if (ss_locked()) {
			pr_warn_ratelimited("refused attempt to unlock config (UID %u)\n",
					    from_kuid(&init_user_ns, current_uid()));
			ss_event("lock: refused unlock attempt by UID %u",
				 from_kuid(&init_user_ns, current_uid()));
			return -EPERM;
		}
		return -EINVAL;
	}
	ss_lock_engage("lock command");
	return count;
}

static ssize_t lock_modules_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.lock_modules));
}

static ssize_t lock_modules_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	bool v;

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	WRITE_ONCE(ss_cfg.lock_modules, v);
	return count;
}

static struct kobj_attribute lock_attr =
	__ATTR(lock, 0600, lock_show, lock_store);
static struct kobj_attribute lock_modules_attr =
	__ATTR(lock_modules, 0600, lock_modules_show, lock_modules_store);

static struct attribute *ss_core_attrs[] = {
	&lock_attr.attr,
	&lock_modules_attr.attr,
	NULL,
};

static const struct attribute_group ss_core_group = {
	.attrs = ss_core_attrs,
};

/*
 * While locked, close the doors a root attacker would use to undo the lock
 * without rebooting: patching kernel memory (/dev/mem, /dev/kmem, kprobes
 * writes, BPF write_user, debugfs writes, ioport/MSR pokes), replacing the
 * kernel without a reboot (kexec), restoring a crafted image (hibernation),
 * and loading code (modules) or new trust anchors (IMA policy, x509 keys).
 * These are exactly the kernel lockdown "integrity" reasons, so we answer the
 * locked_down hook for that whole class; firmware loads stay allowed so
 * hotplugged hardware still works.
 */
static int ss_lock_locked_down(enum lockdown_reason what)
{
	if (!ss_locked())
		return 0;
	if (what > LOCKDOWN_NONE && what < LOCKDOWN_INTEGRITY_MAX) {
		pr_warn_ratelimited("locked: denied %s\n", lockdown_reasons[what]);
		return -EPERM;
	}
	return 0;
}

static int ss_lock_load_id(int is_module, int is_kexec, int is_trust,
			   const char *what)
{
	if (!ss_locked())
		return 0;
	if (is_kexec || is_trust ||
	    (is_module && READ_ONCE(ss_cfg.lock_modules))) {
		pr_warn_ratelimited("locked: denied %s load\n", what);
		ss_event("lock: denied %s load", what);
		return -EPERM;
	}
	return 0;
}

static int ss_lock_read_file(struct file *file, enum kernel_read_file_id id,
			     bool contents)
{
	return ss_lock_load_id(id == READING_MODULE,
			       id == READING_KEXEC_IMAGE ||
			       id == READING_KEXEC_INITRAMFS,
			       id == READING_POLICY ||
			       id == READING_X509_CERTIFICATE,
			       kernel_read_file_id_str(id));
}

static int ss_lock_load_data(enum kernel_load_data_id id, bool contents)
{
	return ss_lock_load_id(id == LOADING_MODULE,
			       id == LOADING_KEXEC_IMAGE ||
			       id == LOADING_KEXEC_INITRAMFS,
			       id == LOADING_POLICY ||
			       id == LOADING_X509_CERTIFICATE,
			       kernel_load_data_id_str(id));
}

static struct security_hook_list ss_lock_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(locked_down,      ss_lock_locked_down),
	LSM_HOOK_INIT(kernel_read_file, ss_lock_read_file),
	LSM_HOOK_INIT(kernel_load_data, ss_lock_load_data),
};

void __init ss_lock_init(void)
{
	security_add_hooks(ss_lock_hooks, ARRAY_SIZE(ss_lock_hooks), &ss_lsmid);
}

/* ------------------------------------------------------------------------- */

static int __init ss_lsm_init(void)
{
	/* Safe defaults: no admin GIDs (root-only) until `secure-sudo load` at
	 * boot pushes the installer-detected list; #1 enforcement toggles on. */
	ss_cfg.block_setid  = true;
	ss_cfg.block_userns = true;
	ss_cfg.block_flash  = true;

	ss_cfg.lock_modules = true;	/* a locked box loads no new code */
	ss_cfg.block_setid_exec = false;	/* conf turns it on with the allowlist */
	ss_cfg.block_tmpfs_exec = false;	/* conf turns it on */
	ss_cfg.timevault_strict_mmap = false;

	ss_cfg.max_ram_percent   = 90;
	ss_cfg.check_interval_ms = 5000;
	ss_cfg.drop_cooldown_ms  = 2000;
	ss_cfg.ram_spike_enabled = false;	/* opt-in: it drops caches */

	ss_cfg.net_mode = SS_NET_MONITOR;

	ss_cfg.block_tmp_exec = true;

	ss_cfg.sudo_max_fails       = 5;
	ss_cfg.sudo_window_sec      = 60;
	ss_cfg.sudo_block_time_sec  = 300;
	ss_cfg.sudo_cooldown_enabled = true;

	ss_cfg.timevault_enabled = false;

	ss_cfg.block_home_write = false;	/* #4 is aggressive: opt-in */
	ss_cfg.binaryvault = false;	/* #17: conf turns it on at boot via load */
	ss_cfg.block_wifi = false;	/* #19 RadioGuard: opt-in */
	ss_cfg.block_bluetooth = false;
	ss_cfg.ethernet_only = false;

	/* Register each protection's hooks. */
	ss_lock_init();
	ss_creds_init();
	ss_exec_init();
	ss_firmware_init();
	ss_tpm_init();
	ss_tmpexec_init();
	ss_net_init();
	ss_node_init();
	ss_cooldown_init();
	ss_driver_init();
	ss_timevault_init();
	ss_home_init();
	ss_binvault_init();
	ss_radio_init();

	pr_info("LSM initialised (id=0x%llx)\n", (unsigned long long)ss_lsmid.id);
	return 0;
}

DEFINE_LSM(secure_sudo) = {
	.name  = SS_NAME,
	.init  = ss_lsm_init,
	.blobs = &ss_blob_sizes,	/* #11 per-task blob (defined in ss_node.c) */
};

/* ------------------------------------------------------------------------- */

static int __init ss_sysfs_init(void)
{
	int ret;

	ss_kobj = kobject_create_and_add(SS_NAME, kernel_kobj);
	if (!ss_kobj) {
		pr_err("failed to create /sys/kernel/%s\n", SS_NAME);
		return -ENOMEM;
	}

	ret = sysfs_create_group(ss_kobj, &ss_core_group);
	if (!ret)
		ret = ss_creds_sysfs(ss_kobj);
	if (!ret)
		ret = ss_firmware_sysfs(ss_kobj);
	if (!ret)
		ret = ss_ram_sysfs(ss_kobj);
	if (!ret)
		ret = ss_tmpexec_sysfs(ss_kobj);
	if (!ret)
		ret = ss_net_sysfs(ss_kobj);
	if (!ret)
		ret = ss_cooldown_sysfs(ss_kobj);
	if (!ret)
		ret = ss_timevault_sysfs(ss_kobj);
	if (!ret)
		ret = ss_home_sysfs(ss_kobj);
	if (!ret)
		ret = ss_binvault_sysfs(ss_kobj);
	if (!ret)
		ret = ss_radio_sysfs(ss_kobj);
	if (ret) {
		pr_err("failed to create sysfs knobs (%d)\n", ret);
		kobject_put(ss_kobj);
		ss_kobj = NULL;
		return ret;
	}

	/* securityfs tree for policy files. */
	ss_secfs_dir = securityfs_create_dir(SS_NAME, NULL);
	if (IS_ERR(ss_secfs_dir)) {
		pr_err("failed to create securityfs dir (%ld)\n",
		       PTR_ERR(ss_secfs_dir));
		ss_secfs_dir = NULL;
	} else {
		ret = ss_log_secfs(ss_secfs_dir);
		if (!ret)
			ret = ss_exec_secfs(ss_secfs_dir);
		if (!ret)
			ret = ss_tmpexec_secfs(ss_secfs_dir);
		if (!ret)
			ret = ss_node_secfs(ss_secfs_dir);
		if (!ret)
			ret = ss_cooldown_secfs(ss_secfs_dir);
		if (!ret)
			ret = ss_driver_secfs(ss_secfs_dir);
		if (!ret)
			ret = ss_timevault_secfs(ss_secfs_dir);
		if (!ret)
			ret = ss_home_secfs(ss_secfs_dir);
		if (!ret)
			ret = ss_binvault_secfs(ss_secfs_dir);
		if (ret)
			pr_err("failed to create securityfs policy files (%d)\n",
			       ret);
	}

	/* Start the RAM-spike worker now that the workqueue is up. */
	ss_ram_start();

	pr_info("sysfs knobs ready under /sys/kernel/%s\n", SS_NAME);
	return 0;
}
late_initcall(ss_sysfs_init);
