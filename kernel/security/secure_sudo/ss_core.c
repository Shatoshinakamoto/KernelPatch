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
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

struct ss_cfg ss_cfg;
DEFINE_MUTEX(ss_cfg_lock);

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

	if (n > SS_MAX_ADMIN_GIDS)
		return -E2BIG;
	if (n) {
		new = kzalloc(sizeof(*new), GFP_KERNEL);
		if (!new)
			return -ENOMEM;
		new->n = n;
		memcpy(new->gid, gids, n * sizeof(u32));
	}

	mutex_lock(&ss_cfg_lock);
	old = rcu_dereference_protected(ss_admin, lockdep_is_held(&ss_cfg_lock));
	rcu_assign_pointer(ss_admin, new);
	mutex_unlock(&ss_cfg_lock);

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

/* --------------------------- #16 config lock ----------------------------- */

static ssize_t lock_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	return sysfs_emit(buf, "%d\n", ss_locked());
}

/*
 * One-way switch: writing a true value locks the config; it can only be
 * cleared by rebooting. TimeVault sets this automatically when it engages.
 */
static ssize_t lock_store(struct kobject *kobj, struct kobj_attribute *attr,
			  const char *buf, size_t count)
{
	bool v;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	if (v)
		WRITE_ONCE(ss_cfg.locked, true);	/* latch; never unset here */
	return count;
}

static struct kobj_attribute lock_attr =
	__ATTR(lock, 0644, lock_show, lock_store);

static struct attribute *ss_core_attrs[] = {
	&lock_attr.attr,
	NULL,
};

static const struct attribute_group ss_core_group = {
	.attrs = ss_core_attrs,
};

/* ------------------------------------------------------------------------- */

static int __init ss_lsm_init(void)
{
	/* Safe defaults: no admin GIDs (root-only) until `secure-sudo load` at
	 * boot pushes the installer-detected list; #1 enforcement toggles on. */
	ss_cfg.block_setid  = true;
	ss_cfg.block_userns = true;
	ss_cfg.block_flash  = true;

	ss_cfg.locked = false;

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

	/* Register each protection's hooks. */
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
