// SPDX-License-Identifier: GPL-2.0
/*
 * ss_cooldown.c - Protection #8: sudo brute-force cooldown.
 *
 * The honest constraint, which v2 papered over: the kernel cannot see whether
 * a sudo/su password was right or wrong - that verdict lives in PAM. So the
 * feed comes from userspace: a pam_secure_sudo module in the auth stack writes
 * "fail <uid>" or "ok <uid>" to /sys/kernel/security/secure_sudo/sudo_auth.
 * The kernel keeps the per-UID counters and, once a UID trips the threshold
 * inside the window, denies it from exec'ing sudo/su for the block period. The
 * daemon is what actually freezes and kills the offending process tree
 * (SIGSTOP then SIGKILL); the kernel's job is to slam the door on retries.
 *
 * v2 kept a similar hashtable but nothing ever fed it, and it read cfg without
 * locking. Here a spinlock guards the table and the feed drives it.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

static DEFINE_SPINLOCK(fail_lock);
static DEFINE_HASHTABLE(fail_table, 7);		/* 128 buckets */

struct fail_entry {
	uid_t uid;
	u32 fails;
	unsigned long window_start;
	unsigned long block_until;		/* 0 = not blocked */
	struct hlist_node node;
};

static struct fail_entry *find_locked(uid_t uid)
{
	struct fail_entry *e;

	hash_for_each_possible(fail_table, e, node, uid)
		if (e->uid == uid)
			return e;
	return NULL;
}

static void record_failure(uid_t uid)
{
	struct fail_entry *e;
	unsigned long now = jiffies;
	u32 max_fails = READ_ONCE(ss_cfg.sudo_max_fails);
	u32 window = READ_ONCE(ss_cfg.sudo_window_sec);
	u32 blktime = READ_ONCE(ss_cfg.sudo_block_time_sec);

	spin_lock(&fail_lock);
	e = find_locked(uid);
	if (!e) {
		e = kzalloc(sizeof(*e), GFP_ATOMIC);
		if (!e) {
			spin_unlock(&fail_lock);
			return;
		}
		e->uid = uid;
		e->window_start = now;
		hash_add(fail_table, &e->node, uid);
	}

	/* Already blocked and still within the block window: nothing to do. */
	if (e->block_until && time_before(now, e->block_until)) {
		spin_unlock(&fail_lock);
		return;
	}

	/* Slide the window. */
	if (time_after(now, e->window_start + (unsigned long)window * HZ)) {
		e->fails = 0;
		e->window_start = now;
		e->block_until = 0;
	}

	if (++e->fails >= max_fails) {
		e->block_until = now + (unsigned long)blktime * HZ;
		pr_warn_ratelimited("cooldown: UID %u blocked from sudo for %us (%u fails)\n",
				    uid, blktime, e->fails);
		ss_event("cooldown: UID %u blocked from sudo %us after %u fails",
			 uid, blktime, e->fails);
	}
	spin_unlock(&fail_lock);
}

static void record_success(uid_t uid)
{
	struct fail_entry *e;

	spin_lock(&fail_lock);
	e = find_locked(uid);
	if (e) {
		e->fails = 0;
		e->block_until = 0;
	}
	spin_unlock(&fail_lock);
}

static bool is_blocked(uid_t uid)
{
	struct fail_entry *e;
	bool blocked = false;

	spin_lock(&fail_lock);
	e = find_locked(uid);
	if (e && e->block_until && time_before(jiffies, e->block_until))
		blocked = true;
	spin_unlock(&fail_lock);
	return blocked;
}

/* ------------------------------- hook ------------------------------------ */

static int ss_cooldown_bprm(struct linux_binprm *bprm)
{
	const char *base = kbasename(bprm->filename);
	uid_t uid;

	if (!READ_ONCE(ss_cfg.sudo_cooldown_enabled))
		return 0;
	if (strcmp(base, "sudo") && strcmp(base, "su"))
		return 0;

	uid = from_kuid(&init_user_ns, current_uid());
	if (is_blocked(uid)) {
		pr_warn_ratelimited("cooldown: UID %u denied %s (in cooldown)\n",
				    uid, base);
		ss_event("cooldown: UID %u denied %s (cooldown active)", uid,
			 base);
		return -EPERM;
	}
	return 0;
}

static struct security_hook_list ss_cooldown_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, ss_cooldown_bprm),
};

void __init ss_cooldown_init(void)
{
	security_add_hooks(ss_cooldown_hooks, ARRAY_SIZE(ss_cooldown_hooks),
			   &ss_lsmid);
}

/* ---------------------------- sysfs knobs -------------------------------- */

#define CD_U32_ATTR(field)						\
static ssize_t field##_show(struct kobject *k, struct kobj_attribute *a,\
			    char *buf)					\
{									\
	return sysfs_emit(buf, "%u\n", READ_ONCE(ss_cfg.field));	\
}									\
static ssize_t field##_store(struct kobject *k, struct kobj_attribute *a,\
			     const char *buf, size_t count)		\
{									\
	u32 v;								\
	if (!capable(CAP_SYS_ADMIN))					\
		return -EPERM;						\
	if (ss_locked())						\
		return -EPERM;						\
	if (kstrtou32(buf, 10, &v))					\
		return -EINVAL;						\
	WRITE_ONCE(ss_cfg.field, v);					\
	return count;							\
}									\
static struct kobj_attribute field##_attr =				\
	__ATTR(field, 0644, field##_show, field##_store)

CD_U32_ATTR(sudo_max_fails);
CD_U32_ATTR(sudo_window_sec);
CD_U32_ATTR(sudo_block_time_sec);

static ssize_t sudo_cooldown_enabled_show(struct kobject *k,
					  struct kobj_attribute *a, char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.sudo_cooldown_enabled));
}
static ssize_t sudo_cooldown_enabled_store(struct kobject *k,
					   struct kobj_attribute *a,
					   const char *buf, size_t count)
{
	bool v;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	WRITE_ONCE(ss_cfg.sudo_cooldown_enabled, v);
	return count;
}
static struct kobj_attribute sudo_cooldown_enabled_attr =
	__ATTR(sudo_cooldown_enabled, 0644,
	       sudo_cooldown_enabled_show, sudo_cooldown_enabled_store);

static struct attribute *ss_cd_attrs[] = {
	&sudo_max_fails_attr.attr,
	&sudo_window_sec_attr.attr,
	&sudo_block_time_sec_attr.attr,
	&sudo_cooldown_enabled_attr.attr,
	NULL,
};
static const struct attribute_group ss_cd_group = {
	.attrs = ss_cd_attrs,
};

int ss_cooldown_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_cd_group);
}

/* ------------------------ securityfs: PAM feed --------------------------- */

static ssize_t auth_write(struct file *file, const char __user *ubuf,
			  size_t count, loff_t *ppos)
{
	char kbuf[64];
	char verb[8];
	unsigned int uid;

	/* Only root (the PAM module runs in the auth stack) may feed this. */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (sscanf(kbuf, "%7s %u", verb, &uid) != 2)
		return -EINVAL;

	if (!strcmp(verb, "fail"))
		record_failure(uid);
	else if (!strcmp(verb, "ok"))
		record_success(uid);
	else
		return -EINVAL;

	return count;
}

static const struct file_operations auth_fops = {
	.write  = auth_write,
	.llseek = noop_llseek,
};

int ss_cooldown_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("sudo_auth", 0200, dir, NULL, &auth_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
	return 0;
}
