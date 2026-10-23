// SPDX-License-Identifier: GPL-2.0
/*
 * ss_creds.c - Protection #1: block non-sudo UID/GID switching.
 *
 * This is the owner's core requirement and the most important protection the
 * v2 LSM had dropped - it only ever existed in v1 (as task_fix_setuid), and
 * even there the hook was never registered. Here it is a real, registered LSM
 * credential hook, extended to cover setgid, setgroups and - the usual way
 * around a UID check - unprivileged user-namespace creation.
 *
 * Model: a change is denied only when the *acting* credentials (the "old"
 * cred, i.e. who the task is right now) are not a sudo user. Legitimate
 * privileged flows (a setuid-root binary such as passwd/su/sudo, which already
 * runs with euid 0 when it calls setuid(); a root daemon dropping privileges)
 * all satisfy ss_cred_is_sudo(old) and pass through untouched. A plain
 * unprivileged process cannot change its IDs anyway (no CAP_SETUID/SETGID), so
 * this hook is defence-in-depth against capability-bearing or namespaced
 * actors, and it is what makes the user-namespace gate meaningful.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/capability.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

/* True if any of the four UIDs differ between the new and old credentials. */
static bool uid_changed(const struct cred *new, const struct cred *old)
{
	return !uid_eq(new->uid,   old->uid)  ||
	       !uid_eq(new->euid,  old->euid) ||
	       !uid_eq(new->suid,  old->suid) ||
	       !uid_eq(new->fsuid, old->fsuid);
}

/* True if any of the four GIDs differ between the new and old credentials. */
static bool gid_changed(const struct cred *new, const struct cred *old)
{
	return !gid_eq(new->gid,   old->gid)  ||
	       !gid_eq(new->egid,  old->egid) ||
	       !gid_eq(new->sgid,  old->sgid) ||
	       !gid_eq(new->fsgid, old->fsgid);
}

static int ss_task_fix_setuid(struct cred *new, const struct cred *old,
			      int flags)
{
	if (!READ_ONCE(ss_cfg.block_setid))
		return 0;
	if (ss_cred_is_sudo(old))
		return 0;
	if (!uid_changed(new, old))
		return 0;

	pr_warn_ratelimited("non-sudo UID %u denied setuid change\n",
			    from_kuid(&init_user_ns, old->uid));
	return -EPERM;
}

static int ss_task_fix_setgid(struct cred *new, const struct cred *old,
			      int flags)
{
	if (!READ_ONCE(ss_cfg.block_setid))
		return 0;
	if (ss_cred_is_sudo(old))
		return 0;
	if (!gid_changed(new, old))
		return 0;

	pr_warn_ratelimited("non-sudo UID %u denied setgid change\n",
			    from_kuid(&init_user_ns, old->uid));
	return -EPERM;
}

static int ss_task_fix_setgroups(struct cred *new, const struct cred *old)
{
	if (!READ_ONCE(ss_cfg.block_setid))
		return 0;
	if (ss_cred_is_sudo(old))
		return 0;

	pr_warn_ratelimited("non-sudo UID %u denied setgroups change\n",
			    from_kuid(&init_user_ns, old->uid));
	return -EPERM;
}

/*
 * Unprivileged user namespaces are the standard route around a UID check: a
 * user becomes root inside a new namespace and from there can hold
 * CAP_SETUID/SETGID. Gating creation keeps the UID/GID block from being a
 * paper wall. @cred is the creating task's current credentials.
 */
static int ss_userns_create(const struct cred *cred)
{
	if (!READ_ONCE(ss_cfg.block_userns))
		return 0;
	if (ss_cred_is_sudo(cred))
		return 0;

	pr_warn_ratelimited("non-sudo UID %u denied user-namespace creation\n",
			    from_kuid(&init_user_ns, cred->uid));
	return -EPERM;
}

static struct security_hook_list ss_creds_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(task_fix_setuid,    ss_task_fix_setuid),
	LSM_HOOK_INIT(task_fix_setgid,    ss_task_fix_setgid),
	LSM_HOOK_INIT(task_fix_setgroups, ss_task_fix_setgroups),
	LSM_HOOK_INIT(userns_create,      ss_userns_create),
};

void __init ss_creds_init(void)
{
	security_add_hooks(ss_creds_hooks, ARRAY_SIZE(ss_creds_hooks),
			   &ss_lsmid);
}

/* ---------------------------- sysfs knobs -------------------------------- */

static ssize_t admin_gid_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	u32 v = READ_ONCE(ss_cfg.admin_gid);

	if (v == SS_GID_UNSET)
		return sysfs_emit(buf, "unset\n");
	return sysfs_emit(buf, "%u\n", v);
}

static ssize_t admin_gid_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	u32 v;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (ss_locked())
		return -EPERM;

	/* Accept "unset" to return to root-only, or a numeric GID. */
	if (sysfs_streq(buf, "unset")) {
		v = SS_GID_UNSET;
	} else if (kstrtou32(buf, 10, &v)) {
		return -EINVAL;
	}

	WRITE_ONCE(ss_cfg.admin_gid, v);
	return count;
}

static ssize_t block_setid_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.block_setid));
}

static ssize_t block_setid_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	bool v;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;

	WRITE_ONCE(ss_cfg.block_setid, v);
	return count;
}

static ssize_t block_userns_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.block_userns));
}

static ssize_t block_userns_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	bool v;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;

	WRITE_ONCE(ss_cfg.block_userns, v);
	return count;
}

static struct kobj_attribute admin_gid_attr =
	__ATTR(admin_gid, 0644, admin_gid_show, admin_gid_store);
static struct kobj_attribute block_setid_attr =
	__ATTR(block_setid, 0644, block_setid_show, block_setid_store);
static struct kobj_attribute block_userns_attr =
	__ATTR(block_userns, 0644, block_userns_show, block_userns_store);

static struct attribute *ss_creds_attrs[] = {
	&admin_gid_attr.attr,
	&block_setid_attr.attr,
	&block_userns_attr.attr,
	NULL,
};

static const struct attribute_group ss_creds_group = {
	.attrs = ss_creds_attrs,
};

int ss_creds_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_creds_group);
}
