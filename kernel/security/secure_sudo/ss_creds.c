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
 *
 * #1b closes the remaining door: a non-sudo user gaining a new identity by
 * *executing* a setuid/setgid or file-capability binary (su, newgrp, pkexec,
 * ...). That transition never goes through task_fix_setuid - the exec itself
 * computes the new creds - so it is gated at bprm_creds_from_file, after the
 * commoncap LSM has filled in bprm->cred. A non-sudo exec that would raise
 * euid/egid or the permitted capability set is denied unless the resolved
 * program is on setid_exec_allow. This is what stops a non-sudo user who
 * knows another account's password from "su"-ing to it, and it removes the
 * entire setuid attack surface (CVE-2021-4034 PwnKit in pkexec, CVE-2021-3156
 * Baron Samedit in sudoedit, CVE-2023-4911 Looney Tunables via setuid ld.so
 * env handling) from non-sudo users except for the few binaries they need.
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
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/mutex.h>
#include <linux/sort.h>
#include <linux/bsearch.h>
#include <linux/uaccess.h>
#include <linux/limits.h>
#include <linux/security.h>
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
	/* This hook fires on the credential-changing path of setuid()/setreuid()/
	 * setresuid() etc., giving us the proposed (new) and current (old) creds
	 * before the change commits. Decision, cheapest test first:
	 * Step 1: feature off -> allow (one lockless read on the hot path). */
	if (!READ_ONCE(ss_cfg.block_setid))
		return 0;
	/* Step 2: sudo users (root or an admin GID) are never restricted. We test
	 * the OLD creds: the question is whether the actor was privileged, not
	 * what they are trying to become. */
	if (ss_cred_is_sudo(old))
		return 0;
	/* Step 3: allow a no-op that changes none of the four UIDs (programs call
	 * setuid() to their current uid routinely). Only a real UID transition by
	 * a non-sudo user is the attack we block. */
	if (!uid_changed(new, old))
		return 0;

	pr_warn_ratelimited("non-sudo UID %u denied setuid change\n",
			    from_kuid(&init_user_ns, old->uid));
	return -EPERM;				/* deny the identity switch */
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

/* ---------------- #1b setid-exec allowlist (sorted, exact match) -------- */

#define SX_MAX_ITEMS	512
#define SX_MAX_TEXT	(64 * 1024)

static DEFINE_MUTEX(sx_lock);
static char **sx_list;		/* sorted resolved absolute paths */
static int sx_count;
static char *sx_text;
static size_t sx_text_len;

static int sx_cmp(const void *a, const void *b)
{
	return strcmp(*(const char * const *)a, *(const char * const *)b);
}

static int sx_key_cmp(const void *key, const void *elt)
{
	return strcmp(key, *(const char * const *)elt);
}

static bool sx_allowed(const char *path)
{
	bool hit;

	mutex_lock(&sx_lock);
	hit = sx_count && bsearch(path, sx_list, sx_count, sizeof(*sx_list),
				  sx_key_cmp);
	mutex_unlock(&sx_lock);
	return hit;
}

/* Would this exec give the task an identity or privilege it does not hold? */
static bool exec_gains_privilege(const struct linux_binprm *bprm)
{
	const struct cred *old = current_cred();
	const struct cred *new = bprm->cred;

	return !uid_eq(new->euid, old->euid) ||
	       !gid_eq(new->egid, old->egid) ||
	       !cap_issubset(new->cap_permitted, old->cap_permitted);
}

static int ss_bprm_creds_from_file(struct linux_binprm *bprm,
				   const struct file *file)
{
	char *buf, *p;
	int ret = -EPERM;			/* default answer is DENY */

	/* Step 1: feature off -> allow. */
	if (!READ_ONCE(ss_cfg.block_setid_exec))
		return 0;
	/* Step 2: sudo users are unrestricted. */
	if (ss_cred_is_sudo(current_cred()))
		return 0;
	/* Step 3: only care about execs that would RAISE privilege (euid/egid up
	 * or a capability superset) - running an ordinary binary is fine. */
	if (!exec_gains_privilege(bprm))
		return 0;

	/* Step 4: a privilege-gaining exec by a non-sudo user is allowed only if
	 * this exact binary is on the setid_exec_allow list. Resolve the path
	 * (chroot-safe) and look it up. */
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;			/* fail closed: no memory -> deny */
	p = ss_file_path(&file->f_path, buf, PATH_MAX);
	/* d_unlinked() guard: refuse a path that has been unlinked, so an
	 * allowlisted name cannot be deleted-and-recreated to point the match at
	 * a different inode between resolution and use. */
	if (!IS_ERR(p) && !d_unlinked(file->f_path.dentry) && sx_allowed(p))
		ret = 0;			/* on the allowlist -> permit */
	if (ret) {
		pr_warn_ratelimited("non-sudo UID %u denied privilege-gaining exec %s\n",
				    from_kuid(&init_user_ns, current_uid()),
				    IS_ERR(p) ? "(unresolvable)" : p);
		ss_event("setid-exec: UID %u denied %s",
			 from_kuid(&init_user_ns, current_uid()),
			 IS_ERR(p) ? "(unresolvable)" : p);
	}
	kfree(buf);
	return ret;
}

static struct security_hook_list ss_creds_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(task_fix_setuid,    ss_task_fix_setuid),
	LSM_HOOK_INIT(task_fix_setgid,    ss_task_fix_setgid),
	LSM_HOOK_INIT(task_fix_setgroups, ss_task_fix_setgroups),
	LSM_HOOK_INIT(userns_create,      ss_userns_create),
	LSM_HOOK_INIT(bprm_creds_from_file, ss_bprm_creds_from_file),
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
	return ss_show_admin_gids(buf);
}

/*
 * Accepts "unset" (root-only) or a list of numeric GIDs separated by commas
 * and/or spaces, e.g. "27,10". The whole list is replaced atomically.
 */
static ssize_t admin_gid_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	u32 gids[SS_MAX_ADMIN_GIDS];
	unsigned int n = 0;
	char *copy, *p, *tok;
	int ret;

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (ss_locked())
		return -EPERM;

	if (sysfs_streq(buf, "unset"))
		return ss_set_admin_gids(NULL, 0) ?: count;

	copy = kstrndup(buf, count, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	p = strim(copy);
	while ((tok = strsep(&p, ", \t\n"))) {
		u32 v;

		if (!*tok)
			continue;
		if (n >= SS_MAX_ADMIN_GIDS || kstrtou32(tok, 10, &v)) {
			kfree(copy);
			return n >= SS_MAX_ADMIN_GIDS ? -E2BIG : -EINVAL;
		}
		gids[n++] = v;
	}
	kfree(copy);

	ret = ss_set_admin_gids(gids, n);
	return ret ? ret : count;
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

	if (!ss_may_admin(NULL))
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

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;

	WRITE_ONCE(ss_cfg.block_userns, v);
	return count;
}

static ssize_t block_setid_exec_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.block_setid_exec));
}

static ssize_t block_setid_exec_store(struct kobject *kobj,
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

	WRITE_ONCE(ss_cfg.block_setid_exec, v);
	return count;
}

static struct kobj_attribute admin_gid_attr =
	__ATTR(admin_gid, 0600, admin_gid_show, admin_gid_store);
static struct kobj_attribute block_setid_attr =
	__ATTR(block_setid, 0600, block_setid_show, block_setid_store);
static struct kobj_attribute block_userns_attr =
	__ATTR(block_userns, 0600, block_userns_show, block_userns_store);
static struct kobj_attribute block_setid_exec_attr =
	__ATTR(block_setid_exec, 0600, block_setid_exec_show,
	       block_setid_exec_store);

static struct attribute *ss_creds_attrs[] = {
	&admin_gid_attr.attr,
	&block_setid_attr.attr,
	&block_userns_attr.attr,
	&block_setid_exec_attr.attr,
	NULL,
};

static const struct attribute_group ss_creds_group = {
	.attrs = ss_creds_attrs,
};

int ss_creds_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_creds_group);
}

/* ------------------- securityfs: setid_exec_allow ------------------------ */

static void sx_free(char **list, int count)
{
	int i;

	if (!list)
		return;
	for (i = 0; i < count; i++)
		kfree(list[i]);
	kfree(list);
}

static ssize_t sx_read(struct file *file, char __user *ubuf, size_t count,
		       loff_t *ppos)
{
	ssize_t ret;

	mutex_lock(&sx_lock);
	ret = simple_read_from_buffer(ubuf, count, ppos,
				      sx_text ? sx_text : "", sx_text_len);
	mutex_unlock(&sx_lock);
	return ret;
}

/* Whole-file replace: one absolute resolved path per line. */
static ssize_t sx_write(struct file *file, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	char *text, *scratch, *p, *line, **list, **old_list, *old_text;
	int n = 0, old_count;

	if (!ss_may_admin(file))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (*ppos != 0)
		return -EINVAL;
	if (count == 0 || count > SX_MAX_TEXT)
		return count ? -EFBIG : 0;

	text = memdup_user_nul(ubuf, count);
	if (IS_ERR(text))
		return PTR_ERR(text);
	scratch = kstrdup(text, GFP_KERNEL);
	list = kcalloc(SX_MAX_ITEMS, sizeof(*list), GFP_KERNEL);
	if (!scratch || !list) {
		kfree(scratch);
		kfree(list);
		kfree(text);
		return -ENOMEM;
	}

	p = scratch;
	while ((line = strsep(&p, "\n"))) {
		line = strim(line);
		if (*line == '\0' || *line == '#')
			continue;
		if (*line != '/' || n >= SX_MAX_ITEMS) {
			sx_free(list, n);
			kfree(scratch);
			kfree(text);
			return n >= SX_MAX_ITEMS ? -E2BIG : -EINVAL;
		}
		list[n] = kstrdup(line, GFP_KERNEL);
		if (!list[n]) {
			sx_free(list, n);
			kfree(scratch);
			kfree(text);
			return -ENOMEM;
		}
		n++;
	}
	kfree(scratch);
	sort(list, n, sizeof(*list), sx_cmp, NULL);

	mutex_lock(&sx_lock);
	old_list = sx_list;
	old_count = sx_count;
	old_text = sx_text;
	sx_list = list;
	sx_count = n;
	sx_text = text;
	sx_text_len = count;
	mutex_unlock(&sx_lock);

	sx_free(old_list, old_count);
	kfree(old_text);
	*ppos = count;
	return count;
}

static const struct file_operations sx_fops = {
	.read   = sx_read,
	.write  = sx_write,
	.llseek = default_llseek,
};

int ss_creds_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("setid_exec_allow", 0600, dir, NULL,
				   &sx_fops);
	return IS_ERR(d) ? PTR_ERR(d) : 0;
}
