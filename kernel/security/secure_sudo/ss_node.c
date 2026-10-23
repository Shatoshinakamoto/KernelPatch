// SPDX-License-Identifier: GPL-2.0
/*
 * ss_node.c - Protection #11: NodeJS child-process guard.
 *
 * Goal: a Node process (the `node`/`nodejs` binary, or a registered single-
 * executable-application / pkg binary) may only spawn children whose program
 * is on an allowlist. This blunts the common "malicious npm dependency shells
 * out to /bin/sh" class of attack.
 *
 * v2 tried to do this by writing a literal 1 into current->security - which is
 * the LSM's own blob pointer; scribbling on it corrupts every LSM. The correct
 * mechanism is an LSM task blob:
 *
 *   - ss_blob_sizes reserves a per-task byte in task_struct->security.
 *   - when a task execs node/SEA, we set SS_TASK_NODE on its blob.
 *   - task_alloc copies the flag to forked children (so a fork of node, before
 *     it execs its target, is still marked).
 *   - at the child's exec, a marked task running a non-node program must find
 *     that program on node_allowed_children, or it is denied. An allowed child
 *     has the flag cleared so it (and its own subtree) runs normally.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
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
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

struct lsm_blob_sizes ss_blob_sizes __ro_after_init = {
	.lbs_task = sizeof(struct ss_task),
};

/* ------------------------- small string list ---------------------------- */

#define SL_MAX_ITEMS	256
#define SL_MAX_TEXT	(64 * 1024)

struct strlist {
	struct mutex lock;
	char **items;
	int count;
	char *text;
	size_t text_len;
};

static struct strlist node_children;	/* allowed child basenames */
static struct strlist node_sea;		/* registered SEA/pkg absolute paths */

static void sl_init(struct strlist *sl)
{
	mutex_init(&sl->lock);
}

static bool sl_has(struct strlist *sl, const char *s)
{
	int i;
	bool found = false;

	mutex_lock(&sl->lock);
	for (i = 0; i < sl->count; i++) {
		if (!strcmp(s, sl->items[i])) {
			found = true;
			break;
		}
	}
	mutex_unlock(&sl->lock);
	return found;
}

static void sl_free_items(char **items, int count)
{
	int i;

	if (!items)
		return;
	for (i = 0; i < count; i++)
		kfree(items[i]);
	kfree(items);
}

static char **sl_parse(char *text, int *out_count)
{
	char **items;
	char *p = text, *line;
	int n = 0;

	items = kcalloc(SL_MAX_ITEMS, sizeof(*items), GFP_KERNEL);
	if (!items)
		return NULL;

	while ((line = strsep(&p, "\n")) && n < SL_MAX_ITEMS) {
		line = strim(line);
		if (*line == '\0' || *line == '#')
			continue;
		items[n] = kstrdup(line, GFP_KERNEL);
		if (!items[n]) {
			sl_free_items(items, n);
			return NULL;
		}
		n++;
	}
	*out_count = n;
	return items;
}

static ssize_t sl_read(struct strlist *sl, char __user *ubuf, size_t count,
		       loff_t *ppos)
{
	ssize_t ret;

	mutex_lock(&sl->lock);
	ret = simple_read_from_buffer(ubuf, count, ppos,
				      sl->text ? sl->text : "", sl->text_len);
	mutex_unlock(&sl->lock);
	return ret;
}

static ssize_t sl_write(struct strlist *sl, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	char *text, *scratch, **new_items, **old_items, *old_text;
	int new_count, old_count;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (*ppos != 0)
		return -EINVAL;
	if (count == 0)
		return 0;
	if (count > SL_MAX_TEXT)
		return -EFBIG;

	text = kmalloc(count + 1, GFP_KERNEL);
	if (!text)
		return -ENOMEM;
	if (copy_from_user(text, ubuf, count)) {
		kfree(text);
		return -EFAULT;
	}
	text[count] = '\0';

	scratch = kmemdup(text, count + 1, GFP_KERNEL);
	if (!scratch) {
		kfree(text);
		return -ENOMEM;
	}
	new_items = sl_parse(scratch, &new_count);
	kfree(scratch);
	if (!new_items) {
		kfree(text);
		return -ENOMEM;
	}

	mutex_lock(&sl->lock);
	old_items = sl->items;
	old_count = sl->count;
	old_text = sl->text;
	sl->items = new_items;
	sl->count = new_count;
	sl->text = text;
	sl->text_len = count;
	mutex_unlock(&sl->lock);

	sl_free_items(old_items, old_count);
	kfree(old_text);

	*ppos = count;
	return count;
}

/* ------------------------------- hooks ----------------------------------- */

static int ss_node_task_alloc(struct task_struct *task,
			      unsigned long clone_flags)
{
	/* Propagate the node mark from the forking parent to the child. */
	ss_task(task)->flags = ss_task(current)->flags & SS_TASK_NODE;
	return 0;
}

static int ss_node_bprm(struct linux_binprm *bprm)
{
	struct ss_task *cur = ss_task(current);
	char *buf = NULL, *resolved;
	const char *base;
	bool target_is_node;
	int ret = 0;

	/* Resolve the program being executed. */
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (buf) {
		resolved = d_path(&bprm->file->f_path, buf, PATH_MAX);
		if (IS_ERR(resolved))
			resolved = NULL;
	} else {
		resolved = NULL;
	}
	base = kbasename(resolved ? resolved : bprm->filename);

	target_is_node = !strcmp(base, "node") || !strcmp(base, "nodejs") ||
			 (resolved && sl_has(&node_sea, resolved));

	if (target_is_node) {
		cur->flags |= SS_TASK_NODE;	/* this image is a node runtime */
		goto out;
	}

	if (cur->flags & SS_TASK_NODE) {
		if (sl_has(&node_children, base)) {
			cur->flags &= ~SS_TASK_NODE;	/* allowed child: run free */
			goto out;
		}
		pr_warn_ratelimited("node guard: UID %u blocked child exec %s\n",
				    from_kuid(&init_user_ns, current_uid()),
				    base);
		ss_event("node-guard: UID %u blocked child exec %s",
			 from_kuid(&init_user_ns, current_uid()), base);
		ret = -EPERM;
	}

out:
	kfree(buf);
	return ret;
}

static struct security_hook_list ss_node_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(task_alloc,          ss_node_task_alloc),
	LSM_HOOK_INIT(bprm_check_security, ss_node_bprm),
};

void __init ss_node_init(void)
{
	sl_init(&node_children);
	sl_init(&node_sea);
	security_add_hooks(ss_node_hooks, ARRAY_SIZE(ss_node_hooks), &ss_lsmid);
}

/* ---------------------------- securityfs --------------------------------- */

static ssize_t children_read(struct file *f, char __user *u, size_t c, loff_t *p)
{
	return sl_read(&node_children, u, c, p);
}
static ssize_t children_write(struct file *f, const char __user *u, size_t c,
			      loff_t *p)
{
	return sl_write(&node_children, u, c, p);
}
static const struct file_operations children_fops = {
	.read = children_read, .write = children_write, .llseek = default_llseek,
};

static ssize_t sea_read(struct file *f, char __user *u, size_t c, loff_t *p)
{
	return sl_read(&node_sea, u, c, p);
}
static ssize_t sea_write(struct file *f, const char __user *u, size_t c,
			 loff_t *p)
{
	return sl_write(&node_sea, u, c, p);
}
static const struct file_operations sea_fops = {
	.read = sea_read, .write = sea_write, .llseek = default_llseek,
};

int ss_node_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("node_allowed_children", 0600, dir, NULL,
				   &children_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);

	d = securityfs_create_file("node_sea_binaries", 0600, dir, NULL,
				   &sea_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
	return 0;
}
