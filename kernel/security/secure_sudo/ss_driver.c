// SPDX-License-Identifier: GPL-2.0
/*
 * ss_driver.c - Protection #6: driver blacklist (Bring-Your-Own-Vulnerable-
 * Driver defence).
 *
 * BYOVD attacks load a legitimately-signed but vulnerable driver to get a
 * kernel-mode primitive. Signature enforcement alone does not stop it, because
 * the driver is validly signed - you have to deny the specific known-bad
 * modules. v2 hooked a "module_permission" hook that does not exist. The real
 * hook is kernel_read_file with READING_MODULE, which fires for finit_module().
 *
 * A module is denied if its SHA-256 matches a blacklisted hash (the robust
 * match - a renamed copy is still caught) or its filename basename matches a
 * blacklisted name. Policy is fed through securityfs by the root-only CLI.
 *
 * The hash is taken over the exact bytes the kernel is about to load, in the
 * kernel_post_read_file (finit_module) and kernel_post_load_data
 * (init_module) hooks. Hashing the file separately before the load would be a
 * time-of-check/time-of-use gap (the file can change between our read and the
 * loader's, e.g. on a network or FUSE filesystem), and init_module(2) - which
 * passes a memory buffer and has no file at all - would bypass the list
 * entirely. Name matching still happens at kernel_read_file, where the file
 * is known. If the blacklist is non-empty and a check cannot be completed,
 * the load is refused (fail closed).
 *
 * (Making signature enforcement actually bite - the playbook's modprobe.d
 * option did nothing - is the installer's job: it sets module.sig_enforce=1 as
 * a kernel parameter. This file handles the "even a signed module can be bad"
 * half.)
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sizes.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/kernel_read_file.h>
#include <crypto/sha2.h>

#include "secure_sudo.h"

#define DRV_MAX_ITEMS	256
#define DRV_MAX_TEXT	(64 * 1024)
#define SHA256_HEX	64

static DEFINE_MUTEX(drv_lock);
static char **drv_hashes;	/* lowercase 64-char hex sha256 */
static int   drv_nhash;
static char **drv_names;	/* module file basenames */
static int   drv_nname;
static char *drv_text;
static size_t drv_text_len;

static bool is_hex64(const char *s)
{
	int i;

	if (strlen(s) != SHA256_HEX)
		return false;
	for (i = 0; i < SHA256_HEX; i++)
		if (!isxdigit(s[i]))
			return false;
	return true;
}

/* SHA-256 the whole file into @hex (caller provides >=65 bytes incl NUL).
 * Shared with ss_timevault.c. Uses the crypto library directly: no tfm
 * allocation (which could trigger a module autoload from inside an exec or
 * module-load hook) and nothing that can fail except the reads. */
int ss_sha256_file(struct file *file, char *hex)
{
	struct sha256_state st;
	u8 digest[SHA256_DIGEST_SIZE];
	loff_t pos = 0, size;
	void *buf;
	int ret = 0;

	size = i_size_read(file_inode(file));
	if (size <= 0)
		return -EINVAL;

	buf = kvmalloc(SZ_64K, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	sha256_init(&st);
	while (pos < size) {
		ssize_t n = kernel_read(file, buf, SZ_64K, &pos);

		if (n < 0) {
			ret = n;
			goto out;
		}
		if (n == 0)
			break;
		sha256_update(&st, buf, n);
	}
	sha256_final(&st, digest);
	bin2hex(hex, digest, sizeof(digest));
	hex[SHA256_HEX] = '\0';
out:
	memzero_explicit(&st, sizeof(st));
	kvfree(buf);
	return ret;
}

static bool hash_blacklisted(const char *hex)
{
	int i;
	bool hit = false;

	mutex_lock(&drv_lock);
	for (i = 0; i < drv_nhash; i++)
		if (!strcasecmp(hex, drv_hashes[i])) {
			hit = true;
			break;
		}
	mutex_unlock(&drv_lock);
	return hit;
}

static bool name_blacklisted(const char *name)
{
	int i;
	bool hit = false;

	mutex_lock(&drv_lock);
	for (i = 0; i < drv_nname; i++)
		if (!strcmp(name, drv_names[i])) {
			hit = true;
			break;
		}
	mutex_unlock(&drv_lock);
	return hit;
}

static int ss_driver_read_file(struct file *file, enum kernel_read_file_id id,
			       bool contents)
{
	char *buf, *resolved;
	int ret = 0;

	/* Step 1: this hook fires for several kinds of kernel read; only module
	 * loads (finit_module) concern the driver blacklist. */
	if (id != READING_MODULE)
		return 0;
	/* Step 2: fast path - no name-based entries configured. (Hash-based
	 * entries are matched later, on the bytes actually loaded.) */
	if (!READ_ONCE(drv_nname))
		return 0;

	/* Step 3: resolve the .ko path and match its basename against the name
	 * blacklist. Unresolvable -> deny (fail closed). */
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;			/* fail closed */
	resolved = ss_file_path(&file->f_path, buf, PATH_MAX);
	if (IS_ERR(resolved)) {
		ret = -EPERM;
	} else if (name_blacklisted(kbasename(resolved))) {
		pr_warn("driver-blacklist: blocked module by name %s\n",
			kbasename(resolved));
		ss_event("driver-blacklist: blocked module name %s",
			 kbasename(resolved));
		ret = -EPERM;
	}
	kfree(buf);
	return ret;
}

/* Hash the bytes actually being loaded. */
static int check_module_buf(const char *buf, loff_t size, const char *how)
{
	char hex[SHA256_HEX + 1];

	if (!READ_ONCE(drv_nhash))
		return 0;
	if (size <= 0)
		return -EINVAL;
	ss_sha256_buf(buf, size, hex);
	if (hash_blacklisted(hex)) {
		pr_warn("driver-blacklist: blocked module (%s) by hash %s\n",
			how, hex);
		ss_event("driver-blacklist: blocked module hash %s via %s",
			 hex, how);
		return -EPERM;
	}
	return 0;
}

static int ss_driver_post_read(struct file *file, char *buf, loff_t size,
			       enum kernel_read_file_id id)
{
	if (id != READING_MODULE)
		return 0;
	return check_module_buf(buf, size, "finit_module");
}

static int ss_driver_post_load(char *buf, loff_t size,
			       enum kernel_load_data_id id, char *description)
{
	if (id != LOADING_MODULE)
		return 0;
	return check_module_buf(buf, size, "init_module");
}

static struct security_hook_list ss_driver_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(kernel_read_file,      ss_driver_read_file),
	LSM_HOOK_INIT(kernel_post_read_file, ss_driver_post_read),
	LSM_HOOK_INIT(kernel_post_load_data, ss_driver_post_load),
};

void __init ss_driver_init(void)
{
	security_add_hooks(ss_driver_hooks, ARRAY_SIZE(ss_driver_hooks),
			   &ss_lsmid);
}

/* ---------------------------- securityfs --------------------------------- */

static void free_items(char **items, int count)
{
	int i;

	if (!items)
		return;
	for (i = 0; i < count; i++)
		kfree(items[i]);
	kfree(items);
}

/* Parse text into two fresh lists: hashes (hex64) and names (everything else). */
static int parse_policy(char *text, char ***phash, int *pnhash,
			char ***pname, int *pnname)
{
	char **hashes, **names;
	char *p = text, *line;
	int nh = 0, nn = 0;

	hashes = kcalloc(DRV_MAX_ITEMS, sizeof(*hashes), GFP_KERNEL);
	names  = kcalloc(DRV_MAX_ITEMS, sizeof(*names), GFP_KERNEL);
	if (!hashes || !names) {
		kfree(hashes);
		kfree(names);
		return -ENOMEM;
	}

	while ((line = strsep(&p, "\n"))) {
		line = strim(line);
		if (*line == '\0' || *line == '#')
			continue;
		if (is_hex64(line) && nh < DRV_MAX_ITEMS) {
			hashes[nh] = kstrdup(line, GFP_KERNEL);
			if (!hashes[nh])
				goto oom;
			nh++;
		} else if (nn < DRV_MAX_ITEMS) {
			names[nn] = kstrdup(line, GFP_KERNEL);
			if (!names[nn])
				goto oom;
			nn++;
		}
	}
	*phash = hashes; *pnhash = nh;
	*pname = names;  *pnname = nn;
	return 0;
oom:
	free_items(hashes, nh);
	free_items(names, nn);
	return -ENOMEM;
}

static ssize_t drv_read(struct file *file, char __user *ubuf, size_t count,
			loff_t *ppos)
{
	ssize_t ret;

	mutex_lock(&drv_lock);
	ret = simple_read_from_buffer(ubuf, count, ppos,
				      drv_text ? drv_text : "", drv_text_len);
	mutex_unlock(&drv_lock);
	return ret;
}

static ssize_t drv_write(struct file *file, const char __user *ubuf,
			 size_t count, loff_t *ppos)
{
	char *text, *scratch;
	char **nh_list, **nn_list, **oh, **on, *old_text;
	int nh, nn, oh_c, on_c;

	if (!ss_may_admin(file))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (*ppos != 0)
		return -EINVAL;
	if (count == 0)
		return 0;
	if (count > DRV_MAX_TEXT)
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
	if (parse_policy(scratch, &nh_list, &nh, &nn_list, &nn)) {
		kfree(scratch);
		kfree(text);
		return -ENOMEM;
	}
	kfree(scratch);

	mutex_lock(&drv_lock);
	oh = drv_hashes; oh_c = drv_nhash;
	on = drv_names;  on_c = drv_nname;
	old_text = drv_text;
	drv_hashes = nh_list; WRITE_ONCE(drv_nhash, nh);
	drv_names  = nn_list; WRITE_ONCE(drv_nname, nn);
	drv_text = text; drv_text_len = count;
	mutex_unlock(&drv_lock);

	free_items(oh, oh_c);
	free_items(on, on_c);
	kfree(old_text);

	*ppos = count;
	return count;
}

static const struct file_operations drv_fops = {
	.read   = drv_read,
	.write  = drv_write,
	.llseek = default_llseek,
};

int ss_driver_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("driver_blacklist", 0600, dir, NULL,
				   &drv_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
	return 0;
}
