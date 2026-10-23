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
#include <crypto/hash.h>

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
 * Shared with ss_timevault.c. Returns 0 on success. */
int ss_sha256_file(struct file *file, char *hex)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 digest[32];
	void *buf;
	loff_t pos = 0, size;
	int ret, i;

	size = i_size_read(file_inode(file));
	if (size <= 0)
		return -EINVAL;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_tfm;
	}
	desc->tfm = tfm;

	buf = kvmalloc(SZ_64K, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_desc;
	}

	ret = crypto_shash_init(desc);
	if (ret)
		goto out_buf;

	while (pos < size) {
		ssize_t n = kernel_read(file, buf, SZ_64K, &pos);

		if (n < 0) {
			ret = n;
			goto out_buf;
		}
		if (n == 0)
			break;
		ret = crypto_shash_update(desc, buf, n);
		if (ret)
			goto out_buf;
	}

	ret = crypto_shash_final(desc, digest);
	if (ret)
		goto out_buf;

	for (i = 0; i < 32; i++)
		sprintf(hex + i * 2, "%02x", digest[i]);
	hex[SHA256_HEX] = '\0';

out_buf:
	kvfree(buf);
out_desc:
	kfree(desc);
out_tfm:
	crypto_free_shash(tfm);
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
	char hex[SHA256_HEX + 1];
	char *buf, *resolved;
	const char *base;
	int ret = 0;

	if (id != READING_MODULE)
		return 0;
	if (!READ_ONCE(drv_nhash) && !READ_ONCE(drv_nname))
		return 0;

	/* Name match first (cheap). */
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (buf) {
		resolved = d_path(&file->f_path, buf, PATH_MAX);
		if (!IS_ERR(resolved)) {
			base = kbasename(resolved);
			if (name_blacklisted(base)) {
				pr_warn("driver-blacklist: blocked module by name %s\n",
					base);
				ss_event("driver-blacklist: blocked module name %s",
					 base);
				ret = -EPERM;
			}
		}
	}
	kfree(buf);
	if (ret)
		return ret;

	/* Hash match. */
	if (READ_ONCE(drv_nhash) && ss_sha256_file(file, hex) == 0 &&
	    hash_blacklisted(hex)) {
		pr_warn("driver-blacklist: blocked module by hash %s\n", hex);
		ss_event("driver-blacklist: blocked module hash %s", hex);
		return -EPERM;
	}
	return 0;
}

static struct security_hook_list ss_driver_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(kernel_read_file, ss_driver_read_file),
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

	if (!capable(CAP_SYS_ADMIN))
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
