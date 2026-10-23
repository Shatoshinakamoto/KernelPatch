// SPDX-License-Identifier: GPL-2.0
/*
 * ss_firmware.c - Protection #3: block firmware / flash access by non-sudo
 * users (GPU VBIOS, motherboard BIOS/Q-Flash, Intel ME, raw memory).
 *
 * v1 had secure_gpu_flash()/secure_mb_flash() stubs that nothing ever called.
 * The flashing a user actually does goes through a handful of device nodes and
 * firmware sysfs attributes, so this merge enforces at file_open:
 *
 *   - /dev/mem, /dev/kmem, /dev/port  (raw physical memory / I/O ports, the
 *     classic path to poke a GPU or SPI flash controller directly)
 *   - /dev/mtd*                       (raw flash / BIOS chip via the MTD layer)
 *   - /dev/mei*                       (Intel Management Engine interface)
 *   - write opens anywhere under /sys/firmware/  (EFI vars, efivarfs, and the
 *     firmware attributes used to stage updates)
 *
 * Sudo users are allowed through - legitimately reflashing firmware is a root
 * operation. The installer additionally turns on kernel lockdown (integrity
 * mode), which closes the same doors for root; the two are complementary.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/kdev_t.h>
#include <linux/major.h>
#include <linux/magic.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/capability.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

/* Fixed char-device minors on MEM_MAJOR (1) that expose raw memory / ports. */
static bool is_raw_mem_dev(umode_t mode, unsigned int major, unsigned int minor)
{
	if (!S_ISCHR(mode) || major != MEM_MAJOR)
		return false;
	/* 1 = /dev/mem, 2 = /dev/kmem, 4 = /dev/port */
	return minor == 1 || minor == 2 || minor == 4;
}

/* Name-based match for nodes whose major is not fixed (mtd, mei). */
static bool is_blocked_dev_path(const char *p)
{
	return !strcmp(p, "/dev/mem")  ||
	       !strcmp(p, "/dev/kmem") ||
	       !strcmp(p, "/dev/port") ||
	       str_has_prefix(p, "/dev/mtd") ||
	       str_has_prefix(p, "/dev/mei");
}

static int ss_file_open(struct file *file)
{
	struct inode *inode = file_inode(file);
	umode_t mode = inode->i_mode;
	unsigned long magic = inode->i_sb->s_magic;
	bool is_dev = S_ISCHR(mode) || S_ISBLK(mode);
	bool fw_write;
	char *buf, *p;
	int ret = 0;

	if (!READ_ONCE(ss_cfg.block_flash))
		return 0;
	if (ss_is_sudo_user())
		return 0;

	/* Write to firmware sysfs / efivarfs is the other dangerous case. */
	fw_write = (file->f_mode & FMODE_WRITE) &&
		   (magic == SYSFS_MAGIC || magic == EFIVARFS_MAGIC);

	/* Cheap exit for the overwhelmingly common case (a normal file). */
	if (!is_dev && !fw_write)
		return 0;

	/* Fixed raw-memory nodes need no path resolution. */
	if (is_dev && is_raw_mem_dev(mode, imajor(inode), iminor(inode))) {
		pr_warn_ratelimited("non-sudo UID %u denied raw-memory device open\n",
				    from_kuid(&init_user_ns, current_uid()));
		return -EPERM;
	}

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;		/* fail closed on a sensitive open */

	p = ss_file_path(&file->f_path, buf, PATH_MAX);
	if (IS_ERR(p)) {
		/* A device node we could not name is still refused if it is one
		 * of the fixed raw-memory nodes (handled above); otherwise a
		 * non-resolvable firmware-sysfs write is denied, not waved. */
		ret = fw_write ? -EPERM : 0;
		goto out;
	}

	if (is_dev && is_blocked_dev_path(p)) {
		pr_warn_ratelimited("non-sudo UID %u denied firmware/flash device %s\n",
				    from_kuid(&init_user_ns, current_uid()), p);
		ret = -EPERM;
		goto out;
	}

	if (fw_write && str_has_prefix(p, "/sys/firmware/")) {
		pr_warn_ratelimited("non-sudo UID %u denied firmware sysfs write %s\n",
				    from_kuid(&init_user_ns, current_uid()), p);
		ret = -EPERM;
		goto out;
	}

out:
	kfree(buf);
	return ret;
}

static struct security_hook_list ss_firmware_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_open, ss_file_open),
};

void __init ss_firmware_init(void)
{
	security_add_hooks(ss_firmware_hooks, ARRAY_SIZE(ss_firmware_hooks),
			   &ss_lsmid);
}

/* ---------------------------- sysfs knob --------------------------------- */

static ssize_t block_flash_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.block_flash));
}

static ssize_t block_flash_store(struct kobject *kobj,
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

	WRITE_ONCE(ss_cfg.block_flash, v);
	return count;
}

static struct kobj_attribute block_flash_attr =
	__ATTR(block_flash, 0600, block_flash_show, block_flash_store);

static struct attribute *ss_firmware_attrs[] = {
	&block_flash_attr.attr,
	NULL,
};

static const struct attribute_group ss_firmware_group = {
	.attrs = ss_firmware_attrs,
};

int ss_firmware_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_firmware_group);
}
