// SPDX-License-Identifier: GPL-2.0
/*
 * ss_tpm.c - Protection #5: block clearing the TPM.
 *
 * The attack is a one-liner:
 *     echo 5 | sudo tee /sys/class/tpm/tpm0/ppi/request
 * which schedules a Physical Presence Interface "clear TPM" at the next boot,
 * wiping sealed keys (disk-encryption keys, measured-boot state, our own
 * TPM-sealed OTP secret). Because it is destructive even for a legitimate
 * admin who fat-fingers it, this block applies to *everyone, root included* -
 * it is not gated on sudo. The only way to allow it is to boot with
 *
 *     secure_sudo.tpm_maint=1
 *
 * i.e. you must deliberately reboot into a maintenance window to clear the TPM.
 *
 * Matching is on the resolved file: the write target's path ends in
 * "/ppi/request" and sits under a TPM device. /sys/class/tpm/tpm0 is a symlink
 * into /sys/devices, so we match on the resolved d_path rather than the class
 * path.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/magic.h>
#include <linux/moduleparam.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

/* Read-only boot parameter: secure_sudo.tpm_maint=1 permits TPM clear. */
static bool tpm_maint;
module_param(tpm_maint, bool, 0444);
MODULE_PARM_DESC(tpm_maint,
		 "secure_sudo: allow writes to TPM ppi/request (TPM clear). Boot-time only.");

static bool is_tpm_ppi_request(const char *p)
{
	size_t len = strlen(p);
	static const char suffix[] = "/ppi/request";
	size_t slen = sizeof(suffix) - 1;

	if (len < slen || strcmp(p + len - slen, suffix) != 0)
		return false;
	/* Must actually be a TPM node, not some unrelated ppi/request. */
	return strstr(p, "/tpm") != NULL;
}

static int ss_tpm_file_open(struct file *file)
{
	unsigned long magic = file_inode(file)->i_sb->s_magic;
	char *buf, *p;
	int ret = 0;

	if (tpm_maint)
		return 0;			/* maintenance boot: allow */
	if (!(file->f_mode & FMODE_WRITE))
		return 0;			/* only writes clear the TPM */
	if (magic != SYSFS_MAGIC)
		return 0;			/* ppi/request lives in sysfs */

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return 0;

	p = d_path(&file->f_path, buf, PATH_MAX);
	if (!IS_ERR(p) && is_tpm_ppi_request(p)) {
		pr_warn_ratelimited("blocked TPM ppi/request write %s (boot with secure_sudo.tpm_maint=1 to allow)\n",
				    p);
		ret = -EPERM;
	}

	kfree(buf);
	return ret;
}

static struct security_hook_list ss_tpm_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_open, ss_tpm_file_open),
};

void __init ss_tpm_init(void)
{
	security_add_hooks(ss_tpm_hooks, ARRAY_SIZE(ss_tpm_hooks), &ss_lsmid);
}
