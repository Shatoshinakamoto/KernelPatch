// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * ss_hooks.c - one registration for every LSM hook that more than one
 * secure_sudo protection uses.
 *
 * Since 6.9 the LSM framework calls hooks through static calls and reserves a
 * fixed number of slots per hook: one per LSM counted in
 * include/linux/lsm_count.h (ci/graft-lsm.sh adds secure_sudo to that count).
 * If one LSM registers the same hook several times, each registration takes
 * a slot, and when they run out the kernel panics in lsm_static_call_init()
 * before userspace starts. Earlier builds registered file_open seven times,
 * which is exactly what that panic looks like.
 *
 * So each shared hook is registered once here and calls the protections'
 * handlers in the order their *_init() used to register them. Like the LSM
 * framework itself, the first non-zero return wins and later handlers are
 * not consulted, so behaviour is unchanged.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

static int ss_hook_bprm_check(struct linux_binprm *bprm)
{
	int rc;

	rc = ss_exec_bprm(bprm);		/* #2 command blacklist */
	if (!rc)
		rc = ss_tmp_bprm(bprm);		/* #12 scratch-tree exec */
	if (!rc)
		rc = ss_node_bprm(bprm);	/* #11 NodeJS child guard */
	if (!rc)
		rc = ss_cooldown_bprm(bprm);	/* #8 sudo cooldown */
	if (!rc)
		rc = ss_timevault_bprm(bprm);	/* #13 TimeVault */
	return rc;
}

static int ss_hook_file_open(struct file *file)
{
	int rc;

	rc = ss_firmware_file_open(file);	/* #3 firmware/flash */
	if (!rc)
		rc = ss_tpm_file_open(file);	/* #5 TPM clear */
	if (!rc)
		rc = ss_timevault_file_open(file);	/* #13 TimeVault */
	if (!rc)
		rc = ss_home_file_open(file);	/* #4 home confinement */
	if (!rc)
		rc = ss_binvault_file_open(file);	/* #17 BinaryVault */
	if (!rc)
		rc = ss_radio_file_open(file);	/* #19 RadioGuard */
	if (!rc)
		rc = ss_sysctl_file_open(file);	/* #23 SysctlGuard */
	return rc;
}

static int ss_hook_mmap_file(struct file *file, unsigned long reqprot,
			     unsigned long prot, unsigned long flags)
{
	int rc;

	rc = ss_tmp_mmap(file, reqprot, prot, flags);		/* #12 */
	if (!rc)
		rc = ss_timevault_mmap(file, reqprot, prot, flags);	/* #13 */
	if (!rc)
		rc = ss_pg_mmap_file(file, reqprot, prot, flags);	/* #20 */
	return rc;
}

static int ss_hook_file_mprotect(struct vm_area_struct *vma,
				 unsigned long reqprot, unsigned long prot)
{
	int rc;

	rc = ss_tmp_mprotect(vma, reqprot, prot);		/* #12 */
	if (!rc)
		rc = ss_timevault_mprotect(vma, reqprot, prot);	/* #13 */
	if (!rc)
		rc = ss_pg_mprotect(vma, reqprot, prot);	/* #20 */
	return rc;
}

static int ss_hook_kernel_read_file(struct file *file,
				    enum kernel_read_file_id id, bool contents)
{
	int rc;

	rc = ss_lock_read_file(file, id, contents);		/* #16 lock */
	if (!rc)
		rc = ss_driver_read_file(file, id, contents);	/* #6 BYOVD */
	if (!rc)
		rc = ss_radio_read_file(file, id, contents);	/* #19 */
	return rc;
}

#ifdef CONFIG_SECURITY_PATH
static int ss_hook_path_truncate(const struct path *path)
{
	int rc = ss_timevault_truncate(path);			/* #13 */

	return rc ? rc : ss_home_path_truncate(path);		/* #4 */
}

static int ss_hook_path_unlink(const struct path *dir, struct dentry *d)
{
	int rc = ss_home_path_unlink(dir, d);			/* #4 */

	return rc ? rc : ss_binvault_path_unlink(dir, d);	/* #17 */
}

static int ss_hook_path_link(struct dentry *old, const struct path *ndir,
			     struct dentry *nd)
{
	int rc = ss_home_path_link(old, ndir, nd);		/* #4 */

	return rc ? rc : ss_binvault_path_link(old, ndir, nd);	/* #17 */
}

static int ss_hook_path_rename(const struct path *odir, struct dentry *od,
			       const struct path *ndir, struct dentry *nd,
			       unsigned int flags)
{
	int rc = ss_home_path_rename(odir, od, ndir, nd, flags);	/* #4 */

	return rc ? rc : ss_binvault_path_rename(odir, od, ndir, nd, flags);
}

static int ss_hook_path_chmod(const struct path *path, umode_t mode)
{
	int rc = ss_home_path_chmod(path, mode);		/* #4 */

	return rc ? rc : ss_binvault_path_chmod(path, mode);	/* #17 */
}
#endif /* CONFIG_SECURITY_PATH */

#ifdef CONFIG_SECURITY_NETWORK
static int ss_hook_socket_create(int family, int type, int protocol, int kern)
{
	int rc = ss_net_socket_create(family, type, protocol, kern);	/* #10 */

	return rc ? rc : ss_radio_socket_create(family, type, protocol, kern);
}
#endif

static struct security_hook_list ss_shared_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, ss_hook_bprm_check),
	LSM_HOOK_INIT(file_open,           ss_hook_file_open),
	LSM_HOOK_INIT(mmap_file,           ss_hook_mmap_file),
	LSM_HOOK_INIT(file_mprotect,       ss_hook_file_mprotect),
	LSM_HOOK_INIT(kernel_read_file,    ss_hook_kernel_read_file),
#ifdef CONFIG_SECURITY_PATH
	LSM_HOOK_INIT(path_truncate,       ss_hook_path_truncate),
	LSM_HOOK_INIT(path_unlink,         ss_hook_path_unlink),
	LSM_HOOK_INIT(path_link,           ss_hook_path_link),
	LSM_HOOK_INIT(path_rename,         ss_hook_path_rename),
	LSM_HOOK_INIT(path_chmod,          ss_hook_path_chmod),
#endif
#ifdef CONFIG_SECURITY_NETWORK
	LSM_HOOK_INIT(socket_create,       ss_hook_socket_create),
#endif
};

void __init ss_hooks_init(void)
{
	security_add_hooks(ss_shared_hooks, ARRAY_SIZE(ss_shared_hooks),
			   &ss_lsmid);
}
