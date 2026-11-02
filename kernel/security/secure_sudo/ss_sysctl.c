// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/*
 * ss_sysctl.c - Protection #23: SysctlGuard (freeze security-critical sysctls).
 *
 * ============================ WHY IT EXISTS ==============================
 * STIG remediation and the installer set a number of kernel hardening sysctls
 * (kptr_restrict, dmesg_restrict, ptrace_scope, randomize_va_space, the fs
 * protected_* links, ...). Any root process can quietly set them back, and a
 * few sysctls are well-known persistence points: kernel.core_pattern and
 * kernel.modprobe name a program the kernel itself runs as root. SysctlGuard
 * freezes that set in the LSM so the hardened values stay as configured.
 *
 * ============================== THE RULE =================================
 * One knob, `sysctl_guard` (root-only, 0600, refused once locked). While it is
 * on, opening any protected sysctl for WRITE is refused for every user, root
 * included. Reads are untouched (`sysctl -a` still works). The usual sequence
 * is: systemd-sysctl applies your values early in boot, then `secure-sudo load`
 * turns the guard on, then the #16 lock makes the knob itself immutable.
 *
 * The match is made on the file's path INSIDE procfs (dentry_path_raw on a
 * PROC_SUPER_MAGIC superblock), not on the mount path, so mounting a second
 * procfs somewhere else does not dodge it. binfmt_misc (its own filesystem,
 * normally at /proc/sys/fs/binfmt_misc) is covered by superblock magic: while
 * the guard is on no new interpreter can be registered.
 *
 * ========================= HONEST LIMITATIONS ===========================
 *   - The list is fixed and global-only. Per-network-namespace sysctls
 *     (net.ipv4.*) are deliberately left alone: container runtimes set them
 *     inside their own namespaces and freezing them would break containers.
 *   - Values applied before the guard engages are whatever boot applied; the
 *     guard keeps them, it does not choose them (that is sysctl.d / STIG).
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/err.h>
#include <linux/magic.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

/* Paths relative to the procfs root. Each entry is matched exactly. */
static const char *const protected_sysctls[] = {
	/* kernel information leaks / debugging surface */
	"/sys/kernel/kptr_restrict",
	"/sys/kernel/dmesg_restrict",
	"/sys/kernel/perf_event_paranoid",
	"/sys/kernel/yama/ptrace_scope",
	"/sys/kernel/sysrq",
	/* code-loading switches */
	"/sys/kernel/kexec_load_disabled",
	"/sys/kernel/modules_disabled",
	"/sys/kernel/unprivileged_bpf_disabled",
	"/sys/kernel/io_uring_disabled",
	"/sys/net/core/bpf_jit_harden",
	"/sys/net/core/bpf_jit_kallsyms",
	/* programs the kernel runs as root */
	"/sys/kernel/core_pattern",
	"/sys/kernel/modprobe",
	"/sys/kernel/usermodehelper/bset",
	"/sys/kernel/usermodehelper/inheritable",
	/* memory-layout hardening */
	"/sys/kernel/randomize_va_space",
	"/sys/vm/mmap_min_addr",
	"/sys/vm/unprivileged_userfaultfd",
	/* filesystem link / dump hardening */
	"/sys/fs/protected_symlinks",
	"/sys/fs/protected_hardlinks",
	"/sys/fs/protected_fifos",
	"/sys/fs/protected_regular",
	"/sys/fs/suid_dumpable",
	/* namespace / tty surface */
	"/sys/user/max_user_namespaces",
	"/sys/kernel/unprivileged_userns_clone",		/* Debian/Ubuntu */
	"/sys/kernel/apparmor_restrict_unprivileged_userns",	/* Ubuntu */
	"/sys/dev/tty/ldisc_autoload",
};

static bool is_protected(const char *p)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(protected_sysctls); i++)
		if (!strcmp(p, protected_sysctls[i]))
			return true;
	return false;
}

int ss_sysctl_file_open(struct file *file)
{
	unsigned long magic;
	char *buf, *p;
	int ret = 0;

	if (!(file->f_mode & FMODE_WRITE) || !READ_ONCE(ss_cfg.sysctl_guard))
		return 0;

	magic = file->f_path.dentry->d_sb->s_magic;

	/* binfmt_misc: refuse every write (register / enable / remove). */
	if (magic == BINFMTFS_MAGIC) {
		pr_warn_ratelimited("sysctl: denied binfmt_misc write by %s\n",
				    current->comm);
		ss_event_typed_self("sysctl_guard", "current_process", "write",
				    "binfmt_misc", "deny", "protected_filesystem",
				    "sysctl: denied binfmt_misc write pid %d (%s)",
				    current->pid, current->comm);
		return -EPERM;
	}
	if (magic != PROC_SUPER_MAGIC)
		return 0;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	p = dentry_path_raw(file->f_path.dentry, buf, PATH_MAX);
	if (IS_ERR(p)) {
		ret = -EPERM;		/* cannot tell what it is: fail closed */
	} else if (is_protected(p)) {
		pr_warn_ratelimited("sysctl: denied write to %s by %s\n", p,
				    current->comm);
		ss_event_typed_self("sysctl_guard", "current_process", "write", p,
				    "deny", "protected_sysctl",
				    "sysctl: denied write %s pid %d (%s) uid %u", p,
				    current->pid, current->comm,
				    from_kuid(&init_user_ns, current_uid()));
		ret = -EPERM;
	}
	kfree(buf);
	return ret;
}



/* ---------------------------- sysfs knob --------------------------------- */
static ssize_t sysctl_guard_show(struct kobject *k, struct kobj_attribute *a,
				 char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.sysctl_guard));
}

static ssize_t sysctl_guard_store(struct kobject *k, struct kobj_attribute *a,
				  const char *buf, size_t count)
{
	bool v;

	if (!ss_may_admin(NULL) || ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	WRITE_ONCE(ss_cfg.sysctl_guard, v);
	return count;
}

static struct kobj_attribute sysctl_guard_attr =
	__ATTR(sysctl_guard, 0600, sysctl_guard_show, sysctl_guard_store);

int ss_sysctl_sysfs(struct kobject *kobj)
{
	return sysfs_create_file(kobj, &sysctl_guard_attr.attr);
}
