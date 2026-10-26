// SPDX-License-Identifier: GPL-2.0
/*
 * ss_bpf.c - Protection #22: BPF & perf guard (anti kernel-rootkit).
 *
 * ============================ WHY IT EXISTS ==============================
 * eBPF and perf are the two most powerful *legitimate* ways to observe and
 * influence the running kernel from userspace, which makes them the modern
 * rootkit toolkit: a tracing BPF program attached to a kprobe/tracepoint can
 * hide processes and files, rewrite syscall results, and harvest credentials,
 * and it needs no module load at all - so the #16 lock's module block and #6
 * BYOVD hashes never see it. perf_event_open gives side-channel and kernel
 * address leaks. The stock sysctls (kernel.unprivileged_bpf_disabled,
 * kernel.perf_event_paranoid) only restrain unprivileged users, and root can
 * flip them back; this guard enforces in the LSM, where root cannot.
 *
 * ============================== THE KNOBS ================================
 *   bpf_guard         1 = deny every bpf(2) command to non-sudo users.
 *   bpf_lock_tracing  1 = (default) once the #16 lock has latched, refuse to
 *                     LOAD tracing-class BPF programs for EVERYONE, root
 *                     included: kprobe, tracepoint, raw tracepoint (incl.
 *                     writable), perf_event, fentry/fexit (TRACING), BPF-LSM
 *                     and freplace (EXT). These are the program types that can
 *                     watch or alter kernel behaviour. Networking and cgroup
 *                     programs (what systemd, firewalls and container runtimes
 *                     use) are untouched.
 *   perf_guard        1 = deny perf_event_open(2) to non-sudo users.
 *
 * All three are ordinary secure_sudo knobs: root-only (0600), refused once the
 * lock latches, loaded at boot by `secure-sudo load`.
 *
 * ========================= HONEST LIMITATIONS ===========================
 *   - bpf_lock_tracing acts at program LOAD. A tracing program loaded before
 *     the lock latched keeps running; latch the lock early in boot (the
 *     daemon's ExecStartPre does) so nothing hostile can get in first.
 *   - BPF struct_ops (TCP congestion control, sched_ext) is deliberately not
 *     in the refused set because real systems use it; lock_modules + the
 *     locked_down integrity class still stop bpf_probe_write_user.
 *   - Kernel-internal programs (kern != 0 paths) never reach these hooks.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

#ifdef CONFIG_BPF_SYSCALL
/* Step 1 (every bpf(2) command): non-sudo users get nothing when bpf_guard. */
static int ss_bpf_cmd(int cmd, union bpf_attr *attr, unsigned int size)
{
	if (!READ_ONCE(ss_cfg.bpf_guard) || ss_is_sudo_user())
		return 0;
	pr_warn_ratelimited("bpf: denied bpf cmd %d for non-sudo uid %u\n", cmd,
			    from_kuid(&init_user_ns, current_uid()));
	ss_event("bpf: denied cmd %d uid %u (%s)", cmd,
		 from_kuid(&init_user_ns, current_uid()), current->comm);
	return -EPERM;
}

/* Is @t a program type that can observe or alter kernel execution? */
static bool tracing_type(enum bpf_prog_type t)
{
	switch (t) {
	case BPF_PROG_TYPE_KPROBE:
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
	case BPF_PROG_TYPE_TRACING:
	case BPF_PROG_TYPE_LSM:
	case BPF_PROG_TYPE_EXT:
		return true;
	default:
		return false;
	}
}

/*
 * Step 2 (program load): after the lock latches, a tracing-class program is
 * refused for everyone. prog->type is set before this hook runs and before
 * the verifier, so a refused program never touches the kernel.
 */
static int ss_bpf_prog_load(struct bpf_prog *prog, union bpf_attr *attr,
			    struct bpf_token *token)
{
	if (!ss_locked() || !READ_ONCE(ss_cfg.bpf_lock_tracing))
		return 0;
	if (!tracing_type(prog->type))
		return 0;
	pr_warn_ratelimited("bpf: locked: refused tracing prog type %d (%s)\n",
			    prog->type, current->comm);
	ss_event("bpf: locked: refused tracing prog type %d by pid %d (%s) uid %u",
		 prog->type, current->pid, current->comm,
		 from_kuid(&init_user_ns, current_uid()));
	return -EPERM;
}
#endif /* CONFIG_BPF_SYSCALL */

#ifdef CONFIG_PERF_EVENTS
/*
 * Step 3: perf_event_open for non-sudo users when perf_guard is on.
 *
 * The hook's shape differs between kernels: 6.12 passes only the security
 * class (PERF_SECURITY_OPEN, _CPU, _KERNEL, _TRACEPOINT); later kernels, and
 * distro kernels that backport the change, also pass the perf_event_attr.
 * Both handlers exist and SS_PERF_HOOK picks the one that matches this
 * tree's security_perf_event_open() at compile time.
 */
static int ss_perf_check(int sec_class, int ev_type)
{
	if (!READ_ONCE(ss_cfg.perf_guard) || ss_is_sudo_user())
		return 0;
	pr_warn_ratelimited("perf: denied perf_event_open for uid %u\n",
			    from_kuid(&init_user_ns, current_uid()));
	ss_event("perf: denied perf_event_open class %d type %d uid %u (%s)",
		 sec_class, ev_type,
		 from_kuid(&init_user_ns, current_uid()), current->comm);
	return -EPERM;
}

static int __maybe_unused ss_perf_open_attr(struct perf_event_attr *attr,
					    int type)
{
	return ss_perf_check(type, attr ? (int)attr->type : -1);
}

static int __maybe_unused ss_perf_open_class(int type)
{
	return ss_perf_check(type, -1);
}

#define SS_PERF_HOOK							\
	__builtin_choose_expr(						\
		__builtin_types_compatible_p(				\
			typeof(security_perf_event_open),		\
			int (struct perf_event_attr *, int)),		\
		ss_perf_open_attr, ss_perf_open_class)
#endif

static struct security_hook_list ss_bpf_hooks[] __ro_after_init = {
#ifdef CONFIG_BPF_SYSCALL
	LSM_HOOK_INIT(bpf,           ss_bpf_cmd),
	LSM_HOOK_INIT(bpf_prog_load, ss_bpf_prog_load),
#endif
#ifdef CONFIG_PERF_EVENTS
	LSM_HOOK_INIT(perf_event_open, SS_PERF_HOOK),
#endif
};

void __init ss_bpf_init(void)
{
	if (ARRAY_SIZE(ss_bpf_hooks))
		security_add_hooks(ss_bpf_hooks, ARRAY_SIZE(ss_bpf_hooks),
				   &ss_lsmid);
}

/* ---------------------------- sysfs knobs -------------------------------- */
/* Same plumbing as every other boolean knob: root-only, refused once locked. */
#define BPF_BOOL(field)							\
static ssize_t field##_show(struct kobject *k, struct kobj_attribute *a,\
			    char *buf)					\
{									\
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.field));		\
}									\
static ssize_t field##_store(struct kobject *k, struct kobj_attribute *a,\
			     const char *buf, size_t count)		\
{									\
	bool v;								\
	if (!ss_may_admin(NULL))					\
		return -EPERM;						\
	if (ss_locked())						\
		return -EPERM;						\
	if (kstrtobool(buf, &v))					\
		return -EINVAL;						\
	WRITE_ONCE(ss_cfg.field, v);					\
	return count;							\
}									\
static struct kobj_attribute field##_attr =				\
	__ATTR(field, 0600, field##_show, field##_store)

BPF_BOOL(bpf_guard);
BPF_BOOL(bpf_lock_tracing);
BPF_BOOL(perf_guard);

static struct attribute *ss_bpf_attrs[] = {
	&bpf_guard_attr.attr,
	&bpf_lock_tracing_attr.attr,
	&perf_guard_attr.attr,
	NULL,
};
static const struct attribute_group ss_bpf_group = {
	.attrs = ss_bpf_attrs,
};

int ss_bpf_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_bpf_group);
}
