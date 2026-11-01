// SPDX-License-Identifier: GPL-2.0
/*
 * ss_prguard.c - Protection #20: Process Runtime Guard.
 *
 * ============================ WHAT IT DOES ===============================
 * Process Runtime Guard protects the *runtime memory* of every process from
 * cross-process tampering and from self-modifying code injection. When it is
 * on, no process may reach into another's address space, and no process may
 * create memory that is writable and executable at the same time - unless its
 * program is explicitly whitelisted as exempt (debuggers, JITs, profilers).
 *
 * The attacks it closes are the ones that work *after* a program is already
 * running, where exec-time controls (#2/#12/#13/#17) no longer help:
 *
 *   - ptrace(PTRACE_ATTACH) - a debugger-style attach that can read and write
 *     another process's registers and memory (code injection, credential
 *     theft from a running daemon).
 *   - process_vm_writev() - write directly into another process's memory. The
 *     kernel gates it through ptrace_may_access(... ATTACH ...), so the same
 *     ptrace_access_check hook covers it.
 *   - writes to /proc/<pid>/mem - another path to another process's memory,
 *     also gated by ptrace_may_access(), so again the ptrace hook covers it.
 *   - W^X violations - mapping or re-protecting memory as writable AND
 *     executable simultaneously (PROT_WRITE|PROT_EXEC), the classic shellcode/
 *     JIT-spray primitive. Enforcing W^X means code pages can be executable or
 *     writable but never both at once.
 *
 * ========================= THE WHITELIST (EXEMPTIONS) ====================
 * "Guard all processes except whitelisted ones." The whitelist holds the
 * absolute paths of *programs that are exempt* - the few that legitimately
 * need these powers: a debugger (gdb, lldb, strace), a profiler (perf), or a
 * JIT/runtime that truly needs W+X pages. A process is identified by the path
 * of its main executable (its mm's exe_file). If the current process's exe is
 * on the list, the guard steps aside for it; every other process is guarded.
 *
 * Managed via securityfs "prguard_allow" (one absolute path per line) and the
 * CLI `secure-sudo prguard add|remove|list|on|off`. The toggle and the list
 * are root-only (0600) and frozen once the #16 config lock latches, so the
 * guard cannot be weakened on a locked box.
 *
 * ============================== THE HOOKS ================================
 *   ptrace_access_check(child, mode) - deny an ATTACH-mode access (covers
 *        ptrace attach, process_vm_writev, /proc/pid/mem) when the *tracer*
 *        (current) is not exempt.
 *   ptrace_traceme(parent)           - deny a process inviting @parent to
 *        trace it, unless @parent is exempt (so a victim cannot be tricked
 *        into opening itself to a non-exempt tracer).
 *   mmap_file / file_mprotect        - deny a mapping that requests PROT_WRITE
 *        and PROT_EXEC together (W^X), unless current is exempt.
 *
 * Read-mode ptrace (PTRACE_MODE_READ, used by non-invasive tools) is left
 * alone; only ATTACH - the mode that permits *writing* another process - is
 * denied. All checks fail closed: if the current exe cannot be resolved while
 * the guard is on, the process is treated as non-exempt (guarded).
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/limits.h>
#include <linux/ptrace.h>
#include <linux/err.h>
#include <linux/sort.h>
#include <linux/bsearch.h>
#include <linux/security.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

#define PG_MAX_ITEMS	1024
#define PG_MAX_TEXT	(128 * 1024)

/* Exempt-program list: sorted absolute exe paths. */
static DEFINE_MUTEX(pg_lock);
static char **pg_list;
static int    pg_count;
static char  *pg_text;
static size_t pg_text_len;

static int pg_cmp(const void *a, const void *b)
{
	return strcmp(*(const char * const *)a, *(const char * const *)b);
}
static int pg_key_cmp(const void *key, const void *elt)
{
	return strcmp(key, *(const char * const *)elt);
}

/*
 * Is the *current* process exempt? Resolves current's main executable path and
 * looks it up in the sorted exemption list. Fails closed: an unresolvable exe
 * means "not exempt" (guarded), never a free pass.
 */
static bool current_exempt(void)
{
	struct mm_struct *mm = current->mm;
	struct file *exe;
	char *buf, *p;
	bool hit = false;

	if (!mm)			/* kernel thread: no user exe to guard */
		return true;
	exe = get_mm_exe_file(mm);	/* takes a reference */
	if (!exe)
		return false;		/* fail closed */

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		fput(exe);
		return false;		/* fail closed */
	}
	p = ss_file_path(&exe->f_path, buf, PATH_MAX);
	if (!IS_ERR(p)) {
		mutex_lock(&pg_lock);
		hit = pg_count && bsearch(p, pg_list, pg_count, sizeof(*pg_list),
					  pg_key_cmp);
		mutex_unlock(&pg_lock);
	}
	kfree(buf);
	fput(exe);
	return hit;
}

/* --------------------------- ptrace hooks -------------------------------- */

static int ss_pg_ptrace_access(struct task_struct *child, unsigned int mode)
{
	/* Observability feed (opt-in, independent of enforcement): emit one event
	 * per cross-process memory access check, classified read vs write, with
	 * the source and target pid/comm, so the GUI can show "who accessed whose
	 * memory". Rate-limited and verbose; off by default. */
	if (READ_ONCE(ss_cfg.prguard_observe) && current->pid != child->pid) {
		const struct cred *child_cred = get_task_cred(child);

		ss_event_typed_pid_uid("process_runtime_guard", child->comm,
				       child->pid, child_cred->uid,
				       (mode & PTRACE_MODE_ATTACH) ?
				       "write_memory" : "read_memory",
				       "process_memory", "observe",
				       "cross_process_access",
				       "prguard: mem-access %s by pid %d (%s) -> pid %d (%s)",
				       (mode & PTRACE_MODE_ATTACH) ? "WRITE" : "READ",
				       current->pid, current->comm, child->pid,
				       child->comm);
		put_cred(child_cred);
	}

	/* Only ATTACH mode can WRITE another process (and gates
	 * process_vm_writev + /proc/pid/mem). Read-only inspection is allowed. */
	if (!READ_ONCE(ss_cfg.prguard_enabled))
		return 0;
	if (!(mode & PTRACE_MODE_ATTACH))
		return 0;
	if (current_exempt())
		return 0;

	pr_warn_ratelimited("prguard: denied ptrace ATTACH by UID %u (pid %d) to pid %d\n",
			    from_kuid(&init_user_ns, current_uid()),
			    current->pid, child->pid);
	{
		const struct cred *child_cred = get_task_cred(child);

		ss_event_typed_pid_uid("process_runtime_guard", child->comm,
				       child->pid, child_cred->uid,
				       "ptrace_attach", "process_memory", "deny",
				       "memory_access_policy",
				       "prguard: denied ptrace ATTACH pid %d -> pid %d",
				       current->pid, child->pid);
		put_cred(child_cred);
	}
	return -EPERM;
}

static int ss_pg_ptrace_traceme(struct task_struct *parent)
{
	/* A process asking @parent to trace it: allow only if the prospective
	 * tracer's program is exempt. We cannot run current_exempt() here (it
	 * would test the child, not the parent), so resolve @parent's exe. */
	struct mm_struct *mm;
	struct file *exe;
	char *buf, *p;
	bool exempt = false;

	if (!READ_ONCE(ss_cfg.prguard_enabled))
		return 0;

	mm = get_task_mm(parent);
	if (!mm)
		return -EPERM;			/* fail closed */
	exe = get_mm_exe_file(mm);
	mmput(mm);
	if (!exe)
		return -EPERM;
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		fput(exe);
		return -EPERM;
	}
	p = ss_file_path(&exe->f_path, buf, PATH_MAX);
	if (!IS_ERR(p)) {
		mutex_lock(&pg_lock);
		exempt = pg_count && bsearch(p, pg_list, pg_count,
					     sizeof(*pg_list), pg_key_cmp);
		mutex_unlock(&pg_lock);
	}
	kfree(buf);
	fput(exe);
	if (exempt)
		return 0;

	pr_warn_ratelimited("prguard: denied PTRACE_TRACEME (pid %d)\n",
			    current->pid);
	ss_event_typed_self("process_runtime_guard", "current_process",
			    "ptrace_traceme", "process_memory", "deny",
			    "tracer_not_allowlisted",
			    "prguard: denied PTRACE_TRACEME pid %d", current->pid);
	return -EPERM;
}

/* ---------------------------- W^X hooks ---------------------------------- */

/* Deny a request that makes a page writable AND executable at once. */
static int wx_check(unsigned long prot, const char *what)
{
	if (!READ_ONCE(ss_cfg.prguard_enabled))
		return 0;
	if ((prot & (PROT_WRITE | PROT_EXEC)) != (PROT_WRITE | PROT_EXEC))
		return 0;			/* not W+X: fine */
	if (current_exempt())
		return 0;

	pr_warn_ratelimited("prguard: denied W^X %s by UID %u (pid %d)\n",
			    what, from_kuid(&init_user_ns, current_uid()),
			    current->pid);
	ss_event_typed_self("process_runtime_guard", "current_process",
			    "request_memory_protection", what, "deny",
			    "write_execute_prohibited",
			    "prguard: denied W^X %s pid %d", what, current->pid);
	return -EPERM;
}

int ss_pg_mmap_file(struct file *file, unsigned long reqprot,
			   unsigned long prot, unsigned long flags)
{
	return wx_check(prot, "mmap");
}

int ss_pg_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
			  unsigned long prot)
{
	return wx_check(prot, "mprotect");
}

static struct security_hook_list ss_pg_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(ptrace_access_check, ss_pg_ptrace_access),
	LSM_HOOK_INIT(ptrace_traceme,      ss_pg_ptrace_traceme),
};

void __init ss_prguard_init(void)
{
	security_add_hooks(ss_pg_hooks, ARRAY_SIZE(ss_pg_hooks), &ss_lsmid);
}

/* ---------------------------- sysfs knob --------------------------------- */

static ssize_t prguard_show(struct kobject *k, struct kobj_attribute *a,
			    char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.prguard_enabled));
}
static ssize_t prguard_store(struct kobject *k, struct kobj_attribute *a,
			     const char *buf, size_t count)
{
	bool v;

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	WRITE_ONCE(ss_cfg.prguard_enabled, v);
	return count;
}
static struct kobj_attribute prguard_attr =
	__ATTR(prguard_enabled, 0600, prguard_show, prguard_store);

static ssize_t observe_show(struct kobject *k, struct kobj_attribute *a,
			    char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.prguard_observe));
}
static ssize_t observe_store(struct kobject *k, struct kobj_attribute *a,
			     const char *buf, size_t count)
{
	bool v;

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	WRITE_ONCE(ss_cfg.prguard_observe, v);
	return count;
}
static struct kobj_attribute prguard_observe_attr =
	__ATTR(prguard_observe, 0600, observe_show, observe_store);

static struct attribute *ss_pg_attrs[] = {
	&prguard_attr.attr,
	&prguard_observe_attr.attr,
	NULL,
};
static const struct attribute_group ss_pg_group = {
	.attrs = ss_pg_attrs,
};

int ss_prguard_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_pg_group);
}

/* --------------------- securityfs: prguard_allow ------------------------- */

static void pg_free(char **list, int count)
{
	int i;

	if (!list)
		return;
	for (i = 0; i < count; i++)
		kfree(list[i]);
	kvfree(list);
}

static char **pg_parse(char *text, int *out_count)
{
	char **list;
	char *p = text, *line;
	int n = 0;

	list = kvcalloc(PG_MAX_ITEMS, sizeof(*list), GFP_KERNEL);
	if (!list)
		return NULL;

	while ((line = strsep(&p, "\n")) && n < PG_MAX_ITEMS) {
		line = strim(line);
		if (*line == '\0' || *line == '#' || *line != '/')
			continue;		/* only absolute paths */
		list[n] = kstrdup(line, GFP_KERNEL);
		if (!list[n]) {
			pg_free(list, n);
			return NULL;
		}
		n++;
	}
	/* Sort so current_exempt() can bsearch. */
	sort(list, n, sizeof(*list), pg_cmp, NULL);
	*out_count = n;
	return list;
}

static ssize_t pg_read(struct file *file, char __user *ubuf, size_t count,
		       loff_t *ppos)
{
	ssize_t ret;

	mutex_lock(&pg_lock);
	ret = simple_read_from_buffer(ubuf, count, ppos,
				      pg_text ? pg_text : "", pg_text_len);
	mutex_unlock(&pg_lock);
	return ret;
}

static ssize_t pg_write(struct file *file, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	char *text, *scratch, **new_list, **old_list, *old_text;
	int new_count, old_count;

	if (!ss_may_admin(file))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (*ppos != 0)
		return -EINVAL;
	if (count == 0)
		return 0;
	if (count > PG_MAX_TEXT)
		return -EFBIG;

	text = kvmalloc(count + 1, GFP_KERNEL);
	if (!text)
		return -ENOMEM;
	if (copy_from_user(text, ubuf, count)) {
		kvfree(text);
		return -EFAULT;
	}
	text[count] = '\0';

	scratch = kvmemdup(text, count + 1, GFP_KERNEL);
	if (!scratch) {
		kvfree(text);
		return -ENOMEM;
	}
	new_list = pg_parse(scratch, &new_count);
	kvfree(scratch);
	if (!new_list) {
		kvfree(text);
		return -ENOMEM;
	}

	mutex_lock(&pg_lock);
	old_list = pg_list;
	old_count = pg_count;
	old_text = pg_text;
	pg_list = new_list;
	pg_count = new_count;
	pg_text = text;
	pg_text_len = count;
	mutex_unlock(&pg_lock);

	pg_free(old_list, old_count);
	kvfree(old_text);

	*ppos = count;
	return count;
}

static const struct file_operations pg_fops = {
	.read   = pg_read,
	.write  = pg_write,
	.llseek = default_llseek,
};

int ss_prguard_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("prguard_allow", 0600, dir, NULL, &pg_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
	return 0;
}
