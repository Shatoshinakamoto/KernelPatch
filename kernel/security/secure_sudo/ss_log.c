// SPDX-License-Identifier: GPL-2.0
/*
 * ss_log.c - Protection #9: security event log, the kernel half.
 *
 * v2 tried to write a log file straight from kernel context (inside the
 * Netfilter softirq, no less), which recurses through the VFS and deadlocks.
 * The correct split, and the one the feature map calls for, is: the kernel
 * emits structured event lines into an in-memory ring; the userspace daemon
 * drains the ring and is the only thing that touches the filesystem, so it can
 * date-stamp, rotate, enforce retention and ship logs off-box (which TimeVault
 * needs). Nothing here ever opens a file.
 *
 * The ring is a byte kfifo behind a spinlock, readable (blocking) and pollable
 * at /sys/kernel/security/secure_sudo/events. ss_event() is safe to call from
 * any of our hooks; it never sleeps and silently drops the oldest bytes if a
 * slow reader lets the ring fill.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kfifo.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <linux/time64.h>
#include <linux/stdarg.h>
#include <linux/security.h>
#include <linux/audit.h>

#include "secure_sudo.h"

#define SS_RING_BYTES	(64 * 1024)
#define SS_LINE_MAX	256

static DEFINE_KFIFO(ss_ring, char, SS_RING_BYTES);
static DEFINE_SPINLOCK(ss_ring_lock);
static DECLARE_WAIT_QUEUE_HEAD(ss_ring_wq);
static bool ss_ring_ready;
/* Lines discarded because a slow reader let the ring fill (never reset). */
static atomic64_t ss_ring_dropped = ATOMIC64_INIT(0);

u64 ss_events_dropped(void)
{
	return atomic64_read(&ss_ring_dropped);
}

/*
 * Optional second sink: the kernel audit subsystem, so auditd / ausearch /
 * SIEM pipelines get every secure_sudo event as an AUDIT_KERNEL_OTHER record
 * (STIG AU family). The message goes through audit_log_untrustedstring(),
 * which hex-encodes it if it contains spaces or quotes, so an attacker-chosen
 * file name cannot forge extra key=value fields in the audit record. GFP_ATOMIC
 * never waits on the audit backlog, so this is safe from any hook.
 */
static void ss_audit_event(const char *msg)
{
#ifdef CONFIG_AUDIT
	struct audit_buffer *ab;

	if (!READ_ONCE(ss_cfg.audit_events))
		return;
	ab = audit_log_start(audit_context(), GFP_ATOMIC, AUDIT_KERNEL_OTHER);
	if (!ab)
		return;
	audit_log_format(ab, "lsm=secure_sudo msg=");
	audit_log_untrustedstring(ab, msg);
	audit_log_end(ab);
#endif
}

void ss_event(const char *fmt, ...)
{
	char line[SS_LINE_MAX];
	struct timespec64 ts;
	va_list args;
	int n, i, msg_off;
	unsigned long flags;

	if (!READ_ONCE(ss_ring_ready))
		return;

	ktime_get_real_ts64(&ts);
	n = scnprintf(line, sizeof(line), "%lld.%03ld ",
		      (long long)ts.tv_sec, ts.tv_nsec / NSEC_PER_MSEC);
	msg_off = n;

	va_start(args, fmt);
	n += vscnprintf(line + n, sizeof(line) - n - 1, fmt, args);
	va_end(args);

	/*
	 * Neutralise control characters. Events embed attacker-chosen strings
	 * (file names, exec paths), and a name containing "\n" would otherwise
	 * forge whole event lines in the log - and the daemon acts on some of
	 * them (CWE-117 log injection).
	 */
	for (i = 0; i < n; i++)
		if ((unsigned char)line[i] < 0x20 || line[i] == 0x7f)
			line[i] = '?';
	line[n] = '\0';

	ss_audit_event(line + msg_off);

	line[n++] = '\n';

	spin_lock_irqsave(&ss_ring_lock, flags);
	/*
	 * Make room by discarding the oldest WHOLE lines, so a reader never
	 * starts mid-event, and count each one so consumers can see that
	 * history is missing instead of assuming they saw everything.
	 */
	while (kfifo_avail(&ss_ring) < n && !kfifo_is_empty(&ss_ring)) {
		char c;

		while (kfifo_get(&ss_ring, &c) && c != '\n')
			;
		atomic64_inc(&ss_ring_dropped);
	}
	kfifo_in(&ss_ring, line, n);
	spin_unlock_irqrestore(&ss_ring_lock, flags);

	wake_up_interruptible(&ss_ring_wq);
}

/*
 * The writer (ss_event) also removes bytes when the ring is full, so the ring
 * has two consumers and must be drained under the same spinlock. We cannot
 * copy_to_user() under a spinlock, so bounce through a kernel buffer.
 */
static ssize_t events_read(struct file *file, char __user *ubuf, size_t count,
			   loff_t *ppos)
{
	unsigned int n;
	char *bounce;
	int ret;

	if (!count)
		return 0;
	if (kfifo_is_empty(&ss_ring)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(ss_ring_wq,
					       !kfifo_is_empty(&ss_ring));
		if (ret)
			return ret;
	}

	count = min_t(size_t, count, SS_RING_BYTES);
	bounce = kvmalloc(count, GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;
	n = kfifo_out_spinlocked(&ss_ring, bounce, count, &ss_ring_lock);
	ret = copy_to_user(ubuf, bounce, n) ? -EFAULT : n;
	kvfree(bounce);
	return ret;
}

static __poll_t events_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &ss_ring_wq, wait);
	return kfifo_is_empty(&ss_ring) ? 0 : (EPOLLIN | EPOLLRDNORM);
}

static const struct file_operations events_fops = {
	.read   = events_read,
	.poll   = events_poll,
	.llseek = noop_llseek,
};

int ss_log_secfs(struct dentry *dir)
{
	struct dentry *d;

	d = securityfs_create_file("events", 0400, dir, NULL, &events_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);

	WRITE_ONCE(ss_ring_ready, true);
	ss_event("secure_sudo event log online");
	return 0;
}
