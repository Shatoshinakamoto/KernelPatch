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
 * any of our hooks; it never sleeps, marks bounded-string truncation, and
 * drops the oldest whole lines if a slow reader lets the ring fill.
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
#include <linux/cred.h>
#include <linux/random.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>

#include "secure_sudo.h"

#define SS_RING_BYTES	(64 * 1024)
#define SS_LINE_MAX	640

static DEFINE_KFIFO(ss_ring, char, SS_RING_BYTES);
static DEFINE_SPINLOCK(ss_ring_lock);
static DECLARE_WAIT_QUEUE_HEAD(ss_ring_wq);
static bool ss_ring_ready;
/* Lines discarded because a slow reader let the ring fill (never reset). */
static atomic64_t ss_ring_dropped = ATOMIC64_INIT(0);
static atomic64_t ss_event_sequence = ATOMIC64_INIT(0);
static atomic64_t ss_audit_dropped = ATOMIC64_INIT(0);
static u8 ss_boot_id[16];

u64 ss_events_dropped(void)
{
	return atomic64_read(&ss_ring_dropped);
}

u64 ss_audit_events_dropped(void)
{
	return atomic64_read(&ss_audit_dropped);
}

/* Last sequence number given to a record this boot (0: none yet). */
u64 ss_events_sequence(void)
{
	return atomic64_read(&ss_event_sequence);
}

/* This boot's event-stream id, as the records carry it (32 hex digits). */
void ss_events_boot_id(char out[33])
{
	int i;

	for (i = 0; i < (int)sizeof(ss_boot_id); i++)
		snprintf(out + 2 * i, 3, "%02x", ss_boot_id[i]);
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
	if (!ab) {
		atomic64_inc(&ss_audit_dropped);
		return;
	}
	audit_log_format(ab, "lsm=secure_sudo msg=");
	audit_log_untrustedstring(ab, msg);
	audit_log_end(ab);
#endif
}

static int ss_json_string(char *line, int n, const char *value,
			  int output_budget, bool *truncated)
{
	static const char hex[] = "0123456789abcdef";
	int start = n, i;

	line[n++] = '"';
	for (i = 0; value && value[i]; i++) {
		unsigned char c = value[i];
		int escaped = c == '"' || c == '\\';
		int unicode = c >= 0x80;
		int needed = unicode ? 6 : escaped ? 2 : 1;

		if (n - start - 1 + needed > output_budget) {
			*truncated = true;
			break;
		}
		if (c < 0x20 || c == 0x7f)
			c = '?';
		if (unicode) {
			line[n++] = '\\';
			line[n++] = 'u';
			line[n++] = '0';
			line[n++] = '0';
			line[n++] = hex[c >> 4];
			line[n++] = hex[c & 0x0f];
		} else if (escaped) {
			line[n++] = '\\';
			line[n++] = c;
		} else {
			line[n++] = c;
		}
	}
	line[n++] = '"';
	return n;
}

static int ss_json_field(char *line, int n, const char *name,
			 const char *value, int output_budget, bool *truncated)
{
	n += scnprintf(line + n, SS_LINE_MAX - n, "\"%s\":", name);
	if (value)
		n = ss_json_string(line, n, value, output_budget, truncated);
	else
		n += scnprintf(line + n, SS_LINE_MAX - n, "null");
	n += scnprintf(line + n, SS_LINE_MAX - n, ",");
	return n;
}

static int ss_json_pid_field(char *line, int n, const char *name,
			     bool valid, pid_t pid)
{
	n += scnprintf(line + n, SS_LINE_MAX - n, "\"%s\":", name);
	if (valid)
		n += scnprintf(line + n, SS_LINE_MAX - n, "%d,", pid);
	else
		n += scnprintf(line + n, SS_LINE_MAX - n, "null,");
	return n;
}

static int ss_json_uid_field(char *line, int n, const char *name,
			     bool valid, kuid_t uid)
{
	n += scnprintf(line + n, SS_LINE_MAX - n, "\"%s\":", name);
	if (valid)
		n += scnprintf(line + n, SS_LINE_MAX - n, "%u,",
			       from_kuid_munged(&init_user_ns, uid));
	else
		n += scnprintf(line + n, SS_LINE_MAX - n, "null,");
	return n;
}

static bool ss_event_type_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '_' || c == '-';
}

static void ss_event_v(const struct ss_event_fields *fields,
		       const char *fmt, va_list args)
{
	char line[SS_LINE_MAX], message[224], event_type[48];
	struct timespec64 ts;
	u64 realtime_ns, monotonic_ns, seq;
	int n, i, msg_len, type_len = 0;
	unsigned long flags;
	unsigned int uid;
	bool truncated = false;
	static const int field_budgets[] = { 32, 24, 64, 16, 40 };

	if (!READ_ONCE(ss_ring_ready)) {
		/* Before securityfs is up there is nowhere to put it: count
		 * it, so the loss is visible rather than silent. */
		atomic64_inc(&ss_ring_dropped);
		return;
	}

	msg_len = vscnprintf(message, sizeof(message), fmt, args);
	if (msg_len == sizeof(message) - 1)
		truncated = true;
	/*
	 * Escape the event payload as a JSON string. Besides making the record
	 * machine-parseable, this prevents attacker-controlled paths from
	 * injecting new records into the ring, local log, or audit feed.
	 */
	for (i = 0; i < msg_len; i++)
		if ((unsigned char)message[i] < 0x20 || message[i] == 0x7f)
			message[i] = '?';
	if (fields && fields->event_type) {
		if (strscpy(event_type, fields->event_type,
			    sizeof(event_type)) < 0)
			truncated = true;
	} else {
		while (type_len < msg_len &&
		       type_len < (int)sizeof(event_type) - 1 &&
		       ss_event_type_char(message[type_len])) {
			event_type[type_len] = message[type_len];
			type_len++;
		}
		if (type_len == (int)sizeof(event_type) - 1 &&
		    type_len < msg_len && ss_event_type_char(message[type_len]))
			truncated = true;
		if (!type_len)
			strscpy(event_type, "secure_sudo", sizeof(event_type));
		else
			event_type[type_len] = '\0';
	}
	uid = from_kuid_munged(&init_user_ns, current_uid());
	/*
	 * Number, stamp and queue the record under the ring lock, so records
	 * reach the ring in sequence order: a consumer can then treat any
	 * jump in "sequence" as records lost (dropped from a full ring), not
	 * as two CPUs racing between numbering and queueing.
	 */
	spin_lock_irqsave(&ss_ring_lock, flags);
	ktime_get_real_ts64(&ts);
	realtime_ns = (u64)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
	monotonic_ns = ktime_get_ns();
	seq = atomic64_inc_return(&ss_event_sequence);
	n = scnprintf(line, sizeof(line),
		      "{\"schema_version\":1,\"boot_id\":\"");
	for (i = 0; i < (int)sizeof(ss_boot_id); i++)
		n += scnprintf(line + n, sizeof(line) - n, "%02x",
			       ss_boot_id[i]);
	n += scnprintf(line + n, sizeof(line) - n,
		       "\",\"sequence\":%llu,\"realtime_ns\":%llu,"
		       "\"monotonic_ns\":%llu,\"event_type\":",
		      (unsigned long long)seq,
		      (unsigned long long)realtime_ns,
		      (unsigned long long)monotonic_ns);
	n = ss_json_string(line, n, event_type, 48, &truncated);
	n += scnprintf(line + n, sizeof(line) - n,
		       ",\"actor\":{\"pid\":%d,\"uid\":%u},",
		       current->pid, uid);
	n = ss_json_field(line, n, "target", fields ? fields->target : NULL,
			  field_budgets[0], &truncated);
	n = ss_json_field(line, n, "operation", fields ? fields->operation : NULL,
			  field_budgets[1], &truncated);
	n = ss_json_field(line, n, "object", fields ? fields->object : NULL,
			  field_budgets[2], &truncated);
	n = ss_json_field(line, n, "decision", fields ? fields->decision : NULL,
			  field_budgets[3], &truncated);
	n = ss_json_field(line, n, "reason", fields ? fields->reason : NULL,
			  field_budgets[4], &truncated);
	n = ss_json_pid_field(line, n, "target_pid",
			      fields && fields->target_pid_valid,
			      fields ? fields->target_pid : 0);
	n = ss_json_uid_field(line, n, "target_uid",
			      fields && fields->target_uid_valid,
			      fields ? fields->target_uid : KUIDT_INIT(0));
	n += scnprintf(line + n, sizeof(line) - n, "\"message\":");
	n = ss_json_string(line, n, message, sizeof(line) - n - 32,
			   &truncated);
	n += scnprintf(line + n, sizeof(line) - n,
		       ",\"truncated\":%s}\n", truncated ? "true" : "false");
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
	/* the audit copy is made outside our lock */
	line[n - 1] = '\0';
	ss_audit_event(line);
}

void ss_event_record(const struct ss_event_fields *fields, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ss_event_v(fields, fmt, args);
	va_end(args);
}

void ss_event(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ss_event_v(NULL, fmt, args);
	va_end(args);
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

	get_random_bytes(ss_boot_id, sizeof(ss_boot_id));
	d = securityfs_create_file("events", 0400, dir, NULL, &events_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);

	WRITE_ONCE(ss_ring_ready, true);
	ss_event_typed("event_log", NULL, "initialize", "kernel_event_ring",
		       "allow", NULL, "secure_sudo event log online");
	return 0;
}
