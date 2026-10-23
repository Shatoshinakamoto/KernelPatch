// SPDX-License-Identifier: GPL-2.0
/*
 * ss_ram.c - Protection #7: RAM-spike detection -> drop caches.
 *
 * A periodic worker samples memory pressure; when usage crosses the configured
 * threshold it drops the page/slab caches, the kernel equivalent of
 *     echo 3 > /proc/sys/vm/drop_caches
 *
 * Two bugs from the v2 version are fixed here:
 *
 *  1. v2 computed "used" as (totalram - freeram), which counts the page cache
 *     as used - so on any busy box it is permanently "spiking" and drops caches
 *     constantly. We measure with si_mem_available(), which already excludes
 *     reclaimable cache, so the threshold means what an admin expects.
 *
 *  2. v2 wrapped the write in set_fs()/get_fs(), removed from the kernel back
 *     in 5.10; it would not compile on 6.12. We drop that.
 *
 * The drop runs entirely in kernel context from this worker - there is no
 * userspace process and no command a user could invoke or hijack, which is the
 * TODO's "private field" requirement. (The kernel exposes no stable symbol to
 * drop page+slab caches directly, so the worker writes to the sysctl itself
 * via kernel_write; that write is issued by the kernel, not by any task.)
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/swap.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/capability.h>
#include <linux/err.h>

#include "secure_sudo.h"

static struct delayed_work ram_work;
static unsigned long last_drop_jiffies;

static void do_drop_caches(void)
{
	struct file *f;
	loff_t pos = 0;
	const char three[] = "3\n";

	f = filp_open("/proc/sys/vm/drop_caches", O_WRONLY, 0);
	if (IS_ERR(f)) {
		pr_warn_ratelimited("ram: cannot open drop_caches (%ld)\n",
				    PTR_ERR(f));
		return;
	}
	kernel_write(f, three, sizeof(three) - 1, &pos);
	filp_close(f, NULL);
}

static void ram_work_fn(struct work_struct *w)
{
	u32 interval_ms = READ_ONCE(ss_cfg.check_interval_ms);
	u32 max_pct     = READ_ONCE(ss_cfg.max_ram_percent);
	u32 cooldown_ms = READ_ONCE(ss_cfg.drop_cooldown_ms);
	unsigned long totalram, avail, used_pct, now;

	if (!READ_ONCE(ss_cfg.ram_spike_enabled))
		goto rearm;

	totalram = totalram_pages();
	if (!totalram)
		goto rearm;

	/* si_mem_available() returns pages; it already discounts reclaimable
	 * page cache and slab, so this is "real" usage. */
	avail = si_mem_available();
	if (avail > totalram)
		avail = totalram;
	used_pct = (totalram - avail) * 100UL / totalram;

	now = jiffies;
	if (used_pct >= max_pct &&
	    (!last_drop_jiffies ||
	     time_after(now, last_drop_jiffies + msecs_to_jiffies(cooldown_ms)))) {
		last_drop_jiffies = now;
		pr_info("ram: usage %lu%% >= %u%% - dropping caches\n",
			used_pct, max_pct);
		do_drop_caches();
	}

rearm:
	schedule_delayed_work(&ram_work,
			      msecs_to_jiffies(interval_ms ? interval_ms : 5000));
}

void __init ss_ram_start(void)
{
	INIT_DELAYED_WORK(&ram_work, ram_work_fn);
	schedule_delayed_work(&ram_work,
			      msecs_to_jiffies(READ_ONCE(ss_cfg.check_interval_ms)));
}

/* ---------------------------- sysfs knobs -------------------------------- */

#define RAM_U32_ATTR(field, lo, hi)					\
static ssize_t field##_show(struct kobject *k, struct kobj_attribute *a,\
			    char *buf)					\
{									\
	return sysfs_emit(buf, "%u\n", READ_ONCE(ss_cfg.field));	\
}									\
static ssize_t field##_store(struct kobject *k, struct kobj_attribute *a,\
			     const char *buf, size_t count)		\
{									\
	u32 v;								\
	if (!ss_may_admin(NULL))					\
		return -EPERM;						\
	if (ss_locked())						\
		return -EPERM;						\
	if (kstrtou32(buf, 10, &v))					\
		return -EINVAL;						\
	if (ss_check_range(v, lo, hi))					\
		return -ERANGE;						\
	WRITE_ONCE(ss_cfg.field, v);					\
	return count;							\
}									\
static struct kobj_attribute field##_attr =				\
	__ATTR(field, 0600, field##_show, field##_store)

/* Ranges keep a root typo from turning the worker into a cache-drop storm. */
RAM_U32_ATTR(max_ram_percent, 1, 100);
RAM_U32_ATTR(check_interval_ms, 100, 3600 * 1000);
RAM_U32_ATTR(drop_cooldown_ms, 1000, 24 * 3600 * 1000);

static ssize_t ram_spike_enabled_show(struct kobject *k,
				      struct kobj_attribute *a, char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.ram_spike_enabled));
}
static ssize_t ram_spike_enabled_store(struct kobject *k,
				       struct kobj_attribute *a,
				       const char *buf, size_t count)
{
	bool v;

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (ss_locked())
		return -EPERM;
	if (kstrtobool(buf, &v))
		return -EINVAL;
	WRITE_ONCE(ss_cfg.ram_spike_enabled, v);
	return count;
}
static struct kobj_attribute ram_spike_enabled_attr =
	__ATTR(ram_spike_enabled, 0600,
	       ram_spike_enabled_show, ram_spike_enabled_store);

static struct attribute *ss_ram_attrs[] = {
	&max_ram_percent_attr.attr,
	&check_interval_ms_attr.attr,
	&drop_cooldown_ms_attr.attr,
	&ram_spike_enabled_attr.attr,
	NULL,
};

static const struct attribute_group ss_ram_group = {
	.attrs = ss_ram_attrs,
};

int ss_ram_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_ram_group);
}
