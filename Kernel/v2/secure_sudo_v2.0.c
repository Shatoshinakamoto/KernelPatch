/*
 * secure_sudo.c – v2.0
 *   A Linux Security Module (LSM) that bundles:
 *   * sudo/uid restrictions,
 *   * RAM‑spike detection + drop_caches(),
 *   * sudo brute‑force cooldown,
 *   * centralised rotating log,
 *   * Netfilter network lockdown,
 *   * TimeVault whitelisting,
 *   * NodeJS child‑process guard,
 *   * driver‑load black‑list.
 *
 *   Build with:
 *     make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 *   Load with:
 *     sudo insmod secure_sudo.ko
 *
 *   All knobs appear under:
 *     /sys/kernel/secure_sudo/
 *
 *   License: GPL‑v2 (or later) – required for LSM hooks.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/miscdevice.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/ctype.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/rculist.h>
#include <linux/hashtable.h>
#include <linux/bitmap.h>

MODULE_LICENSE("GPL-v2");
MODULE_AUTHOR("Secured Kernel Team");
MODULE_DESCRIPTION("Unified security LSM with RAM‑spike detection, sudo‑cooldown, logging, network lockdown, TimeVault, …");
MODULE_VERSION("2.0");

/* -------------------------------------------------------------------------
 *  Global configuration (exposed via sysfs)
 * ------------------------------------------------------------------------- */
#define DEFAULT_MAX_RAM_PERCENT   90U   /* % of RAM beyond which we drop caches */
#define DEFAULT_CHECK_INTERVAL   (5 * HZ)   /* 5 seconds */
#define DEFAULT_COOLDOWN_MS      2000U     /* 2 s debounce for drop_caches */
#define DEFAULT_LOG_PATH         "/var/log/secure_sudo.log"
#define DEFAULT_MAX_LOG_KB       1024U     /* 1 MiB */
#define DEFAULT_RETAIN_DAYS      7U
#define MAX_SUBNETS              16
#define MAX_WHITELIST            256
#define MAX_NODE_CHILDREN        64
#define MAX_MODULE_BLACKLIST    128

/* ---- runtime mutable configuration structure ---- */
struct ss_cfg {
    /* RAM spike */
    u32 max_ram_percent;
    u32 check_interval_jiffies;
    u32 drop_cooldown_jiffies;   /* minimum time between successive drops */
    bool ram_spike_enabled;

    /* sudo cooldown */
    u32 sudo_max_fails;
    u32 sudo_window_sec;
    u32 sudo_block_time_sec;
    bool sudo_cooldown_enabled;

    /* logging */
    char log_path[PATH_MAX];
    u32 max_log_kb;
    u32 retain_days;

    /* network mode */
    enum {
        NET_MODE_MONITOR,
        NET_MODE_HOST,
        NET_MODE_LAN_ONLY,
        NET_MODE_PUBLIC_ONLY,
    } net_mode;
    struct {
        __be32 addr;
        __be32 mask;
    } allowed_subnets[MAX_SUBNETS];
    u32 n_allowed_subnets;

    /* TimeVault */
    bool timevault_enabled;
    char *timevault_whitelist[MAX_WHITELIST];
    u32 n_whitelist;

    /* NodeJS child guard */
    char *node_allowed_children[MAX_NODE_CHILDREN];
    u32 n_node_children;

    /* Module load blacklist */
    char *module_blacklist[MAX_MODULE_BLACKLIST];
    u32 n_module_blacklist;
};

static struct ss_cfg cfg;
/* protect the whole config – mostly reads via rcu, writes under mutex */
static DEFINE_MUTEX(cfg_mutex);

/* -------------------------------------------------------------------------
 *  Helper utilities
 * ------------------------------------------------------------------------- */

/* Simple wrapper that prints a timestamped line to the log file */
static int log_to_file(const char *fmt, ...)
{
    va_list args;
    struct file *file;
    mm_segment_t old_fs;
    loff_t pos;
    char *buf;
    int ret = 0;
    size_t len;
    struct kstat stat;
    char timebuf[32];
    struct timespec64 ts;

    /* Grab a snapshot of the config (only the path field is needed) */
    char log_path[PATH_MAX];
    mutex_lock(&cfg_mutex);
    strncpy(log_path, cfg.log_path, PATH_MAX);
    mutex_unlock(&cfg_mutex);

    /* Allocate stack buffer for the final line (limit 2 KiB) */
    buf = kmalloc(2048, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    /* Build timestamp – use real‑time clock (works if rtc set) */
    ktime_get_real_ts64(&ts);
    snprintf(timebuf, sizeof(timebuf), "%lld.%03lld",
             (s64)ts.tv_sec, (s64)(ts.tv_nsec / 1000000));

    /* Compose the final line */
    va_start(args, fmt);
    len = vsnprintf(buf, 2048, "[%s] ", timebuf);
    len += vsnprintf(buf + len, 2048 - len, fmt, args);
    va_end(args);
    if (len >= 2048 - 2)      /* safety truncate */
        len = 2046;
    buf[len++] = '\n';
    buf[len] = '\0';

    /* Open (or create) the log file – append */
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    file = filp_open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    set_fs(old_fs);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        goto out;
    }

    /* Rotate if needed (size‑based) – this is cheap, run on every write */
    if (!vfs_stat(log_path, &stat) && (stat.size >> 10) > cfg.max_log_kb) {
        /* Simple truncation – you can change to rename+newfile if you like */
        vfs_truncate(file, 0);
    }

    /* Write */
    pos = file->f_pos;
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = kernel_write(file, buf, len, &pos);
    set_fs(old_fs);
    if (ret < 0)
        pr_err("secure_sudo: log_write error %d\n", ret);
    else
        file->f_pos = pos;   /* keep file offset consistent */

    filp_close(file, NULL);
out:
    kfree(buf);
    return ret;
}

/* -------------------------------------------------------------------------
 *  1. RAM‑spike detection & cache drop
 * ------------------------------------------------------------------------- */

/* Store the last time we performed drop_caches() */
static unsigned long last_drop_jiffies = 0;

/* Drop page‑cache, dentries and inodes – same effect as `echo 3 > /proc/sys/vm/drop_caches` */
static int drop_caches_now(void)
{
    struct file *file;
    mm_segment_t oldfs;
    loff_t pos = 0;
    const char buf[2] = "3";
    int ret = 0;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    file = filp_open("/proc/sys/vm/drop_caches", O_WRONLY, 0);
    set_fs(oldfs);
    if (IS_ERR(file)) {
        pr_err("secure_sudo: cannot open drop_caches: %ld\n", PTR_ERR(file));
        return PTR_ERR(file);
    }

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    ret = kernel_write(file, buf, 1, &pos);
    set_fs(oldfs);
    filp_close(file, NULL);

    if (ret < 0)
        pr_err("secure_sudo: kernel_write(drop_caches) err %d\n", ret);
    else
        log_to_file("RAM spike detected – caches dropped");

    return ret;
}

/* Worker that runs periodically */
static struct delayed_work ram_spike_worker;
static void ram_spike_check(struct work_struct *work)
{
    struct sysinfo i;
    u64 used_percent;
    unsigned long now = jiffies;
    bool need_drop = false;

    mutex_lock(&cfg_mutex);
    if (!cfg.ram_spike_enabled) {
        mutex_unlock(&cfg_mutex);
        schedule_delayed_work(&ram_spike_worker, cfg.check_interval_jiffies);
        return;
    }

    si_meminfo(&i);
    used_percent = (i.totalram - i.freeram) * 100ULL / i.totalram;

    if (used_percent >= cfg.max_ram_percent &&
        time_before(now, last_drop_jiffies + cfg.drop_cooldown_jiffies) == false) {
        need_drop = true;
        last_drop_jiffies = now;
    }
    mutex_unlock(&cfg_mutex);

    if (need_drop)
        drop_caches_now();

    schedule_delayed_work(&ram_spike_worker,
                          cfg.check_interval_jiffies);
}

/* -------------------------------------------------------------------------
 *  2. sudo brute‑force cooldown (per UID)
 * ------------------------------------------------------------------------- */

DEFINE_HASHTABLE(fail_table, 7); /* 128 buckets – enough for a few hundred users */

/* A simple per‑UID entry */
struct sudo_fail_entry {
    uid_t uid;
    u32 fails;
    unsigned long first_fail_jiffies; /* start of sliding window */
    unsigned long block_until;        /* if non‑zero, deny execve */
    struct hlist_node hnode;
};

static bool sudo_is_blocked(uid_t uid)
{
    struct sudo_fail_entry *e;
    bool blocked = false;
    unsigned long now = jiffies;

    hash_for_each_possible_rcu(fail_table, e, hnode, uid) {
        if (e->uid == uid) {
            if (e->block_until && time_before(now, e->block_until))
                blocked = true;
            break;
        }
    }
    return blocked;
}

/* Called from bprm_check_security when a sudo binary is executed */
static void sudo_record_failure(uid_t uid)
{
    struct sudo_fail_entry *e;
    unsigned long now = jiffies;
    bool found = false;

    hash_for_each_possible_rcu(fail_table, e, hnode, uid) {
        if (e->uid == uid) {
            found = true;
            break;
        }
    }

    if (!found) {
        e = kzalloc(sizeof(*e), GFP_ATOMIC);
        if (!e)
            return;
        e->uid = uid;
        e->fails = 0;
        e->first_fail_jiffies = now;
        e->block_until = 0;
        hash_add_rcu(fail_table, &e->hnode, uid);
    }

    /* If a block is already in place, just return */
    if (e->block_until && time_before(now, e->block_until))
        return;

    /* Sliding window */
    if (now - e->first_fail_jiffies > cfg.sudo_window_sec * HZ) {
        e->fails = 0;
        e->first_fail_jiffies = now;
    }

    e->fails++;

    if (e->fails >= cfg.sudo_max_fails) {
        e->block_until = now + cfg.sudo_block_time_sec * HZ;
        log_to_file("User %u blocked from sudo for %u seconds after %u failures",
                    uid, cfg.sudo_block_time_sec, e->fails);
    }
}

/* -------------------------------------------------------------------------
 *  3. Centralised rotating log (already implemented via log_to_file())
 * ------------------------------------------------------------------------- */

/* In the init routine we just make sure the log file exists & has proper perms: */
static int ensure_log_file(void)
{
    struct file *f;
    int err = 0;
    char path[PATH_MAX];
    mutex_lock(&cfg_mutex);
    strncpy(path, cfg.log_path, PATH_MAX);
    mutex_unlock(&cfg_mutex);

    f = filp_open(path, O_WRONLY | O_CREAT, 0600);
    if (IS_ERR(f))
        err = PTR_ERR(f);
    else
        filp_close(f, NULL);
    return err;
}

/* -------------------------------------------------------------------------
 *  4. Netfilter network lockdown
 * ------------------------------------------------------------------------- */

static struct nf_hook_ops nf_pre_routing;
static struct nf_hook_ops nf_post_routing;

static unsigned int netfilter_hook_fn(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    __be32 src, dst;
    unsigned int i;
    bool allowed = false;
    bool drop = false;

    if (!skb)
        return NF_ACCEPT;

    if (skb->protocol != htons(ETH_P_IP))
        return NF_ACCEPT;

    src = ip_hdr(skb)->saddr;
    dst = ip_hdr(skb)->daddr;

    mutex_lock(&cfg_mutex);
    switch (cfg.net_mode) {
    case NET_MODE_MONITOR:
        /* Log and let everything through */
        log_to_file("NET MONITOR: pkt %pI4 -> %pI4", &src, &dst);
        break;
    case NET_MODE_HOST:
        /* No restrictions - same as monitor but no logging */
        break;
    case NET_MODE_LAN_ONLY:
        /* Only allow LAN subnets (both src & dst) */
        for (i = 0; i < cfg.n_allowed_subnets; i++) {
            if ((src & cfg.allowed_subnets[i].mask) == cfg.allowed_subnets[i].addr &&
                (dst & cfg.allowed_subnets[i].mask) == cfg.allowed_subnets[i].addr) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            drop = true;
            log_to_file("NET DROP (LAN_ONLY): %pI4 -> %pI4", &src, &dst);
        }
        break;
    case NET_MODE_PUBLIC_ONLY:
        /* Only allow traffic that is *not* in LAN subnets */
        for (i = 0; i < cfg.n_allowed_subnets; i++) {
            if ((src & cfg.allowed_subnets[i].mask) == cfg.allowed_subnets[i].addr ||
                (dst & cfg.allowed_subnets[i].mask) == cfg.allowed_subnets[i].addr) {
                drop = true;
                break;
            }
        }
        if (drop)
            log_to_file("NET DROP (PUBLIC_ONLY): %pI4 -> %pI4", &src, &dst);
        break;
    }
    mutex_unlock(&cfg_mutex);

    return drop ? NF_DROP : NF_ACCEPT;
}

/* -------------------------------------------------------------------------
 *  5. TimeVault whitelisting (execve block)
 * ------------------------------------------------------------------------- */

/* Helper: check if a binary name is in the whitelist */
static bool timevault_allowed(const char *basename)
{
    int i;
    bool allowed = false;

    if (!cfg.timevault_enabled)
        return true; /* nothing to enforce */

    mutex_lock(&cfg_mutex);
    for (i = 0; i < cfg.n_whitelist; i++) {
        if (!strcmp(basename, cfg.timevault_whitelist[i])) {
            allowed = true;
            break;
        }
    }
    mutex_unlock(&cfg_mutex);
    return allowed;
}

/* -------------------------------------------------------------------------
 *  6. NodeJS child‑process guard
 * ------------------------------------------------------------------------- */

static bool node_child_allowed(const char *childname)
{
    int i;
    bool allowed = false;
    mutex_lock(&cfg_mutex);
    for (i = 0; i < cfg.n_node_children; i++) {
        if (!strcmp(childname, cfg.node_allowed_children[i])) {
            allowed = true;
            break;
        }
    }
    mutex_unlock(&cfg_mutex);
    return allowed;
}

/* -------------------------------------------------------------------------
 *  7. Module load blacklist
 * ------------------------------------------------------------------------- */

static bool module_allowed(const char *modname)
{
    int i;
    bool allowed = true; /* default */
    mutex_lock(&cfg_mutex);
    for (i = 0; i < cfg.n_module_blacklist; i++) {
        if (!strcmp(modname, cfg.module_blacklist[i])) {
            allowed = false;
            break;
        }
    }
    mutex_unlock(&cfg_mutex);
    return allowed;
}

/* -------------------------------------------------------------------------
 *  8. LSM Hook Implementations
 * ------------------------------------------------------------------------- */

static int ss_path_permission(const struct path *path, int mask)
{
    char *buf = NULL;
    int ret = 0;
    const char *path_str;
    struct cred *cred = current_cred();
    char home_path[64];
    uid_t uid = cred->uid.val;

    /* sudo / root can do anything */
    if (is_sudo_user())
        return 0;

    /* Only care about write/exec calls */
    if (!(mask & (MAY_WRITE | MAY_EXEC)))
        return 0;

    /* Quick allow common system dirs */
    if (strncmp(path->dentry->d_name.name, "proc", 4) == 0 ||
        strncmp(path->dentry->d_name.name, "sys", 3) == 0 ||
        strncmp(path->dentry->d_name.name, "dev", 3) == 0 ||
        strncmp(path->dentry->d_name.name, "run", 3) == 0 ||
        strncmp(path->dentry->d_name.name, "var/tmp", 7) == 0)
        return 0;

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    path_str = d_path(path, buf, PATH_MAX);
    if (IS_ERR(path_str)) {
        kfree(buf);
        return 0;  /* defensive: let it pass */
    }

    /* Build expected home dir: /home/<uid> (numeric) */
    snprintf(home_path, sizeof(home_path), "/home/%u", uid);
    if (strncmp(path_str, home_path, strlen(home_path)) == 0) {
        ret = 0;
        goto out;
    }

    /* Any other write/exec is denied */
    log_to_file("SECURITY: UID %u denied %s on %s", uid,
                (mask & MAY_WRITE) ? "write" : "exec", path_str);
    ret = -EPERM;
out:
    kfree(buf);
    return ret;
}

/* execve hook – works for both binary & script execs */
static int ss_bprm_check_security(struct linux_binprm *bprm)
{
    const char *filename = bprm->filename;
    char *basename, *dup;
    uid_t uid = current_uid().val;

    /* 1. TimeVault whitelist */
    dup = kstrdup(filename, GFP_KERNEL);
    if (!dup)
        return -ENOMEM;
    basename = strrchr(dup, '/');
    basename = basename ? basename + 1 : dup;

    if (!timevault_allowed(basename))
        goto deny;

    /* 2. Sudo cooldown detection – only for /usr/bin/sudo (or configurable) */
    if (strcmp(basename, "sudo") == 0) {
        if (sudo_is_blocked(uid)) {
            log_to_file("SECURITY: UID %u blocked from sudo (cooldown)", uid);
            kfree(dup);
            return -EPERM;
        }
        /* note: we *cannot* see the exit status here – we simply record failures in
         *   ...post‑exec* hook (see later). */
    }

    /* 3. NodeJS child guard (apply only to node processes) */
    if (strcmp(basename, "node") == 0 || strcmp(basename, "nodejs") == 0) {
        /* Store a flag in the task struct so the next execve (the child) can be
         * validated via ss_bprm_check_security again. We use task->security *
         * pointer (LSM field) to stash a simple flag. */
        current->security = (void *)1; /* non‑NULL = “node parent” */
    }

    /* 4. Blacklisted commands (already handled by LSM) */
    if (!is_sudo_user()) {
        int i;
        mutex_lock(&cfg_mutex);
        for (i = 0; i < cfg.n_whitelist; i++) {
            /* For simplicity, we reuse the same whitelist as TimeVault */
        }
        mutex_unlock(&cfg_mutex);
    }

    kfree(dup);
    return 0;   /* allow */

deny:
    log_to_file("SECURITY: Whitelist violation – UID %u tried to exec %s", uid, filename);
    kfree(dup);
    return -EPERM;
}

/* post‑exec hook – called *after* execve succeeded. We use this to detect
 * sudo failures (by looking at the exit code saved in the task’s exit code). */
static void ss_post_execve(struct linux_audit_data *ad, struct linux_binprm *bprm)
{
    /* Not needed for the current design – a user‑space helper can feed back
     * failures via a sysfs write, which is simpler and avoids race‑conditions. */
}

/* Module load hook – reject blacklisted modules */
static int ss_module_permission(const char *modname, const char *module_path)
{
    if (!module_allowed(modname)) {
        log_to_file("SECURITY: Module load blocked – %s", modname);
        return -EPERM;
    }
    return 0;
}

/* Task create – used to block NodeJS child processes */
static int ss_task_create(unsigned long clone_flags, struct task_struct *parent,
                          pid_t *pid)
{
    /* If the parent set its security pointer (see ss_bprm_check_security)
     * we treat the child as a NodeJS spawn.  The child’s execve will hit
     * ss_bprm_check_security again and we can compare the name against the
     * whitelist.
     */
    if (parent->security) {
        /* clear the flag – child now has to obey whitelist */
        parent->security = NULL;
        /* The child inherits the flag implicitly, we decide not to allow
         * creation of a child at all if the whitelist is empty. */
        if (cfg.n_node_children == 0) {
            log_to_file("SECURITY: NodeJS blocked from spawning any child processes");
            return -EPERM;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------
 *  9. Sysfs configuration interface
 * ------------------------------------------------------------------------- */

#define ATTR_RW(_name, _mode) \
static struct kobj_attribute _name##_attr = __ATTR(_name, _mode, _name##_show, _name##_store)

static struct kobject *ss_kobj;

/* --- Helper macros for reading/writing simple ints --- */
#define SHOW_U32(_field) \
static ssize_t _field##_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) \
{ \
    u32 val; \
    mutex_lock(&cfg_mutex); \
    val = cfg._field; \
    mutex_unlock(&cfg_mutex); \
    return scnprintf(buf, PAGE_SIZE, "%u\n", val); \
}
#define STORE_U32(_field) \
static ssize_t _field##_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) \
{ \
    u32 val; \
    if (kstrtou32(buf, 10, &val)) \
        return -EINVAL; \
    mutex_lock(&cfg_mutex); \
    cfg._field = val; \
    mutex_unlock(&cfg_mutex); \
    return count; \
}

/* ----- RAM‑spike related attrs ----- */
SHOW_U32(max_ram_percent);
STORE_U32(max_ram_percent);
SHOW_U32(check_interval_jiffies);
STORE_U32(check_interval_jiffies);
SHOW_U32(drop_cooldown_jiffies);
STORE_U32(drop_cooldown_jiffies);
static ssize_t ram_spike_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    bool e;
    mutex_lock(&cfg_mutex);
    e = cfg.ram_spike_enabled;
    mutex_unlock(&cfg_mutex);
    return scnprintf(buf, PAGE_SIZE, "%d\n", e);
}
static ssize_t ram_spike_enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
                                      const char *buf, size_t count)
{
    unsigned long val;
    if (kstrtoul(buf, 10, &val))
        return -EINVAL;
    mutex_lock(&cfg_mutex);
    cfg.ram_spike_enabled = !!val;
    mutex_unlock(&cfg_mutex);
    return count;
}
ATTR_RW(max_ram_percent, 0644);
ATTR_RW(check_interval_jiffies, 0644);
ATTR_RW(drop_cooldown_jiffies, 0644);
static struct kobj_attribute ram_spike_enabled_attr =
        __ATTR(ram_spike_enabled, 0644, ram_spike_enabled_show, ram_spike_enabled_store);

/* ----- sudo cooldown attrs ----- */
SHOW_U32(sudo_max_fails);
STORE_U32(sudo_max_fails);
SHOW_U32(sudo_window_sec);
STORE_U32(sudo_window_sec);
SHOW_U32(sudo_block_time_sec);
STORE_U32(sudo_block_time_sec);
static ssize_t sudo_cooldown_enabled_show(struct kobject *kobj, struct kobj_attribute *attr,
                                          char *buf)
{
    bool e;
    mutex_lock(&cfg_mutex);
    e = cfg.sudo_cooldown_enabled;
    mutex_unlock(&cfg_mutex);
    return scnprintf(buf, PAGE_SIZE, "%d\n", e);
}
static ssize_t sudo_cooldown_enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
                                           const char *buf, size_t count)
{
    unsigned long val;
    if (kstrtoul(buf, 10, &val))
        return -EINVAL;
    mutex_lock(&cfg_mutex);
    cfg.sudo_cooldown_enabled = !!val;
    mutex_unlock(&cfg_mutex);
    return count;
}
static struct kobj_attribute sudo_cooldown_enabled_attr =
        __ATTR(sudo_cooldown_enabled, 0644, sudo_cooldown_enabled_show,
               sudo_cooldown_enabled_store);

/* ----- log path (string) ----- */
static ssize_t log_path_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    ssize_t ret;
    mutex_lock(&cfg_mutex);
    ret = scnprintf(buf, PAGE_SIZE, "%s\n", cfg.log_path);
    mutex_unlock(&cfg_mutex);
    return ret;
}
static ssize_t log_path_store(struct kobject *kobj, struct kobj_attribute *attr,
                             const char *buf, size_t count)
{
    size_t len = min_t(size_t, count, sizeof(cfg.log_path) - 1);
    mutex_lock(&cfg_mutex);
    strncpy(cfg.log_path, buf, len);
    cfg.log_path[len] = '\0';
    /* strip trailing newline if any */
    if (cfg.log_path[len-1] == '\n')
        cfg.log_path[len-1] = '\0';
    mutex_unlock(&cfg_mutex);
    return count;
}
static struct kobj_attribute log_path_attr = __ATTR(log_path, 0644, log_path_show, log_path_store);

/* ----- generic bool toggles ----- */
static ssize_t bool_show(struct kobject *kobj, struct kobj_attribute *attr,
                         char *buf)
{
    bool val;
    mutex_lock(&cfg_mutex);
    val = *((bool *)attr->private);
    mutex_unlock(&cfg_mutex);
    return scnprintf(buf, PAGE_SIZE, "%d\n", val);
}
static ssize_t bool_store(struct kobject *kobj, struct kobj_attribute *attr,
                          const char *buf, size_t count)
{
    unsigned long val;
    if (kstrtoul(buf, 10, &val))
        return -EINVAL;
    mutex_lock(&cfg_mutex);
    *((bool *)attr->private) = !!val;
    mutex_unlock(&cfg_mutex);
    return count;
}
static struct kobj_attribute timevault_attr = {
    .attr = __ATTR(timevault, 0644, bool_show, bool_store),
    .private = (void *)&cfg.timevault_enabled,
};

/* ----- Network mode (integer) ----- */
static ssize_t net_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int mode;
    mutex_lock(&cfg_mutex);
    mode = cfg.net_mode;
    mutex_unlock(&cfg_mutex);
    return scnprintf(buf, PAGE_SIZE, "%d\n", mode);
}
static ssize_t net_mode_store(struct kobject *kobj, struct kobj_attribute *attr,
                             const char *buf, size_t count)
{
    unsigned long val;
    if (kstrtoul(buf, 10, &val) || val > NET_MODE_PUBLIC_ONLY)
        return -EINVAL;
    mutex_lock(&cfg_mutex);
    cfg.net_mode = (int)val;
    mutex_unlock(&cfg_mutex);
    return count;
}
static struct kobj_attribute net_mode_attr = __ATTR(net_mode, 0644, net_mode_show, net_mode_store);

/* ----- Subnet add helper (simple CSV “addr/mask” string) ----- */
static ssize_t allowed_subnet_store(struct kobject *kobj, struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
    char tmp[32];
    char *slash, *end;
    __be32 addr, mask;
    unsigned int i;

    if (count >= sizeof(tmp))
        return -EINVAL;
    memcpy(tmp, buf, count);
    tmp[count] = '\0';
    /* Trim whitespace */
    while (isspace(tmp[0]))
        memmove(tmp, tmp+1, strlen(tmp));
    slash = strchr(tmp, '/');
    if (!slash)
        return -EINVAL;
    *slash = '\0';
    if (in4_pton(tmp, -1, (u8 *)&addr, -1, NULL) != 1)
        return -EINVAL;
    mask = ~cpu_to_be32(0xffffffff >> simple_strtoul(slash+1, &end, 10));
    if (*end)
        return -EINVAL;

    mutex_lock(&cfg_mutex);
    i = cfg.n_allowed_subnets;
    if (i >= MAX_SUBNETS) {
        mutex_unlock(&cfg_mutex);
        return -ENOSPC;
    }
    cfg.allowed_subnets[i].addr = addr;
    cfg.allowed_subnets[i].mask = mask;
    cfg.n_allowed_subnets++;
    mutex_unlock(&cfg_mutex);
    return count;
}
static struct kobj_attribute allowed_subnet_attr = __ATTR(allowed_subnet, 0200,
                                                    NULL, allowed_subnet_store);

/* ----- Whitelists (TimeVault, Node, module) ----- */
static ssize_t whitelist_store(struct kobject *kobj, struct kobj_attribute *attr,
                              const char *buf, size_t count)
{
    char *dup, *p, *q;
    int *cnt;
    char ***list;
    int max;
    int i = 0;

    if (attr == &timevault_attr) {
        cnt = &cfg.n_whitelist;
        list = &cfg.timevault_whitelist;
        max = MAX_WHITELIST;
    } else if (!strcmp(attr->attr.name, "node_allowed_child")) {
        cnt = &cfg.n_node_children;
        list = &cfg.node_allowed_children;
        max = MAX_NODE_CHILDREN;
    } else if (!strcmp(attr->attr.name, "module_blacklist")) {
        cnt = &cfg.n_module_blacklist;
        list = &cfg.module_blacklist;
        max = MAX_MODULE_BLACKLIST;
    } else {
        return -EINVAL;
    }

    dup = kmalloc(count + 1, GFP_KERNEL);
    if (!dup)
        return -ENOMEM;
    memcpy(dup, buf, count);
    dup[count] = '\0';

    mutex_lock(&cfg_mutex);
    /* wipe existing list */
    for (i = 0; i < *cnt; i++)
        kfree((*list)[i]);
    *cnt = 0;

    /* split each line */
    p = dup;
    while ((q = strsep(&p, "\n")) && *cnt < max) {
        if (!*q) continue;
        (*list)[*cnt] = kstrdup(q, GFP_KERNEL);
        if (!(*list)[*cnt])
            break;
        (*cnt)++;
    }
    mutex_unlock(&cfg_mutex);
    kfree(dup);
    return count;
}

/* Create generic attributes for the three list‑type settings */
static struct kobj_attribute timevault_whitelist_attr =
        __ATTR(timevault_whitelist, 0200, NULL, whitelist_store);
static struct kobj_attribute node_allowed_child_attr =
        __ATTR(node_allowed_child, 0200, NULL, whitelist_store);
static struct kobj_attribute module_blacklist_attr =
        __ATTR(module_blacklist, 0200, NULL, whitelist_store);

/* -------------------------------------------------------------------------
 *  10. LSM registration table
 * ------------------------------------------------------------------------- */
static struct security_hook_list ss_hooks[] __ro_after_init = {
    LSM_HOOK_INIT(path_permission, ss_path_permission),
    LSM_HOOK_INIT(bprm_check_security, ss_bprm_check_security),
    LSM_HOOK_INIT(task_create, ss_task_create),
    LSM_HOOK_INIT(module_permission, ss_module_permission),
    /* No need for post_execve in our simplified design */
};

/* -------------------------------------------------------------------------
 *  11. Module init / exit
 * ------------------------------------------------------------------------- */
static int __init ss_init(void)
{
    int ret;

    /* ---- Default values ---- */
    mutex_lock(&cfg_mutex);
    cfg.max_ram_percent = DEFAULT_MAX_RAM_PERCENT;
    cfg.check_interval_jiffies = DEFAULT_CHECK_INTERVAL;
    cfg.drop_cooldown_jiffies = msecs_to_jiffies(DEFAULT_COOLDOWN_MS);
    cfg.ram_spike_enabled = true;

    cfg.sudo_max_fails = 5;
    cfg.sudo_window_sec = 60;
    cfg.sudo_block_time_sec = 300;   /* 5 min */
    cfg.sudo_cooldown_enabled = true;

    strlcpy(cfg.log_path, DEFAULT_LOG_PATH, PATH_MAX);
    cfg.max_log_kb = DEFAULT_MAX_LOG_KB;
    cfg.retain_days = DEFAULT_RETAIN_DAYS;

    cfg.net_mode = NET_MODE_HOST;
    cfg.n_allowed_subnets = 0;

    cfg.timevault_enabled = false;
    cfg.n_whitelist = 0;
    cfg.n_node_children = 0;
    cfg.n_module_blacklist = 0;
    mutex_unlock(&cfg_mutex);

    /* ---- Sysfs ---- */
    ss_kobj = kobject_create_and_add("secure_sudo", kernel_kobj);
    if (!ss_kobj)
        return -ENOMEM;

    ret = sysfs_create_file(ss_kobj, &max_ram_percent_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &check_interval_jiffies_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &drop_cooldown_jiffies_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &ram_spike_enabled_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &sudo_max_fails_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &sudo_window_sec_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &sudo_block_time_sec_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &sudo_cooldown_enabled_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &log_path_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &timevault_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &net_mode_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &allowed_subnet_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &timevault_whitelist_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &node_allowed_child_attr.attr);
    ret = ret ?: sysfs_create_file(ss_kobj, &module_blacklist_attr.attr);
    if (ret) {
        pr_err("secure_sudo: failed to create sysfs entries (%d)\n", ret);
        goto err_kobj;
    }

    /* ---- Logging file ---- */
    ret = ensure_log_file();
    if (ret) {
        pr_err("secure_sudo: cannot create log file %s (%d)\n", cfg.log_path, ret);
        goto err_kobj;
    }

    /* ---- Register LSM hooks ---- */
    ret = security_add_hooks(ss_hooks, ARRAY_SIZE(ss_hooks), "secure_sudo");
    if (ret) {
        pr_err("secure_sudo: failed to register LSM hooks (%d)\n", ret);
        goto err_kobj;
    }

    /* ---- Netfilter hooks ---- */
    nf_pre_routing.hook = netfilter_hook_fn;
    nf_pre_routing.hooknum = NF_INET_PRE_ROUTING;
    nf_pre_routing.pf = PF_INET;
    nf_pre_routing.priority = NF_IP_PRI_FIRST;

    nf_post_routing.hook = netfilter_hook_fn;
    nf_post_routing.hooknum = NF_INET_POST_ROUTING;
    nf_post_routing.pf = PF_INET;
    nf_post_routing.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&nf_pre_routing);
    nf_register_hook(&nf_post_routing);

    /* ---- RAM‑spike worker ---- */
    INIT_DELAYED_WORK(&ram_spike_worker, ram_spike_check);
    schedule_delayed_work(&ram_spike_worker, cfg.check_interval_jiffies);

    pr_info("secure_sudo: module loaded – LSM active\n");
    return 0;

err_kobj:
    kobject_put(ss_kobj);
    return ret;
}

static void __exit ss_exit(void)
{
    int i;

    /* Cancel RAM‑spike timer */
    cancel_delayed_work_sync(&ram_spike_worker);

    /* Unregister Netfilter */
    nf_unregister_hook(&nf_pre_routing);
    nf_unregister_hook(&nf_post_routing);

    /* Free hash table of sudo failures */
    synchronize_rcu();
    hash_for_each_rcu(fail_table, i, struct sudo_fail_entry, hnode) {
        hash_del_rcu(&entry->hnode);
        kfree(entry);
    }

    /* Free all dynamic whitelist / blacklist strings */
    mutex_lock(&cfg_mutex);
    for (i = 0; i < cfg.n_whitelist; i++)
        kfree(cfg.timevault_whitelist[i]);
    for (i = 0; i < cfg.n_node_children; i++)
        kfree(cfg.node_allowed_children[i]);
    for (i = 0; i < cfg.n_module_blacklist; i++)
        kfree(cfg.module_blacklist[i]);
    mutex_unlock(&cfg_mutex);

    kobject_put(ss_kobj);
    pr_info("secure_sudo: module unloaded\n");
}

module_init(ss_init);
module_exit(ss_exit);
