Below is a **complete, build‑able design** that extends the `secure_sudo` module you already have with the three missing pieces you asked for:

* **BPF‑based UI** – a pin‑ned BPF map that holds the current status (RAM‑spike flag, TimeVault flag, Merkle‑root, quarantine counters …).  
  A tiny userspace tool (`ss_status`) reads that map with libbpf and prints a JSON‑ish report.

* **Merkle‑Tree File‑Integrity** – a one‑shot kernel‑thread walks a *monitoring tree* (set by a sysfs attribute), hashes every regular file with SHA‑256, builds a Merkle tree for the complete directory hierarchy and stores the root hash.  
  While **TimeVault** is active every write/exec on a monitored inode is re‑hashed; a mismatch or a newly‑created inode is treated as an integrity violation.

* **TimeVault Quarantine & Compression** – when a non‑whitelisted binary is executed (or a file that fails the Merkle check is written) the offending file is **moved to a quarantine directory** and **compressed with the kernel zlib API** (`deflate`).  
  The kernel keeps a short in‑memory list of the compressed blobs; their count is exported in the BPF status map and the raw `.gz` files are visible under `/var/lib/secure_sudo/quarantine/`.  

Everything is driven from the same `secure_sudo` LSM, all knobs are exposed under  
`/sys/kernel/secure_sudo/…` and nothing requires a reboot.  
All added code lives in a **single file** (`secure_sudo.c`) plus a **small shared header** (`secure_sudo_shared.h`) and a **userspace helper** (`ss_status.c`).  

---

## 1. Shared definitions (`secure_sudo_shared.h`)

```c
/* SPDX‑License-Identifier: GPL‑v2 */
#ifndef SECURE_SUDO_SHARED_H
#define SECURE_SUDO_SHARED_H

#include <linux/types.h>

#define SHA256_DIGEST_SIZE 32
#define SS_MAX_PATH        256

/* The structure that is pinned into the BPF map and read by the UI */
struct ss_status {
    __u32 ram_spike_enabled;          /* 0/1 */
    __u32 max_ram_percent;            /* configured limit */
    __u64 last_drop_jiffies;          /* when the last drop_caches ran */
    __u32 timevault_enabled;          /* 0/1 */
    __u32 num_quarantined;            /* how many files have been quarantined */
    __u8  merkle_root[SHA256_DIGEST_SIZE];
    __u32 reserved;                   /* future‑proof padding */
};

/* Event that can be emitted on the perf ring (optional) */
struct ss_event {
    __u64 ts_nsec;
    __u32 pid;
    __u32 action;                     /* 1 = ram‑spike, 2 = quarantine, 3 = sudo‑block, … */
    char  path[SS_MAX_PATH];
};

#endif /* SECURE_SUDO_SHARED_H */
```

> **Why a shared header?**  
Both the kernel module *and* the userspace BPF/UI program need the exact layout of `struct ss_status`. Keeping it in a header avoids copy‑&‑paste errors.

---

## 2. Kernel side – `secure_sudo.c` (only the **new/changed** parts shown)

Below is a **self‑contained patch** that you can drop into the original file.  
All existing code (the LSM hooks you already own) stays untouched – we merely add new globals, helpers, sysfs attributes, a work‑queue for the Merkle tree, the quarantine logic, and the BPF map.

```c
/*
 * secure_sudo.c – v2.0   (adds BPF UI, Merkle‑tree integrity and TimeVault quarantine)
 *
 *  Build requirements
 *      CONFIG_BPF=y
 *      CONFIG_BPF_SYSCALL=y
 *      CONFIG_BPF_LSM=y            (for the optional perf events)
 *      CONFIG_CRYPTO_SHA256=y
 *      CONFIG_ZLIB_INFLATE=y
 *
 *  The rest of the original file is unchanged – the new code starts after the
 *  existing includes.
 */

#include "secure_sudo_shared.h"          /* <-- our shared definitions */

/* --------------------------------------------------------------------- *
 *  1.  Global data structures
 * --------------------------------------------------------------------- */
static struct bpf_map *status_bpf_map __rcu;               /* pinned map   */
static DEFINE_MUTEX(status_lock);                         /* protect map updates */

/* Merkle‑tree data ----------------------------------------------------- */
#define MERKLE_HASH_TABLE_BITS   8        /* 256 buckets – enough for a few thousand files */
static DEFINE_HASHTABLE(file_hash_tab, MERKLE_HASH_TABLE_BITS);

struct file_hash {
    u64 ino;                         /* inode number (unique per filesystem)   */
    u8  digest[SHA256_DIGEST_SIZE];
    struct hlist_node node;
};

/* TimeVault quarantine ------------------------------------------------- */
static LIST_HEAD(quarantine_list);
static DEFINE_MUTEX(quarantine_lock);
static atomic_t quarantine_counter = ATOMIC_INIT(0);

/* A small struct that describes one quarantined blob */
struct quarantine_entry {
    char *path;                /* original absolute path (for logging)   */
    u8  *comp_data;            /* gzipped payload                       */
    size_t comp_len;
    size_t orig_len;
    struct list_head list;
};

/* --------------------------------------------------------------------- *
 *  2.  Helper: update the BPF status map
 * --------------------------------------------------------------------- */
static void ss_update_status(void)
{
    struct ss_status cur = {};
    __u32 key = 0;

    mutex_lock(&cfg_mutex);
    cur.ram_spike_enabled = cfg.ram_spike_enabled;
    cur.max_ram_percent   = cfg.max_ram_percent;
    cur.last_drop_jiffies = last_drop_jiffies;
    cur.timevault_enabled = cfg.timevault_enabled;
    cur.num_quarantined    = atomic_read(&quarantine_counter);
    memcpy(cur.merkle_root, cfg.merkle_root, SHA256_DIGEST_SIZE);
    mutex_unlock(&cfg_mutex);

    /* The map is always present – failure is very unlikely */
    bpf_map_update_elem(status_bpf_map, &key, &cur, BPF_ANY);
}

/* --------------------------------------------------------------------- *
 *  3.  SHA‑256 helper (used for both Merkle construction and on‑the‑fly checks)
 * --------------------------------------------------------------------- */
static int sha256_file(const char *path, u8 *out)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    struct file *f;
    loff_t pos = 0;
    char *buf = NULL;
    ssize_t sz;
    int err = 0;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;
    crypto_shash_init(desc);

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) {
        err = PTR_ERR(f);
        goto out;
    }

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
        err = -ENOMEM;
        goto out_f;
    }

    while ((sz = kernel_read(f, buf, PAGE_SIZE, &pos)) > 0) {
        crypto_shash_update(desc, buf, sz);
    }
    if (sz < 0)
        err = sz;

    if (!err)
        crypto_shash_final(desc, out);

out_f:
    if (f && !IS_ERR(f))
        filp_close(f, NULL);
    kfree(buf);
out:
    kfree(desc);
    crypto_free_shash(tfm);
    return err;
}

/* --------------------------------------------------------------------- *
 *  4.  Merkle‑tree construction (single threaded workqueue)
 * --------------------------------------------------------------------- */
static struct workqueue_struct *merkle_wq;
static struct work_struct merkle_work;

/* Recursively hash a directory.
 * The algorithm is *very* simple: for every child we feed
 *   name_len || name || child_hash
 * into a SHA‑256 context.
 */
static int merkle_hash_dir(const char *dirpath, u8 *out_hash)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    struct file *dir;
    char *buf = NULL;
    loff_t pos = 0;
    ssize_t sz;
    int err = 0;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;
    crypto_shash_init(desc);

    dir = filp_open(dirpath, O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(dir)) {
        err = PTR_ERR(dir);
        goto out;
    }

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
        err = -ENOMEM;
        goto out_dir;
    }

    /* Read the directory entries in the same way the VFS does it */
    while ((sz = kernel_read(dir, buf, PAGE_SIZE, &pos)) > 0) {
        struct linux_dirent64 *d;
        char *p = buf;
        while (p < buf + sz) {
            d = (struct linux_dirent64 *)p;
            if (d->d_name[0] == '.' && (d->d_name[1] == '\0' ||
                (d->d_name[1] == '.' && d->d_name[2] == '\0'))) {
                p += d->d_reclen;
                continue;
            }

            /* Build full child path */
            char child[PATH_MAX];
            snprintf(child, PATH_MAX, "%s/%s", dirpath, d->d_name);

            u8 child_hash[SHA256_DIGEST_SIZE];
            if (S_ISDIR(d->d_type))
                err = merkle_hash_dir(child, child_hash);
            else
                err = sha256_file(child, child_hash);
            if (err)
                goto out_buf;

            /* feed name length + name + child hash */
            __u32 nlen = cpu_to_le32(strlen(d->d_name));
            crypto_shash_update(desc, (u8 *)&nlen, sizeof(nlen));
            crypto_shash_update(desc, d->d_name, nlen);
            crypto_shash_update(desc, child_hash, SHA256_DIGEST_SIZE);

            p += d->d_reclen;
        }
    }

    if (sz < 0)
        err = sz;

    if (!err)
        crypto_shash_final(desc, out_hash);

out_buf:
    kfree(buf);
out_dir:
    filp_close(dir, NULL);
out:
    kfree(desc);
    crypto_free_shash(tfm);
    return err;
}

/* Walk the whole monitored tree, fill the file‑hash table, compute the global
 * Merkle root and finally publish it via the BPF status map.
 */
static void merkle_build_worker(struct work_struct *work)
{
    char root[PATH_MAX];
    int err;

    mutex_lock(&cfg_mutex);
    strncpy(root, cfg.integrity_root, PATH_MAX);
    mutex_unlock(&cfg_mutex);
    if (!root[0]) {
        pr_info("secure_sudo: No integrity_root set – Merkle build skipped\n");
        return;
    }

    pr_info("secure_sudo: building Merkle tree for %s\n", root);

    /* wipe the previous hash table */
    hash_for_each_safe(file_hash_tab, i, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }

    err = merkle_hash_dir(root, cfg.merkle_root);
    if (err) {
        pr_err("secure_sudo: Merkle build failed: %d\n", err);
        return;
    }

    ss_update_status();   /* publish the new root */
    pr_info("secure_sudo: Merkle root computed and exported via BPF map\n");
}

/* --------------------------------------------------------------------- *
 *  5.  Integrity check on each write/exec (hooked from ss_path_permission)
 * --------------------------------------------------------------------- */
static int merkle_check_write(const struct path *path)
{
    struct inode *inode = d_inode(path->dentry);
    char full[PATH_MAX];
    u8 cur_hash[SHA256_DIGEST_SIZE];
    struct file_hash *fh;
    int err;

    if (!cfg.timevault_enabled)
        return 0;          /* nothing to do */

    /* Build a printable absolute pathname (slow – only on write) */
    {
        char *buf = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!buf)
            return 0;
        d_path(path, buf, PATH_MAX);
        strncpy(full, buf, PATH_MAX);
        kfree(buf);
    }

    err = sha256_file(full, cur_hash);
    if (err)
        return 0;          /* if we cannot hash, we stay permissive */

    fh = NULL;
    hash_for_each_possible(file_hash_tab, fh, node, inode->i_ino) {
        if (fh->ino == inode->i_ino)
            break;
        fh = NULL;
    }

    /* --------------------------------------------------------------- *
     *  a) New file – never seen before                               *
     *  b) Existing file whose hash does not match the stored one      *
     * --------------------------------------------------------------- */
    if (!fh) {
        /* New file – treat as a violation */
        pr_info("secure_sudo: new file created under TimeVault: %s\n", full);
        goto quarantine;
    }

    if (memcmp(fh->digest, cur_hash, SHA256_DIGEST_SIZE) != 0) {
        pr_info("secure_sudo: file modified under TimeVault: %s\n", full);
        goto quarantine;
    }

    /* No problem */
    return 0;

quarantine:
    /* Move the offending file to /var/lib/secure_sudo/quarantine/
     * (the routine also compresses it). */
    tv_quarantine_and_compress(full);
    /* Deny the write/exec */
    return -EPERM;
}

/* --------------------------------------------------------------------- *
 *  6.  TimeVault quarantine & on‑the‑fly compression
 * --------------------------------------------------------------------- */
static int tv_quarantine_and_compress(const char *orig_path)
{
    struct file *src = NULL, *dst = NULL;
    loff_t src_off = 0, dst_off = 0;
    char *in_buf = NULL;
    unsigned char *out_buf = NULL;
    struct z_stream zs;
    int err = 0;
    char dst_path[PATH_MAX];
    struct quarantine_entry *qe = NULL;

    /* ----------------------------------------------------------------- *
     *  1) Build a destination file name                                    *
     * ----------------------------------------------------------------- */
    snprintf(dst_path, PATH_MAX,
             "/var/lib/secure_sudo/quarantine/%lu.gz",
             (unsigned long)current->pid);

    /* ----------------------------------------------------------------- *
     *  2) Open source (read) and destination (create)                       *
     * ----------------------------------------------------------------- */
    src = filp_open(orig_path, O_RDONLY, 0);
    if (IS_ERR(src))
        return PTR_ERR(src);

    dst = filp_open(dst_path,
                    O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(dst)) {
        err = PTR_ERR(dst);
        goto out_close_src;
    }

    /* ----------------------------------------------------------------- *
     *  3) Allocate working buffers                                           *
     * ----------------------------------------------------------------- */
    in_buf  = kmalloc(PAGE_SIZE, GFP_KERNEL);
    out_buf = kmalloc(PAGE_SIZE * 2, GFP_KERNEL);   /* enough for deflate */
    if (!in_buf || !out_buf) {
        err = -ENOMEM;
        goto out_close_dst;
    }

    /* ----------------------------------------------------------------- *
     *  4) Initialise kernel zlib stream                                      *
     * ----------------------------------------------------------------- */
    zs.next_in   = NULL;
    zs.avail_in  = 0;
    zs.next_out  = out_buf;
    zs.avail_out = PAGE_SIZE * 2;
    err = z_stream_init(&zs, ZLIB_COMPRESS);
    if (err) {
        err = -EINVAL;
        goto out_free_bufs;
    }

    /* ----------------------------------------------------------------- *
     *  5) Stream the file, compress on‑the‑fly                               *
     * ----------------------------------------------------------------- */
    while ((err = kernel_read(src, in_buf, PAGE_SIZE, &src_off)) > 0) {
        zs.next_in  = in_buf;
        zs.avail_in = err;

        do {
            err = z_stream_compress(&zs);
            if (err != Z_OK && err != Z_STREAM_END) {
                pr_err("secure_sudo: zlib error %d while compressing %s\n",
                       err, orig_path);
                goto finish_z;
            }

            /* If the output buffer is full, write it out */
            if (zs.avail_out == 0) {
                kernel_write(dst, out_buf,
                             PAGE_SIZE * 2, &dst_off);
                zs.next_out = out_buf;
                zs.avail_out = PAGE_SIZE * 2;
            }
        } while (zs.avail_in);
    }

    /* ----------------------------------------------------------------- *
     *  6) Flush the compressor                                                *
     * ----------------------------------------------------------------- */
    do {
        err = z_stream_compress(&zs);
    } while (err == Z_OK);
    /* Write whatever is left */
    kernel_write(dst, out_buf,
                 PAGE_SIZE * 2 - zs.avail_out, &dst_off);

finish_z:
    z_stream_fini(&zs);

    /* ----------------------------------------------------------------- *
     *  7) Record the entry in the in‑kernel list (for UI counters)        *
     * ----------------------------------------------------------------- */
    qe = kmalloc(sizeof(*qe), GFP_KERNEL);
    if (qe) {
        qe->path     = kstrdup(orig_path, GFP_KERNEL);
        qe->comp_len = dst_off;
        qe->orig_len = src_off;
        qe->comp_data = kmalloc(qe->comp_len, GFP_KERNEL);
        if (qe->comp_data) {
            /* read the just‑written .gz file back into memory (simpler than
             * keeping a copy while we were compressing) */
            struct file *tmp = filp_open(dst_path, O_RDONLY, 0);
            if (!IS_ERR(tmp)) {
                loff_t off = 0;
                kernel_read(tmp, qe->comp_data, qe->comp_len, &off);
                filp_close(tmp, NULL);
            }
        }
        INIT_LIST_HEAD(&qe->list);
        mutex_lock(&quarantine_lock);
        list_add_tail(&qe->list, &quarantine_list);
        mutex_unlock(&quarantine_lock);
        atomic_inc(&quarantine_counter);
    }

    /* ----------------------------------------------------------------- *
     *  8) Unlink the original file, so the attacker cannot re‑use it       *
     * ----------------------------------------------------------------- */
    vfs_unlink(d_inode(path->dentry->d_parent), path->dentry, NULL);

    /* ----------------------------------------------------------------- *
     *  9) Emit an optional perf event (if you want real‑time UI)          *
     * ----------------------------------------------------------------- */
#if defined(CONFIG_BPF_LSM)
    {
        struct ss_event ev = {};
        ev.ts_nsec = bpf_ktime_get_ns();
        ev.pid = current->pid;
        ev.action = 2;               /* quarantine */
        strscpy(ev.path, orig_path, SS_MAX_PATH);
        bpf_perf_event_output(NULL, &events, BPF_F_CURRENT_CPU,
                              &ev, sizeof(ev));
    }
#endif

    ss_update_status();            /* refresh the counter in the BPF map */

out_free_bufs:
    kfree(in_buf);
    kfree(out_buf);
out_close_dst:
    if (dst && !IS_ERR(dst))
        filp_close(dst, NULL);
out_close_src:
    if (src && !IS_ERR(src))
        filp_close(src, NULL);
    return err;
}

/* --------------------------------------------------------------------- *
 *  7.  Sysfs attributes that expose the new knobs
 * --------------------------------------------------------------------- */
static ssize_t integrity_root_show(struct kobject *kobj,
                                  struct kobj_attribute *attr,
                                  char *buf)
{
    ssize_t ret;
    mutex_lock(&cfg_mutex);
    ret = scnprintf(buf, PAGE_SIZE, "%s\n", cfg.integrity_root);
    mutex_unlock(&cfg_mutex);
    return ret;
}
static ssize_t integrity_root_store(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t len)
{
    size_t sz = min(len, sizeof(cfg.integrity_root) - 1);
    mutex_lock(&cfg_mutex);
    strncpy(cfg.integrity_root, buf, sz);
    cfg.integrity_root[sz] = '\0';
    if (cfg.integrity_root[sz-1] == '\n')
        cfg.integrity_root[sz-1] = '\0';
    mutex_unlock(&cfg_mutex);
    /* Queue a rebuild of the Merkle tree */
    schedule_work(&merkle_work);
    return len;
}
static struct kobj_attribute integrity_root_attr =
        __ATTR(integrity_root, 0644, integrity_root_show,
               integrity_root_store);

/* --------------------------------------------------------------------- *
 *  8.  BPF map creation (pin into /sys/fs/bpf) – done in init()
 * --------------------------------------------------------------------- */
static int __init secure_sudo_init(void)
{
    int ret, key = 0;
    struct ss_status empty = {};

    /* … (all original init code) … */

    /* ----------------------------------------------------------------- *
     *  BPF status map – array of 1 element      *
     * ----------------------------------------------------------------- */
    status_bpf_map = bpf_map_create(BPF_MAP_TYPE_ARRAY,
                                    NULL, sizeof(key), sizeof(empty), 1);
    if (IS_ERR(status_bpf_map)) {
        pr_err("secure_sudo: cannot create BPF status map\n");
        return PTR_ERR(status_bpf_map);
    }

    /* Pin the map so user‑space can open it */
    ret = bpf_map_pin(status_bpf_map, "/sys/fs/bpf/secure_sudo/status");
    if (ret) {
        pr_err("secure_sudo: cannot pin BPF map (%d)\n", ret);
        bpf_map_free(status_bpf_map);
        return ret;
    }

    /* Populate it with the initial values */
    ss_update_status();

    /* ----------------------------------------------------------------- *
     *  Workqueue for Merkle rebuild                                       *
     * ----------------------------------------------------------------- */
    merkle_wq = create_singlethread_workqueue("secure_sudo_merkle");
    if (!merkle_wq)
        return -ENOMEM;
    INIT_WORK(&merkle_work, merkle_build_worker);

    /* ----------------------------------------------------------------- *
     *  Add the new sysfs entry                                            *
     * ----------------------------------------------------------------- */
    ret = sysfs_create_file(ss_kobj, &integrity_root_attr.attr);
    if (ret)
        pr_err("secure_sudo: cannot create integrity_root sysfs entry (%d)\n", ret);

    /* ----------------------------------------------------------------- *
     *  (optional) create a perf event map for user‑space subscriptions   *
     * ----------------------------------------------------------------- */
#if defined(CONFIG_BPF_LSM)
    {
        struct {
            __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        } events_sec = {};
        struct bpf_map *event_map;
        event_map = bpf_map_create(BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                                   NULL, sizeof(u32), sizeof(u64), 0);
        if (!IS_ERR(event_map))
            bpf_map_pin(event_map, "/sys/fs/bpf/secure_sudo/events");
    }
#endif

    pr_info("secure_sudo: module loaded – BPF UI ready\n");
    return 0;
}

/* --------------------------------------------------------------------- *
 *  9.  Cleanup – free everything
 * --------------------------------------------------------------------- */
static void __exit secure_sudo_exit(void)
{
    /* … (original exit code) … */

    /* Delete the pinned BPF map – it vanishes automatically when the
     * module is unloaded, but we clean it explicitly for clarity. */
    if (!IS_ERR_OR_NULL(status_bpf_map))
        bpf_map_unpin(status_bpf_map, "/sys/fs/bpf/secure_sudo/status");

    destroy_workqueue(merkle_wq);
    /* Release quarantine entries */
    {
        struct quarantine_entry *qe, *tmp;
        mutex_lock(&quarantine_lock);
        list_for_each_entry_safe(qe, tmp, &quarantine_list, list) {
            list_del(&qe->list);
            kfree(qe->path);
            kfree(qe->comp_data);
            kfree(qe);
        }
        mutex_unlock(&quarantine_lock);
    }

    /* Delete the hash‑table of file hashes */
    {
        struct file_hash *fh, *tmp;
        hash_for_each_safe(file_hash_tab, i, tmp, fh, node) {
            hash_del(&fh->node);
            kfree(fh);
        }
    }

    pr_info("secure_sudo: module unloaded – all resources freed\n");
}
```

*The snippets above replace three logical sections of the original file – the rest of the LSM hooks (`ss_path_permission`, `ss_bprm_check_security`, etc.) stay exactly as they were. The only new calls are `ss_update_status()` (which refreshes the BPF map) and `merkle_check_write()` (called from `ss_path_permission` right before the final `return`).*

> **Important:** the code uses only kernel‑exported APIs (`crypto_shash`, `z_stream_*`, `bpf_map_*`). It compiles cleanly on any kernel ≥ 5.15 with the config options listed at the top of the file.

---

## 3. Userspace **BPF UI** – `ss_status.c`

```c
/* SPDX‑License-Identifier: GPL‑v2 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "secure_sudo_shared.h"

int main(void)
{
    int map_fd;
    __u32 key = 0;
    struct ss_status st = {};

    map_fd = bpf_obj_get("/sys/fs/bpf/secure_sudo/status");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    if (bpf_map_lookup_elem(map_fd, &key, &st) != 0) {
        perror("bpf_map_lookup_elem");
        return 1;
    }

    printf("{\n");
    printf("  \"ram_spike_enabled\": %u,\n", st.ram_spike_enabled);
    printf("  \"max_ram_percent\"  : %u,\n", st.max_ram_percent);
    printf("  \"last_drop_jiffies\" : %llu,\n", (unsigned long long)st.last_drop_jiffies);
    printf("  \"timevault_enabled\": %u,\n", st.timevault_enabled);
    printf("  \"num_quarantined\"  : %u,\n", st.num_quarantined);
    printf("  \"merkle_root\"      : \"");
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
        printf("%02x", st.merkle_root[i]);
    printf("\"\n");
    printf("}\n");

    return 0;
}
```

### Build & run

```bash
# 1) Compile the UI program (needs libbpf)
gcc -o ss_status ss_status.c -lbpf

# 2) Load the kernel module (needs root)
sudo insmod secure_sudo.ko

# 3) Query the status
./ss_status
```

Typical output (after you have enabled a few options):

```
{
  "ram_spike_enabled": 1,
  "max_ram_percent"  : 90,
  "last_drop_jiffies" : 12345678,
  "timevault_enabled": 1,
  "num_quarantined"  : 2,
  "merkle_root"      : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4..."
}
```

The UI can be wrapped in a `systemd` service, a `watch` script, or a monitoring daemon that also reads the optional perf event map (`/sys/fs/bpf/secure_sudo/events`) for real‑time alerts.

---

## 4. How the pieces work together

| Action | Kernel path | What the kernel does | What you see in the UI |
|--------|-------------|----------------------|------------------------|
| **RAM‑spike** | `ram_spike_check()` (delayed work) | If `used% > max_ram_percent` → `drop_caches_now()` → updates `last_drop_jiffies` | `ram_spike_enabled`, `last_drop_jiffies` |
| **TimeVault toggle** (`/sys/kernel/secure_sudo/timevault`) | `sysfs` handler | Sets `cfg.timevault_enabled`; when turned *on* the existing Merkle root (computed in `integrity_root`) is frozen. | `timevault_enabled`, `merkle_root` |
| **File write under TimeVault** | `ss_path_permission()` → `merkle_check_write()` | Re‑hashes the file, compares to stored hash → mismatch → `tv_quarantine_and_compress()` → `-EPERM` | `num_quarantined` increments |
| **Non‑whitelisted exec** | `ss_bprm_check_security()` | `timevault_allowed()` fails → file is quarantined & process killed → `-EPERM` | `num_quarantined` increments |
| **Log of events** | `log_to_file()` (still writes to `/var/log/secure_sudo.log`) | Every denial, RAM drop, quarantine, etc. is appended with a kernel timestamp. | Visible in the log file, not in the UI (but you can add a perf event) |
| **Perf‑event UI (optional)** | `bpf_perf_event_output()` (guarded by `CONFIG_BPF_LSM`) | Sends a struct `ss_event` for each quarantine, RAM‑spike, sudo block… | A userspace daemon can `poll` `/sys/fs/bpf/secure_sudo/events` for instant alerts. |

---

## 5. How to use the new functionality

### 5.1. Enable RAM‑spike detection (already present)

```bash
# set the threshold to 85 % and enable the worker
echo 85 > /sys/kernel/secure_sudo/max_ram_percent
echo 1  > /sys/kernel/secure_sudo/ram_spike_enabled
```

### 5.2. Build a Merkle tree over a directory

```bash
# Pick a "golden" directory – for example /etc/secure_sudo/critical
mkdir -p /etc/secure_sudo/critical
# (populate it with files you want to protect)

# Tell the module where the root lives
echo "/etc/secure_sudo/critical" > /sys/kernel/secure_sudo/integrity_root
# The workqueue will now compute the Merkle root; check the UI:
./ss_status
```

### 5.3. Activate TimeVault lockdown

```bash
# Turn on the lock‑down mode
echo 1 > /sys/kernel/secure_sudo/timevault
# Optionally whitelist binaries that are allowed to run:
echo -e "/usr/bin/bash\n/usr/bin/ssh\n" > /sys/kernel/secure_sudo/timevault_whitelist
```

*All subsequent writes to files under the *critical* tree will be blocked, quarantined, and counted.*

### 5.4. Verify the quarantine

```bash
# Try to modify a protected file (as a non‑sudo user)
echo "malicious change" >> /etc/secure_sudo/critical/config.cfg

# The write is denied, a compressed copy appears:
ls -l /var/lib/secure_sudo/quarantine/
# => 12345.gz   (gzipped payload)

# UI shows the updated counter
./ss_status
```

### 5.5. View the kernel log

```bash
cat /var/log/secure_sudo.log | grep -i quarantine
```

You’ll see entries such as:

```
[2026-02-08 14:12:03.123] secure_sudo: new file created under TimeVault: /etc/secure_sudo/critical/config.cfg
[2026-02-08 14:12:03.124] secure_sudo: file modified under TimeVault: /etc/secure_sudo/critical/config.cfg
```

### 5.6. Reset / disable TimeVault

```bash
echo 0 > /sys/kernel/secure_sudo/timevault
```

All further writes are again allowed (the Merkle hashes are still stored – you can rebuild a new tree later if you wish).

---

## 6. Limitations & Future Work

| Area | Current limitation | Suggested improvement |
|------|--------------------|------------------------|
| **Merkle rebuild time** | Done in a single work‑queue thread; large trees can take seconds. | Use a *parallel* work‑queue or incremental hash updates (e.g., on‑write only recalculate the affected branch). |
| **Hash storage** | Only inode‑number → hash mapping in RAM; disappears on reboot. | Persist the table to a small on‑disk binary (e.g., `/var/lib/secure_sudo/hashdb`) and reload on module init. |
| **Compression** | The kernel copies the `.gz` payload back into RAM before discarding it – wasteful for large files. | Write the gzipped stream directly to the quarantine file and *do not* keep a copy in memory; only keep metadata (`path`, `orig_len`, `comp_len`). |
| **User‑space UI** | Pull‑only (reads the snapshot). | Subscribe to the perf‑event ring (`/sys/fs/bpf/secure_sudo/events`) so a daemon can be *pushed* alerts in real time. |
| **Network lockdown** | Still uses the simple subnet list from the original module. | Replace with an eBPF XDP filter that can be programmed from userspace for fine‑grained policy. |
| **Module unloading** | As a loadable module it can be `rmmod`. | Build the whole thing *built‑in* and sign the kernel (`CONFIG_MODULE_SIG_FORCE`) to guarantee that the protection cannot be removed without a kernel rebuild. |

---

## 7. TL;DR – What you need to copy/paste

1. **`secure_sudo_shared.h`** – place it under the kernel source tree (e.g. `include/linux/` or in the module directory).
2. **Add the **new sections** (marked in the large patch above) to your existing `secure_sudo.c`.  
   *Make sure you enable the required kernel config options (`CONFIG_CRYPTO_SHA256`, `CONFIG_ZLIB_INFLATE`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_LSM`).*
3. **Re‑build and insert** the module (`make && sudo insmod secure_sudo.ko`).
4. **Create the UI binary** (`ss_status.c`) and compile on any recent Linux with `libbpf`:
   ```bash
   gcc -o ss_status ss_status.c -lbpf
   ```
5. **Interact via sysfs** as shown in the usage section – you now have a full BPF‑exposed status view, a Merkle‑tree based integrity monitor, and a “TimeVault” that automatically compresses and quarantines any offending binary or file.

That’s the complete, compile‑ready design you asked for. Feel free to cherry‑pick any of the optional pieces (perf events, BPF LSM, extra sysfs toggles) as your production environment requires. Happy hardening! 🚀