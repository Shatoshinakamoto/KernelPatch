/* SPDX-License-Identifier: GPL-2.0 */
/*
 * secure_sudo.h - shared definitions for the secure_sudo LSM.
 *
 * secure_sudo is a built-in Linux Security Module that enforces a set of
 * privilege-escalation and system-integrity protections. It is the merge of
 * the v1 module (Kernel/secure_sudo.c) and the v2 LSM
 * (Kernel/v2/secure_sudo_v2.0.c); see docs/FEATURE_MAP.md for the full map of
 * which feature lives where.
 *
 * This header holds the pieces every protection shares: the runtime config,
 * the "is this actor a sudo user?" helper, and the per-subsystem init hooks.
 */
#ifndef _SECURITY_SECURE_SUDO_H
#define _SECURITY_SECURE_SUDO_H

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/mutex.h>
#include <linux/kobject.h>
#include <linux/lsm_hooks.h>
#include <linux/kernel_read_file.h>

#define SS_NAME "secure_sudo"

#undef pr_fmt
#define pr_fmt(fmt) SS_NAME ": " fmt

/*
 * Custom LSM identifier. Mainline LSMs get an allocated LSM_ID_* value in
 * include/uapi/linux/lsm.h; an out-of-tree / vendor build only needs an id
 * that is unique and non-zero. If this LSM is ever submitted upstream, swap
 * this for a properly allocated LSM_ID_SECURE_SUDO in the uapi header.
 */
#ifndef LSM_ID_SECURE_SUDO
#define LSM_ID_SECURE_SUDO 0x80535544ULL /* high bit set + "SSUD" */
#endif

/*
 * Admin groups: members of ANY of these GIDs count as sudo users (in addition
 * to root). The installer auto-detects every admin group on the box (sudo,
 * wheel, admin, plus any %group granted ALL in sudoers) and loads them at boot.
 * An empty list means root-only.
 */
#define SS_MAX_ADMIN_GIDS 16

/* #10 network mode. The kernel only enforces the raw/packet-socket block in
 * HOST mode; the nft rules for the LAN/public modes are a userspace job. */
enum ss_net_mode {
	SS_NET_MONITOR = 0,	/* observe only, no kernel restriction */
	SS_NET_HOST,		/* deny raw/AF_PACKET sockets (no sniffing) */
	SS_NET_LAN_ONLY,	/* userspace nft; kernel unrestricted */
	SS_NET_PUBLIC_ONLY,	/* userspace nft; kernel unrestricted */
	SS_NET_MODE_MAX = SS_NET_PUBLIC_ONLY,
};

/*
 * Runtime configuration. Scalar fields are read locklessly with READ_ONCE()
 * from the hot paths and written under ss_cfg_lock from sysfs. Subsystems
 * added in later steps extend this struct.
 */
struct ss_cfg {
	/* (the admin-GID list lives behind RCU in ss_core.c, not here) */

	/* ---- #1 non-sudo UID/GID switch block ---- */
	bool block_setid;	/* deny setuid/setgid/setgroups for non-sudo */
	bool block_userns;	/* deny unprivileged user-namespace creation  */

	/* ---- #2 firmware/flash protection ---- */
	bool block_flash;	/* deny non-sudo firmware/flash/raw-mem access */

	/* ---- #1b setuid/setgid/file-cap exec gate for non-sudo users ---- */
	bool block_setid_exec;	/* deny privilege-gaining exec unless allowlisted */

	/* ---- #16 config lock: state lives in ss_lock_state (ss_core.c) ---- */
	bool lock_modules;	/* while locked, refuse ALL module loads */

	/* ---- #7 RAM-spike detection ---- */
	u32  max_ram_percent;	/* drop caches at/above this % used */
	u32  check_interval_ms;	/* how often the worker samples memory */
	u32  drop_cooldown_ms;	/* minimum gap between successive drops */
	bool ram_spike_enabled;

	/* ---- #10 network mode ---- */
	enum ss_net_mode net_mode;

	/* ---- #12 exec from tmp dirs ---- */
	bool block_tmp_exec;
	bool block_tmpfs_exec;	/* also any tmpfs/ramfs mount (/run/user, memfd) */

	/* ---- #8 sudo brute-force cooldown ---- */
	u32  sudo_max_fails;		/* failures in the window before a block */
	u32  sudo_window_sec;		/* sliding window length */
	u32  sudo_block_time_sec;	/* how long a blocked UID stays blocked */
	bool sudo_cooldown_enabled;

	/* ---- #13 TimeVault ---- */
	bool timevault_enabled;		/* when on: exec allowlist + pkg-mgr deny */
	bool timevault_strict_mmap;	/* also gate PROT_EXEC mmap (libraries) */
	bool timevault_allow_autoupdate;/* honour auto-update (no-hash) entries */
	u32  timevault_max_entries;	/* configurable cap on allowlist size */

	/* ---- #20 Process Runtime Guard ---- */
	bool prguard_enabled;		/* memory-tamper guard for all processes */
	bool prguard_observe;		/* emit an event per cross-process mem access
					 * (read/write + source->target) for the GUI;
					 * verbose, opt-in, independent of enforce */

	/* ---- #4 home write-restriction ---- */
	bool block_home_write;		/* confine non-sudo writes to home + allow */

	/* ---- #17 BinaryVault: freeze executables & libraries (all UIDs) ---- */
	bool binaryvault;

	/* ---- #19 RadioGuard: wireless lockdown (Ethernet-only) ---- */
	bool block_wifi;	/* keep Wi-Fi off */
	bool block_bluetooth;	/* keep Bluetooth off */
	bool ethernet_only;	/* master switch: keep BOTH off */

	/* ---- #22 BPF & perf guard ---- */
	bool bpf_guard;		/* deny bpf(2) to non-sudo users */
	bool bpf_lock_tracing;	/* once locked: refuse tracing-class BPF progs (all UIDs) */
	bool perf_guard;	/* deny perf_event_open(2) to non-sudo users */

	/* ---- #23 SysctlGuard ---- */
	bool sysctl_guard;	/* refuse writes to security-critical sysctls (all UIDs) */

	/* ---- #9 event log: also feed the kernel audit subsystem (auditd) ---- */
	bool audit_events;

	/* ---- #16 lock: also refuse lockdown's CONFIDENTIALITY class ---- */
	bool lock_confidentiality;	/* /proc/kcore, kprobes, bpf_probe_read_kernel,
					 * perf/tracefs kernel reads while locked */
};

extern struct ss_cfg ss_cfg;
extern struct mutex ss_cfg_lock;
extern const struct lsm_id ss_lsmid;

/*
 * True when @cred belongs to a "sudo user": root (by real or effective UID)
 * or a member of the configured admin GID (sudo/wheel). Group membership is
 * checked against the real, effective, fs and supplementary groups.
 */
bool ss_cred_is_sudo(const struct cred *cred);

/* Replace the admin-GID list (n may be 0 = root-only). Caller checks perms. */
int ss_set_admin_gids(const u32 *gids, unsigned int n);
/* Print the current list as "27,10\n" (or "unset\n") into a sysfs buffer. */
ssize_t ss_show_admin_gids(char *buf);

/* Convenience wrapper: evaluate the current task's credentials. */
static inline bool ss_is_sudo_user(void)
{
	return ss_cred_is_sudo(current_cred());
}

struct ss_event_fields {
	const char *event_type;
	const char *target;
	pid_t target_pid;
	bool target_pid_valid;
	kuid_t target_uid;
	bool target_uid_valid;
	const char *operation;
	const char *object;
	const char *decision;
	const char *reason;
};

void ss_event_record(const struct ss_event_fields *fields, const char *fmt, ...);
void ss_event(const char *fmt, ...);
#define ss_event_typed(_type, _target, _operation, _object, _decision, \
		       _reason, ...) \
	ss_event_record(&(struct ss_event_fields) { \
		.event_type = (_type), .target = (_target), \
		.operation = (_operation), .object = (_object), \
		.decision = (_decision), .reason = (_reason), \
	}, __VA_ARGS__)
#define ss_event_typed_pid(_type, _target, _target_pid, _operation, \
			   _object, _decision, _reason, ...) \
	ss_event_record(&(struct ss_event_fields) { \
		.event_type = (_type), .target = (_target), \
		.target_pid = (_target_pid), .target_pid_valid = true, \
		.operation = (_operation), .object = (_object), \
		.decision = (_decision), .reason = (_reason), \
	}, __VA_ARGS__)
#define ss_event_typed_pid_uid(_type, _target, _target_pid, _target_uid, \
			       _operation, _object, _decision, _reason, ...) \
	ss_event_record(&(struct ss_event_fields) { \
		.event_type = (_type), .target = (_target), \
		.target_pid = (_target_pid), .target_pid_valid = true, \
		.target_uid = (_target_uid), .target_uid_valid = true, \
		.operation = (_operation), .object = (_object), \
		.decision = (_decision), .reason = (_reason), \
	}, __VA_ARGS__)

/*
 * #16: once config is locked, every knob refuses writes until the next reboot.
 * The state is a one-way atomic latch: ss_lock_engage() is the only writer and
 * nothing in the kernel ever clears it. A sysfs/securityfs store calls this
 * after its privilege check:
 *	if (ss_locked()) return -EPERM;
 */
extern atomic_t ss_lock_state;
static inline bool ss_locked(void)
{
	return atomic_read(&ss_lock_state) != 0;
}
/* Latch the lock (idempotent). @why is logged once, on the first latch. */
void ss_lock_engage(const char *why);

/*
 * Privilege check for policy writes. CAP_SYS_ADMIN in the initial namespace,
 * checked against BOTH the writing task and, for securityfs files, the
 * credentials the file was opened with - so a less-privileged opener cannot
 * hand the fd to a privileged process and have it write for them (the classic
 * "write via setuid stderr" confused-deputy pattern).
 */
bool ss_may_admin(const struct file *file);

/*
 * Resolve @path to a string for policy matching. Uses d_absolute_path() so the
 * result is relative to the mount-namespace root, not the caller's chroot (a
 * chrooted task must not be able to make /jail/usr/bin/x look like
 * /usr/bin/x). Falls back to d_path() for pseudo files (memfd, pipes) that
 * have no absolute path. Returns ERR_PTR on failure; callers MUST treat a
 * failure as a deny where a deny is the safe answer (fail closed).
 */
struct path;
char *ss_file_path(const struct path *path, char *buf, int buflen);

/* "dir" matches "dir" and "dir/..." but never "dirx"; a prefix that already
 * ends in '/' matches anything below it. */
bool ss_path_under(const char *path, const char *prefix);

/* SHA-256 of a memory buffer into @hex (>= 65 bytes). Never fails. */
void ss_sha256_buf(const void *data, size_t len, char *hex);

/* Clamp helper for numeric knobs: -ERANGE outside [lo, hi]. */
static inline int ss_check_range(u32 v, u32 lo, u32 hi)
{
	return (v < lo || v > hi) ? -ERANGE : 0;
}

/*
 * #9: emit a line into the kernel event ring the daemon drains. Safe from any
 * of our hooks; never sleeps; a no-op until the ring is set up. Pair it with a
 * pr_warn_ratelimited() when a human reading dmesg should also see the event.
 */
__printf(1, 2) void ss_event(const char *fmt, ...);
/* #9: number of event lines dropped from the ring since boot. */
u64 ss_events_dropped(void);
u64 ss_audit_events_dropped(void);

/* SHA-256 a file's full contents into @hex_out (>=65 bytes, hex + NUL). Defined
 * in ss_driver.c, shared with TimeVault. Returns 0 on success. */
struct file;
int ss_sha256_file(struct file *file, char *hex_out);

/*
 * LSM task blob (#11 NodeJS guard). After LSM init, ss_blob_sizes.lbs_task
 * holds the offset of our slice inside task_struct->security.
 */
struct ss_task {
	u8 flags;
	u8 pending;		/* flags to apply if the current exec commits */
	u8 pending_valid;	/* pending was computed by this exec's checks */
};
#define SS_TASK_NODE	0x01	/* this task descends from a node/SEA exec */

extern struct lsm_blob_sizes ss_blob_sizes;

static inline struct ss_task *ss_task(const struct task_struct *t)
{
	return t->security + ss_blob_sizes.lbs_task;
}

/*
 * Per-subsystem setup. Each protection lives in its own file and exposes up to
 * two entry points:
 *   *_init()  - called from the LSM .init (very early); registers the LSM
 *               hooks that only this protection uses.
 *   *_sysfs() - called from a late_initcall; creates the /sys knobs.
 * Splitting the two matters: LSM .init runs long before the driver model and
 * sysfs are ready, so kobjects must not be created there.
 *
 * A hook used by more than one protection is registered exactly once, by
 * ss_hooks.c, which calls each protection's handler (declared at the end of
 * this file) in a fixed order. Since 6.9 the kernel gives every LSM a fixed
 * number of static-call slots per hook; registering one hook several times
 * from the same LSM runs out of slots and panics at boot.
 */
void ss_creds_init(void);
int  ss_creds_sysfs(struct kobject *kobj);

/* #1b setid-exec allowlist (securityfs "setid_exec_allow"). */
int  ss_creds_secfs(struct dentry *dir);

/* #16 lock enforcement hooks (locked_down, module/kexec loads). */
void ss_lock_init(void);

/* #2 command blacklist: bprm handler (shared); securityfs "blacklist" late. */
int  ss_exec_secfs(struct dentry *dir);

/* #3 firmware/flash protection: file_open handler (shared), sysfs knob late. */
int  ss_firmware_sysfs(struct kobject *kobj);

/* #5 TPM-clear block: file_open handler only (shared; applies to everyone). */

/* #7 RAM-spike detection: no hooks (a kthread/worker); start it late. */
int  ss_ram_sysfs(struct kobject *kobj);
void ss_ram_start(void);

/* #12 exec-from-tmp restriction: bprm + mmap handlers (shared); knobs late. */
int  ss_tmpexec_sysfs(struct kobject *kobj);
int  ss_tmpexec_secfs(struct dentry *dir);

/* #10 network socket block (HOST mode): socket_create handler (shared). */
int  ss_net_sysfs(struct kobject *kobj);

/* #9 event log: ring has no hooks; create the securityfs "events" file late. */
int  ss_log_secfs(struct dentry *dir);

/* #11 NodeJS child guard: task_alloc + bprm hooks early, securityfs lists late. */
void ss_node_init(void);
int  ss_node_secfs(struct dentry *dir);

/* #8 sudo brute-force cooldown: bprm handler (shared); knobs + PAM feed late. */
int  ss_cooldown_sysfs(struct kobject *kobj);
int  ss_cooldown_secfs(struct dentry *dir);

/* #6 driver blacklist (BYOVD): kernel_read_file hook early; hash list late. */
void ss_driver_init(void);
int  ss_driver_secfs(struct dentry *dir);

/* #13 TimeVault exec allowlist: handlers (shared); knob + allowlist late. */
int  ss_timevault_sysfs(struct kobject *kobj);
int  ss_timevault_secfs(struct dentry *dir);

/* #4 home write-restriction: file_open + path_* hooks early; knob + maps late. */
void ss_home_init(void);
int  ss_home_sysfs(struct kobject *kobj);
int  ss_home_secfs(struct dentry *dir);

/* #17 BinaryVault: file/path/xattr hooks early; knob + allowlist late. */
void ss_binvault_init(void);
int  ss_binvault_sysfs(struct kobject *kobj);
int  ss_binvault_secfs(struct dentry *dir);

/* #19 RadioGuard: module-load/socket/file handlers (shared); knobs late. */
int  ss_radio_sysfs(struct kobject *kobj);

/* #20 Process Runtime Guard: ptrace/mprotect/mmap hooks early; knob + list late. */
void ss_prguard_init(void);
int  ss_prguard_sysfs(struct kobject *kobj);
int  ss_prguard_secfs(struct dentry *dir);

/* #22 BPF & perf guard: bpf/bpf_prog_load/perf_event_open hooks early; knobs late. */
void ss_bpf_init(void);
int  ss_bpf_sysfs(struct kobject *kobj);

/* #23 SysctlGuard: file_open handler (shared); knob late. */
int  ss_sysctl_sysfs(struct kobject *kobj);

/*
 * Handlers for hooks shared by several protections, registered once by
 * ss_hooks.c (see the note above the *_init() list). Same signatures and
 * return conventions as the LSM hooks they serve.
 */
struct linux_binprm;
struct vm_area_struct;
struct path;
struct file;

void ss_hooks_init(void);

int ss_exec_bprm(struct linux_binprm *bprm);
int ss_tmp_bprm(struct linux_binprm *bprm);
int ss_node_bprm(struct linux_binprm *bprm);
int ss_cooldown_bprm(struct linux_binprm *bprm);
int ss_timevault_bprm(struct linux_binprm *bprm);

int ss_firmware_file_open(struct file *file);
int ss_tpm_file_open(struct file *file);
int ss_timevault_file_open(struct file *file);
int ss_home_file_open(struct file *file);
int ss_binvault_file_open(struct file *file);
int ss_radio_file_open(struct file *file);
int ss_sysctl_file_open(struct file *file);

int ss_tmp_mmap(struct file *file, unsigned long reqprot, unsigned long prot,
		unsigned long flags);
int ss_timevault_mmap(struct file *file, unsigned long reqprot,
		      unsigned long prot, unsigned long flags);
int ss_pg_mmap_file(struct file *file, unsigned long reqprot,
		    unsigned long prot, unsigned long flags);

int ss_tmp_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		    unsigned long prot);
int ss_timevault_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
			  unsigned long prot);
int ss_pg_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		   unsigned long prot);

int ss_lock_read_file(struct file *file, enum kernel_read_file_id id,
		      bool contents);
int ss_driver_read_file(struct file *file, enum kernel_read_file_id id,
			bool contents);
int ss_radio_read_file(struct file *file, enum kernel_read_file_id id,
		       bool contents);

#ifdef CONFIG_SECURITY_PATH
int ss_timevault_truncate(const struct path *path);
int ss_home_path_truncate(const struct path *path);
int ss_home_path_unlink(const struct path *dir, struct dentry *d);
int ss_binvault_path_unlink(const struct path *dir, struct dentry *d);
int ss_home_path_link(struct dentry *old, const struct path *ndir,
		      struct dentry *nd);
int ss_binvault_path_link(struct dentry *old_dentry, const struct path *new_dir,
			  struct dentry *new_dentry);
int ss_home_path_rename(const struct path *odir, struct dentry *od,
			const struct path *ndir, struct dentry *nd,
			unsigned int flags);
int ss_binvault_path_rename(const struct path *odir, struct dentry *od,
			    const struct path *ndir, struct dentry *nd,
			    unsigned int flags);
int ss_home_path_chmod(const struct path *path, umode_t mode);
int ss_binvault_path_chmod(const struct path *path, umode_t mode);
#endif

#ifdef CONFIG_SECURITY_NETWORK
int ss_net_socket_create(int family, int type, int protocol, int kern);
int ss_radio_socket_create(int family, int type, int protocol, int kern);
#endif

#endif /* _SECURITY_SECURE_SUDO_H */
