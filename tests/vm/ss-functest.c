// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * ss-functest - in-VM functional tests for the secure_sudo LSM (TODO P0-2/3).
 *
 * Runs as root inside the disposable QEMU guest built by tests/vm/ and prints
 * TAP on stdout. It drives the real kernel interface (/sys/kernel/secure_sudo,
 * /sys/kernel/security/secure_sudo) and checks both sides of every control:
 * the denial for a non-sudo caller AND the legitimate workflow (sudo caller,
 * or the control switched off). Tests that change the one-way lock run last.
 *
 * "Non-sudo with capabilities" children are uid 1000 that keep exactly the
 * capability the kernel's own DAC check needs (CAP_SETUID, CAP_NET_RAW, ...),
 * so a denial can only come from secure_sudo and not from ordinary
 * permissions.
 *
 * Build: gcc -static -O2 -Wall -Wextra -o ss-functest ss-functest.c
 * Never run it on a real host: it rewrites policy and latches the lock.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <grp.h>
#include <dirent.h>

#define KNOB  "/sys/kernel/secure_sudo/"
#define SECFS "/sys/kernel/security/secure_sudo/"
#define USER  1000
#define ADMIN_GID 27

static int n_test, n_fail;
static char modpath[512];	/* test_module.ko */
static char hwsimpath[512];	/* mac80211_hwsim.ko: a module RadioGuard knows */

static void tap(int pass, const char *fmt, ...)
{
	va_list ap;

	n_test++;
	if (!pass)
		n_fail++;
	printf("%s %d - ", pass ? "ok" : "not ok", n_test);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
}

static void diag(const char *fmt, ...)
{
	va_list ap;

	printf("# ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
}

/* ------------------------------------------------------------------ io */

static int wr(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	ssize_t n;

	if (fd < 0)
		return -errno;
	n = write(fd, val, strlen(val));
	n = n < 0 ? -errno : 0;
	close(fd);
	return (int)n;
}

static int rd(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -errno;
	n = read(fd, buf, len - 1);
	if (n < 0) {
		n = -errno;
		close(fd);
		return (int)n;
	}
	buf[n] = '\0';
	while (n > 0 && buf[n - 1] == '\n')
		buf[--n] = '\0';
	close(fd);
	return 0;
}

static int knob_set(const char *k, const char *v)
{
	char p[256];

	snprintf(p, sizeof(p), KNOB "%s", k);
	return wr(p, v);
}

static const char *knob_get(const char *k)
{
	static char buf[256];
	char p[256];

	snprintf(p, sizeof(p), KNOB "%s", k);
	if (rd(p, buf, sizeof(buf)))
		snprintf(buf, sizeof(buf), "<unreadable>");
	return buf;
}

static int copy_file(const char *from, const char *to, mode_t mode)
{
	char buf[65536];
	int in = open(from, O_RDONLY), out;
	ssize_t n;

	if (in < 0)
		return -errno;
	/* "busybox --install -s" leaves a symlink for every applet name
	 * (dpkg, su, ...): replace it rather than write through it. */
	unlink(to);
	out = open(to, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, mode);
	if (out < 0) {
		close(in);
		return -errno;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0)
		if (write(out, buf, n) != n)
			break;
	close(in);
	close(out);
	return chmod(to, mode) ? -errno : 0;
}

/* Make @path a different program: valid ELF, one byte longer. */
static void append_byte(const char *path)
{
	int fd = open(path, O_WRONLY | O_APPEND);

	if (fd < 0 || write(fd, "x", 1) != 1)
		printf("# append to %s failed: %s\n", path, strerror(errno));
	if (fd >= 0)
		close(fd);
}

/* ------------------------------------------------- run as another user */

struct who {
	uid_t uid;
	gid_t gid;
	int ngroups;
	gid_t groups[4];
	uint64_t caps;		/* capabilities to keep after the switch */
};

static const struct who ROOT = { 0, 0, 0, {0}, 0 };
static const struct who NONSUDO = { USER, USER, 0, {0}, 0 };

static int set_caps(uint64_t caps)
{
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2];

	memset(d, 0, sizeof(d));
	d[0].effective = d[0].permitted = (uint32_t)caps;
	d[1].effective = d[1].permitted = (uint32_t)(caps >> 32);
	return (int)syscall(SYS_capset, &h, d);
}

static int become(const struct who *w)
{
	if (w->uid == 0 && w->gid == 0)
		return 0;
	if (w->caps && prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0))
		return -1;
	if (setgroups(w->ngroups, w->groups) || setresgid(w->gid, w->gid, w->gid) ||
	    setresuid(w->uid, w->uid, w->uid))
		return -1;
	if (w->caps && set_caps(w->caps))
		return -1;
	/* A credential change clears "dumpable"; restore it so ordinary
	 * same-user ptrace works and only secure_sudo can refuse it. */
	prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	return 0;
}

/*
 * Run fn as @w in a child. fn returns 0 when the operation succeeded, or an
 * errno. Returns that value, 254 if the identity switch itself failed, 255 if
 * the child died.
 */
static int as(const struct who *w, int (*fn)(void *), void *arg)
{
	pid_t pid = fork();
	int st;

	if (pid < 0)
		return 255;
	if (pid == 0) {
		if (become(w))
			_exit(254);
		_exit(fn(arg) & 0xff);
	}
	if (waitpid(pid, &st, 0) < 0 || !WIFEXITED(st))
		return 255;
	return WEXITSTATUS(st);
}

#define DENIED(r)  ((r) == EPERM || (r) == EACCES)

/* ------------------------------------------------------------ actions */

static int do_setresuid(void *a)
{
	uid_t to = (uid_t)(uintptr_t)a;

	return setresuid(to, to, to) ? errno : 0;
}

static int do_setresgid(void *a)
{
	gid_t to = (gid_t)(uintptr_t)a;

	return setresgid(to, to, to) ? errno : 0;
}

static int do_setgroups(void *a)
{
	gid_t g = (gid_t)(uintptr_t)a;

	return setgroups(1, &g) ? errno : 0;
}

static int do_userns(void *a)
{
	(void)a;
	return unshare(CLONE_NEWUSER) ? errno : 0;
}

/*
 * Exec a copy of busybox at @path as "busybox true"; 0 means the program ran
 * and exited 0, anything else is the errno execve() failed with.
 */
static int do_exec(void *a)
{
	const char *path = a;
	pid_t pid = fork();
	int st;

	if (pid == 0) {
		char *argv[] = { "busybox", "true", NULL };
		char *envp[] = { NULL };

		execve(path, argv, envp);
		_exit(errno & 0xff);
	}
	if (pid < 0 || waitpid(pid, &st, 0) < 0 || !WIFEXITED(st))
		return 255;
	return WEXITSTATUS(st);
}

static int do_memfd_exec(void *a)
{
	(void)a;
	int fd = (int)syscall(SYS_memfd_create, "ss-functest", 0), in;
	char buf[65536];
	ssize_t n;
	pid_t pid;
	int st;

	if (fd < 0)
		return errno;
	in = open("/bin/busybox", O_RDONLY);
	if (in < 0)
		return errno;
	while ((n = read(in, buf, sizeof(buf))) > 0)
		if (write(fd, buf, n) != n)
			return EIO;
	close(in);
	pid = fork();
	if (pid == 0) {
		char *argv[] = { "busybox", "true", NULL };
		char *envp[] = { NULL };

		fexecve(fd, argv, envp);
		_exit(errno & 0xff);
	}
	if (pid < 0 || waitpid(pid, &st, 0) < 0 || !WIFEXITED(st))
		return 255;
	return WEXITSTATUS(st);
}

static int do_mmap_exec(void *a)
{
	int fd = open(a, O_RDONLY);
	void *p;

	if (fd < 0)
		return errno;
	p = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	close(fd);
	if (p == MAP_FAILED)
		return errno;
	munmap(p, 4096);
	return 0;
}

static int do_wx_anon(void *a)
{
	void *p;

	(void)a;
	p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return errno;
	munmap(p, 4096);
	return 0;
}

static int do_open_ro(void *a)
{
	int fd = open(a, O_RDONLY);

	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int do_packet_socket(void *a)
{
	int fd;

	(void)a;
	fd = socket(AF_PACKET, SOCK_RAW, 0);
	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int do_perf(void *a)
{
	struct perf_event_attr pa;
	int fd;

	(void)a;
	memset(&pa, 0, sizeof(pa));
	pa.size = sizeof(pa);
	pa.type = PERF_TYPE_SOFTWARE;
	pa.config = PERF_COUNT_SW_CPU_CLOCK;
	pa.exclude_kernel = 1;
	pa.exclude_hv = 1;
	fd = (int)syscall(SYS_perf_event_open, &pa, 0, -1, -1, 0);
	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int bpf(int cmd, union bpf_attr *attr)
{
	return (int)syscall(SYS_bpf, cmd, attr, sizeof(*attr));
}

static int do_bpf_map(void *a)
{
	union bpf_attr at;
	int fd;

	(void)a;
	memset(&at, 0, sizeof(at));
	at.map_type = BPF_MAP_TYPE_ARRAY;
	at.key_size = 4;
	at.value_size = 4;
	at.max_entries = 1;
	fd = bpf(BPF_MAP_CREATE, &at);
	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int do_bpf_prog(void *a)
{
	/* r0 = 0; exit */
	struct bpf_insn insns[2] = {
		{ .code = 0xb7, .dst_reg = 0, .imm = 0 },
		{ .code = 0x95 },
	};
	union bpf_attr at;
	int fd;

	memset(&at, 0, sizeof(at));
	at.prog_type = (uint32_t)(uintptr_t)a;
	at.insns = (uint64_t)(uintptr_t)insns;
	at.insn_cnt = 2;
	at.license = (uint64_t)(uintptr_t)"GPL";
	fd = bpf(BPF_PROG_LOAD, &at);
	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int do_write_file(void *a)
{
	const char **kv = a;
	int r = wr(kv[0], kv[1]);

	return r < 0 ? -r : 0;
}

/* ptrace / process_vm_writev / /proc/pid/mem against a sleeping child. */
enum { SS_PT_ATTACH, SS_PT_VMWRITE, SS_PT_PROCMEM };
static int do_ptrace(void *a)
{
	int how = (int)(uintptr_t)a, r = 0, st;
	static char victim_buf[16] = "victim";
	pid_t pid = fork();

	if (pid == 0) {
		pause();
		_exit(0);
	}
	if (pid < 0)
		return 255;
	usleep(20000);
	if (how == SS_PT_ATTACH) {
		if (ptrace(PTRACE_ATTACH, pid, 0, 0))
			r = errno;
		else {
			waitpid(pid, &st, 0);
			ptrace(PTRACE_DETACH, pid, 0, 0);
		}
	} else if (how == SS_PT_VMWRITE) {
		char src[4] = "abc";
		struct iovec l = { src, 4 }, rv = { victim_buf, 4 };

		if (process_vm_writev(pid, &l, 1, &rv, 1, 0) < 0)
			r = errno;
	} else {
		char p[64];
		int fd;

		snprintf(p, sizeof(p), "/proc/%d/mem", pid);
		fd = open(p, O_RDWR);
		if (fd < 0)
			r = errno;
		else {
			if (pwrite(fd, "abc", 3, (off_t)(uintptr_t)victim_buf) < 0)
				r = errno;
			close(fd);
		}
	}
	kill(pid, SIGKILL);
	waitpid(pid, &st, 0);
	return r;
}

static int load_finit_named(const char *path, const char *name)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC), r = 0;

	if (fd < 0)
		return errno;
	if (syscall(SYS_finit_module, fd, "", 0))
		r = errno;
	close(fd);
	if (!r)
		syscall(SYS_delete_module, name, O_NONBLOCK);
	return r;
}

static int load_finit_path(const char *path)
{
	return load_finit_named(path, "test_module");
}

static int load_finit(void)
{
	return load_finit_path(modpath);
}

static int load_init_path(const char *path, const char *name)
{
	struct stat st;
	int fd = open(path, O_RDONLY | O_CLOEXEC), r = 0;
	void *img;

	if (fd < 0 || fstat(fd, &st))
		return errno;
	img = malloc(st.st_size);
	if (!img || read(fd, img, st.st_size) != st.st_size) {
		close(fd);
		return EIO;
	}
	close(fd);
	if (syscall(SYS_init_module, img, (unsigned long)st.st_size, ""))
		r = errno;
	free(img);
	if (!r)
		syscall(SYS_delete_module, name, O_NONBLOCK);
	return r;
}

static int load_init(void)
{
	return load_init_path(modpath, "test_module");
}

static int find_module(const char *dir, const char *want, char *out,
		       size_t outlen, int depth)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	char p[512];
	int found = 0;

	if (!d || depth > 6)
		return d ? (closedir(d), 0) : 0;
	while (!found && (e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
		if (!strcmp(e->d_name, want)) {
			snprintf(out, outlen, "%s", p);
			found = 1;
		} else if (e->d_type == DT_DIR) {
			found = find_module(p, want, out, outlen, depth + 1);
		}
	}
	closedir(d);
	return found;
}

static int sha256_of(const char *path, char out[65])
{
	/* Delegate to busybox: the guest has no crypto library. */
	char cmd[600];
	FILE *f;

	snprintf(cmd, sizeof(cmd), "/bin/busybox sha256sum %s", path);
	f = popen(cmd, "r");
	if (!f || fscanf(f, "%64s", out) != 1) {
		if (f)
			pclose(f);
		return -1;
	}
	pclose(f);
	return 0;
}

/* Drain the event ring (non-blocking) into buf. Returns bytes read. */
static size_t drain_events(char *buf, size_t len)
{
	int fd = open(SECFS "events", O_RDONLY | O_NONBLOCK);
	size_t got = 0;
	ssize_t n;

	if (fd < 0)
		return 0;
	while (got < len - 1 && (n = read(fd, buf + got, len - 1 - got)) > 0)
		got += (size_t)n;
	close(fd);
	buf[got] = '\0';
	return got;
}

static unsigned long long line_seq(const char *l)
{
	const char *p = strstr(l, "\"sequence\":");

	return p ? strtoull(p + 11, NULL, 10) : 0;
}

/* The integer after @key in record @l; 0 if the key is missing or null. */
static int line_num(const char *l, const char *key, long long *out)
{
	const char *p = l ? strstr(l, key) : NULL;
	char *end;

	if (!p)
		return 0;
	p += strlen(key);
	*out = strtoll(p, &end, 10);
	return end != p;
}

/* The first record in @buf (lines) with "event_type":"@type", NUL-ended. */
static char *find_event(char *buf, const char *type)
{
	char want[80], *l, *save;

	snprintf(want, sizeof(want), "\"event_type\":\"%s\"", type);
	for (l = strtok_r(buf, "\n", &save); l; l = strtok_r(NULL, "\n", &save))
		if (strstr(l, want))
			return l;
	return NULL;
}

static int line_is_event(const char *l)
{
	static const char prefix[] = "{\"schema_version\":1,\"boot_id\":\"";

	return l && strlen(l) > sizeof(prefix) &&
	       !strncmp(l, prefix, sizeof(prefix) - 1) &&
	       strstr(l, "\"sequence\":") &&
	       strstr(l, "\"realtime_ns\":") &&
	       strstr(l, "\"monotonic_ns\":") &&
	       strstr(l, "\"event_type\":") &&
	       strstr(l, "\"actor\":{\"pid\":") &&
	       strstr(l, "\"kernel_started\":") &&
	       strstr(l, "\"target\":") &&
	       strstr(l, "\"operation\":") &&
	       strstr(l, "\"object\":") &&
	       strstr(l, "\"decision\":") &&
	       strstr(l, "\"reason\":") &&
	       strstr(l, "\"target_pid\":") &&
	       strstr(l, "\"target_uid\":") &&
	       strstr(l, "\"truncated\":") &&
	       strstr(l, "\"message\":\"") && l[strlen(l) - 1] == '}';
}

/* The first record in @buf of @type whose text also contains @needle. */
static char *find_event_with(char *buf, const char *type, const char *needle)
{
	char want[80], *l, *save;

	snprintf(want, sizeof(want), "\"event_type\":\"%s\"", type);
	for (l = strtok_r(buf, "\n", &save); l; l = strtok_r(NULL, "\n", &save))
		if (strstr(l, want) && strstr(l, needle))
			return l;
	return NULL;
}

/* Discard the ring, so the next saw_deny() sees only what follows. */
static void events_reset(void)
{
	static char junk[1 << 16];

	(void)drain_events(junk, sizeof(junk));
}

/* Was a well-formed deny record of @type containing @needle raised since
 * events_reset()? */
static int saw_deny(const char *type, const char *needle)
{
	static char evbuf[1 << 16];
	char *ev;

	drain_events(evbuf, sizeof(evbuf));
	ev = find_event_with(evbuf, type, needle);
	return ev && strstr(ev, "\"decision\":\"deny\"") && line_is_event(ev);
}

/* ============================================================== tests */

static void t_registration(void)
{
	char lsm[512];
	const char *s, *y;
	struct stat st;
	DIR *d;
	struct dirent *e;
	int bad = 0, n = 0;

	rd("/sys/kernel/security/lsm", lsm, sizeof(lsm));
	diag("active LSMs: %s", lsm);
	s = strstr(lsm, "secure_sudo");
	tap(s != NULL, "secure_sudo is in the active LSM list");
	tap(strstr(lsm, "landlock") && strstr(lsm, "lockdown") && strstr(lsm, "yama"),
	    "stacks with landlock, lockdown and yama");
	y = strstr(lsm, "yama");
	tap(s && y && y < s, "secure_sudo is ordered after yama (CONFIG_LSM order)");

	d = opendir(KNOB);
	tap(d != NULL, "knob directory " KNOB " exists");
	while (d && (e = readdir(d))) {
		char p[300];

		if (e->d_name[0] == '.')
			continue;
		snprintf(p, sizeof(p), KNOB "%s", e->d_name);
		if (stat(p, &st) == 0) {
			n++;
			if (st.st_mode & 077) {
				bad++;
				diag("knob %s has mode %o", e->d_name, st.st_mode & 0777);
			}
		}
	}
	if (d)
		closedir(d);
	tap(n > 30 && bad == 0, "all %d knobs are root-only (no group/other bits)", n);
	tap(stat(SECFS "events", &st) == 0 && (st.st_mode & 0777) == 0400,
	    "events file exists with mode 0400");
}

static void t_defaults(void)
{
	static const char *const want[][2] = {
		{ "block_setid", "1" }, { "block_userns", "1" }, { "block_flash", "1" },
		{ "lock", "0" }, { "lock_modules", "1" }, { "block_tmp_exec", "1" },
		{ "block_tmpfs_exec", "0" }, { "timevault", "0" }, { "prguard_enabled", "0" },
		{ "bpf_guard", "0" }, { "bpf_lock_tracing", "1" }, { "perf_guard", "0" },
		{ "sysctl_guard", "0" }, { "binaryvault", "0" }, { "audit_events", "0" },
		{ "admin_gid", "unset" }, { "block_home_write", "0" },
		{ "ram_spike_enabled", "0" }, { "sudo_cooldown_enabled", "1" },
		{ "block_wifi", "0" }, { "block_bluetooth", "0" }, { "ethernet_only", "0" },
		{ "prguard_observe", "0" }, { "timevault_strict_mmap", "0" },
		{ "timevault_allow_autoupdate", "1" }, { "lock_confidentiality", "0" },
	};
	unsigned int i;

	for (i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
		const char *v = knob_get(want[i][0]);

		tap(!strcmp(v, want[i][1]), "default %s = %s (got %s)",
		    want[i][0], want[i][1], v);
	}
}

static int do_read_knob(void *a)
{
	char buf[64];

	return -rd(a, buf, sizeof(buf));
}

/* Expect a write to be refused with @err and the knob to keep its value. */
static void expect_reject(const char *k, const char *v, int err)
{
	char before[256];
	int r;

	snprintf(before, sizeof(before), "%s", knob_get(k));
	r = knob_set(k, v);
	tap(r == -err && !strcmp(knob_get(k), before),
	    "%s=%s rejected with %s, value kept (got %d, now %s)",
	    k, v, strerror(err), r, knob_get(k));
}

static void t_knob_access(void)
{
	int r;

	r = as(&NONSUDO, do_read_knob, KNOB "block_setid");
	tap(DENIED(r), "non-root cannot read a knob (got %d)", r);
	expect_reject("block_setid", "banana", EINVAL);
	expect_reject("max_ram_percent", "101", ERANGE);
	expect_reject("max_ram_percent", "0", ERANGE);
	expect_reject("max_ram_percent", "-5", EINVAL);
	tap(knob_set("max_ram_percent", "90") == 0, "max_ram_percent 90 accepted");
	expect_reject("timevault_max_entries", "0", ERANGE);
	expect_reject("timevault_max_entries", "131073", ERANGE);
	expect_reject("admin_gid", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17", E2BIG);
	expect_reject("admin_gid", "27,abc", EINVAL);
	expect_reject("net_mode", "bogus", EINVAL);
}

static void t_creds(void)
{
	struct who nscap = { USER, USER, 0, {0}, 1ULL << CAP_SETUID | 1ULL << CAP_SETGID };
	struct who admcap = { USER, USER, 1, { ADMIN_GID }, 1ULL << CAP_SETUID | 1ULL << CAP_SETGID };
	int r;

	r = as(&nscap, do_setresuid, (void *)(uintptr_t)1001);
	tap(r == EPERM, "#1 non-sudo with CAP_SETUID cannot change UID (got %d)", r);
	r = as(&nscap, do_setresuid, (void *)(uintptr_t)USER);
	tap(r == 0, "#1 non-sudo may make a no-op setresuid to its own UID (got %d)", r);
	r = as(&nscap, do_setresgid, (void *)(uintptr_t)1001);
	tap(r == EPERM, "#1 non-sudo with CAP_SETGID cannot change GID (got %d)", r);
	r = as(&nscap, do_setgroups, (void *)(uintptr_t)1001);
	tap(r == EPERM, "#1 non-sudo with CAP_SETGID cannot setgroups (got %d)", r);
	r = as(&admcap, do_setresuid, (void *)(uintptr_t)1001);
	tap(r == EPERM, "#1 admin group not yet configured: still denied (got %d)", r);
	tap(knob_set("admin_gid", "27") == 0, "set admin_gid=27");
	r = as(&admcap, do_setresuid, (void *)(uintptr_t)1001);
	tap(r == 0, "#1 member of admin GID 27 may change UID (got %d)", r);
	r = as(&ROOT, do_setresuid, (void *)(uintptr_t)1002);
	tap(r == 0, "#1 root may change UID (got %d)", r);
	tap(knob_set("block_setid", "0") == 0, "block_setid=0");
	r = as(&nscap, do_setresuid, (void *)(uintptr_t)1001);
	tap(r == 0, "#1 with block_setid=0 the ordinary capability rules apply (got %d)", r);
	knob_set("block_setid", "1");

	r = as(&NONSUDO, do_userns, NULL);
	tap(r == EPERM, "#1 non-sudo cannot create a user namespace (got %d)", r);
	r = as(&ROOT, do_userns, NULL);
	tap(r == 0, "#1 root can create a user namespace (got %d)", r);
	knob_set("block_userns", "0");
	r = as(&NONSUDO, do_userns, NULL);
	tap(r == 0, "#1 with block_userns=0 non-sudo can create a user namespace (got %d)", r);
	knob_set("block_userns", "1");
}

static void t_setid_exec(void)
{
	int r;

	copy_file("/bin/busybox", "/bin/suidtest", 04755);
	knob_set("block_setid_exec", "1");
	r = as(&NONSUDO, do_exec, "/bin/suidtest");
	tap(DENIED(r), "#1b non-sudo exec of an unlisted setuid binary denied (got %d)", r);
	tap(wr(SECFS "setid_exec_allow", "/bin/suidtest\n") == 0, "allowlist /bin/suidtest");
	r = as(&NONSUDO, do_exec, "/bin/suidtest");
	tap(r == 0, "#1b allowlisted setuid binary runs (got %d)", r);
	wr(SECFS "setid_exec_allow", "\n");
	r = as(&ROOT, do_exec, "/bin/suidtest");
	tap(r == 0, "#1b root may exec setuid binaries (got %d)", r);
	knob_set("block_setid_exec", "0");
	unlink("/bin/suidtest");
}

static void t_blacklist(void)
{
	int r;

	copy_file("/bin/busybox", "/bin/bltest", 0755);
	append_byte("/bin/bltest");	/* not byte-identical to /bin/busybox */
	tap(wr(SECFS "blacklist", "/bin/bltest\n") == 0, "#2 blacklist /bin/bltest");
	events_reset();
	r = as(&NONSUDO, do_exec, "/bin/bltest");
	tap(DENIED(r), "#2 non-sudo exec of a blacklisted binary denied (got %d)", r);
	tap(saw_deny("command_blacklist", "\"object\":\"/bin/bltest\""),
	    "#2 the denial is logged as a typed event");
	r = as(&NONSUDO, do_exec, "/bin/busybox");
	tap(r == 0, "#2 other binaries still run (got %d)", r);
	if (link("/bin/bltest", "/bin/bltest-link") == 0) {
		events_reset();
		r = as(&NONSUDO, do_exec, "/bin/bltest-link");
		tap(DENIED(r), "#2 a hard link to the blacklisted inode is denied too (got %d)", r);
		tap(saw_deny("command_blacklist", "\"reason\":\"blacklisted_inode\""),
		    "#2 the hard-link denial is logged as an inode match");
	} else {
		tap(0, "#2 create a hard link for the inode test (%s)", strerror(errno));
	}
	/* A copy is a new inode at a new path: the content match catches it. */
	copy_file("/bin/bltest", "/bin/bltest-copy", 0755);
	events_reset();
	r = as(&NONSUDO, do_exec, "/bin/bltest-copy");
	tap(DENIED(r), "#2 a copy of the blacklisted binary at another path is denied (got %d)", r);
	tap(saw_deny("command_blacklist", "\"reason\":\"blacklisted_content\""),
	    "#2 the copy denial is logged as a content match");
	append_byte("/bin/bltest-copy");
	r = as(&NONSUDO, do_exec, "/bin/bltest-copy");
	tap(r == 0, "#2 a changed copy is a different program and runs (documented limit) (got %d)", r);
	unlink("/bin/bltest-copy");
	r = as(&ROOT, do_exec, "/bin/bltest");
	tap(r == 0, "#2 root may exec a blacklisted binary (got %d)", r);
	wr(SECFS "blacklist", "\n");
	r = as(&NONSUDO, do_exec, "/bin/bltest");
	tap(r == 0, "#2 cleared blacklist: binary runs again (got %d)", r);
	unlink("/bin/bltest-link");
	unlink("/bin/bltest");
}

static void t_tmpexec(void)
{
	int r;

	copy_file("/bin/busybox", "/tmp/bb", 0755);
	events_reset();
	r = as(&NONSUDO, do_exec, "/tmp/bb");
	tap(DENIED(r), "#12 non-sudo exec from /tmp denied (got %d)", r);
	tap(saw_deny("tmp_exec", "\"object\":\"/tmp/bb\""),
	    "#12 the exec denial is logged as a typed event");
	events_reset();
	r = as(&NONSUDO, do_mmap_exec, "/tmp/bb");
	tap(DENIED(r), "#12 non-sudo PROT_EXEC mmap of a /tmp file denied (got %d)", r);
	tap(saw_deny("tmp_exec", "\"operation\":\"mmap_exec\""),
	    "#12 the mmap denial is logged as a typed event");
	r = as(&ROOT, do_exec, "/tmp/bb");
	tap(r == 0, "#12 root may exec from /tmp (got %d)", r);
	tap(wr(SECFS "tmp_exec_allow", "/tmp/bb\n") == 0, "#12 allowlist /tmp/bb");
	r = as(&NONSUDO, do_exec, "/tmp/bb");
	tap(r == 0, "#12 allowlisted /tmp binary runs (got %d)", r);
	wr(SECFS "tmp_exec_allow", "\n");

	r = as(&NONSUDO, do_memfd_exec, NULL);
	tap(r == 0, "#12 memfd exec allowed while block_tmpfs_exec=0 (got %d)", r);
	knob_set("block_tmpfs_exec", "1");
	r = as(&NONSUDO, do_memfd_exec, NULL);
	tap(DENIED(r), "#12 non-sudo fileless memfd exec denied with block_tmpfs_exec=1 (got %d)", r);
	r = as(&ROOT, do_memfd_exec, NULL);
	tap(r == 0, "#12 root memfd exec still allowed (got %d)", r);
	knob_set("block_tmpfs_exec", "0");
	unlink("/tmp/bb");
}

static void t_firmware(void)
{
	/* /dev/mem itself demands CAP_SYS_RAWIO, so keep it: only the LSM
	 * should be able to refuse. */
	struct who rawio = { USER, USER, 0, {0}, 1ULL << CAP_SYS_RAWIO };
	int r;

	if (access("/dev/mem", F_OK)) {
		tap(1, "# SKIP /dev/mem not present");
		return;
	}
	chmod("/dev/mem", 0666);	/* so only the LSM can say no */
	events_reset();
	r = as(&rawio, do_open_ro, "/dev/mem");
	tap(DENIED(r), "#3 non-sudo open of /dev/mem denied despite mode 0666 + CAP_SYS_RAWIO (got %d)", r);
	tap(saw_deny("firmware_guard", "\"object\":\"raw_memory_device\""),
	    "#3 the denial is logged as a typed event");
	r = as(&ROOT, do_open_ro, "/dev/mem");
	tap(r == 0, "#3 root may open /dev/mem (got %d)", r);
	knob_set("block_flash", "0");
	r = as(&rawio, do_open_ro, "/dev/mem");
	tap(r == 0, "#3 with block_flash=0 only the kernel's own checks apply (got %d)", r);
	knob_set("block_flash", "1");
	chmod("/dev/mem", 0640);
}

static void t_net(void)
{
	struct who rawcap = { USER, USER, 0, {0}, 1ULL << CAP_NET_RAW };
	int r;

	r = as(&rawcap, do_packet_socket, NULL);
	tap(r == 0, "#10 monitor mode: packet socket allowed with CAP_NET_RAW (got %d)", r);
	tap(knob_set("net_mode", "host") == 0, "#10 net_mode=host");
	events_reset();
	r = as(&rawcap, do_packet_socket, NULL);
	tap(r == EPERM, "#10 host mode: packet socket denied (got %d)", r);
	tap(saw_deny("network_guard", "\"object\":\"AF_PACKET\""),
	    "#10 the denial is logged as a typed event");
	r = as(&ROOT, do_packet_socket, NULL);
	tap(r == EPERM, "#10 host mode applies to root too (got %d)", r);
	knob_set("net_mode", "monitor");
}

static void t_perf_bpf(void)
{
	int r;

	r = as(&NONSUDO, do_perf, NULL);
	tap(r == 0, "#22 perf_guard=0: non-sudo self-profiling allowed (got %d)", r);
	knob_set("perf_guard", "1");
	r = as(&NONSUDO, do_perf, NULL);
	tap(r == EPERM, "#22 perf_guard=1: non-sudo perf_event_open denied (got %d)", r);
	r = as(&ROOT, do_perf, NULL);
	tap(r == 0, "#22 perf_guard=1: root perf_event_open allowed (got %d)", r);
	knob_set("perf_guard", "0");

	wr("/proc/sys/kernel/unprivileged_bpf_disabled", "0");
	r = as(&NONSUDO, do_bpf_map, NULL);
	tap(r == 0, "#22 bpf_guard=0: unprivileged bpf map allowed when the sysctl permits (got %d)", r);
	knob_set("bpf_guard", "1");
	r = as(&NONSUDO, do_bpf_map, NULL);
	tap(r == EPERM, "#22 bpf_guard=1: non-sudo bpf(2) denied (got %d)", r);
	r = as(&ROOT, do_bpf_map, NULL);
	tap(r == 0, "#22 bpf_guard=1: root bpf(2) allowed (got %d)", r);
	knob_set("bpf_guard", "0");
	r = as(&ROOT, do_bpf_prog, (void *)(uintptr_t)BPF_PROG_TYPE_TRACEPOINT);
	tap(r == 0, "#22 before lock: root may load a tracepoint program (got %d)", r);
}

static void t_sysctl(void)
{
	const char *kv_kptr[2] = { "/proc/sys/kernel/kptr_restrict", "2" };
	const char *kv_dom[2] = { "/proc/sys/kernel/domainname", "sstest" };
	int r;

	r = as(&ROOT, do_write_file, kv_kptr);
	tap(r == 0, "#23 sysctl_guard=0: root may write kptr_restrict (got %d)", r);
	knob_set("sysctl_guard", "1");
	r = as(&ROOT, do_write_file, kv_kptr);
	tap(r == EPERM, "#23 sysctl_guard=1: root cannot write kptr_restrict (got %d)", r);
	r = as(&ROOT, do_write_file, kv_dom);
	tap(r == 0, "#23 unprotected sysctls stay writable (got %d)", r);
	mkdir("/proc/sys/fs/binfmt_misc", 0755);
	if (mount("binfmt_misc", "/proc/sys/fs/binfmt_misc", "binfmt_misc", 0, NULL) == 0 ||
	    errno == EBUSY) {
		const char *kv_bin[2] = { "/proc/sys/fs/binfmt_misc/register",
					  ":sstest:E::sstest::/bin/busybox:" };

		r = as(&ROOT, do_write_file, kv_bin);
		tap(DENIED(r), "#23 binfmt_misc registration refused (got %d)", r);
	} else {
		tap(1, "# SKIP binfmt_misc not mountable (%s)", strerror(errno));
	}
	knob_set("sysctl_guard", "0");
}

static void t_prguard(void)
{
	int r;

	r = as(&NONSUDO, do_ptrace, (void *)SS_PT_ATTACH);
	tap(r == 0, "#20 prguard off: same-user ptrace attach allowed (got %d)", r);
	r = as(&NONSUDO, do_wx_anon, NULL);
	tap(r == 0, "#20 prguard off: W+X anonymous mapping allowed (got %d)", r);
	knob_set("prguard_enabled", "1");
	r = as(&NONSUDO, do_ptrace, (void *)SS_PT_ATTACH);
	tap(DENIED(r), "#20 ptrace attach denied (got %d)", r);
	r = as(&NONSUDO, do_ptrace, (void *)SS_PT_VMWRITE);
	tap(DENIED(r), "#20 process_vm_writev denied (got %d)", r);
	r = as(&NONSUDO, do_ptrace, (void *)SS_PT_PROCMEM);
	tap(DENIED(r), "#20 /proc/pid/mem write denied (got %d)", r);
	r = as(&ROOT, do_ptrace, (void *)SS_PT_ATTACH);
	tap(DENIED(r), "#20 applies to root too (got %d)", r);
	r = as(&NONSUDO, do_wx_anon, NULL);
	tap(DENIED(r), "#20 W+X anonymous mapping denied (got %d)", r);
	tap(wr(SECFS "prguard_allow", "/ss-functest\n") == 0, "#20 exempt /ss-functest");
	r = as(&NONSUDO, do_ptrace, (void *)SS_PT_ATTACH);
	tap(r == 0, "#20 exempt program may attach (got %d)", r);
	wr(SECFS "prguard_allow", "\n");
	knob_set("prguard_enabled", "0");
}

static void t_modules(void)
{
	char hash[65], line[80];
	int r;

	if (!modpath[0]) {
		tap(0, "test_module.ko found in /lib/modules");
		return;
	}
	r = load_finit();
	tap(r == 0, "#6 unlocked: finit_module of test_module loads (got %d)", r);
	r = load_init();
	tap(r == 0, "#6 unlocked: init_module of test_module loads (got %d)", r);
	tap(wr(SECFS "driver_blacklist", "test_module.ko\n") == 0, "#6 blacklist module by name");
	r = load_finit();
	tap(r == EPERM, "#6 name-blacklisted module refused via finit_module (got %d)", r);
	r = load_init();
	tap(r == EPERM, "#6 name-blacklisted module refused via init_module (no file name) (got %d)", r);
	copy_file(modpath, "/tmp/renamed-mod.ko", 0644);
	r = load_finit_path("/tmp/renamed-mod.ko");
	tap(r == EPERM, "#6 a renamed copy is refused by the module's own name (got %d)", r);
	unlink("/tmp/renamed-mod.ko");
	if (sha256_of(modpath, hash) == 0) {
		snprintf(line, sizeof(line), "%s\n", hash);
		tap(wr(SECFS "driver_blacklist", line) == 0, "#6 blacklist module by SHA-256");
		r = load_finit();
		tap(r == EPERM, "#6 hash-blacklisted module refused via finit_module (got %d)", r);
		r = load_init();
		tap(r == EPERM, "#6 hash-blacklisted module refused via init_module (got %d)", r);
	} else {
		tap(0, "sha256 of test_module.ko computed");
	}
	wr(SECFS "driver_blacklist", "\n");
	r = load_finit();
	tap(r == 0, "#6 cleared blacklist: module loads again (got %d)", r);
}

/*
 * P1-5: the controls below had no in-kernel test before the threat model
 * (docs/THREAT_MODEL.md) mapped each control to one. Each checks the denial
 * and the legitimate path next to it, then puts the policy back.
 */

static int do_create(void *a)
{
	int fd = open(a, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (fd < 0)
		return errno;
	close(fd);
	return unlink(a) ? errno : 0;
}

static int do_mkdir(void *a)
{
	if (mkdir(a, 0755))
		return errno;
	return rmdir(a) ? errno : 0;
}

static int do_open_wr(void *a)
{
	int fd = open(a, O_WRONLY);

	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static void t_home(void)
{
	int r;

	mkdir("/home", 0755);
	mkdir("/home/u1000", 0700);
	if (chown("/home/u1000", USER, USER))
		diag("chown /home/u1000: %s", strerror(errno));
	mkdir("/srv", 0755);
	mkdir("/srv/hw", 0777);
	chmod("/srv/hw", 0777);		/* so only the LSM can say no */
	r = as(&NONSUDO, do_create, "/srv/hw/f");
	tap(r == 0, "#4 block_home_write=0: non-sudo may write a mode-0777 directory (got %d)", r);
	tap(wr(SECFS "home_map", "1000 /home/u1000\n") == 0, "#4 home_map 1000 -> /home/u1000");
	tap(knob_set("block_home_write", "1") == 0, "#4 block_home_write=1");
	r = as(&NONSUDO, do_create, "/srv/hw/f");
	tap(DENIED(r), "#4 non-sudo file write outside its home denied despite mode 0777 (got %d)", r);
	r = as(&NONSUDO, do_mkdir, "/srv/hw/d");
	tap(DENIED(r), "#4 non-sudo mkdir outside its home denied (got %d)", r);
	r = as(&NONSUDO, do_create, "/home/u1000/f");
	tap(r == 0, "#4 non-sudo write inside its own home allowed (got %d)", r);
	r = as(&NONSUDO, do_create, "/tmp/ss-home-f");
	tap(r == 0, "#4 /tmp stays writable (got %d)", r);
	r = as(&ROOT, do_create, "/srv/hw/f");
	tap(r == 0, "#4 root is not confined (got %d)", r);
	tap(wr(SECFS "home_write_allow", "/srv/hw\n") == 0, "#4 home_write_allow /srv/hw");
	r = as(&NONSUDO, do_create, "/srv/hw/f");
	tap(r == 0, "#4 an allowlisted prefix becomes writable (got %d)", r);
	wr(SECFS "home_write_allow", "\n");
	wr(SECFS "home_map", "\n");
	knob_set("block_home_write", "0");
}

/* How many times @needle appears in the kernel log; -1 if it is unreadable. */
static int klog_count(const char *needle)
{
	static char kb[1 << 18];
	int len = klogctl(3 /* SYSLOG_ACTION_READ_ALL */, kb, (int)sizeof(kb) - 1);
	int n = 0;
	char *p;

	if (len <= 0)
		return -1;
	kb[len] = '\0';
	for (p = kb; (p = strstr(p, needle)); p += strlen(needle))
		n++;
	return n;
}

static void t_ram(void)
{
	/* The 1% threshold is only ever set here, so this text is ours. */
	static const char mark[] = ">= 1% - dropping caches";
	int before = klog_count(mark), now = before, i;

	knob_set("max_ram_percent", "1");
	knob_set("check_interval_ms", "100");
	knob_set("drop_cooldown_ms", "1000");
	events_reset();
	tap(knob_set("ram_spike_enabled", "1") == 0, "#7 ram_spike_enabled=1, threshold 1%");
	/* The worker was last armed with the old 5 s interval. */
	for (i = 0; i < 80 && now <= before; i++) {
		usleep(100000);
		now = klog_count(mark);
	}
	tap(before >= 0 && now > before,
	    "#7 above the threshold the kernel worker drops caches (%d drop(s) logged)",
	    now - before);
	{
		static char evbuf[1 << 16];
		char *ev;

		drain_events(evbuf, sizeof(evbuf));
		ev = find_event_with(evbuf, "ram_guard", "\"operation\":\"drop_caches\"");
		tap(ev && strstr(ev, "\"kernel_started\":true") && line_is_event(ev),
		    "#7 the drop is logged as an event raised by the kernel worker");
	}
	knob_set("ram_spike_enabled", "0");
	usleep(300000);
	before = klog_count(mark);
	usleep(1500000);
	now = klog_count(mark);
	tap(now == before, "#7 ram_spike_enabled=0: no further drops (%d)", now - before);
	knob_set("max_ram_percent", "90");
	knob_set("check_interval_ms", "5000");
	knob_set("drop_cooldown_ms", "2000");
}

static void t_cooldown(void)
{
	static char buf[1 << 16];
	const struct who other = { 1001, 1001, 0, {0}, 0 };
	const char *kv_fail[2] = { SECFS "sudo_auth", "fail 1000" };
	long long tuid = -1;
	char *ev;
	int r, i;

	copy_file("/bin/busybox", "/bin/sudo", 0755);
	copy_file("/bin/busybox", "/bin/sutool", 04755);
	r = as(&NONSUDO, do_exec, "/bin/sudo");
	tap(r == 0, "#8 no failures recorded: non-sudo may run sudo (got %d)", r);
	r = as(&NONSUDO, do_write_file, kv_fail);
	tap(DENIED(r), "#8 non-root cannot feed sudo_auth (got %d)", r);
	for (i = 0; i < 4; i++)
		wr(SECFS "sudo_auth", "fail 1000");
	r = as(&NONSUDO, do_exec, "/bin/sudo");
	tap(r == 0, "#8 4 failures (limit 5): sudo still runs (got %d)", r);
	(void)drain_events(buf, sizeof(buf));
	tap(wr(SECFS "sudo_auth", "fail 1000") == 0, "#8 5th failure reported");
	drain_events(buf, sizeof(buf));
	ev = find_event(buf, "sudo_cooldown");
	tap(ev && line_num(ev, "\"target_uid\":", &tuid) && tuid == USER &&
	    strstr(ev, "\"decision\":\"deny\""),
	    "#8 block event names the user in target_uid (what secure-sudod kills by) (%lld)",
	    tuid);
	r = as(&NONSUDO, do_exec, "/bin/sudo");
	tap(DENIED(r), "#8 in cooldown: sudo exec denied (got %d)", r);
	r = as(&NONSUDO, do_exec, "/bin/sutool");
	tap(DENIED(r), "#8 in cooldown: any setuid-root program denied too (got %d)", r);
	r = as(&NONSUDO, do_exec, "/bin/busybox");
	tap(r == 0, "#8 in cooldown: ordinary programs still run (got %d)", r);
	r = as(&other, do_exec, "/bin/sudo");
	tap(r == 0, "#8 another user is not affected (got %d)", r);
	tap(wr(SECFS "sudo_auth", "ok 1000") == 0, "#8 a successful authentication is reported");
	r = as(&NONSUDO, do_exec, "/bin/sudo");
	tap(r == 0, "#8 after a success the block is lifted (got %d)", r);
	unlink("/bin/sutool");
	unlink("/bin/sudo");
}

/*
 * Run @a (a copy of busybox whose name makes it a Node runtime) as "sh -c
 * 'exec /bin/busybox true'": the shell is the Node process, /bin/busybox is
 * the child it spawns. 0 = child ran; the shell exits 126 when its exec is
 * refused; 250 = the runtime itself did not start.
 */
#define NODE_REFUSED(r) ((r) != 0 && (r) < 250)
static int do_node_child(void *a)
{
	pid_t pid = fork();
	int st;

	if (pid == 0) {
		char *argv[] = { "sh", "-c", "exec /bin/busybox true", NULL };
		char *envp[] = { NULL };

		execve(a, argv, envp);
		_exit(250);
	}
	if (pid < 0 || waitpid(pid, &st, 0) < 0 || !WIFEXITED(st))
		return 255;
	return WEXITSTATUS(st);
}

static void t_node(void)
{
	static char buf[1 << 16];
	long long apid = 0, tpid = -1;
	char *ev;
	int r;

	mkdir("/srv", 0755);
	mkdir("/srv/nodetest", 0755);
	copy_file("/bin/busybox", "/srv/nodetest/node", 0755);
	copy_file("/bin/busybox", "/srv/nodetest/app", 0755);
	r = as(&NONSUDO, do_node_child, "/srv/nodetest/app");
	tap(r == 0, "#11 an ordinary program may spawn children (got %d)", r);
	(void)drain_events(buf, sizeof(buf));
	r = as(&NONSUDO, do_node_child, "/srv/nodetest/node");
	tap(NODE_REFUSED(r), "#11 a node process cannot spawn an unlisted child (got %d)", r);
	drain_events(buf, sizeof(buf));
	ev = find_event_with(buf, "node_guard", "\"object\":\"/bin/busybox\"");
	tap(ev && strstr(ev, "\"decision\":\"deny\"") &&
	    line_num(ev, "\"actor\":{\"pid\":", &apid) &&
	    line_num(ev, "\"target_pid\":", &tpid) && apid == tpid,
	    "#11 the denial is logged with the blocked child as object");
	r = as(&ROOT, do_node_child, "/srv/nodetest/node");
	tap(NODE_REFUSED(r), "#11 applies to root too (got %d)", r);
	tap(wr(SECFS "node_allowed_children", "busybox\n") == 0, "#11 allow child basename busybox");
	r = as(&NONSUDO, do_node_child, "/srv/nodetest/node");
	tap(r == 0, "#11 an allowlisted child runs (got %d)", r);
	tap(wr(SECFS "node_allowed_children", "\n") == 0 &&
	    wr(SECFS "node_sea_binaries", "/srv/nodetest/app\n") == 0,
	    "#11 register /srv/nodetest/app as a single-executable Node app");
	r = as(&NONSUDO, do_node_child, "/srv/nodetest/app");
	tap(NODE_REFUSED(r), "#11 a registered SEA binary is guarded like node (got %d)", r);
	wr(SECFS "node_sea_binaries", "\n");
	unlink("/srv/nodetest/node");
	unlink("/srv/nodetest/app");
	rmdir("/srv/nodetest");
}

static void t_binvault(void)
{
	int r, fd;

	mkdir("/usr", 0755);
	mkdir("/usr/lib", 0755);
	copy_file("/bin/busybox", "/bin/bvtest", 0755);
	copy_file("/bin/busybox", "/usr/lib/libbv.so.1", 0644);
	fd = open("/bin/bvdata", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0)
		close(fd);
	tap(knob_set("binaryvault", "1") == 0, "#17 binaryvault=1");
	r = do_open_wr("/bin/bvtest");
	tap(r == EPERM, "#17 root cannot open an executable for writing (got %d)", r);
	r = unlink("/bin/bvtest") ? errno : 0;
	tap(r == EPERM, "#17 root cannot unlink an executable (got %d)", r);
	r = rename("/bin/bvtest", "/bin/bvtest2") ? errno : 0;
	tap(r == EPERM, "#17 root cannot rename an executable (got %d)", r);
	r = link("/bin/bvtest", "/bin/bvlink") ? errno : 0;
	tap(r == EPERM, "#17 root cannot hard-link an executable (got %d)", r);
	r = chmod("/bin/bvtest", 0644) ? errno : 0;
	tap(r == EPERM, "#17 root cannot chmod an executable (got %d)", r);
	r = setxattr("/bin/bvtest", "trusted.ss_test", "x", 1, 0) ? errno : 0;
	tap(r == EPERM, "#17 root cannot set an xattr on an executable (got %d)", r);
	r = do_open_wr("/usr/lib/libbv.so.1");
	tap(r == EPERM, "#17 a shared library without +x under /usr/lib is frozen too (got %d)", r);
	r = do_open_wr("/bin/bvdata");
	tap(r == 0, "#17 a plain data file stays writable (got %d)", r);
	r = do_create("/bin/bvnew");
	tap(r == 0, "#17 creating a new file is not blocked (got %d)", r);
	r = as(&NONSUDO, do_exec, "/bin/bvtest");
	tap(r == 0, "#17 frozen executables still run (got %d)", r);
	tap(wr(SECFS "binvault_allow", "/bin/bvtest\n") == 0, "#17 binvault_allow /bin/bvtest");
	r = do_open_wr("/bin/bvtest");
	tap(r == 0, "#17 an allowlisted path is writable (got %d)", r);
	wr(SECFS "binvault_allow", "\n");
	knob_set("binaryvault", "0");
	r = do_open_wr("/bin/bvtest");
	tap(r == 0, "#17 binaryvault=0: the executable is writable again (got %d)", r);
	unlink("/bin/bvtest");
	unlink("/bin/bvdata");
	unlink("/usr/lib/libbv.so.1");
}

static int do_bt_socket(void *a)
{
	int fd;

	(void)a;
	fd = socket(AF_BLUETOOTH, SOCK_RAW, 1 /* BTPROTO_HCI */);
	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static void t_radio(void)
{
	static const char *const names[] = {
		"/tmp/ssradio/bluetooth.ko", "/tmp/ssradio/cfg80211.ko",
		"/tmp/ssradio/cfg80211.ko.zst", "/tmp/ssradio/mac80211-hwsim.ko",
	};
	int r, standin = 0, fd;
	unsigned int i;

	r = as(&ROOT, do_bt_socket, NULL);
	tap(r != EPERM, "#19 radios allowed: AF_BLUETOOTH is not refused by secure_sudo (%s)",
	    r ? strerror(r) : "socket created");
	knob_set("block_bluetooth", "1");
	r = as(&NONSUDO, do_bt_socket, NULL);
	tap(r == EPERM, "#19 block_bluetooth=1: AF_BLUETOOTH socket denied (got %d)", r);
	r = as(&ROOT, do_bt_socket, NULL);
	tap(r == EPERM, "#19 block_bluetooth=1 applies to root too (got %d)", r);

	if (access("/dev/rfkill", F_OK)) {
		/* No rfkill driver in this kernel: the guard matches the path,
		 * so a stand-in file at /dev/rfkill exercises the same check. */
		fd = open("/dev/rfkill", O_WRONLY | O_CREAT, 0644);
		if (fd >= 0) {
			close(fd);
			standin = 1;
			diag("no /dev/rfkill in this kernel; using a stand-in file");
		}
	}
	r = do_open_wr("/dev/rfkill");
	tap(r == EPERM, "#19 radios blocked: root cannot write /dev/rfkill (got %d)", r);
	r = do_open_ro("/dev/rfkill");
	tap(r == 0, "#19 reading /dev/rfkill (rfkill list) still works (got %d)", r);

	if (!modpath[0]) {
		tap(0, "#19 test_module.ko available for the module-name checks");
	} else {
		mkdir("/tmp/ssradio", 0700);
		for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
			copy_file(modpath, names[i], 0644);
		r = load_finit_path(names[0]);
		tap(r == EPERM, "#19 block_bluetooth=1: a module file named bluetooth.ko is refused (got %d)", r);
		knob_set("block_bluetooth", "0");
		knob_set("block_wifi", "1");
		r = load_finit_path(names[1]);
		tap(r == EPERM, "#19 block_wifi=1: cfg80211.ko refused (got %d)", r);
		r = load_finit_path(names[2]);
		tap(r == EPERM, "#19 block_wifi=1: the .ko.zst spelling is refused too (got %d)", r);
		r = load_finit_path(names[3]);
		tap(r == EPERM, "#19 block_wifi=1: mac80211-hwsim.ko (dash spelling) refused (got %d)", r);
		r = load_finit();
		tap(r == 0, "#19 block_wifi=1: other modules still load (got %d)", r);
		knob_set("block_wifi", "0");
		knob_set("ethernet_only", "1");
		r = load_finit_path(names[1]);
		tap(r == EPERM, "#19 ethernet_only=1 refuses Wi-Fi modules (got %d)", r);
		r = as(&ROOT, do_bt_socket, NULL);
		tap(r == EPERM, "#19 ethernet_only=1 refuses AF_BLUETOOTH (got %d)", r);
		knob_set("ethernet_only", "0");
		if (hwsimpath[0]) {
			copy_file(hwsimpath, "/tmp/ssradio/renamed.ko", 0644);
			knob_set("block_wifi", "1");
			r = load_finit_named("/tmp/ssradio/renamed.ko", "mac80211_hwsim");
			tap(r == EPERM, "#19 block_wifi=1: a renamed copy of mac80211_hwsim is refused by its module name (got %d)", r);
			r = load_init_path("/tmp/ssradio/renamed.ko", "mac80211_hwsim");
			tap(r == EPERM, "#19 block_wifi=1: init_module of the same bytes is refused too (got %d)", r);
			knob_set("block_wifi", "0");
			r = load_finit_named("/tmp/ssradio/renamed.ko", "mac80211_hwsim");
			tap(r == 0, "#19 radios allowed: the renamed copy loads (got %d)", r);
			unlink("/tmp/ssradio/renamed.ko");
		} else {
			tap(0, "#19 mac80211_hwsim.ko available for the module-name check");
		}
		/* The file-name check is about the file name only: this file
		 * holds test_module, so with the radios allowed it loads. */
		r = load_finit_path(names[1]);
		tap(r == 0, "#19 radios allowed again: the same file loads (got %d)", r);
		for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
			unlink(names[i]);
		rmdir("/tmp/ssradio");
	}
	knob_set("block_bluetooth", "0");
	knob_set("block_wifi", "0");
	knob_set("ethernet_only", "0");
	if (standin)
		unlink("/dev/rfkill");
}

/*
 * #13 TimeVault. Engaging it latches the lock, so the allowlist is loaded
 * before t_lock and the vault is engaged after it, as the last test. The
 * guest must still be able to run /bin/busybox afterwards (the init script
 * calls dmesg, grep and poweroff), so busybox is on the list.
 */
static int tv_ready, tv_engaged, tv_busybox_ok;

static void t_timevault_prepare(void)
{
	char hb[65], hf[65], list[512];
	struct stat st;

	/* The vault only runs root-owned binaries that are not group or world
	 * writable. The initramfs keeps the builder's uid, so give the guest's
	 * own programs the ownership a real system has. */
	if (stat("/bin/busybox", &st) == 0 && st.st_uid != 0)
		diag("initramfs files are owned by uid %u; making the guest's programs root-owned",
		     (unsigned int)st.st_uid);
	if (chown("/bin/busybox", 0, 0) || chmod("/bin/busybox", 0755) ||
	    chown("/ss-functest", 0, 0) || chmod("/ss-functest", 0755))
		diag("chown/chmod of the guest programs failed: %s", strerror(errno));
	copy_file("/bin/busybox", "/bin/tvok", 0755);
	copy_file("/bin/busybox", "/bin/tvbad", 0755);
	copy_file("/bin/busybox", "/bin/dpkg", 0755);
	copy_file("/bin/busybox", "/bin/tvmod", 0755);
	tap(knob_set("timevault", "1") == -ENOENT && !strcmp(knob_get("timevault"), "0") &&
	    !strcmp(knob_get("lock"), "0"),
	    "#13 engaging with an empty allowlist is refused and does not lock");
	if (sha256_of("/bin/busybox", hb) || sha256_of("/ss-functest", hf)) {
		tap(0, "#13 sha256 of /bin/busybox and /ss-functest computed");
		return;
	}
	/* tvmod is listed with busybox's hash, then changed. */
	append_byte("/bin/tvmod");
	snprintf(list, sizeof(list),
		 "/bin/busybox %s\n/ss-functest %s\n/bin/tvok %s\n/bin/dpkg %s\n/bin/tvmod %s\n",
		 hb, hf, hb, hb, hb);
	tv_ready = wr(SECFS "timevault_allow", list) == 0;
	tap(tv_ready, "#13 allowlist (path + SHA-256) loaded before the lock");
}

static void t_timevault(void)
{
	static char buf[1 << 16];
	char v[64];
	unsigned long long d0 = 0, d1 = 0;
	char *ev;
	int r;

	if (!tv_ready) {
		tap(0, "#13 allowlist was loaded before the lock");
		return;
	}
	if (rd(KNOB "timevault_denied", v, sizeof(v)) == 0)
		d0 = strtoull(v, NULL, 10);
	(void)drain_events(buf, sizeof(buf));
	tv_engaged = knob_set("timevault", "1") == 0 && !strcmp(knob_get("timevault"), "1");
	tap(tv_engaged, "#13 the vault engages (on a locked box)");
	r = as(&NONSUDO, do_exec, "/bin/busybox");
	tv_busybox_ok = r == 0;
	tap(tv_busybox_ok, "#13 an allowlisted binary with a matching hash runs (got %d)", r);
	r = as(&NONSUDO, do_exec, "/bin/tvok");
	tap(r == 0, "#13 a second copy listed with the same hash runs (got %d)", r);
	r = as(&NONSUDO, do_exec, "/bin/tvbad");
	tap(DENIED(r), "#13 a binary not on the allowlist is denied (got %d)", r);
	r = as(&ROOT, do_exec, "/bin/tvbad");
	tap(DENIED(r), "#13 the vault applies to root too (got %d)", r);
	r = as(&ROOT, do_exec, "/bin/tvmod");
	tap(DENIED(r), "#13 a listed path whose bytes changed is denied (got %d)", r);
	r = as(&ROOT, do_exec, "/bin/dpkg");
	tap(DENIED(r), "#13 a package manager is denied even when listed with its hash (got %d)", r);
	r = as(&ROOT, do_memfd_exec, NULL);
	tap(DENIED(r), "#13 fileless memfd exec is denied for root (got %d)", r);
	r = do_open_wr("/bin/tvok");
	tap(r == EPERM, "#13 root cannot open an allowlisted binary for writing (got %d)", r);
	drain_events(buf, sizeof(buf));
	ev = find_event_with(buf, "time_vault", "\"object\":\"/bin/tvbad\"");
	tap(ev && strstr(ev, "\"reason\":\"not on allowlist\"") &&
	    strstr(ev, "\"decision\":\"deny\""),
	    "#13 the denial is logged with the path and reason (what secure-sudod quarantines by)");
	if (rd(KNOB "timevault_denied", v, sizeof(v)) == 0)
		d1 = strtoull(v, NULL, 10);
	tap(d1 >= d0 + 5, "#13 timevault_denied counts the denials (+%llu)", d1 - d0);
	tap(knob_set("timevault", "0") == -EPERM && !strcmp(knob_get("timevault"), "1"),
	    "#13 an engaged vault cannot be disengaged before reboot");
}

struct churn { int id; };
static int do_policy_churn(void *a)
{
	char buf[128];
	int i, err = 0;

	(void)a;
	for (i = 0; i < 300; i++) {
		snprintf(buf, sizeof(buf), "/bin/churn-%d\n/bin/churn-x%d\n", i, i);
		if (wr(SECFS "blacklist", buf))
			err++;
		if (rd(SECFS "blacklist", buf, sizeof(buf)) < 0)
			err++;
	}
	return err ? EIO : 0;
}

static void t_concurrency(void)
{
	pid_t kids[4];
	int i, st, bad = 0, r;

	for (i = 0; i < 4; i++) {
		kids[i] = fork();
		if (kids[i] == 0)
			_exit(do_policy_churn(NULL));
	}
	for (i = 0; i < 300; i++) {
		r = as(&NONSUDO, do_exec, "/bin/busybox");
		if (r)
			bad++;
	}
	for (i = 0; i < 4; i++)
		if (waitpid(kids[i], &st, 0) < 0 || !WIFEXITED(st) || WEXITSTATUS(st))
			bad++;
	tap(bad == 0, "concurrent blacklist rewrites + execs: no errors (%d bad)", bad);
	wr(SECFS "blacklist", "\n");
}

/*
 * P1-1 sustained throughput: one non-sudo process raises denials as fast as
 * it can while this process drains the ring. Every record raised in the
 * window must be either read or counted in events_dropped: none may vanish.
 * The rates are printed for the record; they depend on the machine.
 */
#define SS_BURST 20000
static void t_event_throughput(char *buf, size_t len)
{
	char v[64];
	unsigned long long seq0 = 0, seq1 = 0, drop0 = 0, drop1 = 0;
	unsigned long long lines = 0, bytes = 0, produced, dropped;
	unsigned long long split = 0, bad = 0;
	struct timespec t0, t1;
	int fd, done = 0, st;
	double secs;
	pid_t kid;

	(void)drain_events(buf, len);
	if (rd(KNOB "events_sequence", v, sizeof(v)) == 0)
		seq0 = strtoull(v, NULL, 10);
	if (rd(KNOB "events_dropped", v, sizeof(v)) == 0)
		drop0 = strtoull(v, NULL, 10);
	fd = open(SECFS "events", O_RDONLY | O_NONBLOCK);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	kid = fork();
	if (kid == 0) {
		int i;

		if (become(&NONSUDO))
			_exit(254);
		for (i = 0; i < SS_BURST; i++)
			if (do_perf(NULL) == 0)
				_exit(1);	/* must be denied every time */
		_exit(0);
	}
	while (fd >= 0 && kid > 0) {
		/* 4 KiB reads, like a daemon's: smaller than the ring, so the
		 * reader works on a ring that wraps under it */
		ssize_t n = read(fd, buf, 4096);

		if (n > 0) {
			char *l, *save;

			bytes += (unsigned long long)n;
			if (buf[n - 1] != '\n')
				split++;
			buf[n] = '\0';
			for (l = strtok_r(buf, "\n", &save); l;
			     l = strtok_r(NULL, "\n", &save)) {
				lines++;
				if (!line_is_event(l) && bad++ == 0)
					diag("not a whole record: '%.80s'", l);
			}
			continue;
		}
		if (done)
			break;		/* the producer has exited and the ring is empty */
		if (waitpid(kid, &st, WNOHANG) == kid)
			done = 1;
		else
			sched_yield();
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	if (fd >= 0)
		close(fd);
	if (rd(KNOB "events_sequence", v, sizeof(v)) == 0)
		seq1 = strtoull(v, NULL, 10);
	if (rd(KNOB "events_dropped", v, sizeof(v)) == 0)
		drop1 = strtoull(v, NULL, 10);
	produced = seq1 - seq0;
	dropped = drop1 - drop0;
	secs = (double)(t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
	tap(done && WIFEXITED(st) && WEXITSTATUS(st) == 0 && produced >= SS_BURST,
	    "#9 sustained burst: %d denials each raised a record (%llu)",
	    SS_BURST, produced);
	tap(split == 0 && bad == 0,
	    "#9 sustained burst: every read ends at a record boundary and every "
	    "line is a whole record (%llu split reads, %llu bad lines)", split, bad);
	tap(lines + dropped == produced,
	    "#9 sustained burst: every record was read or counted as dropped "
	    "(%llu read + %llu dropped = %llu raised)", lines, dropped, produced);
	diag("throughput: %llu records in %.3f s (%.0f/s); reader got %llu "
	     "(%.0f/s, %llu bytes, %llu avg) and %llu were dropped",
	     produced, secs, secs > 0 ? produced / secs : 0.0, lines,
	     secs > 0 ? lines / secs : 0.0, bytes, lines ? bytes / lines : 0,
	     dropped);
}

static void t_events(void)
{
	static char buf[1 << 18];
	size_t n;
	char *l, *save;
	int lines = 0, bad = 0, i, ordered = 1;
	char dropped[64], knobval[64], boot[40] = "";
	unsigned long long before_seq = 0, before_drop = 0, first_seq = 0;
	unsigned long long prev = 0, s;
	long long apid = 0, tpid = -1, tuid = -1;

	knob_set("perf_guard", "1");
	(void)drain_events(buf, sizeof(buf));
	as(&NONSUDO, do_perf, NULL);
	n = drain_events(buf, sizeof(buf));
	tap(n > 0 && strstr(buf, "perf: denied"), "#9 a denial produces an event line");
	tap(line_is_event(strtok(buf, "\n")),
	    "#9 event carries schema, boot, sequence, clocks, actor and typed fields");
	tap(strstr(buf, "\"event_type\":\"perf\"") &&
	    strstr(buf, "\"operation\":\"perf_event_open\"") &&
	    strstr(buf, "\"decision\":\"deny\"") &&
	    strstr(buf, "\"truncated\":false") &&
	    strstr(buf, "\"reason\":\"perf_guard\""),
	    "#9 producer supplies typed event classification and decision");
	/* P1-1: a denial of the calling task's own action names that task and
	 * its user as the typed target (no label-only targets). */
	tap(line_num(buf, "\"actor\":{\"pid\":", &apid) &&
	    line_num(buf, "\"target_pid\":", &tpid) &&
	    line_num(buf, "\"target_uid\":", &tuid) &&
	    apid > 0 && tpid == apid && tuid == USER,
	    "#9 a self-targeted denial carries typed target_pid/target_uid "
	    "(pid %lld, actor %lld, uid %lld)", tpid, apid, tuid);
	tap(strstr(buf, "\"kernel_started\":false}") != NULL,
	    "#9 an ordinary process is not marked kernel_started");

	knob_set("prguard_observe", "1");
	(void)drain_events(buf, sizeof(buf));
	(void)as(&NONSUDO, do_ptrace, (void *)SS_PT_ATTACH);
	n = drain_events(buf, sizeof(buf));
	tap(n > 0 && strstr(buf, "\"target_pid\":") &&
	    !strstr(buf, "\"target_pid\":null") &&
	    strstr(buf, "\"target_uid\":") &&
	    !strstr(buf, "\"target_uid\":null"),
	    "#9 cross-process memory events identify the target PID and UID");
	knob_set("prguard_observe", "0");

	/* P1-1: a path up to 256 bytes stays whole in the typed object field,
	 * so a consumer never has to take it from the message. */
	{
		static const char comp[] =
			"/a-directory-name-of-exactly-fifty-bytes-0123456789";
		char path[300] = "/srv", file[320];
		const char *kv[2] = { file, "x" };
		char want[340], *ev;
		int k, fd, r;

		mkdir(path, 0755);
		for (k = 0; k < 4; k++) {
			strcat(path, comp);
			mkdir(path, 0755);
		}
		snprintf(file, sizeof(file), "%s/target-file", path);
		fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (fd >= 0) {
			fchmod(fd, 0666);
			close(fd);
		}
		knob_set("block_home_write", "1");
		(void)drain_events(buf, sizeof(buf));
		r = as(&NONSUDO, do_write_file, kv);
		knob_set("block_home_write", "0");
		n = drain_events(buf, sizeof(buf));
		ev = n ? find_event(buf, "home_write") : NULL;
		snprintf(want, sizeof(want), "\"object\":\"%s\"", file);
		tap(DENIED(r) && ev && strstr(ev, want) &&
		    strstr(ev, "\"truncated\":false") && line_is_event(ev),
		    "#9 a %zu-byte path is whole in object, record not truncated "
		    "(write %d)", strlen(file), r);
		diag("record: %.200s", ev ? ev : "(none)");
		unlink(file);
		for (k = 0; k < 4; k++) {
			rmdir(path);
			*strrchr(path, '/') = '\0';
		}
		rmdir(path);
	}

	/* The audit feed (audit_events=1) gets its own copy of each record:
	 * the ring still gets every one, and the copy reaches the audit
	 * subsystem (printed to the kernel log, as no auditd runs here) or is
	 * counted in audit_events_dropped. */
	{
		unsigned long long a0 = 0, a1 = 0, got = 0;
		int k, seen = 0;
		char *l, *save;

		if (rd(KNOB "audit_events_dropped", knobval, sizeof(knobval)) == 0)
			a0 = strtoull(knobval, NULL, 10);
		(void)drain_events(buf, sizeof(buf));
		knob_set("audit_events", "1");
		for (k = 0; k < 20; k++)
			as(&NONSUDO, do_perf, NULL);
		knob_set("audit_events", "0");
		n = drain_events(buf, sizeof(buf));
		for (l = strtok_r(buf, "\n", &save); l; l = strtok_r(NULL, "\n", &save))
			got += line_is_event(l) && strstr(l, "\"event_type\":\"perf\"");
		tap(got == 20, "#9 audit feed on: 20 denials still give 20 ring records (%llu)",
		    got);
		for (k = 0; k < 20 && !seen; k++) {
			int len = klogctl(3 /* SYSLOG_ACTION_READ_ALL */, buf,
					  (int)sizeof(buf) - 1);

			if (len > 0) {
				buf[len] = '\0';
				seen = strstr(buf, "lsm=secure_sudo") != NULL;
			}
			if (!seen)
				usleep(100000);
		}
		if (rd(KNOB "audit_events_dropped", knobval, sizeof(knobval)) == 0)
			a1 = strtoull(knobval, NULL, 10);
		tap(seen || a1 > a0,
		    "#9 audit feed on: records reach the audit subsystem or are "
		    "counted (%s, %llu dropped)", seen ? "seen in kernel log" : "not seen",
		    a1 - a0);
	}

	/* P1-1 deferred work: a core-dump pipe handler is a process the kernel
	 * starts itself. Its denials must say so (kernel_started), not pass
	 * as the helper acting on its own. The handler is this program again
	 * (see main), writing a protected sysctl. */
	{
		char self[256], pattern[300], old_pattern[256] = "", *ev = NULL;
		const char *kv[2] = { "/proc/sys/kernel/core_pattern", pattern };
		const char *kv_old[2] = { "/proc/sys/kernel/core_pattern", old_pattern };
		ssize_t len = readlink("/proc/self/exe", self, sizeof(self) - 1);
		int k;

		if (len > 0) {
			self[len] = '\0';
			rd("/proc/sys/kernel/core_pattern", old_pattern,
			   sizeof(old_pattern));
			snprintf(pattern, sizeof(pattern), "|%s --core-helper", self);
		}
		if (len > 0 && do_write_file(kv) == 0) {
			pid_t kid;

			(void)drain_events(buf, sizeof(buf));
			knob_set("sysctl_guard", "1");
			kid = fork();
			if (kid == 0) {
				struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };

				setrlimit(RLIMIT_CORE, &rl);
				prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
				abort();
			}
			if (kid > 0)
				waitpid(kid, NULL, 0);
			/* the handler runs asynchronously: give it up to 5 s */
			for (k = 0; k < 50 && !ev; k++) {
				n = drain_events(buf, sizeof(buf));
				ev = n ? find_event(buf, "sysctl_guard") : NULL;
				if (!ev)
					usleep(100000);
			}
			knob_set("sysctl_guard", "0");
			if (old_pattern[0])
				do_write_file(kv_old);
			tap(ev && strstr(ev, "\"kernel_started\":true") &&
			    strstr(ev, "\"object\":\"/sys/kernel/kptr_restrict\"") &&
			    line_num(ev, "\"target_uid\":", &tuid) && tuid == 0,
			    "#9 a kernel-started helper's denial is marked kernel_started");
			diag("helper record: %.200s", ev ? ev : "(none)");
		} else {
			tap(1, "# SKIP core_pattern not settable (%s)", strerror(errno));
		}
	}

	/* Overflow the 64 KiB ring, then check that what the reader gets is
	 * still whole lines and that the loss is counted. */
	if (rd(KNOB "events_sequence", knobval, sizeof(knobval)) == 0)
		before_seq = strtoull(knobval, NULL, 10);
	if (rd(KNOB "events_dropped", dropped, sizeof(dropped)) == 0)
		before_drop = strtoull(dropped, NULL, 10);
	for (i = 0; i < 3000; i++)
		as(&NONSUDO, do_perf, NULL);
	n = drain_events(buf, sizeof(buf));
	for (l = strtok_r(buf, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
		const char *b = strstr(l, "\"boot_id\":\"");

		lines++;
		if (!line_is_event(l)) {
			if (bad++ == 0)
				diag("partial line after wrap: '%.60s'", l);
			continue;
		}
		s = line_seq(l);
		if (!first_seq)
			first_seq = s;
		if (prev && s != prev + 1)
			ordered = 0;
		prev = s;
		if (b && !boot[0])
			snprintf(boot, sizeof(boot), "%.32s", b + 11);
	}
	/* P1-1: numbers are given in ring order, so what survives is one
	 * contiguous run, and the records before it are exactly the dropped
	 * ones. */
	tap(ordered && lines > 0, "#9 surviving records have consecutive sequence numbers");
	if (rd(KNOB "events_dropped", dropped, sizeof(dropped)) == 0)
		tap(first_seq == before_seq + (strtoull(dropped, NULL, 10) - before_drop) + 1,
		    "#9 the sequence gap equals events_dropped (first %llu, before %llu)",
		    first_seq, before_seq);
	tap(rd(KNOB "events_sequence", knobval, sizeof(knobval)) == 0 &&
	    strtoull(knobval, NULL, 10) == prev,
	    "#9 events_sequence is the last record's sequence (%llu)", prev);
	tap(rd(KNOB "events_boot_id", knobval, sizeof(knobval)) == 0 &&
	    boot[0] && !strncmp(knobval, boot, 32),
	    "#9 events_boot_id matches the records' boot_id");
	diag("read %zu bytes / %d lines after overflow", n, lines);
	tap(n > 0 && n <= 64 * 1024, "#9 ring holds at most 64 KiB after overflow (%zu)", n);
	tap(lines > 0 && bad == 0, "#9 after wrap every line read is a whole event (%d partial)", bad);
	if (rd(KNOB "events_dropped", dropped, sizeof(dropped)) == 0)
		tap(strtoull(dropped, NULL, 10) > 0, "#9 events_dropped counts the loss (%s)", dropped);
	else
		tap(0, "#9 events_dropped counter exists");
	if (rd(KNOB "audit_events_dropped", dropped, sizeof(dropped)) == 0)
		tap(1, "#9 audit_events_dropped counter exists (%s)", dropped);
	else
		tap(0, "#9 audit_events_dropped counter exists");
	t_event_throughput(buf, sizeof(buf));
	knob_set("perf_guard", "0");
}


/* ------------------------------ G4 (#5) ---------------------------------- */
/* TPM character devices made with mknod: there is no TPM in the test VM, so
 * a permitted open fails with ENXIO (no chip behind the number) and a
 * refused one with EPERM, before the driver is reached. */
#define TPMRM_NODE "/dev/ss-tpmrm"
#define TPM0_NODE  "/dev/ss-tpm0"

static int do_tpm_open(void *a)
{
	int fd = open((const char *)a, O_RDWR);

	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

/* Open @a from /bin/tpmprobe, a copy of this program under another name. */
static int do_tpm_probe(void *a)
{
	pid_t pid = fork();
	int st;

	if (pid == 0) {
		char *argv[] = { "tpmprobe", "--tpm-open", a, NULL };
		char *envp[] = { NULL };

		execve("/bin/tpmprobe", argv, envp);
		_exit(errno & 0xff);
	}
	if (pid < 0 || waitpid(pid, &st, 0) < 0 || !WIFEXITED(st))
		return 255;
	return WEXITSTATUS(st);
}

static int tpm_major(void)
{
	FILE *f = fopen("/proc/devices", "r");
	char line[128], name[64];
	int maj, found = -1, chr = 0;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "Character devices:", 18))
			chr = 1;
		else if (!strncmp(line, "Block devices:", 14))
			chr = 0;
		else if (chr && sscanf(line, "%d %63s", &maj, name) == 2 &&
			 !strcmp(name, "tpm"))
			found = maj;
	}
	fclose(f);
	return found;
}

static int tpm_nodes;

static void t_tpm_prepare(void)
{
	char buf[1024];
	int maj = tpm_major(), r;

	tap(rd(SECFS "tpm_openers", buf, sizeof(buf)) == 0 &&
	    strstr(buf, "/usr/bin/systemd-creds\n"),
	    "G4 tpm_openers starts with the defaults (systemd-creds, ...)");
	tap(!strstr(buf, "systemd-pcrextend") && !strstr(buf, "tpm2-abrmd"),
	    "P2-1 the defaults leave out PCR extenders (systemd-pcrextend, tpm2-abrmd)");
	tap(maj > 0, "G4 the TPM driver core registered its major (%d)", maj);
	unlink(TPMRM_NODE);
	unlink(TPM0_NODE);
	/* tpmrm0 is minor TPM_NUM_DEVICES (65536) of the tpm major */
	tpm_nodes = maj > 0 &&
		    mknod(TPMRM_NODE, S_IFCHR | 0600, makedev(maj, 65536)) == 0 &&
		    mknod(TPM0_NODE, S_IFCHR | 0600, makedev(10, 224)) == 0;
	tap(tpm_nodes, "G4 TPM device nodes made with mknod");
	copy_file("/ss-functest", "/bin/tpmprobe", 0755);
	tap(wr(SECFS "tpm_openers", "# test\n/ss-functest\nnot-absolute\n") == 0,
	    "G4 tpm_openers set to /ss-functest (relative entries ignored)");
	tap(rd(SECFS "tpm_openers", buf, sizeof(buf)) == 0 &&
	    strstr(buf, "/ss-functest"), "G4 tpm_openers reads back");
	r = as(&ROOT, do_tpm_probe, TPMRM_NODE);
	tap(r == ENXIO || r == ENODEV || (r == 0 && !access("/sys/class/tpm/tpm0", F_OK)),
	    "G4 unlocked: any root program reaches the TPM driver (got %d)", r);
}

static void t_tpm_locked(void)
{
	int r;

	if (!tpm_nodes) {
		tap(0, "G4 locked TPM checks need the device nodes");
		return;
	}
	events_reset();
	r = as(&ROOT, do_tpm_probe, TPMRM_NODE);
	tap(r == EPERM, "G4 locked: root's unlisted program cannot open tpmrm (got %d)", r);
	r = as(&ROOT, do_tpm_probe, TPM0_NODE);
	tap(r == EPERM, "G4 locked: ... nor tpm0, misc 10:224 (got %d)", r);
	r = as(&ROOT, do_tpm_open, TPMRM_NODE);
	tap(r == ENXIO || r == ENODEV || (r == 0 && !access("/sys/class/tpm/tpm0", F_OK)),
	    "G4 locked: a program on tpm_openers still reaches the driver (got %d)", r);
	r = as(&NONSUDO, do_tpm_probe, TPMRM_NODE);
	tap(DENIED(r), "G4 locked: non-root unlisted program refused too (got %d)", r);
	tap(wr(SECFS "tpm_openers", "/bin/tpmprobe\n") == -EPERM,
	    "G4 locked: tpm_openers cannot be changed");
	r = as(&ROOT, do_tpm_probe, TPMRM_NODE);
	tap(r == EPERM, "G4 locked: ... so the probe stays refused (got %d)", r);
	tap(saw_deny("tpm_guard", "\"reason\":\"tpm_opener_not_allowed\""),
	    "G4 a refused TPM open is logged (tpm_guard / tpm_opener_not_allowed)");
	unlink(TPMRM_NODE);
	unlink(TPM0_NODE);
	unlink("/bin/tpmprobe");
}

/* ------------------------------------------- P2-1 policy measurement */

/* A small SHA-256 (FIPS 180-4) so the test can check the kernel's digests
 * and replay the PCR without linking a crypto library into a static binary. */
static const uint32_t sha_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_block(uint32_t h[8], const unsigned char *p)
{
	uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
		       (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	for (; i < 64; i++)
		w[i] = w[i - 16] + (ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3)) +
		       w[i - 7] + (ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10));
	a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
	for (i = 0; i < 64; i++) {
		t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + sha_k[i] + w[i];
		t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
		hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha256(const void *data, size_t len, unsigned char out[32])
{
	uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	const unsigned char *p = data;
	unsigned char blk[64];
	size_t i, rest = len % 64;
	uint64_t bits = (uint64_t)len * 8;

	for (i = 0; i + 64 <= len; i += 64)
		sha_block(h, p + i);
	memset(blk, 0, sizeof(blk));
	memcpy(blk, p + i, rest);
	blk[rest] = 0x80;
	if (rest >= 56) {
		sha_block(h, blk);
		memset(blk, 0, sizeof(blk));
	}
	for (i = 0; i < 8; i++)
		blk[63 - i] = (unsigned char)(bits >> (8 * i));
	sha_block(h, blk);
	for (i = 0; i < 32; i++)
		out[i] = (unsigned char)(h[i / 4] >> (24 - 8 * (i % 4)));
}

static void to_hex(const unsigned char *b, size_t n, char *out)
{
	size_t i;

	for (i = 0; i < n; i++)
		sprintf(out + 2 * i, "%02x", b[i]);
}

static int from_hex(const char *s, unsigned char *b, size_t n)
{
	size_t i;
	unsigned int v;

	for (i = 0; i < n; i++) {
		if (sscanf(s + 2 * i, "%2x", &v) != 1)
			return -1;
		b[i] = (unsigned char)v;
	}
	return 0;
}

#define PLOG SECFS "policy_log"
static char plog[1 << 18];

/* The whole log (seq_file hands it out a page at a time). */
static int plog_read(void)
{
	int fd = open(PLOG, O_RDONLY);
	size_t n = 0;
	ssize_t r;

	if (fd < 0)
		return -errno;
	while (n < sizeof(plog) - 1 && (r = read(fd, plog + n, sizeof(plog) - 1 - n)) > 0)
		n += (size_t)r;
	close(fd);
	plog[n] = '\0';
	return 0;
}

static unsigned int plog_hdr(const char *key)
{
	char k[32], *p, *nl = strchr(plog, '\n');

	snprintf(k, sizeof(k), " %s=", key);
	p = strstr(plog, k);
	return (p && (!nl || p < nl)) ? (unsigned int)strtoul(p + strlen(k), NULL, 10) : ~0u;
}

/* The event text of the entry @back from the end (0 = last), foreign
 * markers skipped; "" if there is none. Works on a copy of plog. */
static const char *plog_last(int back)
{
	static char copy[sizeof(plog)], t[256];
	char *line, *end;
	int f;

	memcpy(copy, plog, sizeof(copy));
	t[0] = '\0';
	end = copy + strlen(copy);
	while (end > copy) {
		if (end[-1] == '\n')
			*--end = '\0';
		line = strrchr(copy, '\n');
		line = line ? line + 1 : copy;
		if (line != copy && !strstr(line, "F 1 ")) {
			char *sp = line;

			for (f = 0; f < 3 && sp; f++)
				sp = strchr(sp + 1, ' ');
			if (sp && back-- == 0) {
				snprintf(t, sizeof(t), "%s", sp + 1);
				return t;
			}
		}
		end = line;
	}
	return t;
}

/* Wait for the worker to extend everything, then replay the log the way a
 * verifier does and compare with the TPM's own PCR (sysfs pcr-sha256). */
static void plog_replay_check(const char *when)
{
	unsigned char st[32] = { 0 }, dg[32], buf[64], seen[32];
	char path[64], pcr[80], *line, *save = NULL, calc[65];
	unsigned int i, bad = 0, foreign = 0, pcrn;

	if (access("/sys/class/tpm/tpm0", F_OK)) {
		diag("P2-1 no TPM in this guest: the PCR replay is not checked (%s)", when);
		return;
	}
	/* Each entry costs a PCR read and an extend; a burst of ~1300 policy
	 * writes (the tests above) takes a few seconds under KVM. Wait up to
	 * a minute, and report how long it took. */
	for (i = 0; i < 600; i++) {
		plog_read();
		if (plog_hdr("count") == plog_hdr("extended"))
			break;
		usleep(100000);
	}
	diag("P2-1 %s: %u entries extended after %u.%u s", when, plog_hdr("extended"),
	     i / 10, i % 10);
	tap(plog_hdr("count") == plog_hdr("extended"),
	    "P2-1 %s: the worker extended every entry (count=%u extended=%u tpm=%d)", when,
	    plog_hdr("count"), plog_hdr("extended"), (int)plog_hdr("tpm"));
	pcrn = plog_hdr("pcr");
	line = strchr(plog, '\n');
	for (line = line ? strtok_r(line + 1, "\n", &save) : NULL; line;
	     line = strtok_r(NULL, "\n", &save)) {
		char idx[16], ext[4], hex[65];
		int off = 0;

		if (sscanf(line, "%15s %3s %64s %n", idx, ext, hex, &off) != 3 || !off) {
			bad++;
			continue;
		}
		if (strcmp(ext, "1"))	/* not in the PCR yet: the verifier skips it too */
			continue;
		sha256(line + off, strlen(line + off), dg);
		to_hex(dg, 32, calc);
		if (strcmp(calc, hex) && bad++ < 3)
			diag("digest mismatch: %.200s", line);
		if (!strncmp(line + off, "foreign pcr ", 12)) {
			foreign++;
			if (from_hex(line + off + 12, seen, 32) == 0)
				memcpy(st, seen, 32);
		}
		memcpy(buf, st, 32);
		memcpy(buf + 32, dg, 32);
		sha256(buf, 64, st);
	}
	plog_read();
	snprintf(path, sizeof(path), "/sys/class/tpm/tpm0/pcr-sha256/%u", pcrn);
	tap(rd(path, pcr, sizeof(pcr)) == 0, "P2-1 %s: PCR %u readable", when, pcrn);
	to_hex(st, 32, calc);
	for (i = 0; pcr[i]; i++)
		pcr[i] = (char)tolower((unsigned char)pcr[i]);
	tap(!bad, "P2-1 %s: every log line's digest is sha256 of its text", when);
	tap(!strcmp(calc, pcr), "P2-1 %s: the log replays to the TPM's PCR %u", when, pcrn);
	if (strcmp(calc, pcr))
		diag("replay %s, PCR %s", calc, pcr);
	tap(!foreign, "P2-1 %s: nothing but the kernel extended PCR %u", when, pcrn);
}

static void t_measure(void)
{
	char want[160], blk[8192], old[16], hex[65];
	const char *kv_ram[] = { KNOB "max_ram_percent", "50" };
	unsigned char dg[32];
	unsigned int n;
	struct stat st;
	int r;

	tap(stat(PLOG, &st) == 0 && (st.st_mode & 0777) == 0400,
	    "P2-1 policy_log exists, root read-only");
	r = plog_read();
	tap(r == 0 && !strncmp(plog, "secure_sudo-policy-log v1 pcr=", 30),
	    "P2-1 policy_log has its header (%.70s)", plog);
	r = as(&NONSUDO, do_open_ro, PLOG);
	tap(r == EACCES || r == EPERM, "P2-1 a non-sudo user cannot read the log (got %d)", r);
	tap(strstr(plog, " list tpm_openers ") != NULL,
	    "P2-1 the boot-time tpm_openers defaults are measured");
	if (!strstr(plog, " list tpm_openers "))
		diag("policy_log: %.400s", plog);

	snprintf(old, sizeof(old), "%s", knob_get("max_ram_percent"));
	tap(knob_set("max_ram_percent", "77") == 0, "P2-1 set max_ram_percent 77");
	plog_read();
	tap(!strcmp(plog_last(0), "knob max_ram_percent 77"),
	    "P2-1 a knob write is measured (last: %s)", plog_last(0));
	n = plog_hdr("count");
	knob_set("max_ram_percent", "77");
	plog_read();
	tap(plog_hdr("count") == n, "P2-1 the same value again adds nothing");
	r = as(&NONSUDO, do_write_file, kv_ram);
	plog_read();
	tap(r != 0 && plog_hdr("count") == n, "P2-1 a refused write is not measured (got %d)", r);
	knob_set("max_ram_percent", old);

	tap(rd(SECFS "blacklist", blk, sizeof(blk) - 64) == 0, "P2-1 read the blacklist");
	strcat(blk, "\n# measured\n");
	tap(wr(SECFS "blacklist", blk) == 0, "P2-1 rewrite the blacklist");
	sha256(blk, strlen(blk), dg);
	to_hex(dg, 32, hex);
	snprintf(want, sizeof(want), "list blacklist %s", hex);
	plog_read();
	tap(!strcmp(plog_last(0), want),
	    "P2-1 a list write is measured as the sha256 of the text the kernel kept");
	plog_replay_check("before the lock");
}

static void t_measure_locked(void)
{
	plog_read();
	tap(!strcmp(plog_last(0), "lock lock_command 1") && !strcmp(plog_last(1), "knob lock 1"),
	    "P2-1 locking is measured: knob lock 1, then the lock (last: %s)", plog_last(0));
	plog_replay_check("after the lock");
}

static void t_lock(void)
{
	int r;

	tap(knob_set("lock", "0") == 0 || 1, "lock=0 before latching is harmless");
	tap(knob_set("lock", "1") == 0, "#16 lock=1 latches");
	tap(!strcmp(knob_get("lock"), "1"), "#16 lock reads 1");
	tap(knob_set("lock", "0") == -EPERM, "#16 lock cannot be cleared");
	tap(knob_set("block_setid", "0") == -EPERM, "#16 boolean knobs refuse writes when locked");
	tap(knob_set("admin_gid", "1") == -EPERM, "#16 admin_gid refuses writes when locked");
	tap(knob_set("max_ram_percent", "50") == -EPERM, "#16 numeric knobs refuse writes when locked");
	tap(wr(SECFS "blacklist", "/bin/x\n") == -EPERM, "#16 policy lists refuse writes when locked");
	tap(!strcmp(knob_get("block_setid"), "1"), "#16 enforcement stayed on");
	r = load_finit();
	tap(r == EPERM, "#16 locked + lock_modules: finit_module refused (got %d)", r);
	r = load_init();
	tap(r == EPERM, "#16 locked + lock_modules: init_module refused (got %d)", r);
	r = as(&ROOT, do_bpf_prog, (void *)(uintptr_t)BPF_PROG_TYPE_TRACEPOINT);
	tap(r == EPERM, "#22 locked: tracing BPF program refused for root (got %d)", r);
	r = as(&ROOT, do_bpf_prog, (void *)(uintptr_t)BPF_PROG_TYPE_SOCKET_FILTER);
	tap(r == 0, "#22 locked: socket-filter BPF program still allowed (got %d)", r);
	r = as(&NONSUDO, do_exec, "/bin/busybox");
	tap(r == 0, "#16 normal exec still works after locking (got %d)", r);
}

int main(int argc, char **argv)
{
	struct utsname u;
	char mods[300];

	/* Run by the kernel as a core-dump pipe handler (t_events): try one
	 * protected sysctl write, so secure_sudo logs a denial from a process
	 * the kernel started, then let the core go unread. */
	if (argc > 1 && !strcmp(argv[1], "--core-helper"))
		return wr("/proc/sys/kernel/kptr_restrict", "2") ? 0 : 1;
	/* Run as /bin/tpmprobe (t_tpm): a program that is not on tpm_openers
	 * opening a TPM device; exits with the errno (0 if it opened). */
	if (argc > 2 && !strcmp(argv[1], "--tpm-open"))
		return do_tpm_open(argv[2]);
	setvbuf(stdout, NULL, _IOLBF, 0);
	uname(&u);
	diag("ss-functest on %s %s", u.sysname, u.release);
	snprintf(mods, sizeof(mods), "/lib/modules/%s", u.release);
	find_module(mods, "test_module.ko", modpath, sizeof(modpath), 0);
	find_module(mods, "mac80211_hwsim.ko", hwsimpath, sizeof(hwsimpath), 0);
	if (modpath[0])
		diag("test module: %s", modpath);

	t_registration();
	t_defaults();
	t_knob_access();
	t_creds();
	t_setid_exec();
	t_blacklist();
	t_tmpexec();
	t_firmware();
	t_net();
	t_perf_bpf();
	t_sysctl();
	t_prguard();
	t_modules();
	t_home();
	t_ram();
	t_cooldown();
	t_node();
	t_binvault();
	t_radio();
	t_concurrency();
	t_events();
	t_measure();		/* P2-1: before the lock */
	t_timevault_prepare();	/* the allowlist must be in before the lock */
	t_tpm_prepare();	/* tpm_openers, likewise */
	t_lock();		/* irreversible from here on */
	t_tpm_locked();
	t_measure_locked();
	t_timevault();		/* engages TimeVault: keep last */

	printf("1..%d\n", n_test);
	printf("SS_FUNCTEST_DONE pass=%d fail=%d\n", n_test - n_fail, n_fail);
	fflush(stdout);
	if (tv_engaged && !tv_busybox_ok) {
		/* The init script could not run dmesg or poweroff: stop here
		 * rather than leave the guest to the boot-test timeout. */
		diag("TimeVault blocks /bin/busybox; powering off from ss-functest");
		sync();
		reboot(RB_POWER_OFF);
	}
	return n_fail ? 1 : 0;
}
