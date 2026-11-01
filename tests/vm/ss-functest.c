// SPDX-License-Identifier: GPL-2.0
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
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <grp.h>
#include <dirent.h>

#define KNOB  "/sys/kernel/secure_sudo/"
#define SECFS "/sys/kernel/security/secure_sudo/"
#define USER  1000
#define ADMIN_GID 27

static int n_test, n_fail;
static char modpath[512];

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
	out = open(to, O_WRONLY | O_CREAT | O_TRUNC, mode);
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

static int load_finit(void)
{
	int fd = open(modpath, O_RDONLY | O_CLOEXEC), r = 0;

	if (fd < 0)
		return errno;
	if (syscall(SYS_finit_module, fd, "", 0))
		r = errno;
	close(fd);
	if (!r)
		syscall(SYS_delete_module, "test_module", O_NONBLOCK);
	return r;
}

static int load_init(void)
{
	struct stat st;
	int fd = open(modpath, O_RDONLY | O_CLOEXEC), r = 0;
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
		syscall(SYS_delete_module, "test_module", O_NONBLOCK);
	return r;
}

static int find_module(const char *dir, int depth)
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
		if (!strcmp(e->d_name, "test_module.ko")) {
			snprintf(modpath, sizeof(modpath), "%s", p);
			found = 1;
		} else if (e->d_type == DT_DIR) {
			found = find_module(p, depth + 1);
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
		{ "admin_gid", "unset" },
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
	tap(wr(SECFS "blacklist", "/bin/bltest\n") == 0, "#2 blacklist /bin/bltest");
	r = as(&NONSUDO, do_exec, "/bin/bltest");
	tap(DENIED(r), "#2 non-sudo exec of a blacklisted binary denied (got %d)", r);
	r = as(&NONSUDO, do_exec, "/bin/busybox");
	tap(r == 0, "#2 other binaries still run (got %d)", r);
	if (link("/bin/bltest", "/bin/bltest-link") == 0) {
		r = as(&NONSUDO, do_exec, "/bin/bltest-link");
		tap(DENIED(r), "#2 a hard link to the blacklisted inode is denied too (got %d)", r);
	} else {
		tap(0, "#2 create a hard link for the inode test (%s)", strerror(errno));
	}
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
	r = as(&NONSUDO, do_exec, "/tmp/bb");
	tap(DENIED(r), "#12 non-sudo exec from /tmp denied (got %d)", r);
	r = as(&NONSUDO, do_mmap_exec, "/tmp/bb");
	tap(DENIED(r), "#12 non-sudo PROT_EXEC mmap of a /tmp file denied (got %d)", r);
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
	r = as(&rawio, do_open_ro, "/dev/mem");
	tap(DENIED(r), "#3 non-sudo open of /dev/mem denied despite mode 0666 + CAP_SYS_RAWIO (got %d)", r);
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
	r = as(&rawcap, do_packet_socket, NULL);
	tap(r == EPERM, "#10 host mode: packet socket denied (got %d)", r);
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
	knob_set("perf_guard", "0");
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
	setvbuf(stdout, NULL, _IOLBF, 0);
	uname(&u);
	diag("ss-functest on %s %s", u.sysname, u.release);
	snprintf(mods, sizeof(mods), "/lib/modules/%s", u.release);
	find_module(mods, 0);
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
	t_concurrency();
	t_events();
	t_lock();		/* irreversible: keep last */

	printf("1..%d\n", n_test);
	printf("SS_FUNCTEST_DONE pass=%d fail=%d\n", n_test - n_fail, n_fail);
	fflush(stdout);
	return n_fail ? 1 : 0;
}
