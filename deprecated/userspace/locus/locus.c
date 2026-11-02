// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
/*
 * secure-sudo-locus - Locus (runtime guard): the location allocator.
 *
 * The guards (ProcGuard, DriverGuard, BootGuard) store compressed quarantine /
 * backups in directories that ROTATE EVERY HOUR. To stop two components from
 * racing on the same rotated path, Locus is the single authority that hands out
 * locations. It does exactly ONE thing and nothing more:
 *
 *   - an ALLOCATOR socket (the LAN request point): a client sends
 *         ALLOC <purpose>\n
 *     and Locus replies
 *         OK <absolute-path>\n
 *     naming the current hour's directory under the root configured for that
 *     purpose (created 0700). It never reads, writes, lists, or deletes files,
 *     never runs anything, and only ever emits paths under its configured
 *     roots. This tiny, fixed protocol is the whole attack surface.
 *
 *   - a read-only GUI (HTTP): serves one page that DISPLAYS the configured
 *     roots and each purpose's current location. GET only; no inputs, no file
 *     serving, no path parameters - so the display cannot be turned into a way
 *     to read the disk.
 *
 * Both listeners bind to configurable addresses (see locus.conf): put the
 * allocator on a LAN address if other hosts need locations; keep the GUI on
 * localhost unless you deliberately expose it. Configure the main root
 * directories per purpose in the same file.
 *
 * Config: /etc/secure_sudo/addons/locus.conf
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>

#include "ssaddon_log.h"
#include "ssaddon_store.h"

#define CONF		"/etc/secure_sudo/addons/locus.conf"
#define MAX_ROOTS	32

struct root_map {
	char purpose[64];
	char path[PATH_MAX];
};

static struct {
	char alloc_bind[64];
	char alloc_port[16];
	char gui_bind[64];
	char gui_port[16];
	char default_root[PATH_MAX];
	struct root_map roots[MAX_ROOTS];
	int nroots;
} C;

static void trim(char *s)
{
	size_t n = strlen(s);
	while (n && isspace((unsigned char)s[n - 1]))
		s[--n] = '\0';
}

static void load_cfg(void)
{
	FILE *f;
	char line[PATH_MAX + 128];

	snprintf(C.alloc_bind, sizeof(C.alloc_bind), "127.0.0.1");
	snprintf(C.alloc_port, sizeof(C.alloc_port), "8787");
	snprintf(C.gui_bind, sizeof(C.gui_bind), "127.0.0.1");
	snprintf(C.gui_port, sizeof(C.gui_port), "8788");
	C.default_root[0] = '\0';
	C.nroots = 0;

	f = fopen(CONF, "re");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char *eq, *k, *v;

		trim(line);
		if (line[0] == '#' || line[0] == '\0')
			continue;
		/* "root <purpose> = <path>" */
		if (!strncmp(line, "root ", 5) && C.nroots < MAX_ROOTS) {
			char *sp = line + 5, *e = strchr(sp, '=');

			if (!e)
				continue;
			*e = '\0';
			trim(sp);
			v = e + 1;
			while (*v == ' ' || *v == '\t') v++;
			snprintf(C.roots[C.nroots].purpose,
				 sizeof(C.roots[C.nroots].purpose), "%.63s", sp);
			snprintf(C.roots[C.nroots].path,
				 sizeof(C.roots[C.nroots].path), "%s", v);
			C.nroots++;
			continue;
		}
		eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = '\0';
		k = line; v = eq + 1;
		while (*k == ' ' || *k == '\t') k++;
		trim(k);
		while (*v == ' ' || *v == '\t') v++;
		if (!strcmp(k, "alloc_bind")) snprintf(C.alloc_bind, sizeof(C.alloc_bind), "%s", v);
		else if (!strcmp(k, "alloc_port")) snprintf(C.alloc_port, sizeof(C.alloc_port), "%s", v);
		else if (!strcmp(k, "gui_bind")) snprintf(C.gui_bind, sizeof(C.gui_bind), "%s", v);
		else if (!strcmp(k, "gui_port")) snprintf(C.gui_port, sizeof(C.gui_port), "%s", v);
		else if (!strcmp(k, "default_root")) snprintf(C.default_root, sizeof(C.default_root), "%s", v);
	}
	fclose(f);
}

static const char *root_for(const char *purpose)
{
	int i;

	for (i = 0; i < C.nroots; i++)
		if (!strcmp(C.roots[i].purpose, purpose))
			return C.roots[i].path;
	return C.default_root[0] ? C.default_root : NULL;
}

/* A purpose must be a short token: letters, digits, '-'. Anything else is
 * rejected, so the protocol cannot be coaxed into naming an arbitrary path. */
static int valid_purpose(const char *p)
{
	size_t i, n = strlen(p);

	if (n == 0 || n >= 64)
		return 0;
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)p[i]) && p[i] != '-')
			return 0;
	return 1;
}

static int listen_on(const char *addr, const char *port)
{
	struct addrinfo hints, *res, *rp;
	int fd = -1, yes = 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo(addr, port, &hints, &res) != 0)
		return -1;
	for (rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC,
			    rp->ai_protocol);
		if (fd < 0)
			continue;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen(fd, 16) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

/* ---- allocator ---- */
static void handle_alloc(int cfd)
{
	char buf[256], purpose[64], bucket[PATH_MAX], resp[PATH_MAX + 16];
	const char *root;
	ssize_t r;

	r = recv(cfd, buf, sizeof(buf) - 1, 0);
	if (r <= 0)
		return;
	buf[r] = '\0';
	trim(buf);

	if (!strcmp(buf, "PING")) {
		send(cfd, "PONG\n", 5, MSG_NOSIGNAL);
		return;
	}
	if (strncmp(buf, "ALLOC ", 6) != 0) {
		send(cfd, "ERR bad request\n", 16, MSG_NOSIGNAL);
		return;
	}
	snprintf(purpose, sizeof(purpose), "%.63s", buf + 6);
	trim(purpose);
	if (!valid_purpose(purpose)) {
		send(cfd, "ERR bad purpose\n", 16, MSG_NOSIGNAL);
		ssl_warn("alloc rejected: bad purpose");
		return;
	}
	root = root_for(purpose);
	if (!root) {
		send(cfd, "ERR no root for purpose\n", 24, MSG_NOSIGNAL);
		ssl_warn("alloc rejected: no root for '%s'", purpose);
		return;
	}
	if (store_current_bucket(root, bucket, sizeof(bucket)) != 0) {
		send(cfd, "ERR cannot create bucket\n", 25, MSG_NOSIGNAL);
		ssl_err("alloc failed: cannot create bucket under %s", root);
		return;
	}
	snprintf(resp, sizeof(resp), "OK %s\n", bucket);
	send(cfd, resp, strlen(resp), MSG_NOSIGNAL);
	ssl_info("alloc %s -> %s", purpose, bucket);
}

/* ---- GUI (read-only HTTP) ---- */
static void handle_gui(int cfd)
{
	char req[1024], body[8192], hdr[256];
	size_t bo = 0;
	ssize_t r;
	int i;

	r = recv(cfd, req, sizeof(req) - 1, 0);
	if (r <= 0)
		return;
	req[r] = '\0';

	/* Only GET is honoured; no path is interpreted as a filesystem path, so
	 * the GUI can never be used to read a file. */
	if (strncmp(req, "GET ", 4) != 0) {
		const char *m = "HTTP/1.1 405 Method Not Allowed\r\n"
				"Content-Length: 0\r\nConnection: close\r\n\r\n";
		send(cfd, m, strlen(m), MSG_NOSIGNAL);
		return;
	}

	bo += snprintf(body + bo, sizeof(body) - bo,
"<!doctype html><html><head><meta charset=utf-8>"
"<meta name=viewport content='width=device-width,initial-scale=1'>"
"<title>secure_sudo Locus</title><style>"
"body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}"
"header{padding:16px 20px;background:#1a2330;border-bottom:1px solid #2a3647}"
"h1{margin:0;font-size:17px}main{padding:20px;max-width:900px}"
"table{border-collapse:collapse;width:100%%;margin-top:8px}"
"th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3647;"
"font-family:ui-monospace,monospace;font-size:13px}"
"th{color:#8bb4e0}.note{color:#9aa7b5;font-size:12px;margin-top:16px}"
"code{background:#1a2330;padding:1px 5px;border-radius:4px}</style></head><body>"
"<header><h1>secure_sudo &middot; Locus location allocator</h1></header><main>"
"<p>Read-only view of the rotating storage locations this allocator hands out. "
"The current location for each purpose is this hour's bucket under its root.</p>"
"<table><tr><th>Purpose</th><th>Configured root</th><th>Current location (this hour)</th></tr>");

	for (i = 0; i < C.nroots && bo < sizeof(body) - 1024; i++) {
		char bucket[PATH_MAX];

		if (store_current_bucket(C.roots[i].path, bucket, sizeof(bucket)) != 0)
			snprintf(bucket, sizeof(bucket), "(unavailable)");
		bo += snprintf(body + bo, sizeof(body) - bo,
			"<tr><td>%s</td><td>%s</td><td>%s</td></tr>",
			C.roots[i].purpose, C.roots[i].path, bucket);
	}
	bo += snprintf(body + bo, sizeof(body) - bo,
		"</table><p class=note>Default root for unlisted purposes: <code>%s</code>. "
		"Allocator request point: <code>%s:%s</code> (protocol: "
		"<code>ALLOC &lt;purpose&gt;</code> &rarr; <code>OK &lt;path&gt;</code>). "
		"This page is display-only.</p></main></body></html>",
		C.default_root[0] ? C.default_root : "(none)", C.alloc_bind, C.alloc_port);

	snprintf(hdr, sizeof(hdr),
		"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
		"Content-Length: %zu\r\nConnection: close\r\n"
		"X-Content-Type-Options: nosniff\r\n\r\n", bo);
	send(cfd, hdr, strlen(hdr), MSG_NOSIGNAL);
	send(cfd, body, bo, MSG_NOSIGNAL);
}

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static int run_serve(void)
{
	int afd, gfd;
	struct pollfd pfd[2];

	load_cfg();
	afd = listen_on(C.alloc_bind, C.alloc_port);
	gfd = listen_on(C.gui_bind, C.gui_port);
	if (afd < 0 && gfd < 0) {
		ssl_err("could not bind allocator (%s:%s) or GUI (%s:%s)",
			C.alloc_bind, C.alloc_port, C.gui_bind, C.gui_port);
		fprintf(stderr, "locus: could not bind any listener\n");
		return 1;
	}
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	signal(SIGPIPE, SIG_IGN);
	ssl_info("locus serving: allocator %s:%s, GUI %s:%s, %d root(s)",
		 C.alloc_bind, C.alloc_port, C.gui_bind, C.gui_port, C.nroots);

	while (!stop) {
		int n = 0;

		if (afd >= 0) { pfd[n].fd = afd; pfd[n].events = POLLIN; n++; }
		if (gfd >= 0) { pfd[n].fd = gfd; pfd[n].events = POLLIN; n++; }
		if (poll(pfd, n, 1000) <= 0)
			continue;
		for (int i = 0; i < n; i++) {
			if (!(pfd[i].revents & POLLIN))
				continue;
			int cfd = accept(pfd[i].fd, NULL, NULL);
			if (cfd < 0)
				continue;
			if (pfd[i].fd == afd)
				handle_alloc(cfd);
			else
				handle_gui(cfd);
			close(cfd);
		}
	}
	ssl_info("locus stopping");
	if (afd >= 0) close(afd);
	if (gfd >= 0) close(gfd);
	return 0;
}

static int cmd_status(void)
{
	int i;

	load_cfg();
	printf("Locus\n");
	printf("allocator bind:  %s:%s  (ALLOC <purpose> -> OK <path>)\n",
	       C.alloc_bind, C.alloc_port);
	printf("GUI bind:        %s:%s  (read-only HTTP)\n", C.gui_bind, C.gui_port);
	printf("default root:    %s\n", C.default_root[0] ? C.default_root : "(none)");
	printf("roots (%d):\n", C.nroots);
	for (i = 0; i < C.nroots; i++)
		printf("  %-28s %s\n", C.roots[i].purpose, C.roots[i].path);
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
"usage: secure-sudo-locus <serve|status>\n"
"  serve    run the allocator + read-only GUI listeners\n"
"  status   show the configured binds and roots\n"
"\nConfig: " CONF "\n");
}

int main(int argc, char **argv)
{
	if (geteuid() != 0) {
		fprintf(stderr, "locus: must run as root\n");
		return 1;
	}
	if (argc < 2) {
		usage();
		return 2;
	}
	ssl_init("locus");

	if (!strcmp(argv[1], "serve"))
		return run_serve();
	if (!strcmp(argv[1], "status"))
		return cmd_status();

	usage();
	ssl_close();
	return 2;
}
