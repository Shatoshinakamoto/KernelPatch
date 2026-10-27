// SPDX-License-Identifier: GPL-2.0
#define main secure_sudod_entrypoint
#include "../../userspace/daemon/secure-sudod.c"
#undef main

static int queue_test(void)
{
	struct cfg cfg = { .remote_queue_max_mb = 1 };
	char path[512];
	int fd;

	if (geteuid() != 0)
		return 77;
	strcpy(cfg.remote_transport, "tls");
	if (remote_queue_dir() != 0)
		return 1;
	snprintf(path, sizeof(path), "%s/event-00000000000000000000-00000000.msg",
		 REMOTE_QUEUE);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0 || ftruncate(fd, 1024 * 1024) != 0)
		return 1;
	close(fd);
	if (remote_queue_event(&cfg, "overflow", 8) == 0 ||
	    strcmp(remote_state, "queue_full") || remote_queue_dropped != 1)
		return 1;
	if (unlink(path) != 0 ||
	    remote_queue_event(&cfg, "queued-event", 12) != 0 ||
	    remote_queue_records != 1)
		return 1;
	snprintf(cfg.remote_syslog, sizeof(cfg.remote_syslog), "127.0.0.1:1");
	snprintf(cfg.remote_ca_file, sizeof(cfg.remote_ca_file), "/missing/ca.pem");
	flush_remote_queue(&cfg);
	return remote_queue_records == 1 &&
	       !strcmp(remote_state, "tls_queued") && remote_failures > 0 ? 0 : 1;
}

static int queue_verify(void)
{
	if (geteuid() != 0)
		return 77;
	return remote_queue_stats() == 0 && remote_queue_records == 1 ? 0 : 1;
}

static int queue_deliver(const char *host, const char *port, const char *ca)
{
	struct cfg cfg = { .remote_queue_max_mb = 1 };

	strcpy(cfg.remote_transport, "tls");
	snprintf(cfg.remote_syslog, sizeof(cfg.remote_syslog), "%s:%s",
		 host, port);
	snprintf(cfg.remote_ca_file, sizeof(cfg.remote_ca_file), "%s", ca);
	if (remote_queue_event(&cfg, "queue-delivery-test",
			       sizeof("queue-delivery-test") - 1) != 0)
		return 1;
	flush_remote_queue(&cfg);
	return remote_queue_records == 0 && remote_sent == 1 &&
	       !strcmp(remote_state, "tls_idle") ? 0 : 1;
}

int main(int argc, char **argv)
{
	struct cfg cfg = { .remote_queue_max_mb = 1 };

	strcpy(cfg.remote_transport, "tls");

	if (argc == 2 && !strcmp(argv[1], "queue"))
		return queue_test();
	if (argc == 2 && !strcmp(argv[1], "queue-verify"))
		return queue_verify();
	if (argc == 5 && !strcmp(argv[1], "queue-deliver"))
		return queue_deliver(argv[2], argv[3], argv[4]);
	if (argc == 5 && (!strcmp(argv[1], "send") ||
			  !strcmp(argv[1], "reject"))) {
		snprintf(cfg.remote_syslog, sizeof(cfg.remote_syslog), "%s:%s",
			 argv[2], argv[3]);
		snprintf(cfg.remote_ca_file, sizeof(cfg.remote_ca_file), "%s",
			 argv[4]);
		if (!strcmp(argv[1], "send"))
			return send_remote(&cfg, "forwarding-test", 15) ? 0 : 1;
		return send_remote(&cfg, "must-not-deliver", 16) ? 1 : 0;
	}
	fprintf(stderr, "invalid forwarding test arguments\n");
	return 2;
}
