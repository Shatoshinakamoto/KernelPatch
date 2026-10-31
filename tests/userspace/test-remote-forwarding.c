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

static void queue_clear(void)
{
	DIR *d = opendir(REMOTE_QUEUE);
	struct dirent *de;
	char path[512];

	if (!d)
		return;
	while ((de = readdir(d)))
		if (!strncmp(de->d_name, "event-", 6)) {
			snprintf(path, sizeof(path), "%s/%s", REMOTE_QUEUE,
				 de->d_name);
			unlink(path);
		}
	closedir(d);
	remote_queue_known = 0;
}

/* Several queued events go out over ONE connection, oldest first. */
static int queue_batch(const char *host, const char *port, const char *ca)
{
	struct cfg cfg = { .remote_queue_max_mb = 1 };
	static const char *ev[] = { "batch-event-1", "batch-event-2",
				    "batch-event-3" };
	unsigned i;

	if (geteuid() != 0)
		return 77;
	strcpy(cfg.remote_transport, "tls");
	snprintf(cfg.remote_syslog, sizeof(cfg.remote_syslog), "%s:%s",
		 host, port);
	snprintf(cfg.remote_ca_file, sizeof(cfg.remote_ca_file), "%s", ca);
	if (remote_queue_dir() != 0)
		return 1;
	queue_clear();
	for (i = 0; i < 3; i++)
		if (remote_queue_event(&cfg, ev[i], strlen(ev[i])) != 0)
			return 1;
	return flush_remote_queue(&cfg) == 0 && remote_queue_records == 0 &&
	       remote_sent == 3 ? 0 : 1;
}

/*
 * An event only queues (no connection attempt inline), and a failing
 * collector is retried after 5 s, then 10 s, ... rather than per event.
 */
static int queue_backoff(void)
{
	struct cfg cfg = { .remote_queue_max_mb = 1 };

	if (geteuid() != 0)
		return 77;
	strcpy(cfg.remote_transport, "tls");
	snprintf(cfg.remote_syslog, sizeof(cfg.remote_syslog), "127.0.0.1:1");
	snprintf(cfg.remote_ca_file, sizeof(cfg.remote_ca_file), "/missing/ca.pem");
	if (remote_queue_dir() != 0)
		return 1;
	queue_clear();
	forward_remote(&cfg, "backoff-1", 9);
	if (remote_failures != 0 || remote_queue_records != 1 ||
	    remote_next_flush != 0)
		return 1;
	maybe_flush_remote(&cfg, 1000);		/* refused: back off 5 s */
	if (remote_failures != 1 || remote_backoff != 5 ||
	    remote_next_flush != 1005)
		return 1;
	forward_remote(&cfg, "backoff-2", 9);	/* no retry while backing off */
	maybe_flush_remote(&cfg, 1004);
	if (remote_failures != 1 || remote_next_flush != 1005 ||
	    remote_queue_records != 2)
		return 1;
	maybe_flush_remote(&cfg, 1005);		/* retry, then 10 s */
	if (remote_failures != 2 || remote_backoff != 10 ||
	    remote_next_flush != 1015 || remote_queue_records != 2 ||
	    strcmp(remote_state, "tls_queued"))
		return 1;
	queue_clear();
	return 0;
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
	if (argc == 5 && !strcmp(argv[1], "queue-batch"))
		return queue_batch(argv[2], argv[3], argv[4]);
	if (argc == 2 && !strcmp(argv[1], "queue-backoff"))
		return queue_backoff();
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
