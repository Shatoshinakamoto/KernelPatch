// SPDX-License-Identifier: GPL-2.0
/*
 * test-daemon-events.c - how secure-sudod reads kernel events and acts on
 * them (cooldown kill, TimeVault quarantine/wipe). Built by
 * test-daemon-events.sh with LOGDIR, QUARANTINE and HELPER_QUAR pointed
 * into a scratch directory; prints TAP lines.
 */
#define main secure_sudod_entrypoint
#include "../../userspace/daemon/secure-sudod.c"
#undef main

static int n_test, n_fail;

static void tap(int pass, const char *what)
{
	printf("%s %d - %s\n", pass ? "ok" : "not ok", ++n_test, what);
	if (!pass)
		n_fail++;
}

/* A record in exactly the layout ss_log.c writes. */
static void rec(char *out, size_t n, const char *type, const char *op,
		const char *object, const char *decision, const char *reason,
		const char *target_uid, const char *message, const char *trunc)
{
	snprintf(out, n,
		 "{\"schema_version\":1,\"boot_id\":\"0123456789abcdef0123456789abcdef\","
		 "\"sequence\":7,\"realtime_ns\":1761000000000000000,"
		 "\"monotonic_ns\":12345,\"event_type\":\"%s\","
		 "\"actor\":{\"pid\":42,\"uid\":1000},\"target\":\"user\","
		 "\"operation\":\"%s\",\"object\":\"%s\",\"decision\":\"%s\","
		 "\"reason\":\"%s\",\"target_pid\":null,\"target_uid\":%s,"
		 "\"message\":\"%s\",\"truncated\":%s}",
		 type, op, object, decision, reason, target_uid, message, trunc);
}

static int exists(const char *p)
{
	struct stat st;

	return lstat(p, &st) == 0;
}

static int write_file(const char *p, const char *s)
{
	FILE *f = fopen(p, "we");

	if (!f)
		return -1;
	fputs(s, f);
	return fclose(f);
}

static int count_archives(void)
{
	DIR *d = opendir(QUARANTINE);
	struct dirent *de;
	int n = 0;

	if (!d)
		return -1;
	while ((de = readdir(d))) {
		size_t l = strlen(de->d_name);

		if ((l > 4 && !strcmp(de->d_name + l - 4, ".zip")) ||
		    (l > 7 && !strcmp(de->d_name + l - 7, ".tar.gz")))
			n++;
	}
	closedir(d);
	return n;
}

static int incoming_empty(void)
{
	DIR *d = opendir(QUARANTINE "/.incoming");
	struct dirent *de;
	int n = 0;

	if (!d)
		return 1;
	while ((de = readdir(d)))
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, ".."))
			n++;
	closedir(d);
	return n == 0;
}

static int log_has(const char *needle)
{
	char path[512], line[4096];
	FILE *f;
	int n = 0;

	todays_logpath(path, sizeof(path));
	f = fopen(path, "re");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\n")] = '\0';
		if (!strcmp(line, needle))
			n++;
	}
	fclose(f);
	return n;
}

static int log_contains(const char *needle)
{
	char path[512], line[4096];
	FILE *f;
	int n = 0;

	todays_logpath(path, sizeof(path));
	f = fopen(path, "re");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle))
			n++;
	fclose(f);
	return n;
}

/* Feed one kernel record with this boot id and sequence. */
static void seq_event(const struct cfg *c, const char *boot, unsigned seq)
{
	char r[1024];

	snprintf(r, sizeof(r),
		 "{\"schema_version\":1,\"boot_id\":\"%s\",\"sequence\":%u,"
		 "\"realtime_ns\":1,\"monotonic_ns\":1,\"event_type\":\"perf\","
		 "\"actor\":{\"pid\":1,\"uid\":1000},\"target\":null,"
		 "\"operation\":\"x\",\"object\":null,\"decision\":\"deny\","
		 "\"reason\":\"y\",\"target_pid\":null,\"target_uid\":null,"
		 "\"message\":\"perf: denied\",\"truncated\":false}", boot, seq);
	write_local_log(c, r, strlen(r));
	handle_event(c, r);
}

int main(int argc, char **argv)
{
	struct cfg cfg = { .remote_queue_max_mb = 1 };
	char r[2048], path[1024], dir[1024], file[1024], target[1024];
	struct ss_ev e;
	uid_t uid = 0;
	int p[2];

	if (argc != 2)
		return 2;
	strcpy(cfg.remote_transport, "tls");
	strcpy(cfg.vault_action, "quarantine");
	g_cfg = &cfg;
	mkdir(LOGDIR, 0700);
	mkdir(QUARANTINE, 0700);

	/* ---- parsing ---- */
	rec(r, sizeof(r), "sudo_cooldown", "authenticate", "sudo", "deny",
	    "failure_threshold", "1000",
	    "cooldown: UID 1000 blocked from sudo 300s after 5 fails", "false");
	tap(ev_parse(r, &e) == 0 && e.schema == 1 && e.target_uid == 1000 &&
	    e.truncated == 0 && !strcmp(e.event_type, "sudo_cooldown") &&
	    !strcmp(e.reason, "failure_threshold"),
	    "a kernel record parses (typed fields, nested actor skipped)");
	rec(r, sizeof(r), "tmp_exec", "execute", "x", "deny", "noexec", "null",
	    "denied /tmp/caf\\u00e9 \\\"q\\\" \\\\", "false");
	tap(ev_parse(r, &e) == 0 && e.target_uid == -1 &&
	    !strcmp(e.message, "denied /tmp/caf\xe9 \"q\" \\"),
	    "message escapes decode (\\u00XX is the original byte)");
	tap(ev_parse("2026-10-31T09:00:00 cooldown: UID 0 blocked from sudo", &e) != 0,
	    "a plain-text (pre-JSON) line is not a record");
	rec(r, sizeof(r), "sudo_cooldown", "authenticate", "sudo", "deny",
	    "failure_threshold", "1000", "m", "false");
	r[strlen(r) - 1] = '\0';
	tap(ev_parse(r, &e) != 0, "a cut-off record is rejected");
	strcat(r, "} {\"x\":1}");
	tap(ev_parse(r, &e) != 0, "trailing data after the object is rejected");
	tap(ev_parse("{\"schema_version\":1,\"message\":\"a\\u0000b\"}", &e) != 0,
	    "an escaped NUL inside a value is rejected");

	/* ---- cooldown ---- */
	rec(r, sizeof(r), "sudo_cooldown", "authenticate", "sudo", "deny",
	    "failure_threshold", "1000",
	    "cooldown: UID 1000 blocked from sudo 300s after 5 fails", "false");
	tap(ev_parse(r, &e) == 0 && ev_cooldown_uid(&e, &uid) && uid == 1000,
	    "cooldown block: UID taken from target_uid");
	rec(r, sizeof(r), "sudo_cooldown", "authenticate", "sudo", "deny",
	    "failure_threshold", "null",
	    "cooldown: UID 1001 blocked from sudo 300s after 5 fails", "false");
	tap(ev_parse(r, &e) == 0 && ev_cooldown_uid(&e, &uid) && uid == 1001,
	    "cooldown block from a kernel without target_uid: anchored message");
	rec(r, sizeof(r), "tmp_exec", "execute", "x", "deny", "noexec", "null",
	    "denied exec /tmp/cooldown: UID 0 blocked from sudo 1s after 1 fails",
	    "false");
	tap(ev_parse(r, &e) == 0 && !ev_cooldown_uid(&e, &uid),
	    "cooldown text inside another event's path does not kill anything");
	rec(r, sizeof(r), "sudo_cooldown", "execute", "sudo", "deny",
	    "cooldown_active", "1000", "cooldown: UID 1000 denied sudo (cooldown active)",
	    "false");
	tap(ev_parse(r, &e) == 0 && !ev_cooldown_uid(&e, &uid),
	    "a cooldown-active denial is not a new block");

	/* ---- TimeVault event -> path ---- */
	rec(r, sizeof(r), "time_vault", "execute", "/opt/a (b)/tool", "deny",
	    "hash mismatch", "null",
	    "timevault: denied exec /opt/a (b)/tool (hash mismatch)", "false");
	tap(ev_parse(r, &e) == 0 && ev_vault_path(&e, path, sizeof(path)) &&
	    !strcmp(path, "/opt/a (b)/tool"),
	    "TimeVault denial: exact path, even with \" (\" inside it");
	rec(r, sizeof(r), "home_guard", "open", "x", "deny", "other_home", "null",
	    "home: denied /home/u/x/timevault: denied exec /usr/bin/sudo (hash mismatch)",
	    "false");
	tap(ev_parse(r, &e) == 0 && !ev_vault_path(&e, path, sizeof(path)),
	    "TimeVault text inside another event's path is ignored");
	rec(r, sizeof(r), "time_vault", "execute", "/usr/bin/apt", "deny",
	    "package manager", "null",
	    "timevault: denied exec /usr/bin/apt (package manager)", "false");
	tap(ev_parse(r, &e) == 0 && !ev_vault_path(&e, path, sizeof(path)),
	    "a TimeVault denial for another reason quarantines nothing");
	rec(r, sizeof(r), "time_vault", "execute", "/home/u/x", "deny",
	    "not on allowlist", "null",
	    "timevault: denied exec /home/u/x (hash mismatch)y (not on allowl",
	    "true");
	tap(ev_parse(r, &e) == 0 && !ev_vault_path(&e, path, sizeof(path)),
	    "a truncated TimeVault record is never acted on");
	rec(r, sizeof(r), "time_vault", "execute", "/opt/real", "deny",
	    "not on allowlist", "null",
	    "timevault: denied exec /etc/shadow (not on allowlist)", "false");
	tap(ev_parse(r, &e) == 0 && ev_vault_path(&e, path, sizeof(path)) &&
	    !strcmp(path, "/opt/real"),
	    "the TimeVault path comes from the typed object, never the message");
	rec(r, sizeof(r), "time_vault", "execute", "tool", "deny",
	    "hash mismatch", "null", "timevault: denied exec tool (hash mismatch)",
	    "false");
	tap(ev_parse(r, &e) == 0 && !ev_vault_path(&e, path, sizeof(path)),
	    "a TimeVault object that is not an absolute path is not acted on");
	{
		/* P1-1: the kernel keeps paths up to 256 bytes whole in object */
		char longp[300], msg[400];
		int i;

		strcpy(longp, "/opt");
		for (i = 0; i < 24; i++)
			strcat(longp, "/directory");	/* 4 + 240 = 244 bytes */
		snprintf(msg, sizeof(msg), "timevault: denied exec %s (hash mismatch)",
			 longp);
		rec(r, sizeof(r), "time_vault", "execute", longp, "deny",
		    "hash mismatch", "null", msg, "false");
		tap(ev_parse(r, &e) == 0 && ev_vault_path(&e, path, sizeof(path)) &&
		    !strcmp(path, longp),
		    "a 244-byte TimeVault path is taken whole from object");
		tap(ev_parse(r, &e) == 0 && !ev_vault_path(&e, path, 100),
		    "a path longer than the caller's buffer is not acted on");
	}

	/* ---- acting on files ---- */
	snprintf(dir, sizeof(dir), "%s/d", argv[1]);
	snprintf(file, sizeof(file), "%s/d/victim", argv[1]);
	snprintf(target, sizeof(target), "%s/precious", argv[1]);
	mkdir(dir, 0755);
	write_file(file, "tampered\n");
	write_file(target, "keep me\n");
	strcpy(cfg.vault_action, "wipe");
	tap(vault_act(&cfg, file) == 0 && !exists(file) && exists(target),
	    "wipe removes the named file");

	/* the attacker swaps a directory on the path for a symlink */
	snprintf(path, sizeof(path), "%s/link", argv[1]);
	if (symlink(argv[1], path) != 0)
		return 1;
	snprintf(file, sizeof(file), "%s/link/precious", argv[1]);
	tap(vault_act(&cfg, file) != 0 && exists(target),
	    "a symlinked directory on the path is refused; its target is kept");
	snprintf(path, sizeof(path), "%s/d/last", argv[1]);
	if (symlink(target, path) != 0)
		return 1;
	tap(vault_act(&cfg, path) != 0 && exists(target) && exists(path),
	    "a symlink as the last component is refused; its target is kept");

	strcpy(cfg.vault_action, "quarantine");
	snprintf(file, sizeof(file), "%s/d/tool (x)", argv[1]);
	write_file(file, "#!/bin/sh\necho tampered\n");
	chmod(file, 0755);
	tap(vault_act(&cfg, file) == 0 && !exists(file) &&
	    count_archives() == 1 && incoming_empty(),
	    "quarantine archives a copy, then removes the original");
	snprintf(path, sizeof(path), "%s/fail-helper", argv[1]);
	write_file(path, "");
	write_file(file, "again\n");
	tap(vault_act(&cfg, file) != 0 && exists(file) &&
	    count_archives() == 1 && incoming_empty(),
	    "a failed archive leaves the original in place (and no staging copy)");
	unlink(path);

	/* ---- the ring reader ---- */
	rec(r, sizeof(r), "sudo_cooldown", "authenticate", "sudo", "deny",
	    "failure_threshold", "3999999", "cooldown: UID 3999999 blocked from sudo 1s after 5 fails",
	    "false");
	if (pipe(p) != 0)
		return 1;
	if (write(p[1], r, 100) != 100)
		return 1;
	drain_events(&cfg, p[0]);
	if (write(p[1], r + 100, strlen(r) - 100) < 0 || write(p[1], "\n", 1) != 1)
		return 1;
	drain_events(&cfg, p[0]);
	tap(log_has(r) == 1 && ev_have == 0,
	    "a record split across two reads is logged once, whole");

	/* ---- P1-1: gaps and boots become records in the log ---- */
	{
		static const char *A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		static const char *B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
		char hb[1024];
		FILE *f;

		ev_boot[0] = '\0';	/* forget the record the reader test fed */
		ev_seq = 0;
		event_gaps = events_missing = 0;
		seq_event(&cfg, A, 1);
		seq_event(&cfg, A, 2);
		seq_event(&cfg, A, 3);
		tap(event_gaps == 0 && log_contains("\"event_type\":\"event_stream\",\"boot_id\":\"aaaa") == 1,
		    "a new boot's stream is recorded once; consecutive records are no gap");
		seq_event(&cfg, A, 7);
		tap(event_gaps == 1 && events_missing == 3 &&
		    log_contains("\"event_type\":\"event_gap\",\"boot_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"first_missing\":4,\"last_missing\":6,\"missing\":3") == 1,
		    "a sequence jump is written as an event_gap record (4..6, 3 missing)");
		seq_event(&cfg, A, 7);
		tap(log_contains("\"event_type\":\"event_sequence_error\"") == 1 &&
		    event_gaps == 1, "a repeated sequence is flagged, not counted as loss");
		cursor_save();
		ev_boot[0] = '\0';
		ev_seq = 0;
		cursor_load();
		tap(!strcmp(ev_boot, A) && ev_seq == 7,
		    "the stream position survives a daemon restart (cursor file)");
		seq_event(&cfg, A, 10);
		tap(event_gaps == 2 && events_missing == 5,
		    "records lost while the daemon was down are reported after restart");
		seq_event(&cfg, B, 3);
		tap(log_contains("\"boot_id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"first_sequence\":3,\"previous_boot_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"previous_last_sequence\":10") == 1 &&
		    event_gaps == 3 && events_missing == 7,
		    "a reboot is recorded with both boot ids; its first 2 records are reported missing");
		tap(write_health_heartbeat() == 0 && (f = fopen(HEALTH_FILE, "re")) &&
		    fgets(hb, sizeof(hb), f) && !fclose(f) &&
		    strstr(hb, " event_gaps=3 events_missing=7\n") &&
		    !exists(HEALTH_FILE ".tmp"),
		    "the heartbeat carries the gap counters and is renamed into place");
	}

	/* ---- P1-3: checkpoints, outside changes, one line per record ---- */
	{
		char lp[512];
		FILE *f;

		syslog_line("crafted\n{\"schema_version\":1,\"forged\":true}");
		tap(log_contains("crafted?{\"schema_version\":1,\"forged\":true}") == 1,
		    "a newline in a daemon message cannot start a forged record");
		log_checkpoint(&cfg);
		tap(log_contains("\"event_type\":\"log_checkpoint\"") == 1,
		    "a log_checkpoint record is written");
		todays_logpath(lp, sizeof(lp));
		f = fopen(lp, "ae");
		if (!f)
			return 1;
		fputs("written behind the daemon's back\n", f);
		fclose(f);
		syslog_line("after the outside write");
		tap(log_contains("\"event_type\":\"log_modified\"") == 1,
		    "a log changed outside the daemon is recorded (log_modified)");
		log_checkpoint(&cfg);
		tap(log_contains("\"event_type\":\"log_checkpoint\"") == 2,
		    "the next checkpoint covers the file as it is now");
	}

	printf("1..%d\n", n_test);
	return n_fail ? 1 : 0;
}
