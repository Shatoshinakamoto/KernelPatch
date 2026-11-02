// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
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

/* The value of "key":"..." in the last log record of this type. */
static int last_field(const char *type, const char *key, char *out, size_t n)
{
	char path[512], line[4096], want[96], k[64];
	FILE *f;
	int found = 0;

	snprintf(want, sizeof(want), "\"event_type\":\"%s\"", type);
	snprintf(k, sizeof(k), "\"%s\":\"", key);
	todays_logpath(path, sizeof(path));
	f = fopen(path, "re");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *v, *q;

		if (!strstr(line, want) || !(v = strstr(line, k)))
			continue;
		v += strlen(k);
		q = strchr(v, '"');
		if (!q || (size_t)(q - v) >= n)
			continue;
		memcpy(out, v, (size_t)(q - v));
		out[q - v] = '\0';
		found = 1;
	}
	fclose(f);
	return found ? 0 : -1;
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
	setvbuf(stdout, NULL, _IOLBF, 0);	/* whole lines between helper output */
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

	/* ---- #11 node-scan runs in the background ---- */
	{
		char calls[1024], got[256] = "";
		pid_t first;
		FILE *f;
		int i;

		snprintf(calls, sizeof(calls), "%s/cli-calls", argv[1]);
		node_scan_start();
		first = node_scan_pid;
		tap(first > 0, "node-scan starts as a child, without waiting for it");
		node_scan_start();
		tap(node_scan_pid == first, "a second start while one runs forks nothing");
		node_scan_reap();
		tap(node_scan_pid == first, "a scan still running is not reaped");
		for (i = 0; i < 100 && node_scan_pid > 0; i++) {
			usleep(100000);
			node_scan_reap();
		}
		tap(node_scan_pid == 0, "a finished scan is reaped");
		f = fopen(calls, "re");
		if (f) {
			if (!fgets(got, sizeof(got), f))
				got[0] = '\0';
			fclose(f);
		}
		tap(!strcmp(got, "node-scan --quiet nice=10\n"),
		    "it runs `secure-sudo node-scan --quiet` at nice 10");
		tap(log_contains("node-scan: did not complete (status 3)") == 1,
		    "a failed scan is logged with its exit status");
	}

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
		    strstr(hb, " event_gaps=3 events_missing=7 ") &&
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


	/* ---- G2: the TimeVault manifest and its Merkle root ---- */
	{
		char w[1024], fa[1100], fb[1100], fsp[1100], fnl[1100], fc[1100];
		char r1[80], got[80], m[1200], prev[1200];
		int arch;
		struct tv_set s2;
		FILE *f;

		snprintf(w, sizeof(w), "%s/tv-watch", argv[1]);
		mkdir(w, 0700);
		snprintf(m, sizeof(m), "%s/tv-watch/sub", argv[1]);
		mkdir(m, 0700);
		snprintf(fa, sizeof(fa), "%s/a", w);
		snprintf(fb, sizeof(fb), "%s/sub/b", w);
		snprintf(fsp, sizeof(fsp), "%s/with space", w);
		snprintf(fnl, sizeof(fnl), "%s/new\nline\\x", w);
		snprintf(fc, sizeof(fc), "%s/c", w);
		write_file(fa, "alpha\n");
		write_file(fb, "bravo\n");
		write_file(fsp, "space\n");
		write_file(fnl, "newline\n");
		snprintf(cfg.vault_watch, sizeof(cfg.vault_watch), "%s", w);
		mkdir(SYSFS, 0700);
		write_file(SYSFS "/timevault", "1\n");
		arch = count_archives();

		rec(r, sizeof(r), "time_vault", "engage", "execution_allowlist",
		    "enforce", "null", "null", "timevault: engaged", "false");
		handle_event(&cfg, r);
		vault_scan(&cfg);
		tap(log_contains("\"event_type\":\"timevault_baseline\",\"reason\":\"engaged\"") == 1 &&
		    log_contains("\"leaves\":4") == 1 && count_archives() == arch &&
		    exists(fa) && exists(fb) && exists(fsp) && exists(fnl),
		    "G2: the first scan after `timevault on` is a baseline: 4 files recorded, none quarantined");
		tap(last_field("timevault_baseline", "root", r1, sizeof(r1)) == 0 &&
		    strlen(r1) == 64, "G2: the baseline record carries a 64-hex Merkle root");
		f = fopen(MANIFEST, "re");
		tap(f && fgets(m, sizeof(m), f) && !strcmp(m, TV_HEADER "\n") &&
		    !fclose(f), "G2: the manifest file is v2 (header line)");

		vault_scan(&cfg);
		vault_scan(&cfg);
		tap(log_contains("\"event_type\":\"timevault_merkle\"") == 0 &&
		    count_archives() == arch && exists(fa),
		    "G2: rescans of an unchanged tree act on nothing and log nothing");
		tv_checkpoint(&cfg);
		tap(last_field("timevault_merkle", "root", got, sizeof(got)) == 0 &&
		    !strcmp(got, r1) &&
		    log_contains("\"reason\":\"checkpoint\"") == 1,
		    "G2: the checkpoint record repeats the same root (a legitimate rescan)");

		tv_free(&tv);		/* a daemon restart */
		tv_loaded = 0;
		vault_scan(&cfg);
		tap(log_contains("\"event_type\":\"timevault_merkle\",\"reason\":\"loaded\"") == 1 &&
		    last_field("timevault_merkle", "root", got, sizeof(got)) == 0 &&
		    !strcmp(got, r1) && tv.n == 4,
		    "G2: after a restart the manifest is loaded (escaped names too) with the same root");

		write_file(fb, "tampered\n");
		vault_scan(&cfg);
		tap(!exists(fb) && count_archives() == arch + 1 &&
		    log_contains("\"reason\":\"scan\",\"root\":\"") == 1 &&
		    log_contains("\"new\":0,\"changed\":1,\"acted\":1") == 1,
		    "G2: a changed file is quarantined and the scan record says so");
		tap(!strcmp(tv_root, r1),
		    "G2: quarantining does not change the manifest (root unchanged)");
		write_file(fb, "tampered\n");
		write_file(fc, "charlie\n");
		vault_scan(&cfg);
		tap(!exists(fb) && !exists(fc) && count_archives() == arch + 3 &&
		    log_contains("\"new\":1,\"changed\":1,\"acted\":2") == 1,
		    "G2: the same tampered file dropped again is caught again; a new file too");
		write_file(fb, "bravo\n");
		vault_scan(&cfg);
		tap(exists(fb) && count_archives() == arch + 3,
		    "G2: the original content put back matches the baseline again");

		/* The tree itself. */
		tap(tv_read(MANIFEST, &s2, NULL) == 0 && s2.n == 4, "G2: manifest re-read");
		tap(tv_root_hex(&s2, got) == 0 && !strcmp(got, r1),
		    "G2: the root is a function of the entries alone");
		s2.e[1].hash[10] = s2.e[1].hash[10] == '0' ? '1' : '0';
		tap(tv_root_hex(&s2, got) == 0 && strcmp(got, r1),
		    "G2: one changed hash changes the root");
		s2.e[1].hash[10] = s2.e[1].hash[10] == '0' ? '1' : '0';
		s2.e[2].path[strlen(s2.e[2].path) - 1] ^= 1;
		tap(tv_root_hex(&s2, got) == 0 && strcmp(got, r1),
		    "G2: one changed path changes the root");
		s2.e[2].path[strlen(s2.e[2].path) - 1] ^= 1;
		free(s2.e[3].path);
		s2.n = 3;
		tap(tv_root_hex(&s2, got) == 0 && strcmp(got, r1),
		    "G2: a dropped entry changes the root");
		tv_free(&s2);

		/* Someone rewrites the manifest to bless their file. */
		{
			char hb[65], line[1300];
			FILE *in, *out;

			snprintf(prev, sizeof(prev), "%s.edit", MANIFEST);
			write_file(fb, "evil\n");
			tap(sha256_hex(fb, hb) == 0, "G2: hash of the planted file");
			in = fopen(MANIFEST, "re");
			out = fopen(prev, "we");
			while (in && out && fgets(line, sizeof(line), in)) {
				if (strstr(line, "/sub/b\n"))
					snprintf(line, sizeof(line), "%s %s\n", hb, fb);
				fputs(line, out);
			}
			if (in)
				fclose(in);
			if (out)
				fclose(out);
			rename(prev, MANIFEST);
		}
		vault_scan(&cfg);
		tap(log_contains("\"event_type\":\"timevault_manifest_modified\"") == 1 &&
		    last_field("timevault_manifest_modified", "expected_root", got, sizeof(got)) == 0 &&
		    !strcmp(got, r1) &&
		    last_field("timevault_manifest_modified", "found_root", got, sizeof(got)) == 0 &&
		    strlen(got) == 64 && strcmp(got, r1) &&
		    log_contains("\"restored\":true") == 1,
		    "G2: a rewritten manifest is recorded with both roots and put back");
		tap(!exists(fb) && tv_read(MANIFEST, &s2, NULL) == 0 &&
		    tv_root_hex(&s2, got) == 0 && !strcmp(got, r1),
		    "G2: the blessed file is still quarantined; the file on disk has the baseline root again");
		tv_free(&s2);
		write_file(fb, "bravo\n");
		{
			struct timespec ts[2] = { { 0, UTIME_NOW }, { 0, UTIME_NOW } };

			utimensat(AT_FDCWD, MANIFEST, ts, 0);
		}
		vault_scan(&cfg);
		tap(log_contains("\"event_type\":\"timevault_manifest_modified\"") == 1,
		    "G2: a manifest only touched (same content) is not reported");
		unlink(MANIFEST);
		vault_scan(&cfg);
		tap(log_contains("\"found_root\":\"missing\"") == 1 && exists(MANIFEST),
		    "G2: a deleted manifest is reported and written back");

		/* Reboot: TimeVault is off again. */
		write_file(SYSFS "/timevault", "0\n");
		vault_scan(&cfg);
		snprintf(prev, sizeof(prev), "%s.prev", MANIFEST);
		tap(log_contains("\"event_type\":\"timevault_disengaged\",\"root\":\"") == 1 &&
		    !exists(MANIFEST) && exists(prev) && !tv_loaded,
		    "G2: TimeVault off: the engagement's manifest is set aside (.prev)");
		vault_scan(&cfg);
		tap(log_contains("\"event_type\":\"timevault_disengaged\"") == 1,
		    "G2: and that is recorded once");
		write_file(SYSFS "/timevault", "1\n");
		vault_scan(&cfg);
		tap(log_contains("\"event_type\":\"timevault_baseline\",\"reason\":\"no_manifest\"") == 1 &&
		    last_field("timevault_baseline", "root", got, sizeof(got)) == 0 &&
		    !strcmp(got, r1),
		    "G2: engaged with no engage record seen: a baseline marked no_manifest");

		/* A manifest that cannot be read is never taken as empty. */
		tv_free(&tv);
		tv_loaded = 0;
		write_file(MANIFEST, TV_HEADER "\nnot a manifest line\n");
		write_file(fc, "charlie\n");
		vault_scan(&cfg);
		vault_scan(&cfg);
		tap(log_contains("\"event_type\":\"timevault_manifest_unreadable\"") == 1 &&
		    exists(fc) && exists(fa) && !tv_loaded,
		    "G2: an unreadable manifest: nothing quarantined, reported once");
		unlink(fc);

		/* A v1 manifest (appended "PATH HASH", first entry wins). */
		{
			char ha[65], hs[65];

			sha256_hex(fa, ha);
			sha256_hex(fsp, hs);
			f = fopen(MANIFEST, "we");
			if (f) {
				fprintf(f, "%s %s\n%s %s\n%s %s\n", fa, ha, fsp, hs,
					fa, "0000000000000000000000000000000000000000000000000000000000000000");
				fclose(f);
			}
		}
		vault_scan(&cfg);
		f = fopen(MANIFEST, "re");
		tap(log_contains("\"reason\":\"loaded_v1\"") == 1 && tv.n == 2 &&
		    tv_find(&tv, fsp) && f && fgets(m, sizeof(m), f) &&
		    !strcmp(m, TV_HEADER "\n"),
		    "G2: a v1 manifest is read (spaces in names, first entry wins) and rewritten as v2");
		if (f)
			fclose(f);
		vault_scan(&cfg);
		tap(exists(fa) && exists(fsp) && !exists(fb) &&
		    log_contains("\"new\":2,\"changed\":0") == 1,
		    "G2: files the v1 manifest never listed are treated as new");
	}

	/* ---- P1-8: net_mode apply, refresh, pending and stop ----
	 * HELPER_NET is net-wrapper.sh: it appends its arguments to net-calls
	 * and exits with the status in net-rc. NET_REFRESH_SECS is 0, so every
	 * pass of an applied lan-only/public-only mode is a refresh. */
	{
		char calls[1024], hb[1024];
		FILE *f;
		size_t n;

#define NET_RC(v) write_file(NETDIR "/net-rc", v "\n")
#define NET_CALLS() (snprintf(path, sizeof(path), NETDIR "/net-calls"), \
		     (f = fopen(path, "re")) ? (n = fread(calls, 1, sizeof(calls) - 1, f), \
		     calls[n] = '\0', fclose(f), calls) : (calls[0] = '\0', calls))
#define NET_RESET() unlink(NETDIR "/net-calls")
		mkdir(SYSFS, 0700);
		write_file(SYSFS "/net_mode", "lan-only\n");
		NET_RC("3");
		apply_net_mode();
		apply_net_mode();
		tap(!strcmp(NET_CALLS(), "lan-only\nlan-only\n") &&
		    !strcmp(net_state, "pending"),
		    "P1-8: no LAN subnet yet (helper 3): pending, retried on every pass");
		NET_RESET();
		NET_RC("0");
		apply_net_mode();
		tap(!strcmp(NET_CALLS(), "lan-only\n") && !strcmp(net_state, "applied"),
		    "P1-8: the real rules load once a subnet appears");
		NET_RESET();
		apply_net_mode();
		apply_net_mode();
		tap(!strcmp(NET_CALLS(), "lan-only\nlan-only\n") &&
		    !strcmp(net_state, "applied"),
		    "P1-8: an applied lan-only mode is refreshed (DHCP/subnet changes are picked up)");
		NET_RESET();
		NET_RC("1");
		apply_net_mode();
		tap(!strcmp(net_state, "failing"),
		    "P1-8: a failed refresh is reported (the loaded rules stay)");
		NET_RC("3");
		apply_net_mode();
		tap(!strcmp(net_state, "pending"),
		    "P1-8: losing the subnet after a refresh failure: pending");
		NET_RESET();
		NET_RC("0");
		write_file(SYSFS "/net_mode", "monitor\n");
		apply_net_mode();
		apply_net_mode();
		tap(!strcmp(NET_CALLS(), "monitor\n") && !strcmp(net_state, "off"),
		    "P1-8: monitor is applied once and not refreshed");
		write_health_heartbeat();
		f = fopen(HEALTH_FILE, "re");
		n = f ? fread(hb, 1, sizeof(hb) - 1, f) : 0;
		hb[n] = '\0';
		if (f)
			fclose(f);
		tap(strstr(hb, " net_state=off\n") != NULL,
		    "P1-8: the heartbeat reports the network policy state");
		NET_RESET();
		net_on_stop();
		tap(!strcmp(NET_CALLS(), "stop\n"),
		    "P1-8: a clean stop runs the helper's on_stop policy");
	}

	printf("1..%d\n", n_test);
	return n_fail ? 1 : 0;
}
