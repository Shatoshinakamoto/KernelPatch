# Security policy

secure_sudo is a defensive hardening stack: a Linux Security Module plus
userspace. A flaw in it can weaken the machines it protects, so please report
problems privately and give us time to fix them.

## Reporting a vulnerability

* **Use GitHub private vulnerability reporting** on this repository: the
  **Security** tab, then **Report a vulnerability**. Do not open a public
  issue, pull request or discussion for a vulnerability.
* **Owner action needed:** private vulnerability reporting must be enabled
  in the repository settings (Settings, Code security). Until the owner has
  confirmed it is on, there is no tested private channel; the owner decides
  whether to add an e-mail address here. No personal contact details are
  published in this file on purpose.
* Include: the release (the `VERSION` file), the
  kernel (`uname -r`) and distribution, what you did, what you expected, what
  happened, and whether you can reproduce it on a clean install. A test that
  fails before the fix and passes after is the most useful thing you can send.

## What happens next (proposed targets; the owner confirms them)

| Step | Target |
|---|---|
| Acknowledge the report | 3 days |
| Triage: confirm, classify, decide the severity | 7 days |
| Fix released: critical (privilege escalation by a non-sudo user, a bypass of the lock or of a guard's core control, remote effect) | 14 days |
| Fix released: high (a weakened control, evidence or log forgery, data loss on repair) | 30 days |
| Fix released: medium and low | 90 days, or the next release |
| Public disclosure | when the fix is released, or at 90 days, whichever is first, credited to the reporter unless they ask not to be |

The process behind these steps, including how a fix becomes a tracked, tested
release, is in [docs/MAINTENANCE.md](docs/MAINTENANCE.md).

## Supported releases

Only releases the [support matrix](docs/SUPPORT.md) lists as supported get
fixes: the latest release, and the previous one for 90 days after its
successor ships.

## Scope

In scope: the kernel LSM, the userspace programs, the installers, the
add-ons in `temporary/`, the management console, and the build and release
scripts (a flaw that lets a build or update be substituted counts).

Out of scope: a vulnerability in Linux itself or in a distribution package
(report it upstream; tell us if secure_sudo should work around it), results
that need root before the lock is engaged (root can change every setting then,
and the threat model says so: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)),
things the threat model lists as outside scope for root after the lock, and
findings about the test environments only.
