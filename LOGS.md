Important finding while working the roadmap: the v11 kernel panics at boot. Since kernel 6.9 each LSM gets one slot per hook, and secure_sudo registered some hooks up to 7 times. Please don't install v11.

It's fixed: the patched kernel now boots in a test VM and passes all 118 in-VM tests. I also found and fixed a 6.12 build break and a missing `setid_exec_allow` file. Still working through P0; v12 to follow.

Checking on you it seems you may have stalled out on me

Not stalled, two VM test runs are going. Checking where they are now so I can give you real numbers.

Still working, just slowly. This machine has no KVM, so every VM reboot takes about 4 minutes, and the build machine restarted once at 15:19, which cost me the runs in progress. I restarted both at 18:07.

Where it stands right now:
- **Install test, second run:** 27 of 28 checks pass so far. That covers install, the trial boot with AppArmor running next to secure_sudo, the services, verify, and the automatic fallback to the old kernel. The one miss is a preflight flag, already fixed in the tree. Still to run: commit, the four recovery drills, rollback and clean removal.
- **STIG run:** the secure_sudo kernel is installed and committed in a second VM, and the first scan is running.
- **First run:** it found three real installer problems, all fixed now. The worst was that userspace install failed on a fresh machine whose package lists had never been downloaded.

Both runs should finish in roughly an hour. After that I'll write the roadmap status, run the final build gate and package v12. Nothing has been pushed.

Been roughly an hour just checking on you and your status

Good news on the main test, and the STIG run is in its last stretch.

- **Install and recovery test: passing.** The second run passed 50 of 51 checks. The one miss was a preflight flag, which I fixed. A third run on the final code is nearly done and has passed everything so far, including all four recovery drills on the real kernel: a wrong admin group, a missing allowlist entry, a broken PAM line and an accidental lock. It is now running rollback and clean removal.
- **STIG run: second remediation pass.** Before hardening, the VM scored 57 pass, 64 fail, 0 errors, so AppArmor now checks cleanly, which the container never could. Most of the time went into building the AIDE file database, which is very slow without KVM. Two scans and a reboot are left, about 40 minutes.

One thing you should know now: the STIG rule that requires FIPS mode will probably stay failed. Only a vendor-certified kernel such as Ubuntu Pro FIPS can satisfy it, and a self-built kernel like secure_sudo can't be certified. Once the final scan is in, I'll show you the exact list and ask how you want that rule recorded. Nothing has been pushed.


Heads-up: please don't install v11, because its kernel panics at boot. [Kernel LSM merge](#cmsg_01NMeDuERb4gfZpUgwCstoaKHE1Pm6gx86LE9FBnWw5fW1) found and fixed the cause. The fixed kernel now boots in a test VM and passes all 118 tests, and v12 will follow once the rest of the top-priority work is done.

Step 1 (P0-4, P0-1, P0-2): verified kernel sources, build gate (all 7 stages pass), 304 host test checks, real bugs fixed (v11 boot panic, OTP replay, PAM stack, IPv6 leak, quarantine data loss)

P0-5: installer rewritten: preflight, trial boot with automatic fallback, commit, rollback, clean uninstall (106 host checks)

P0-6: secure-sudo lint and a load that refuses bad policy before it is applied

Docs: recovery guide, hardware smoke-test plan, README status, kernel integration table, security review #35–#45

VM run 2: 50 of 51 (the 1 miss fixed); evidence saved

VM run 3 on the final tree: everything passing so far incl. all 4 recovery drills; rollback and removal running

STIG run: baseline 57 pass / 64 fail / 0 errors; remediation pass 2 applying, then 2 scans and a reboot (~40 min)

Decide with Pheonix how to record the FIPS rule (likely stays failed on a self-built kernel)

Fill in the roadmap status from the runs

Final build gate and package v12