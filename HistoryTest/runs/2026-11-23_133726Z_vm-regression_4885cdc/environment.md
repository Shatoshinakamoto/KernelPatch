# Environment
- Owner's PC: Windows 11, Docker Desktop (WSL2 backend, 20 CPUs, 47 GB), container kp-vm (privileged), volume kp-work.
- No KVM (Windows VBS); VM tests run under QEMU TCG.
- Guest (VM runs): Ubuntu 24.04 cloud image, software TPM (swtpm).
- Raw logs, TAP files and reports stay in the kp-work volume on that PC; this run holds the report the PC sent.
