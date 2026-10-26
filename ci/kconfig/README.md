# Kernel config variants for the build gate

`ci/build-gate.sh --kernel-tree DIR` compiles the secure_sudo LSM in-tree once
per file here, each layered on `x86_64_defconfig` + `tests/vm/kernel.config`.
The point is to exercise the `#ifdef` paths a distro config can switch off.

| Variant | What it turns off / on |
|---------|------------------------|
| `default.config` | nothing extra: audit, BPF, perf, modules all on |
| `no-audit.config` | `CONFIG_AUDIT` off (the auditd feed compiles out) |
| `no-bpf.config` | `CONFIG_BPF_SYSCALL` off (the bpf hooks compile out) |
| `no-modules.config` | `CONFIG_MODULES` off (module-load paths unused) |
| `modsig.config` | module signing enforced, as `install.sh` configures it |
| `stack-apparmor.config` | AppArmor stacked first, as Ubuntu/Debian/SUSE ship |

`CONFIG_PERF_EVENTS` cannot be switched off on x86 (the architecture selects
it), so there is no no-perf variant; the perf hook's `#ifdef` is covered by
the compile check on other architectures only.
