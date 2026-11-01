# deprecated/ — kept as backups, not used

Nothing here is built, installed, tested or shipped as a component. The
files are kept unchanged, as backups, so nothing is lost. Git history has
them too.

## `deprecated/userspace/` (moved 2026-11-01)

These are the earlier "runtime guard" copies of the add-ons, from before v8
moved the add-ons into `temporary/`. They were left under `userspace/` when
`temporary/` became the add-ons' home. No build, installer, test or release
step used them: `install.sh` builds only `userspace/{cli,daemon,pam,otp,pheonixbox}`,
the build gate's `addons` stage builds `temporary/*`, and
`temporary/install-temporary.sh` installs from `temporary/`.

| Old copy (here) | Current version | Difference |
|---|---|---|
| `userspace/bootguard/` | `temporary/bootguard/` | same functions; the current one adds the `rotate` setting (hourly-rotating or fixed backup location) |
| `userspace/driverguard/` | `temporary/driverguard/` | same functions, plus `rotate` |
| `userspace/procguard/` | `temporary/procguard/` | same functions, plus `rotate` |
| `userspace/locus/` | `temporary/locus/` | identical apart from the header comment |
| `userspace/common/` | `temporary/common/` | every function is in the current one, which adds `store_bucket()` (the rotate/fixed choice) and the `notify_cmd` alerting in the logger |
| `userspace/systemd/` | `temporary/systemd/` | identical apart from the `Description=` text; `temporary/systemd/` also has the BiosGuard, TamperWatch and GUI units |
| `userspace/config/addons/` | `temporary/config/` | the current templates add `rotate` and the logging/notify settings; `temporary/config/` also has `biosguard.conf` and `gui.conf` |

The current versions are built with `-Werror` by the build gate on every
push and pull request, and `secure-sudo health` is tested against their unit
names (`tests/userspace/test-cli.sh`). Their monitor and enforce modes are
not yet exercised in a VM (docs/ROADMAP_STATUS.md, P0-2).

To bring one back, move it to its old path (`git mv deprecated/userspace/<dir> userspace/<dir>`).
Its Makefile still finds `../common` there.
