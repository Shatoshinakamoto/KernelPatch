<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `ci/check-addon-maturity.py`

Check temporary/maturity.json against the add-on promotion rules.

- **Source:** [`ci/check-addon-maturity.py`](../../ci/check-addon-maturity.py)
- **Run by:** the gate's lint stage

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
check-addon-maturity.py [ROOT] - hold the temporary/ add-ons to their
published maturity status (TODO P2-2).

temporary/maturity.json says, per add-on, what it does, its default mode, its
units and which maturity requirements are done or still open. This checks
that the tree agrees with it:

  - every add-on in temporary/ and every unit in temporary/systemd/ is listed;
  - each requirement is done, open or not applicable - never unaccounted;
  - "check-config" done: the source has the command and refuses bad configs;
  - every unit has OnFailure= reporting, MemoryMax=, TasksMax=,
    NoNewPrivileges=, no restart loop on a config error, a clean
    `systemd-analyze verify`, and a `systemd-analyze security` exposure at
    most its max_exposure;
  - the shipped config template's mode is the published default, and an
    acting default carries a note saying why that is safe;
  - the installer enables no unit;
  - docs/ADDONS.md has a maturity row and a threat model per add-on and the
    upgrade/rollback section;
  - the promotion criteria are operator-approved (who, when) and complete;
  - an add-on above "experimental" has no open item and a promotion record
    that meets them: who approved it and when, the soak host, a soak (and,
    for stable, an enforcing period) at least as long as the criteria say,
    every alert in it explained, and for stable a recorded recovery drill.

Needs systemd-analyze (systemd >= 250) unless SS_NO_SYSTEMD_ANALYZE=1.
Exit 0 if all pass. Prints one line per check, failures first.
```

## Related

- [Script reference](../SCRIPTS.md)
- [ADDONS.md](../ADDONS.md)
