<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `ci/check-config-docs.py`

Fail if docs/configuration/ or docs/files/ drift from the code and templates.

- **Source:** [`ci/check-config-docs.py`](../../ci/check-config-docs.py)
- **Run by:** the gate's lint stage

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
check-config-docs.py - the per-file configuration pages in
docs/configuration/ (CLAUDE.MD section 5) must stay in step with the code:
  - every kernel setting (ss_knobs in userspace/cli/policy.c) and every
    daemon key (daemon_keys there) has exactly one row in
    docs/configuration/secure-sudo-conf.md, and no row names a key the
    code does not know;
  - each kernel row's "Built-in default" matches ss_core.c;
  - each row's "Shipped" column matches the template in userspace/config/
    (the value, "(commented)" or "(absent)");
  - net.conf rows match the template and apply-net.sh's defaults;
  - every policy list (ss_lists) has docs/files/<list>.md whose limit marker
    matches the kernel limit in ss_lists and whose entries table lists
    exactly the template's active entries;
  - each temporary/ add-on config page lists exactly the keys its parser
    table accepts, with shipped values matching temporary/config/, and
    procguard_allow.md matches its template's entries;
  - every page in docs/configuration/ and docs/files/ is linked from
    docs/README.md.
Usage: check-config-docs.py ROOT. Prints "FAIL ..." lines to stderr and
exits 1 on any problem.
```

## Related

- [Script reference](../SCRIPTS.md)
- [secure-sudo-conf.md](../configuration/secure-sudo-conf.md)
