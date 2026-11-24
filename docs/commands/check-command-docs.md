<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `ci/check-command-docs.py`

Fail if a command, script, add-on binary or feature has no page, a copied header drifted, or a page is not indexed.

- **Source:** [`ci/check-command-docs.py`](../../ci/check-command-docs.py)
- **Run by:** the gate's lint stage

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
check-command-docs.py - the per-command and per-feature pages (CLAUDE.MD
section 5) must stay in step with the code:
  - every `secure-sudo` subcommand the CLI dispatches has
    docs/commands/secure-sudo-<name>.md;
  - every script in scripts/, ci/ and userspace/daemon/helpers/, plus
    tests/run-all.sh and temporary/install-temporary.sh, is named (by its
    path) on some docs/commands/ page;
  - every temporary/ add-on binary has docs/commands/<binary>.md;
  - a page that copies a source file's header ("The script's own header is
    the reference") still matches that header;
  - every docs/features/ page has the eight required sections;
  - every docs/commands/ and docs/features/ page is linked from
    docs/README.md.
Usage: check-command-docs.py ROOT. Prints "FAIL ..." lines to stderr and
exits 1 on any problem.
```

## Related

- [Script reference](../SCRIPTS.md)
- [README.md](../README.md)
