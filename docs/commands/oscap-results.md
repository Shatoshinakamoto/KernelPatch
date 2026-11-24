<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `scripts/oscap-results.py`

Run as root. Part of the [script reference](../SCRIPTS.md).

Reads OpenSCAP results (XCCDF/ARF XML, or saved `oscap xccdf eval` console
output with its `\r` rewrites) and is what `stig-harden.sh` and the STIG gate
use to count and compare results.

```
oscap-results.py tally FILE                    pass=… fail=… error=… notapplicable=… notchecked=…
oscap-results.py rules FILE [--not-pass]       "<result> <rule>" per rule (short ids)
oscap-results.py skip-fix FIX.sh REGEX         drop matching fix blocks (lists them in FIX.sh.skipped)
oscap-results.py gate FILE --expect EXPECT [--mode release|diagnostic]
```

`gate` compares **rule IDs**, not totals: every result that is not
pass/notapplicable must be listed in the expect file
(`tests/oscap/ubuntu2404-stig.expect`) with a reason; `error` and `unknown`
never pass in release mode; a listed rule missing from the results fails
(the profile changed); entries marked `container-only` are tolerated only in
`--mode diagnostic`.

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
