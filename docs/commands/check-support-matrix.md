<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `ci/check-support-matrix.py`

Check docs/SUPPORT.md's matrix against the code and recorded evidence.

- **Source:** [`ci/check-support-matrix.py`](../../ci/check-support-matrix.py)
- **Run by:** the gate's lint stage

## Usage and options

The script's own header is the reference; it is copied here unchanged
(`ci/check-command-docs.py` fails if the two differ).

```text
check-support-matrix.py - the release-support matrix (docs/SUPPORT.md, TODO
P3-1) must be current for the release being built. Fails when:
  - the "Release:" line is missing or differs from VERSION;
  - "Matrix reviewed:" is not a real date;
  - a table row's status is not tested, compile-checked, expected or
    unsupported;
  - a tested or compile-checked row names no date (YYYY-MM-DD);
  - the document lacks the kernels, distributions, boot methods, toolchain
    and end-of-support sections.
Usage: check-support-matrix.py ROOT   (prints "ok ..." / "FAIL ..." lines)
```

## Related

- [Script reference](../SCRIPTS.md)
- [SUPPORT.md](../SUPPORT.md)
