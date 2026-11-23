# add-on TLS log shipping suite

- **Run id:** `2026-11-23_220553Z_unit-addon-log-tls_2894faf`
- **Area:** unit-addon-log-tls
- **Commit:** `2894faf`
- **Date (UTC):** 2026-11-23T22:05:53+00:00
- **Where:** cloud container (Ubuntu)
- **Verdict:** **pass**

## What was tested and why
New remote_proto = tls for the temporary/ add-ons: delivery over verified TLS, untrusted certificate, wrong DNS name, wrong IP, dead and returning collector, collector restart, plain tcp reconnect, check-config of remote_ca_file.

## How
`bash tests/userspace/test-addon-log-tls.sh` (exit code 0).

## Results
20 ok, 0 not ok, 0 skipped (TAP lines in logs/stdout.log).

## Failures
None.

## Reproduce
From the repository root at commit `2894faf`:

```
bash tests/userspace/test-addon-log-tls.sh
```
