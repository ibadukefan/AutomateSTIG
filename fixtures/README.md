# Sanitized validation fixtures

This directory contains deliberately small, sanitized fixtures used to prove parser and workflow behavior without storing controlled, proprietary, or environment-specific data.

Fixture classes:
- `disa-xccdf/` — sanitized DISA-style STIG benchmark inputs.
- `network/` — sanitized Cisco IOS-XE Router NDM running configurations.
- `ontap/` and `bsd/` — plan-bound evidence v2 JSON. Each directory includes compliant, designed-finding, and typed transport-failure cases.
- `ckl/` — sanitized STIG Viewer checklist files.
- `cklb/` — sanitized JSON checklist files.
- `scanner_scenarios/` — synthetic analyst/manager workflow manifests that bind
  the device inputs to existing exact STIG Manager assignments and exercise
  sparse create/update previews, exact remote no-op verification, incomplete,
  conflict, and selected-run handoff behavior without credentials or live
  destinations.

The transport-failure fixtures deliberately place an SSH diagnostic containing
`port 22` in failed stdout. End-to-end tests prove affected ONTAP and FreeBSD
rules become `Not_Reviewed`, the incomplete result cannot be persisted or
exported as compliance evidence, and CLI evaluation exits nonzero. Fixture
documents use the real generated plan digest and are rejected if the installed
collection plan changes. The sanitized success/finding fixtures exercise the
15 ONTAP, 6 FreeBSD, and 33 Cisco executable checks. The reviewed profiles
also retain 40 rules for manual review and leave 180 full-benchmark rules
outside the reviewed scanner profile: ONTAP 15 automated/7 manual/22
reviewed/29 full, FreeBSD 6/24/30/203, and Cisco 33/9/42/42.

These sanitized files validate deterministic and fail-closed behavior, but they do not substitute for acceptance against representative devices and the target system of record.

Validate the scanner scenario contract with:

```bash
python3 scripts/validate-scanner-scenarios.py
```
