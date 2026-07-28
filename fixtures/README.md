# Sanitized validation fixtures

This directory contains deliberately small, sanitized fixtures used to prove parser and workflow behavior without storing controlled, proprietary, or environment-specific data.

Fixture classes:
- `disa-xccdf/` — sanitized DISA-style STIG benchmark inputs.
- `network/` — sanitized Cisco IOS-XE Router NDM running configurations.
- `ontap/` and `bsd/` — plan-bound evidence v2 JSON. Each directory includes compliant, designed-finding, and typed transport-failure cases.
- `ckl/` — sanitized STIG Viewer checklist files.
- `cklb/` — sanitized JSON checklist files.

The transport-failure fixtures deliberately place an SSH diagnostic containing
`port 22` in failed stdout. End-to-end tests prove affected ONTAP and FreeBSD
rules become `Not_Reviewed`, the incomplete result cannot be persisted or
exported as compliance evidence, and CLI evaluation exits nonzero. Fixture
documents use the real generated plan digest and are rejected if the installed
collection plan changes. The sanitized success/finding fixtures exercise the
16 ONTAP, 3 FreeBSD, and 21 Cisco executable checks; they do not represent the
46 rules retained as manual across the reviewed candidate inventories.

These sanitized files validate deterministic and fail-closed behavior, but they do not substitute for acceptance against representative devices and the target system of record.
