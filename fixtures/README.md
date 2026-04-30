# Sanitized validation fixtures

This directory contains deliberately small, sanitized fixtures used to prove parser and workflow behavior without storing controlled, proprietary, or environment-specific data.

Fixture classes:
- `disa-xccdf/` — sanitized DISA-style STIG benchmark inputs.
- `scc-results/` — sanitized SCC XCCDF result output.
- `openscap-results/` — sanitized OpenSCAP XCCDF result output.
- `ckl/` — sanitized STIG Viewer checklist files.
- `cklb/` — sanitized JSON checklist files.

These are not full DISA releases. Full replacement readiness requires adding authorized real-world fixture corpora and updating `docs/validation-report.md`.
