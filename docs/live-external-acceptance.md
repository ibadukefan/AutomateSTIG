# Live External Acceptance

AutomateSTIG now has two external workflow gates:

1. `scripts/validate-external-workflows.py` — offline contract validation for CKL, CKLB, STIG Manager JSON, eMASS CSV, and DISA XCCDF ZIP fixtures. This runs in default CI.
2. `scripts/run-live-external-acceptance.py --require-live` — live acceptance smoke checks against configured external tools/services. This must be run in a controlled staging environment because it requires external tooling, network endpoints, and non-production credentials.

## Required live configuration

Set these only in a controlled acceptance environment. Do not commit values.

```bash
export STIG_VIEWER_CLI=/path/to/stig-viewer-cli-or-wrapper
export STIG_MANAGER_URL=https://stig-manager.example.test
export STIG_MANAGER_TOKEN=...
export EMASS_URL=https://emass.example.test/api/...
export EMASS_API_KEY=...
python3 scripts/run-live-external-acceptance.py --repo-root . --require-live
```

The script redacts by design: it reports only success/failure and does not print tokens or response bodies.

## Current status

No live STIG Viewer, STIG Manager, or eMASS endpoint/credential configuration is present in normal CI, so the default CI gate verifies offline contract compatibility and reports live checks as skipped. Full production replacement claims still require an acceptance run with `--require-live` against authorized staging instances.
