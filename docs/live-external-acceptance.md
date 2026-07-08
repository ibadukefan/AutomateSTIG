# Live External Acceptance

AutomateSTIG now has two external workflow gates:

1. `scripts/validate-external-workflows.py` — offline contract validation for CKL, CKLB, STIG Manager JSON, and DISA XCCDF ZIP fixtures. This runs in default CI.
2. `scripts/run-live-external-acceptance.py --require-live` — live acceptance smoke checks against configured external tools/services. This must be run in a controlled staging environment because it requires external tooling, network endpoints, and non-production credentials.

## Required live configuration

Set these only in a controlled acceptance environment. Do not commit values.

```bash
export STIG_VIEWER_CLI=/path/to/stig-viewer-cli-or-wrapper
export STIG_MANAGER_URL=https://stig-manager.example.test
export STIG_MANAGER_TOKEN=...
python3 scripts/run-live-external-acceptance.py --repo-root . --require-live
```

The script redacts by design: it reports only success/failure and does not print tokens or response bodies.

## Current status

No live STIG Viewer or STIG Manager endpoint/credential configuration is present in normal CI, so the default CI gate verifies offline contract compatibility and reports live checks as skipped. Full production replacement claims still require an acceptance run with `--require-live` against authorized staging instances.

## Containerized staging rig

`staging/stigman/` provides a docker-compose rig (real STIG Manager, demo Keycloak, MySQL) plus `run-staging-acceptance.py`, which proves the full AutomateSTIG -> STIG Manager round-trip: OAuth2 client-credentials auth, DISA benchmark import, checklist push, review-for-review verification, and a CKL export from STIG Manager that must match what was pushed. CI runs it weekly and on demand via `.github/workflows/stigman-staging.yml`; see `staging/stigman/README.md` for local usage.
