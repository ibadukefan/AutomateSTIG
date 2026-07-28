# STIG Manager Staging Rig

A containerized, real STIG Manager + Keycloak + MySQL used to prove the full
AutomateSTIG → STIG Manager round-trip without touching any production or
accredited environment. Demo-grade credentials throughout — run only on
localhost or in CI.

## What it proves

`run-staging-acceptance.py` drives the entire integration end to end:

1. Provisions a confidential OAuth2 client (service account + stig-manager
   scopes) in the demo Keycloak — the same client-credentials flow
   AutomateSTIG uses against a production STIG Manager.
2. Imports the authorized Cisco IOS-XE NDM benchmark into STIG Manager and creates
   a collection.
3. Starts `automatestig-gui`, imports the same benchmark, evaluates a sanitized
   running-config fixture, configures the STIG-Manager integration, and pushes the
   checklist through `POST /api/stigman/push/{checklist_id}`.
4. Independently verifies in STIG Manager that the asset exists and every
   review result matches the source checklist finding-for-finding.
5. Fetches the CKL **from STIG Manager** and confirms statuses round-trip —
   i.e. what reviewers later export (e.g. into Vulnerator) is what was pushed.
6. Runs `scripts/run-live-external-acceptance.py` against the rig.

## Usage

```bash
cargo build --release --locked --bin automatestig-gui
docker compose -f staging/stigman/docker-compose.yml up -d
python3 staging/stigman/run-staging-acceptance.py \
  --binary target/release/automatestig-gui \
  --evidence-output stig-manager-acceptance.json
docker compose -f staging/stigman/docker-compose.yml down -v
```

The protected workflow runs on demand via `.github/workflows/stigman-staging.yml`.
The compose file pins all three images by digest so a scheduled run cannot
silently change its acceptance environment. Updating a digest is a reviewed
dependency change: record the upstream version and rerun the entire rig.

Note: the STIG Manager images publish linux/amd64 only; the compose file pins
`platform: linux/amd64`, so Apple Silicon hosts run them under emulation.
