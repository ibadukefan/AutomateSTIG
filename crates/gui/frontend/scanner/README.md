# Scanner-first frontend

This directory is the self-contained ES-module frontend served by the
AutomateSTIG scanner GUI. The Rust server exposes the versioned API and injects
the loopback in-memory auth token into `scanner/index.html`. The frontend also
accepts `window.__AUTH_TOKEN__` and otherwise offers a memory-only access-token
field under Connection for protected non-loopback deployments. Tokens and
device secrets are never written to browser storage.

## Modules

- `app.js`: session mode, first-open behavior, shell composition, and routing.
- `api.js`: `/api/v1` transport, envelope normalization, helpful availability
  errors, run polling, and memory-only API auth.
- `router.js`: stable Scan, Deliveries, Scanner Content, and Connection hashes.
- `scan.js`: live destination selection, collection-method inputs, preflight,
  collection/evaluation progress, and the read-only delivery preview.
- `deliveries.js`: durable run list, result preview, sparse-review proposals,
  handoffs, remote no-op checks, immutable receipts, and STIG Manager deep link.
- `content.js`: exact scanner profiles, trust, compatibility, coverage boundary,
  and acceptance status. It contains no broad benchmark catalog or imports.
- `connection.js`: save/test/disconnect for one STIG Manager destination.
- `ui.js`: dependency-free accessible DOM helpers.

## Expected API contract

All JSON endpoints may return data directly or inside the existing
`{ "success": true, "data": ... }` envelope. Errors should include an HTTP
status and preferably `{ "error": { "code", "message", "details" } }`.

| Method | Path | Expected result |
| --- | --- | --- |
| `GET` | `/api/v1/status` | Scanner/API version and readiness. |
| `GET` | `/api/v1/stig-manager/connection` | Sanitized connection state; never the saved client secret. |
| `PUT` | `/api/v1/stig-manager/connection` | Save HTTPS API/token URLs, client ID/secret, and TLS policy. |
| `DELETE` | `/api/v1/stig-manager/connection` | Remove the saved destination credentials only. |
| `POST` | `/api/v1/stig-manager/connection/test` | Test submitted, unsaved values and return identity, version, capabilities, and privileges. |
| `GET` | `/api/v1/stig-manager/collections` | Live collections available to the service account. |
| `GET` | `/api/v1/stig-manager/collections/{collectionId}/assets` | Live existing assets in the selected collection. |
| `GET` | `/api/v1/stig-manager/collections/{collectionId}/assets/{assetId}/assignments` | Assigned STIGs, exact revisions, scanner-profile IDs, readiness, and unsupported reasons. |
| `GET` | `/api/v1/scanner/profiles` | Exact release-bundled profiles with methods, trust, hashes, tested versions, and automated/manual/reviewed/full counts. |
| `POST` | `/api/v1/runs/preflight` | Bound destination/target compatibility and visible read-only operation plan plus a short-lived `preflight_token`. |
| `POST` | `/api/v1/runs/ssh` | Enqueue a durable live-collection job and return `202` with `job_id` before device I/O. |
| `POST` | `/api/v1/runs/evidence` | Run a multipart evidence/configuration evaluation and return its immutable run identity. |
| `GET` | `/api/v1/runs/jobs` | List durable SSH coordination jobs without credentials. |
| `GET` | `/api/v1/runs/jobs/{jobId}` | Read queued/running/completed/failed job state and resulting run identity. |
| `GET` | `/api/v1/runs` | Short-lived operational run/delivery records. |
| `GET` | `/api/v1/runs/{runId}` | Current steps, immutable result, sparse delivery preview, attempts, and receipt. |
| `POST` | `/api/v1/runs/{runId}/deliver` | Recheck remote state and confirm only an exact no-op; changed reviews remain handoff-only. |
| `GET` | `/api/v1/runs/{runId}/handoff` | Download the verified selected-run handoff for a complete run. |

Collection and asset IDs are always selected before a connected preflight.
Assignments must bind an exact STIG revision to a scanner profile. A preflight
response should resemble:

```json
{
  "ready": true,
  "preflight_token": "opaque-short-lived-token",
  "device_identity": { "hostname": "filer01", "version": "9.15.1" },
  "compatibility": { "supported": true, "observed_version": "9.15.1" },
  "privilege": { "summary": "read-only commands authorized" },
  "operations": [
    { "name": "Read NTP configuration", "command": "cluster time-service ntp server show" }
  ]
}
```

The run detail exposes `state`, `stage`, step states, immutable evidence
and provenance, collection completeness, and a delivery object. Its delivery
preview contains only scanner-owned reviews and reports create/update/unchanged
or conflict disposition plus manual/out-of-scope counts that remain untouched.
The delivery object should retain the exact request digest, every attempt,
remote IDs, exact-no-op receipt, and an HTTPS `remote_url` for **Open in STIG Manager**.
Create/update previews are safety-gated when the destination lacks an atomic
conditional-write contract; only an exact remote no-op is confirmed directly.

Every complete run returns a same-origin `/api/v1/...` `handoff_url`. That
artifact is one selected-run delivery bundle, not a local checklist portfolio.
Replay evidence is encrypted separately and expires under the configured local
retention policy; immutable result hashes and purge metadata remain available.

## Local checks

From this directory, with Node 24 or later:

```bash
npm run check
npm test
```
