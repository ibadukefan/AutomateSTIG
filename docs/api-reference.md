# API Reference

The scanner GUI exposes its supported API under `/api/v1`. Paths in the
scanner-first table below are written relative to `/api`. Unversioned workflow
routes are retired compatibility seams, not a product contract for new clients.

Responses use this envelope:

```json
{
  "success": true,
  "data": {},
  "error": null
}
```

On failure, `success` is false and `error` contains the error message.
Scanner-first handlers use meaningful HTTP status codes and typed error codes;
clients must always inspect both the status and response envelope.

## Auth

Auth is enforced on every `/api/*` route except the status endpoint.

Use the `X-Auth-Token` header. Download endpoints require the header too;
query-string tokens are intentionally not accepted.

Loopback desktop mode auto-generates a random per-session token and injects it
into the served frontend, so the local browser is authenticated automatically.
Non-loopback binds require `AUTOMATESTIG_AUTH_TOKEN` with at least 16 visible
ASCII characters and no whitespace or the server refuses to start.

## Scanner-first v1

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/status` | Scanner/API version and readiness. |
| GET | `/v1/stig-manager/connection` | Return sanitized connection state; never the client secret. |
| PUT | `/v1/stig-manager/connection` | Save one HTTPS API/OAuth destination. |
| DELETE | `/v1/stig-manager/connection` | Remove saved destination credentials only. |
| POST | `/v1/stig-manager/connection/test` | Test submitted values and return version, capabilities, and privileges. |
| GET | `/v1/stig-manager/collections` | Read live available collections. |
| GET | `/v1/stig-manager/collections/{collection_id}/assets` | Read live existing assets. |
| GET | `/v1/stig-manager/collections/{collection_id}/assets/{asset_id}/assignments` | Read exact assignments and scanner readiness reasons. |
| GET | `/v1/scanner/profiles` | List exact release-bundled profiles, hashes, compatibility, coverage, and readiness. |
| POST | `/v1/runs/preflight` | Bind destination, target fingerprint, exact profile, privilege, and read-only operation plan. |
| POST | `/v1/runs/ssh` | Enqueue an authorized ONTAP/FreeBSD live collection from a valid preflight; returns `202` before device I/O. |
| POST | `/v1/runs/evidence` | Start strict evidence or IOS-XE configuration evaluation from a valid preflight. |
| GET | `/v1/runs/jobs` | List durable SSH coordination jobs; submitted credentials are never returned or persisted. |
| GET | `/v1/runs/jobs/{job_id}` | Read queued/running/completed/failed SSH job state and its resulting run ID, when complete. |
| GET | `/v1/runs` | List short-lived technical scan and handoff records. |
| GET | `/v1/runs/{run_id}` | Read run steps, immutable result/provenance, sparse preview, attempts, and receipt. |
| POST | `/v1/runs/{run_id}/deliver` | Recheck remote ownership/state; confirm an exact no-op or return an actionable handoff/conflict result. |
| GET | `/v1/runs/{run_id}/handoff` | Download the selected-run handoff for any complete run. |

Connected preflight requires a live existing collection, asset, assignment, and
exact STIG revision; the API has no asset-create or assignment mutation.
Preflight returns a short-lived single-use token bound to all nonsecret inputs.
Device credentials and passphrases are accepted only with preflight/run
submission and are never present in run or connection responses.

A complete connected run persists its immutable result, separately encrypted
replay evidence, and sparse handoff state in one transaction. Incomplete runs
have no handoff. The preview contains only scanner-owned evaluations.
Create/update rows are handoff-only because the current STIG Manager API has no
atomic conditional review precondition. `POST .../deliver` can record a
technical receipt only when the exact scanner result is already present
remotely; a conflict remains blocked. Long-running SSH collection returns a
job identifier and is observed through the job endpoints.

The handoff endpoint emits
`automatestig.selected-run-handoff.v3`. Its required payloads are
`manifest.json`, `scanner-run.json`, `sparse-reviews.json`, `fallback.cklb`,
`results.xccdf.xml`, and `integrity.json`; retained bundles also contain
`evidence-envelope.json`. The staged STIG Manager transport maps
`sparse-reviews.json` to the Review API for the existing exact assignment.
The XCCDF 1.2 and CKLB members are digest-bound supplemental projections, not
reference STIG content, asset/assignment creation requests, or evidence that a
native file-import workflow was exercised. An incomplete run receives `409
handoff_not_available` instead of a partial export.

## Retired unversioned API

Do not build clients against unversioned routes. Every former unversioned
product route below, for reads and writes alike, returns HTTP `410 Gone` with
`data.code = "legacy_surface_retired"` and migration guidance. They do not
create assets, change assignments or reviews, run a scan outside the versioned
run service, import a broad catalog, or produce a portfolio export.

| Retired capability | Routes returning `410 Gone` |
| --- | --- |
| Broad library/content management | `/library/benchmarks`, `/library/benchmarks/{id}`, `/library/import-disa`, `/library/import-stigpack`, `/disa/available`, `/disa/fetch`, `/disa/fetch-all`, `/disa/check-updates`, `/offline-pack`, `/offline-pack/trust-key` |
| Local checklist portfolio and review state | `/checklists`, `/checklists/import`, `/checklists/{id}`, `/checklists/{id}/findings/{vuln_id}`, `/answer-files`, `/answer-files/{id}`, `/audit-log` |
| Local asset and assignment state | `/assets`, `/assets/{id}`, `/assets/bulk-assign-stig`, `/assets/bulk-update` |
| Portfolio and selected-checklist exports | `/export/ckl/{id}`, `/export/cklb/{id}`, `/export/all-zip` |
| Old STIG Manager connection, mirror, and push surface | `/stigman/config`, `/stigman/test`, `/stigman/collections`, `/stigman/collections/{collection_id}/assets`, `/stigman/sync/{collection_id}`, `/stigman/diff/{collection_id}`, `/stigman/push/{checklist_id}` |
| Run-service bypass | `/evaluate/with-evidence`, `/scan/ssh` |

Only `/api/v1`, `/api/status`, and `/api/auth/check` perform runtime work.
Unknown `/api/v1` paths return `404`, not a legacy tombstone. Use the verified
selected-run handoff for changed reviews and STIG Manager for inventory, human
review, governance, reporting, and long-term history. Preserved local data is
available through the separate transition CLI, not the retired HTTP surface.
