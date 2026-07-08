# API Reference

The GUI exposes an HTTP API under `/api`. All paths below are relative to `/api`.

Responses use this envelope:

```json
{
  "success": true,
  "data": {},
  "error": null
}
```

On failure, `success` is false and `error` contains the error message.

## Auth

Auth is enforced on every `/api/*` route except `/api/status`.

Use either:

- `X-Auth-Token` header.
- `?token=` query string for downloads.

Loopback desktop mode auto-generates a random per-session token and injects it into the served frontend, so the local browser is authenticated automatically. Non-loopback binds require `AUTOMATESTIG_AUTH_TOKEN` with at least 16 characters or the server refuses to start.

## Status

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/status` | Application status. |

## Library

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/library/benchmarks` | List installed benchmarks with real CAT counts. |
| GET | `/library/benchmarks/{id}` | Get benchmark detail. |
| POST | `/library/import-disa` | Multipart import of DISA XCCDF XML or ZIP content. |
| POST | `/library/import-stigpack` | Multipart import of a `.stigpack`. |
| POST | `/library/generate-checks/{id}` | Generate checks for a benchmark. |

## Checklists

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/checklists` | List checklists. |
| GET | `/checklists/{id}` | Get checklist detail. |
| DELETE | `/checklists/{id}` | Delete a checklist. |
| POST | `/checklists/import` | Multipart import of a checklist. |
| PATCH | `/checklists/{id}/findings/{vuln_id}` | Update finding status/details/comments. |
| POST | `/checklists/{id}/re-evaluate` | Re-evaluate a checklist. |

## Evaluate

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/evaluate` | Evaluate with JSON body containing `stig_id`, `hostname`, and optional `asset_id`. |
| POST | `/evaluate/batch` | Batch evaluation. |
| POST | `/evaluate/with-scan` | Multipart evaluation with scan file and optional `asset_id`. |

## DISA

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/disa/available` | List available DISA downloads. |
| POST | `/disa/fetch` | Fetch one DISA item. |
| POST | `/disa/fetch-all` | Fetch DISA items in bulk. |
| GET | `/disa/check-updates` | Check available DISA updates. |

## Offline Pack

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/offline-pack` | Generate an offline `.stigpack`. |

## STIG-Manager

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/stigman/config` | Get STIG-Manager config. |
| POST | `/stigman/config` | Save STIG-Manager config. |
| POST | `/stigman/test` | Test STIG-Manager connection. |
| GET | `/stigman/collections` | List collections. |
| GET | `/stigman/collections/{cid}/assets` | List collection assets. |
| POST | `/stigman/sync/{cid}` | Sync collection assets. |
| GET | `/stigman/diff/{cid}` | Diff collection assets. |
| POST | `/stigman/push/{checklist_id}` | Push checklist reviews. |

## Remote Scan

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/scan/ssh` | Run SSH collection. |

## Assets

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/assets` | List assets. |
| POST | `/assets` | Create asset. |
| GET | `/assets/{id}` | Get asset. |
| PUT | `/assets/{id}` | Update asset. |
| DELETE | `/assets/{id}` | Delete asset. |
| POST | `/assets/bulk-assign-stig` | Bulk assign STIGs. |
| POST | `/assets/bulk-update` | Bulk update assets. |

## Credentials

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/credentials` | List credentials. |
| POST | `/credentials` | Create credential. |
| DELETE | `/credentials/{id}` | Delete credential. |

## Answer Files

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/answer-files` | List answer files. |
| POST | `/answer-files` | Save answer file. |

## Export

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/export/ckl/{id}` | Export CKL. |
| GET | `/export/cklb/{id}` | Export CKLB. |
| GET | `/export/all-zip` | Export all checklists as ZIP. |
