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

Handlers also return meaningful HTTP statuses. Content import uses `400` for
malformed input, `413` for size/decompression limits, `415` for unsupported
media, `422` for structurally invalid content, and `500` for local storage.
Connected DISA fetch failures use `502` after the initial request has passed URL
validation. Partial SSH/evidence evaluations return `207` without persisting a
checklist, with `collection_complete=false` and keyed `collection_errors`.

## Auth

Auth is enforced on every `/api/*` route except `/api/status`.

Use:

- `X-Auth-Token` header.

Download endpoints also require the header; query-string tokens are intentionally not accepted.

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

Each import endpoint accepts exactly one file. DISA uploads are capped at 32
MiB compressed ZIP input (raw XML at 16 MiB); `.stigpack` uploads are capped at
256 MiB. Parsing/decompression runs off the async request executor, all library
writes are serialized, and a multi-benchmark file commits as one batch.

Raw DISA/XCCDF import installs benchmark reference content only. It never turns
check prose into executable scanner decisions. Additional executable checks must
arrive in a trusted, signed `.stigpack`.

## Checklists

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/checklists` | List checklists. |
| GET | `/checklists/{id}` | Get checklist detail. |
| DELETE | `/checklists/{id}` | Delete a checklist. |
| POST | `/checklists/import` | Multipart import of a checklist. |
| PATCH | `/checklists/{id}/findings/{vuln_id}` | Update finding status/details/comments. |

Checklist list and detail responses expose two distinct optional score fields:

- `assessed_pass_pct`: `NotAFinding / (NotAFinding + Open) * 100`.
  `NotApplicable` and `NotReviewed` are excluded from this denominator.
- `benchmark_coverage_pct`: `assessed controls / total benchmark controls * 100`.

`compliance_pct` is retained as a deprecated compatibility alias for
`assessed_pass_pct`. New clients should use the explicit fields. Scores are
`null` for imported or otherwise unverified results; the raw finding counts
remain available, but must not be presented as a verified grade.

## Evaluate

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/evaluate/with-evidence` | Multipart evaluation with `stig_id`, `hostname`, `platform`, `input_type`, `evidence`, optional `asset_id`, and the Cisco policy fields described below. |

`input_type=config` is accepted for Cisco IOS-XE Router NDM running configurations. `input_type=transcript` requires strict `automatestig-evidence/v2` JSON for ONTAP or FreeBSD. The document's platform and plan digest must match the selected platform and currently installed check pack. Marker-based v1 evidence is rejected; unlike the CLI migration switch, the API has no unsafe legacy override.

Cisco configuration evaluation also requires both `organization_policy` and
`organization_policy_signature` multipart files. They must be supplied as a
pair, are rejected for transcript evaluation, and are verified against the
dedicated organization-policy trust directory before any result is produced.

A complete evaluation returns HTTP `200`. If one or more typed collection records failed validation, successfully collected rules still evaluate and dependent rules become `Not_Reviewed`; the API returns HTTP `207 Multi-Status`. The response remains in the standard envelope and adds:

```json
{
  "success": true,
  "data": {
    "collection_complete": false,
    "collection_errors": {
      "cluster time-service ntp server show": "SSH channel closed without an exit status"
    },
    "evaluation_errors": ["V-246935: Command collection failed: SSH channel closed without an exit status"],
    "id": null,
    "persisted": false,
    "assessed_pass_pct": null,
    "benchmark_coverage_pct": null,
    "compliance_pct": null
  },
  "error": null
}
```

## DISA

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/disa/available` | List available DISA downloads. |
| POST | `/disa/fetch` | Fetch one DISA item. |
| POST | `/disa/fetch-all` | Fetch DISA items in bulk. |
| GET | `/disa/check-updates` | Check available DISA updates. |

`/disa/fetch` accepts only exact allowlisted DISA HTTPS hosts, validates every
redirect, and counts at most 32 MiB of response bytes regardless of the remote
`Content-Length` header.

## Offline Pack

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/offline-pack` | Generate an offline `.stigpack` only when an external signing key is explicitly configured. |
| GET | `/offline-pack/trust-key` | Download that external key's public trust anchor. |

Both endpoints return `503 Service Unavailable` by default. Enabling them
requires `AUTOMATESTIG_OFFLINE_SIGNING_KEY` to name an existing key outside the
application data directory; no API request creates or stores key material.
Prefer signing through the CLI on an offline signing workstation.

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

The request selects a STIG/check-pack plan and carries one SSH authentication object:

```json
{
  "host": "filer.example.mil",
  "port": 22,
  "username": "scanner",
  "auth": { "type": "password", "password": "session-secret" },
  "stig_id": "NetApp_ONTAP_DSC_9-x_STIG",
  "platform": "ontap"
}
```

Key authentication uses `{"type":"key_file","path":"/approved/id_ed25519","passphrase":null}`. The configured server process must be able to read that path. Unknown server keys are rejected unless the operator explicitly enables trust-on-first-use enrollment; a changed enrolled key is always rejected.

The endpoint executes the generated plan through the shared SSH collector. Stdout, stderr, exit status, timeout, protocol, and output-limit states remain separate. An ONTAP `Error:` envelope is a semantic failure even with SSH exit status zero. FreeBSD's `service auditd onestatus` exit status 1 is accepted only as the successfully observed stopped-service state.

Complete collection returns HTTP `200`. Incomplete collection returns HTTP `207 Multi-Status` and an append-only `evaluation.incomplete` audit event, but no checklist is persisted. The response includes:

- `collection_complete`: `false`.
- `collection_errors`: map of plan data key to collection/validation error.
- `evaluation_errors`: affected rule IDs and their collection/evaluation errors.
- `id`: `null` and `persisted`: `false`.
- `assessed_pass_pct`, `benchmark_coverage_pct`, and the deprecated
  `compliance_pct` alias: `null`.
- `server_key_fingerprint`: the observed SHA-256 SSH server-key fingerprint, when a key exchange completed.

No failed command's stdout can be evaluated as compliance evidence. The diagnostic response identifies dependent `Not_Reviewed` rules, but no partial result can be edited, exported, or pushed as compliance evidence.

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

## Answer Files

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/answer-files` | List answer files. |
| POST | `/answer-files` | Save answer file. |

## Audit Trail

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/audit-log` | Read append-only checklist evaluation, import, edit, and deletion events with snapshots. |

## Export

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/export/ckl/{id}` | Export CKL. |
| GET | `/export/cklb/{id}` | Export CKLB. |
| GET | `/export/all-zip` | Export all checklists as ZIP. |
