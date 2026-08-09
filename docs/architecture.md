# Architecture

AutomateSTIG is a Rust workspace with 10 crates and two binaries.

## Crate Map

| Crate | Purpose |
| --- | --- |
| `archive-safety` | Shared bounded ZIP parsing and archive policy enforcement. |
| `collector` | Shared fail-closed SSH transport and typed command evidence. |
| `core` | Data models, deterministic evaluation engine, checks, and answer files. |
| `parsers` | CKL, CKLB, XCCDF, and strict evidence v2 parsing/plan binding. |
| `storage` | SQLite persistence. |
| `stigpack` | `.stigpack` build, verify, import, manifest, hashes, and Ed25519 signing support. |
| `integrations` | STIG Manager lookup, sparse-review projection, remote no-op verification, and handoff integration. |
| `cli` | `automatestig` command-line binary. |
| `gui` | `automatestig-gui` local web GUI and HTTP API. |
| `tests` | Workspace integration tests. |

## Binaries

- `automatestig` - CLI.
- `automatestig-gui` - local web GUI.

## Scanner application flow

1. Resolve one immutable release-bundled profile and exact target/revision.
2. Bind an observed device fingerprint and preview a read-only adapter plan.
3. Collect authorized live evidence or validate an offline evidence/configuration artifact.
4. Reject unsupported versions and incomplete, denied, truncated, malformed, or ambiguous observations.
5. Deterministically evaluate scanner-owned rules and bind evidence/content/build provenance.
6. Persist the immutable run, encrypted replay evidence, and sparse handoff
   state in one local transaction.
7. Compare with current remote reviews. Confirm only an exact no-op remotely;
   keep create/update rows in the verified selected-run handoff, and persist
   technical or reconciliation receipts without making a changed-review write.

Evaluation is deterministic and does not use AI or ML.

Legacy library, answer-file, checklist merge, and conversion paths remain only
for the non-destructive transition and maintainer tooling. They cannot promote
manual/imported state into scanner-owned results.

The release scanner boundary is exactly ONTAP 9.x, FreeBSD/GPOS, and Cisco
IOS-XE Router NDM running configurations. See [Supported Targets](supported-targets.md);
format parsing and content-library breadth are not device support claims.

## Storage

Default data directory:

```text
~/.automatestig
```

Contents:

- `data.db`
- `library/`

The GUI uses SQLite persistence through the storage crate. Scanner-first tables
retain scan run state, immutable result/provenance JSON, separately encrypted
and expiring replay evidence, a transactional handoff/outbox record, retry
leases, conflicts, and receipts. Existing asset,
checklist, answer-file, and audit tables are preserved during the migration
window but do not become authoritative STIG Manager mirrors.

## Embedded GUI

The GUI is served by the `automatestig-gui` binary as a local web application. It binds to `127.0.0.1` on a random port unless `PORT` is set, opens the browser automatically, and injects the per-session auth token into the served frontend in loopback desktop mode.

## Offline And Connected Boundaries

Disconnected scan/evaluation makes no destination call. These features are
connected and opt-in:

- Live STIG Manager collection/asset/assignment lookup, ownership preview,
  exact no-op verification, and selected-run handoff generation. Changed
  reviews cross the boundary only through a verified handoff into the existing
  exact assignment.
- Remote SSH collection.

Broad DISA fetch/import is maintainer or legacy transition tooling, not a
normal scanner GUI workflow.
