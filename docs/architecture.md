# Architecture

AutomateSTIG is a Rust workspace with 11 crates and two binaries.

## Crate Map

| Crate | Purpose |
| --- | --- |
| `archive-safety` | Shared bounded ZIP parsing and archive policy enforcement. |
| `collector` | Shared fail-closed SSH transport and typed command evidence. |
| `core` | Shared models, check definitions, custody controls, and scanner contracts. |
| `parsers` | Supplemental CKLB/XCCDF and preserved transition-format parsing. |
| `storage` | SQLite persistence. |
| `stigpack` | `.stigpack` build, verify, import, manifest, hashes, and Ed25519 signing support. |
| `integrations` | STIG Manager lookup, sparse-review projection, remote no-op verification, and handoff integration. |
| `scanner` | Shared bundled-profile resolution, target-adapter collection, evidence validation, and deterministic evaluation application service. |
| `cli` | `automatestig` command-line binary. |
| `gui` | `automatestig-gui` local web GUI and HTTP API. |
| `tests` | Workspace integration tests. |

## Binaries

- `automatestig` - CLI.
- `automatestig-gui` - local web GUI.

## Scanner application flow

Both the CLI and GUI call the `scanner` crate for the authoritative scan path:

1. Resolve one immutable release-bundled profile and exact target/revision.
2. Bind an observed device fingerprint and preview a read-only adapter plan.
3. Collect authorized live evidence or validate an offline evidence/configuration artifact.
4. Reject unsupported versions and incomplete, denied, truncated, malformed, or ambiguous observations.
5. Deterministically evaluate scanner-owned rules and bind evidence/content/build provenance.
6. Return one native `ScannerEvaluation`. The CLI writes it as scanner-result
   JSON (or a complete-only supplemental CKLB) without saving legacy database
   state. The GUI persists the immutable run, encrypted replay evidence, and
   sparse handoff state in one local transaction.
7. A connected GUI run compares with current remote reviews. It confirms only
   an exact no-op remotely, keeps create/update rows in the verified
   selected-run handoff, and persists technical or reconciliation receipts
   without making a changed-review write.

Evaluation is deterministic and does not use AI or ML.

The product scanner path has no legacy transcript, answer-file,
prior-checklist merge, CKL export, or mutable-library evaluation branch.
Read-only migration tooling can inventory/export preserved pre-scanner data,
and a feature-enabled maintainer build can prepare content; neither can promote
preserved state into scanner-owned results.

The release scanner boundary is exactly ONTAP 9.x, FreeBSD/GPOS, and Cisco
IOS-XE Router NDM running configurations. See [Supported Targets](supported-targets.md);
format parsing and content-library breadth are not device support claims.

## Storage

Default data directory:

```text
~/.automatestig
```

Contents:

- `data.db`, including separately encrypted replay-evidence records
- encryption and trust material
- rotating structured logs
- a preserved `library/` only when transition/maintainer data already exists

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

The connected STIG Manager boundary selects the exact retained adapter for
server build `1.6.13+1`. Other reported versions fail capability discovery and
must use disconnected scanning plus a verified selected-run handoff.
