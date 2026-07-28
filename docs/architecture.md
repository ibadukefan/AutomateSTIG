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
| `integrations` | STIG-Manager export and push integration code. |
| `cli` | `automatestig` command-line binary. |
| `gui` | `automatestig-gui` local web GUI and HTTP API. |
| `tests` | Workspace integration tests. |

## Binaries

- `automatestig` - CLI.
- `automatestig-gui` - local web GUI.

## Evaluation Engine Flow

1. Load a benchmark from the local library.
2. Initialize checklist findings from benchmark rules.
3. Evaluate device evidence/configuration with structured checks.
4. Apply answer files.
5. Merge prior checklist entries when requested.
6. Export results or persist checklist state.

Evaluation is deterministic and does not use AI or ML.

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

The GUI uses SQLite persistence through the storage crate.

## Embedded GUI

The GUI is served by the `automatestig-gui` binary as a local web application. It binds to `127.0.0.1` on a random port unless `PORT` is set, opens the browser automatically, and injects the per-session auth token into the served frontend in loopback desktop mode.

## Offline And Connected Boundaries

No network calls are made by default. These features are connected and opt-in:

- DISA fetch and update checks.
- STIG-Manager calls.
- Remote SSH collection.
