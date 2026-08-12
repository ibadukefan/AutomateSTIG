# AutomateSTIG

Deterministic STIG evidence collection and evaluation for three hard-to-scan
targets: NetApp ONTAP 9.x, FreeBSD/GPOS, and Cisco IOS-XE Router NDM running
configurations. The shipped boundary is 54 executable checks across 94 reviewed
candidate rules; importing other benchmarks does not add scanner support.

## Architecture

Rust workspace with these crates:

- `crates/archive-safety` — bounded ZIP/archive validation
- `crates/collector` — fail-closed SSH transport and typed outcomes
- `crates/core` — shared contracts, models, custody controls, and checks
- `crates/parsers` — CKL, CKLB, XCCDF, and transition-format parsers
- `crates/storage` — SQLite persistence
- `crates/stigpack` — signed `.stigpack` build, verification, and import
- `crates/integrations` — STIG Manager lookup, sparse handoff, and exact no-op verification
- `crates/scanner` — shared profile, adapter, collection, and evaluation service
- `crates/cli` — analyst CLI plus separately gated transition tooling
- `crates/gui` — localhost scanner GUI and API
- `crates/tests` — workspace integration tests

## Build & Test

```bash
cargo build --workspace        # Build all crates
cargo test --workspace         # Run all tests
cargo build --release          # Release build
cargo clippy --workspace       # Lint
cargo fmt --all                # Format
```

## Key Design Principles

- **100% deterministic** — No AI, no ML, no probabilistic logic
- **Air-gapped first** — Connected DISA, STIG Manager, and SSH operations are opt-in
- **Signed content** — Normal .stigpack build/import workflows require Ed25519 trust and SHA-256 integrity
- **STIG Manager boundary** — AutomateSTIG produces scanner evidence and sparse handoffs; assets, assignments, human review, governance, and reporting remain in STIG Manager
- **Traceable results** — Evaluation and handoff state append SQLite audit events; changed-review reconciliation remains an approved receiver responsibility
- Third-party versions are reproducible through the committed `Cargo.lock`
