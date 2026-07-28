# AutomateSTIG

Deterministic STIG evidence collection and evaluation for three hard-to-scan
targets: NetApp ONTAP 9.x, FreeBSD/GPOS, and Cisco IOS-XE Router NDM running
configurations. The shipped boundary is 37 executable checks across 86 reviewed
candidate rules; importing other benchmarks does not add scanner support.

## Architecture

Rust workspace with these crates:
- `crates/core` — Data models, rule engine, answer files, STIG library
- `crates/parsers` — CKL, CKLB, XCCDF, and evidence transcript parsers
- `crates/storage` — SQLite persistence layer
- `crates/stigpack` — .stigpack format (build, verify, import)
- `crates/integrations` — STIG-Manager export/push
- `crates/cli` — CLI binary (`automatestig`)

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
- **Traceable changes** — Evaluation and manual finding changes append SQLite audit events; external system-of-record acceptance remains deployment-specific
- Third-party versions are reproducible through the committed `Cargo.lock`
