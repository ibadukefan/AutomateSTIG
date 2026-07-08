# AutomateSTIG

Cross-platform, open-source STIG evaluation and compliance automation platform.

## Architecture

Rust workspace with these crates:
- `crates/core` — Data models, rule engine, answer files, STIG library
- `crates/parsers` — CKL, CKLB, XCCDF, config dump parsers
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
- **Air-gapped first** — No network calls, no auto-updates
- **Signed content** — All .stigpack files are SHA-256 verified
- **Audit-ready** — Full traceability, evaluation logs in SQLite
- All third-party dependencies are pinned in Cargo.toml
