<p align="center">
  <strong>AutomateSTIG</strong><br>
  <em>Cross-platform STIG evaluation and compliance automation</em>
</p>

<p align="center">
  <a href="#features">Features</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="#cli-reference">CLI Reference</a> &middot;
  <a href="#comparison">Comparison</a> &middot;
  <a href="#contributing">Contributing</a>
</p>

---

**AutomateSTIG** is a deterministic, air-gapped-first STIG evaluation platform that automates checklist population from scan results, provides a modern answer file system, and generates audit-ready compliance artifacts.

- **100% Deterministic** &mdash; No AI, no ML, no probabilistic logic. Every result is reproducible.
- **Air-gapped first** &mdash; No network calls, no auto-updates. Designed for sandbox/SCIF environments.
- **Signed content** &mdash; All `.stigpack` files are SHA-256 verified with Ed25519 signatures.
- **Cross-platform** &mdash; Native binaries for Windows, macOS, and Linux. No PowerShell dependency.
- **Open source** &mdash; MIT licensed. Community contributions welcome.

---

## Features

**Core Evaluation**
- Auto-populate `.ckl` / `.cklb` checklists from SCC, ACAS/Tenable, and OpenSCAP scan results
- Parse XCCDF benchmarks directly from DISA downloads (`automatestig disa-import`)
- Evaluate Cisco IOS/NX-OS/ASA configurations against network STIGs
- JSON/YAML answer file system with validation, templates, and bulk operations
- Merge previous checklists to preserve manual entries across re-evaluations

**Output & Reporting**
- CKL, CKLB, and JSON output formats
- Professional HTML compliance reports with dark-mode styling
- STIG-Manager export with Result Engine metadata (marks automated results correctly)
- eMASS CSV export for POA&M and control assessment workflows

**Content Management**
- Signed `.stigpack` content packs with integrity verification and rollback
- Direct DISA XCCDF import from `cyber.mil` ZIP downloads
- STIG library with SHA-256 integrity checking on every load
- Version-controlled answer file templates

**Remediation**
- PowerShell, Bash, and Ansible script generation
- Risk levels (Low / Medium / High) and rollback support per script
- Remediation plans with reboot tracking

---

## Quick Start

### Install

```bash
# Build from source
git clone https://github.com/ibadukefan/AutomateSTIG.git
cd AutomateSTIG
cargo build --release

# The binary is at target/release/automatestig
```

### Initialize

```bash
# Set up the STIG library
automatestig library init

# Import STIG content from a DISA XCCDF ZIP (downloaded from cyber.mil)
automatestig disa-import --input U_MS_Windows_Server_2022_V1R4_STIG.zip

# Or import a signed .stigpack
automatestig import --pack quarterly-stigs-2024q4.stigpack
```

### Evaluate

```bash
# Evaluate a STIG against scan results
automatestig evaluate \
  --stig Windows_Server_2022_STIG \
  --scan scc_results.xml \
  --answer site-answers.yaml \
  --output webserver01.ckl

# View a summary
automatestig summary --input webserver01.ckl --open-only

# Generate an HTML report
automatestig report \
  --input webserver01.ckl \
  --input dbserver01.ckl \
  --output compliance-report.html \
  --title "Q4 2024 STIG Assessment"
```

### Convert & Export

```bash
# Convert between formats
automatestig convert --input old.ckl --output new.cklb

# Export to STIG-Manager
automatestig export \
  --input webserver01.ckl \
  --output results.json \
  --format stig-manager \
  --collection "NAVAIR Systems"

# Export to eMASS
automatestig export \
  --input webserver01.ckl \
  --output emass-results.csv \
  --format emass-csv
```

---

## Architecture

```
AutomateSTIG/
  crates/
    core/           Data models, rule engine, answer files, STIG library
    parsers/        CKL, CKLB, XCCDF, config dump parsers
    storage/        SQLite persistence layer
    stigpack/       .stigpack format (build, verify, import)
    remediation/    Remediation script generation
    integrations/   STIG-Manager, eMASS export
    cli/            CLI binary (automatestig)
    tests/          Cross-platform integration test suite
```

**Key design decisions:**

| Decision | Rationale |
|----------|-----------|
| Rust | Memory safety, performance, single-binary distribution, no runtime dependency |
| Data-driven rules | Content updates don't require code changes. Engine stays thin and stable. |
| SQLite | Single-file database, no server, portable across platforms |
| Signed packs | Zero-trust content model for air-gapped environments |
| No AI/ML | 100% deterministic results. Strengthens ATO case for DoD environments. |

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `evaluate` | Evaluate a STIG against scan results and answer files |
| `summary` | Show compliance summary of a checklist |
| `report` | Generate HTML compliance report from checklists |
| `convert` | Convert between CKL, CKLB, and JSON formats |
| `export` | Export to STIG-Manager or eMASS formats |
| `disa-import` | Import DISA STIG content from XCCDF files or ZIPs |
| `import` | Import a signed `.stigpack` content pack |
| `verify` | Verify a `.stigpack` file integrity and signature |
| `build-pack` | Build a `.stigpack` from source files |
| `gen-answer` | Generate answer file template from an existing checklist |
| `library list` | List installed STIG benchmarks |
| `library show` | Show details of a specific benchmark |
| `library init` | Initialize the STIG library |
| `status` | Show application and library status |

Use `automatestig <command> --help` for detailed usage.

---

## Comparison

See [docs/website/index.html](docs/website/index.html) for a thorough feature-by-feature comparison with Evaluate-STIG covering 50+ capabilities across core functionality, platform support, reliability, integrations, remediation, and architecture.

**Key advantages over Evaluate-STIG:**

| | Evaluate-STIG | AutomateSTIG |
|---|---|---|
| Platform | PowerShell (Windows-centric) | Native binary (Windows/macOS/Linux) |
| Distribution | CAC-only portals | Open source on GitHub |
| Content updates | Wait for NSWC Crane | Import public DISA XCCDF directly |
| Answer files | Tedious XML | JSON/YAML with validation |
| STIG-Manager | No native support | Full API export with Result Engine |
| Content signing | None | SHA-256 + Ed25519 |
| Report generation | No | Professional HTML reports |
| Remediation | Check only | Fix scripts with rollback |

---

## Build & Test

```bash
cargo build --workspace          # Build all crates
cargo test --workspace           # Run all tests (70 tests across 8 crates)
cargo clippy --workspace         # Lint (zero warnings)
cargo fmt --all                  # Format
cargo build --release            # Release build
```

The CI pipeline runs on **Windows, macOS, and Linux** via GitHub Actions.

---

## Content Pipeline

AutomateSTIG does **not** depend on government-provided software or CAC-protected portals for updates:

```
DISA publishes XCCDF on cyber.mil (public, quarterly)
  |
  v
automatestig disa-import --input <DISA_ZIP>
  |
  v
STIG Library updated with new benchmarks
  |
  v
automatestig evaluate --stig <ID> --scan <results.xml>
```

For controlled distribution, build signed `.stigpack` archives:

```bash
automatestig build-pack \
  --id quarterly-2024q4 \
  --name "Q4 2024 STIGs" \
  --version 2024.4.0 \
  --source ./pack-content/ \
  --output quarterly-2024q4.stigpack
```

---

## Contributing

AutomateSTIG is MIT licensed and welcomes contributions. See [CLAUDE.md](CLAUDE.md) for development instructions.

```bash
# Clone and build
git clone https://github.com/ibadukefan/AutomateSTIG.git
cd AutomateSTIG
cargo build --workspace
cargo test --workspace
```

---

<p align="center">
  <em>AutomateSTIG &mdash; Zero to CKL in seconds, with zero manual drudgery.</em>
</p>
