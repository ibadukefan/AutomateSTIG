# AutomateSTIG

**Cross-platform, open-source STIG evaluation and compliance automation.**

Zero to CKL in seconds. 100% deterministic. Air-gapped first. Built for DoD, Navy, NAVAIR, and contractor environments.

---

## Quick Start

```bash
# Clone
git clone https://github.com/ibadukefan/AutomateSTIG.git
cd AutomateSTIG

# Build
cargo build --release --workspace

# Launch the GUI
cargo run --release --bin automatestig-gui

# Or use the CLI
cargo run --release --bin automatestig -- --help
```

The GUI opens in your browser automatically. No Node.js, no npm, no external dependencies.

## What It Does

AutomateSTIG automates STIG checklist population from scan results, provides a modern answer file system, and generates audit-ready compliance artifacts. It replaces the manual process of populating .ckl files (1-4 hours per asset) with seconds-fast automation.

### Key Features

- **Auto-populate checklists** from SCC, ACAS, OpenSCAP scans and device config dumps
- **DISA auto-download** — fetches the latest STIGs directly from cyber.mil with one click
- **STIG-Manager integration** — push results directly via REST API with Result Engine metadata
- **Modern answer files** — JSON/YAML templates replace tedious XML
- **Built-in remediation** — PowerShell, Bash, and Ansible scripts
- **eMASS export** — CSV format for POA&M and control assessments
- **Drift detection** — compare evaluations over time, detect compliance regressions
- **Air-gapped mode** — generate offline .stigpack files for sandbox transfer
- **Plugin system** — extend with custom checks for new STIGs/platforms
- **Agent mode** — scheduled scans with automatic drift detection
- **Batch processing** — evaluate multiple assets against multiple STIGs in one operation
- **100% deterministic** — no AI, no ML, no probabilistic logic

## Architecture

Rust workspace with 8 crates:

```
crates/
  core/           Data models, evaluation engine, automated check system,
                  answer files, agent mode, drift detection, plugin system,
                  remote data collection framework
  parsers/        CKL, CKLB, XCCDF, Cisco config dump parsers
  storage/        SQLite persistence + audit logs
  stigpack/       .stigpack format (build, verify, import)
  remediation/    Remediation script generation
  integrations/   STIG-Manager API, eMASS export
  cli/            CLI binary with 12+ commands
  gui/            Desktop GUI (embedded web server + premium dark-mode frontend)
```

### Automated Check System

Checks are data-driven JSON definitions — no code changes when DISA updates STIGs:

```json
{
  "vuln_id": "V-254239",
  "platform": "windows",
  "check": {
    "type": "registry",
    "path": "HKLM\\SYSTEM\\...\\TLS 1.2\\Client",
    "value_name": "Enabled"
  },
  "expected": { "type": "equals", "value": 1 }
}
```

Supports: Windows registry, security policy, audit policy, services, features | Linux file content, file permissions, sysctl, packages | Cisco IOS/NX-OS/ASA config lines | command output | compound AND/OR checks.

## Desktop GUI

Launch with `cargo run --bin automatestig-gui`. Premium dark-mode interface:

| Page | Description |
|------|-------------|
| **Dashboard** | Compliance overview with stats grid, checklist table, progress bars |
| **Evaluate** | Select STIG + hostname, upload scan results, batch evaluate multiple hosts |
| **STIG Library** | Browse installed benchmarks, drill into individual rules by severity |
| **Checklists** | View all checklists, edit findings inline, export CKL/CKLB, push to STIG-Manager |
| **Get Content** | One-click download from DISA, browse available STIGs, export offline packs |
| **Import Files** | Drag-and-drop for CKL, CKLB, .stigpack, and DISA ZIP files |
| **Settings** | STIG-Manager OAuth2 config, agent mode, notifications |

## CLI

```bash
automatestig evaluate --stig Windows_Server_2022_STIG --scan results.xml --answer site-answers.yaml
automatestig disa-import --input U_Windows_Server_2022_STIG.zip
automatestig summary --input server01.ckl --open-only
automatestig export --input server01.ckl --output results.json --format stig-manager
automatestig convert --input old.ckl --output new.cklb
automatestig report --input server01.ckl --input server02.ckl --output compliance.html
automatestig build-pack --id my-pack --name "My Pack" --version 1.0.0 --source ./content --output my.stigpack
automatestig verify --pack update.stigpack
automatestig import --pack update.stigpack
automatestig library list
automatestig status
```

## Air-Gapped Workflow

For SCIF/sandbox environments with no internet:

1. **Connected machine**: run AutomateSTIG, click **Get Content** > **Get All STIGs**
2. Click **Export Pack** — generates a signed `.stigpack` with all current benchmarks
3. **Transfer** the `.stigpack` to the air-gapped system via USB/DVD
4. **Air-gapped machine**: click **Import Files** > drop the `.stigpack`

All content is SHA-256 verified on import.

## STIG-Manager Integration

One-click push from any checklist:

1. **Settings** > enter STIG-Manager API URL + Keycloak OAuth2 credentials
2. **Test Connection** to verify
3. From any checklist, click **Push** to send results directly
4. Results include **Result Engine metadata** — STIG-Manager shows them as automated evaluations

## Build & Test

```bash
cargo build --workspace           # Build all crates
cargo test --workspace            # Run 100+ tests
cargo clippy --workspace          # Lint (zero warnings)
cargo fmt --all                   # Format
cargo build --release             # Release build
```

## Design Principles

- **100% deterministic** — no AI/ML. Same inputs always produce same outputs.
- **Air-gapped first** — designed for disconnected environments. Connected mode is optional.
- **Signed content** — .stigpack files are SHA-256 + Ed25519 verified.
- **Audit-ready** — full evaluation logs in SQLite with timestamps, sources, evidence.
- **Data-driven** — checks are JSON definitions, not compiled code. Update content without updating the app.
- **Cross-platform** — native on Windows, macOS, Linux. Single binary, no runtime deps.

## License

MIT
