# AutomateSTIG

AutomateSTIG is a cross-platform, offline-capable STIG evaluation and compliance automation platform. It is a Rust workspace with 9 crates and two binaries:

- `automatestig` - command-line interface
- `automatestig-gui` - local web GUI

Evaluation is deterministic. There is no AI or ML in the evaluation path. The default workflow makes no network calls; DISA fetching, STIG-Manager integration, remote SSH/WinRM scanning, and webhooks are opt-in connected features.

## Features

- Import DISA XCCDF XML or ZIP benchmark content.
- Evaluate benchmarks from scan results, answer files, and installed check packs.
- Generate and persist deterministic auto check packs from structured DISA check content where possible.
- Manage assets, assessments, findings, reports, schedules, credentials, and STIG-Manager settings in the local GUI.
- Export CKL, CKLB, STIG-Manager JSON, eMASS CSV, HTML reports, remediation scripts, and offline `.stigpack` transfer packs.
- Run local, batch, scheduled, and remote SSH/WinRM-backed evaluations when the needed live infrastructure is available.
- Keep air-gapped workflows first-class through local storage, signed `.stigpack` import, and offline pack generation.

## Quick Start

Install the prebuilt binaries — one command for your OS:

```bash
# macOS
curl -fsSL https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-macos.sh | sh

# Linux
curl -fsSL https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-linux.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-windows.ps1 | iex
```

See [installation](docs/installation.md) for manual release downloads, checksums, and build-from-source instructions.

Build from source requires the Rust stable toolchain.

```bash
cargo build --release --workspace
```

Run the GUI:

```bash
cargo run --release --bin automatestig-gui
```

The GUI binds to `127.0.0.1` on a random port unless `PORT` is set, opens the browser automatically, and stores data in `~/.automatestig` (`data.db` plus `library/`).

Run the CLI:

```bash
cargo run --release --bin automatestig -- --help
cargo run --release --bin automatestig -- status
```

## GUI

The actual GUI navigation pages are:

- Overview
- Assessments
- Assets
- Standards
- Findings
- Reports
- Settings

Checklist detail opens from assessment or finding rows. It is not a separate navigation item.

## CLI Examples

```bash
cargo run --release --bin automatestig -- disa-import --input U_STIG.zip
cargo run --release --bin automatestig -- library list
cargo run --release --bin automatestig -- evaluate --stig <STIG_ID> --scan results.xml --host server01 --output server01.ckl --format ckl
cargo run --release --bin automatestig -- summary --input server01.ckl --open-only
cargo run --release --bin automatestig -- remediate --input server01.ckl --format bash --output remediate.sh
```

## Workspace

```text
crates/
  core/          Data models, deterministic evaluation engine, answer files, checks, agent and scheduling models
  parsers/       CKL, CKLB, XCCDF, and scan/config parsers
  storage/       SQLite persistence
  stigpack/      .stigpack build, verify, import, manifest, hashes, and Ed25519 signing support
  remediation/   PowerShell, Bash, and Ansible remediation generation
  integrations/  STIG-Manager and eMASS integration code
  cli/           automatestig binary
  gui/           automatestig-gui local web GUI and HTTP API
  tests/         Workspace integration tests
```

## Documentation

Start with [docs/README.md](docs/README.md) for installation, quickstart, CLI, GUI, API, security, architecture, integrations, and governance documentation.

## Container Deployment

A `Dockerfile` and `railway.toml` are present for hosted deployment scenarios.

## License

MIT
