# AutomateSTIG

AutomateSTIG is a cross-platform, offline-capable STIG evidence collection and evaluation platform. It is a Rust workspace with 8 crates and two binaries:

- `automatestig` - command-line interface
- `automatestig-gui` - local web GUI

AutomateSTIG focuses on collecting evidence from devices that scripted scanners cannot reach, including network devices through configuration files, Linux/UNIX systems through SSH, and NetApp ONTAP filers through CLI evidence transcripts and GUI SSH scan. Evaluation is deterministic. There is no AI or ML in the evaluation path. The default workflow makes no network calls; DISA fetching, STIG-Manager integration, and remote SSH collection are opt-in connected features.

## Features

- Import DISA XCCDF XML or ZIP benchmark content.
- Evaluate benchmarks from scan results, network device configuration evidence, Linux/UNIX SSH collection, answer files, and installed check packs.
- Evaluate NetApp ONTAP filers from read-only CLI evidence transcripts (DISA ONTAP DSC 9.x STIG).
- Generate and persist deterministic auto check packs from structured DISA check content where possible.
- Manage assets, assessments, findings, credentials, and STIG-Manager settings in the local GUI.
- Deliver results through STIG-Manager API push, STIG-Manager JSON export, and CKL/CKLB file import.
- Transfer content with signed offline `.stigpack` packs.
- Run local, batch, and remote SSH-backed evaluations when the needed live infrastructure is available.
- Keep air-gapped workflows first-class through local storage, signed `.stigpack` import, and offline pack generation.

## Quick Start

### Desktop app (double-click installers)

Launching the desktop app starts the local AutomateSTIG GUI and opens it in your browser at a localhost address. The CLI (`automatestig`) is included in every archive and installed on `PATH` by the command-line installers.

- macOS: download `AutomateSTIG-<tag>-macos-<arch>.dmg` (`arm64` for Apple Silicon, `x86_64` for Intel), open it, drag **AutomateSTIG** to Applications, then launch it. On first launch, right-click **AutomateSTIG** and choose Open because the app is not notarized.
- Windows: download `AutomateSTIG-<tag>-windows-x64-setup.exe`, run it, click through the wizard, then launch from the Start Menu or Desktop shortcut. On first run, SmartScreen may require More info, then Run anyway because the installer is not signed.
- Linux: download `AutomateSTIG-<tag>-linux-x86_64.AppImage`, run `chmod +x AutomateSTIG-<tag>-linux-x86_64.AppImage`, then double-click it or run it from a terminal.

### Command-line installers

Install the prebuilt binaries with one command for your OS:

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

The GUI navigation pages are:

- Assessments
- Assets
- Standards
- Findings
- Settings

Checklist detail opens from assessment or finding rows. It is not a separate navigation item.

## CLI Examples

```bash
cargo run --release --bin automatestig -- disa-import --input U_STIG.zip
cargo run --release --bin automatestig -- library list
cargo run --release --bin automatestig -- evaluate --stig <STIG_ID> --scan results.xml --host server01 --output server01.ckl --format ckl
cargo run --release --bin automatestig -- summary --input server01.ckl --open-only
cargo run --release --bin automatestig -- export --input server01.ckl --output stigman.json --format stig-manager --collection "Production"
```

## Workspace

```text
crates/
  core/          Data models, deterministic evaluation engine, answer files, and checks
  parsers/       CKL, CKLB, XCCDF, and scan/config parsers
  storage/       SQLite persistence
  stigpack/      .stigpack build, verify, import, manifest, hashes, and Ed25519 signing support
  integrations/  STIG-Manager export/push
  cli/           automatestig binary
  gui/           automatestig-gui local web GUI and HTTP API
  tests/         Workspace integration tests
```

## Documentation

Start with [docs/README.md](docs/README.md) for installation, quickstart, CLI, GUI, API, security, architecture, integrations, and governance documentation.

## License

MIT
