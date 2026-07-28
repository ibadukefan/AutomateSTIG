# AutomateSTIG

AutomateSTIG is an offline-capable STIG evidence collection and evaluation platform. Supported release binaries are published for Linux and macOS. It is a Rust workspace with two binaries:

- `automatestig` - command-line interface
- `automatestig-gui` - local web GUI

AutomateSTIG v0.3 has a deliberately narrow scanner scope: NetApp ONTAP 9.x against the DISA ONTAP DSC STIG, FreeBSD against DISA GPOS, and Cisco IOS-XE Router NDM from an authorized running configuration. ONTAP and FreeBSD use read-only SSH command evidence; IOS-XE does not use remote collection. SSH evidence records each command's stdout, stderr, exit status, duration, collection error, plan digest, and SSH server-key fingerprint. Evaluation is deterministic. There is no AI or ML in the evaluation path. The default workflow makes no network calls; DISA fetching, STIG-Manager integration, and remote SSH collection are opt-in connected features.

The shipped inventories contain 86 reviewed candidate rules and 40 executable checks: ONTAP 22 reviewed/16 automated/6 manual, FreeBSD 30/3/27, and Cisco IOS-XE 34/21/13. These are curated evidence boundaries, not claims of complete benchmark automation.

General Linux/AIX/Solaris scanning, Windows scanning, Cisco NX-OS, and Cisco ASA are not v0.3 targets. Importing or converting another benchmark/checklist does not imply scanning support. See the [supported-target contract](docs/supported-targets.md).

Windows remains a CI portability-test platform, but Windows release binaries
and operational support are withheld until equivalent Windows filesystem
ownership, ACL, and reparse-point custody controls are implemented. Do not use
a source-built Windows binary for security-sensitive work.

## Features

- Import bounded DISA XCCDF XML or ZIP benchmark content for the local library and format workflows.
- Evaluate the three target families from plan-bound evidence v2 documents or an IOS-XE running configuration using curated shipped check packs.
- Evaluate NetApp ONTAP filers from read-only SSH evidence with ONTAP error/table validation (DISA ONTAP DSC 9.x STIG).
- Evaluate FreeBSD hosts against the DISA GPOS SRG using three direct effective-state observations: `auditd`, timezone, and 64-bit ASLR.
- Manage assets, assessments, findings, and STIG-Manager settings in the local GUI.
- Deliver results through STIG-Manager API push, STIG-Manager JSON export, and CKL/CKLB file import.
- Transfer content with signed offline `.stigpack` packs.
- Run local evidence/config evaluations and remote SSH-backed ONTAP/FreeBSD evaluations when the needed live infrastructure is available.
- Keep air-gapped workflows first-class through local storage, signed `.stigpack` import, and offline pack generation.

## Quick Start

### Release archives

Launching the desktop app starts the local AutomateSTIG GUI and opens it in your browser at a localhost address. The CLI (`automatestig`) is included in every archive and installed on `PATH` by the command-line installers.

- macOS/Linux: download the target-specific `.tar.gz`, verify its checksum and
  Sigstore bundle, extract it, and run `automatestig-gui`.

### Command-line installers

Install the prebuilt Linux or macOS binaries with one command. The installers
require `cosign` and refuse an archive unless its tagged CI workflow identity
and exact checksum both verify:

```bash
# macOS
curl --proto '=https' --proto-redir '=https' -fsSL \
  https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-macos.sh | sh

# Linux
curl --proto '=https' --proto-redir '=https' -fsSL \
  https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-linux.sh | sh
```

See [installation](docs/installation.md) for manual release downloads,
signature/provenance verification, checksums, and build-from-source
instructions. See the [security model](docs/security-model.md) and
[connected-mode threat model](docs/connected-mode-threat-model.md) before
enabling DISA fetch, STIG Manager, or SSH scan integrations.

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
AUTOMATESTIG_SSH_PASSWORD='...' cargo run --release --bin automatestig -- collect --stig NetApp_ONTAP_DSC_9-x_STIG --host filer01 --username scanner --output filer01-evidence.json
cargo run --release --bin automatestig -- evaluate --stig NetApp_ONTAP_DSC_9-x_STIG --evidence filer01-evidence.json --output filer01.ckl --format ckl
cargo run --release --bin automatestig -- summary --input filer01.ckl --open-only
cargo run --release --bin automatestig -- export --input filer01.ckl --output stigman.json --format stig-manager --collection "Production"
```

## Workspace

```text
crates/
  archive-safety/ Bounded ZIP/archive validation shared by all import paths
  collector/     Shared fail-closed SSH transport and typed collection outcomes
  core/          Data models, deterministic evaluation engine, answer files, and checks
  parsers/       CKL, CKLB, XCCDF, and evidence v2 parsers
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
