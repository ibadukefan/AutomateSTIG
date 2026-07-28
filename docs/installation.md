# Installation

## Download & Install (prebuilt)

AutomateSTIG publishes release archives that contain both binaries:

- `automatestig`
- `automatestig-gui`

### One-line installers — one per OS

macOS:

```bash
curl --proto '=https' --proto-redir '=https' -fsSL \
  https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-macos.sh | sh
```

Linux:

```bash
curl --proto '=https' --proto-redir '=https' -fsSL \
  https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-linux.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-windows.ps1 | iex
```

Each installer picks the right build for your CPU (Intel/x86_64 or Apple
Silicon/arm64) automatically. The installers require
[Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) and stop
unless both the exact archive checksum and its keyless Sigstore signature from
this repository's tagged CI workflow verify. Download and inspect an installer
before running it if your environment does not permit piping remote scripts to
a shell.

Set `AUTOMATESTIG_VERSION` to pin a specific release tag, such as `v0.3.0`.
On macOS and Linux, set `AUTOMATESTIG_INSTALL_DIR` to choose a different
install directory.

### Manual download

Download the archive for your platform from the [latest GitHub Release](https://github.com/ibadukefan/AutomateSTIG/releases/latest):

| Platform | Target | Archive |
| --- | --- | --- |
| Linux x86_64 | `x86_64-unknown-linux-gnu` | `automatestig-<tag>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux arm64 | `aarch64-unknown-linux-gnu` | `automatestig-<tag>-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Intel | `x86_64-apple-darwin` | `automatestig-<tag>-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `aarch64-apple-darwin` | `automatestig-<tag>-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `x86_64-pc-windows-msvc` | `automatestig-<tag>-x86_64-pc-windows-msvc.zip` |

For macOS and Linux:

```bash
tar -xzf automatestig-<tag>-<target>.tar.gz
chmod +x automatestig automatestig-gui
./automatestig-gui
```

Move `automatestig` and `automatestig-gui` to a directory on `PATH`, such as `$HOME/.local/bin` or `/usr/local/bin`.

For Windows:

```powershell
Expand-Archive .\automatestig-<tag>-x86_64-pc-windows-msvc.zip -DestinationPath .\automatestig
.\automatestig\automatestig-gui.exe
```

Move `automatestig.exe` and `automatestig-gui.exe` to a directory on `PATH`, such as `%LOCALAPPDATA%\AutomateSTIG`.

### Launching

Run `automatestig-gui` to open the local web GUI. Run `automatestig --help` for the CLI.

### macOS Gatekeeper

The release binaries are not notarized. The installer deliberately does not
remove macOS quarantine metadata or bypass Gatekeeper. If Gatekeeper blocks a
verified binary, use your organization's approved exception process or build
from reviewed source. Do not clear quarantine merely to make an unfamiliar
download run.

### Verification and provenance

Tagged release CI publishes `<archive>.sha256` and
`<archive>.sigstore.bundle` next to every archive. A checksum detects accidental
or post-download changes but does not authenticate the publisher, so verify the
bundle against the exact workflow identity before extracting:

```bash
archive=automatestig-v0.3.0-x86_64-unknown-linux-gnu.tar.gz
cosign verify-blob \
  --bundle "$archive.sigstore.bundle" \
  --certificate-identity \
    "https://github.com/ibadukefan/AutomateSTIG/.github/workflows/ci.yml@refs/tags/v0.3.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$archive"
sha256sum -c "$archive.sha256"
```

The release also includes a CycloneDX SBOM, dependency inventory, GitHub
artifact attestation, provenance record, and hash-complete release manifest.
With GitHub CLI installed, verify the independent GitHub attestation using the
same repository, workflow identity, tag ref, and source commit recorded by the
release.

## Prerequisites

- Rust toolchain, stable channel.

## Build

From the repository root:

```bash
cargo build --release --workspace
```

The workspace builds two binaries:

- `automatestig`
- `automatestig-gui`

## Run The GUI

```bash
cargo run --release --bin automatestig-gui
```

Or run the built `automatestig-gui` binary from the release target directory.

The GUI:

- Binds to `127.0.0.1` on a random port, or uses the `PORT` environment variable.
- Opens the browser automatically.
- Stores local data under `~/.automatestig`.

The data directory contains:

- `data.db`
- `library/`

## Run The CLI

```bash
cargo run --release --bin automatestig -- --help
cargo run --release --bin automatestig -- status
```

Use the built binary directly after a release build:

```bash
./target/release/automatestig status
```
