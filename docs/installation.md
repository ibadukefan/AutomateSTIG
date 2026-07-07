# Installation

## Download & Install (prebuilt)

AutomateSTIG publishes release archives that contain both binaries:

- `automatestig`
- `automatestig-gui`

### One-line installers — one per OS

macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-macos.sh | sh
```

Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-linux.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-windows.ps1 | iex
```

Each installer picks the right build for your CPU (Intel/x86_64 or Apple Silicon/arm64) automatically.

Set `AUTOMATESTIG_VERSION` to pin a specific release tag, such as `v0.1.0`. On macOS and Linux, set `AUTOMATESTIG_INSTALL_DIR` to choose a different install directory.

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

The release binaries are not notarized. The install script removes the quarantine attribute from both binaries. If you install manually and macOS blocks the GUI, run:

```bash
xattr -d com.apple.quarantine automatestig-gui
```

You can also right-click `automatestig-gui` and choose Open the first time.

### Verification and provenance

Tagged release CI publishes SHA-256 checksum files next to every archive. Download the matching `.sha256` file from the release and verify it before extracting.

The existing CI workflow also produces SBOM, artifact attestation, and Sigstore provenance artifacts for release-build outputs.

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

## Container

A `Dockerfile` and `railway.toml` exist for hosted deployment.

```bash
docker build -t automatestig .
```

For non-loopback hosted binds, `/api/*` requires an explicit `AUTOMATESTIG_AUTH_TOKEN` of at least 16 characters. `/api/status` is the only unauthenticated API route.
