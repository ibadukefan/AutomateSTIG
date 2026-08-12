# Installation

## Download & Install (prebuilt)

AutomateSTIG publishes release archives that contain both application binaries
and the protected-state recovery utility:

- `automatestig`
- `automatestig-gui`
- `automatestig-backup-restore`

The separately feature-gated `automatestig-transition` migration and handoff
producer-signing executable is not part of the analyst product archive. Build
it only from reviewed, version-pinned source on the applicable controlled host;
see [Migration and Transition](migration-transition.md) and
[Handoff Verification](handoff-verification.md).

Prebuilt, supported releases are published for Linux and macOS only. Windows
remains in CI for source-portability testing, but no Windows archive is
published or supported until Windows filesystem ownership, ACL, and
reparse-point custody controls match the Unix release boundary.

### Version-pinned installers

macOS:

```bash
version=v0.3.0
gh release verify "$version" --repo ibadukefan/AutomateSTIG
curl --proto '=https' --proto-redir '=https' -fsSL \
  "https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/$version/install-macos.sh" \
  -o install-macos.sh
AUTOMATESTIG_VERSION="$version" sh ./install-macos.sh
```

Linux:

```bash
version=v0.3.0
gh release verify "$version" --repo ibadukefan/AutomateSTIG
curl --proto '=https' --proto-redir '=https' -fsSL \
  "https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/$version/install-linux.sh" \
  -o install-linux.sh
AUTOMATESTIG_VERSION="$version" sh ./install-linux.sh
```

Each supported installer picks the right build for your CPU (Intel/x86_64 or
Apple Silicon/arm64) automatically. The installers require
[Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) and
Python 3.10 or newer. Python is the runtime for the installed protected-state
recovery entrypoint. The installers stop
unless both the exact archive checksum and its keyless Sigstore signature from
this repository's tagged CI workflow verify. `gh release verify` authenticates
the immutable release before the installer is downloaded from that same exact
tag; do not substitute a mutable branch such as `main`. Inspect the downloaded
script before running it when required by local policy.

Set `AUTOMATESTIG_VERSION` to pin a specific release tag, such as `v0.3.0`.
On macOS and Linux, set `AUTOMATESTIG_INSTALL_DIR` to choose a different
install directory. The installer stages both binaries and the recovery utility
inside that destination, moves the complete old toolset aside, and rolls back
on an error or catchable interruption. It never publishes a mixed-version CLI,
GUI, and recovery toolset.

### Manual download

Download the archive for your platform from the [latest GitHub Release](https://github.com/ibadukefan/AutomateSTIG/releases/latest):

| Platform | Target | Archive |
| --- | --- | --- |
| Linux x86_64 | `x86_64-unknown-linux-gnu` | `automatestig-<tag>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux arm64 | `aarch64-unknown-linux-gnu` | `automatestig-<tag>-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Intel | `x86_64-apple-darwin` | `automatestig-<tag>-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `aarch64-apple-darwin` | `automatestig-<tag>-aarch64-apple-darwin.tar.gz` |

For macOS and Linux:

```bash
tar -xzf automatestig-<tag>-<target>.tar.gz
chmod +x automatestig automatestig-gui automatestig-backup-restore
./automatestig-gui
```

Move all three `automatestig*` entry points to a directory on `PATH`, such as
`$HOME/.local/bin` or `/usr/local/bin`. Manual installation also requires a
`python3` command at version 3.10 or newer for
`automatestig-backup-restore`.

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

Each archive also has a target-specific `release-equivalence-<target>.json`.
That manifest records the SHA-256 and size of both binaries and the recovery
utility before packaging, the same values after extraction, the archive
SHA-256, package version, target, and source commit. Tagged CI executes the
exact extracted CLI and GUI on a native runner for all four supported targets.
The same native job executes the exact extracted recovery entrypoint through a
real backup/restore round trip, verifies state preservation and credential
removal, and provenance binds that utility's exact bytes.

The release also includes a CycloneDX SBOM with locked Cargo component
checksums, source references, dependency relationships, and hashes for both
release executables and the recovery utility. Its metadata identifies the
archive as the analyst product and records that the protected transition CLI
is absent. The complete Cargo metadata inventory, provenance record, and signed
hash-complete release manifest bind those shipped hashes to the archive, source
commit, workflow run, checksum, and attestations.
With GitHub CLI installed, verify the independent GitHub attestation using the
same repository, workflow identity, tag ref, and source commit recorded by the
release.

## Prerequisites

- Rust toolchain, stable channel.
- Python 3.10 or newer for protected-state recovery.

## Build

From the repository root:

```bash
cargo build --release --workspace
```

This source build is supported for Linux and macOS. A Windows build may compile
for portability testing, but is not a supported deployment artifact and must
not be used for security-sensitive operation.

The default workspace build produces the two product binaries:

- `automatestig`
- `automatestig-gui`

To compile the separately named protected transition executable without adding
its operations to the product CLI:

```bash
cargo build --release --locked --no-default-features \
  --features transition --bin automatestig-transition
```

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

Use `automatestig-backup-restore` for protected state backup and restore from an
installed release (`python3 scripts/backup-restore.py` in a source checkout);
it captures committed WAL frames and keeps database, encryption key, scanner
library, SSH trust, and public-key trust stores in one verified recovery unit.

## Run The CLI

```bash
cargo run --release --bin automatestig -- --help
cargo run --release --bin automatestig -- status
```

Use the built binary directly after a release build:

```bash
./target/release/automatestig status
```
