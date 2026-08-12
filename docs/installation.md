# Installation

This page covers supported prebuilt installation, upgrades, removal, manual
verification, and source builds. For the complete first-use flow, follow the
[Quickstart](quickstart.md).

> **Current status:** scanner-first `v0.3.x` is an unreleased pilot candidate.
> The public `v0.2.x` release is legacy and does not contain this scanner,
> unified installer, or release-integrity contract. Do not install `v0.2.x`
> expecting the workflow below.

## Supported release hosts

Prebuilt pilot archives are produced for:

| Host | CPU | Release target |
| --- | --- | --- |
| GNU/Linux | x86-64 | `x86_64-unknown-linux-gnu` |
| GNU/Linux | arm64 | `aarch64-unknown-linux-gnu` |
| macOS | Intel | `x86_64-apple-darwin` |
| macOS | Apple Silicon | `aarch64-apple-darwin` |

Windows deployment is unsupported. Windows remains in CI for source
portability only, and no Windows release archive is published until equivalent
filesystem ownership, ACL, and reparse-point custody controls exist.

The pilot has not yet published a complete minimum macOS or GNU/Linux
distro/glibc qualification matrix. In particular, do not infer RHEL or musl
compatibility merely from the presence of a Linux archive. Tagged CI executes
each packaged binary on its declared native release runner. The installer also
executes the authenticated staged CLI before replacing any installed file and
stops without changing the existing installation if the binary cannot run.

## One installer for macOS and Linux

The normal path requires a current GitHub CLI with `gh release verify`, plus
standard `curl`, `tar`, and SHA-256 tooling. Set `version` to the exact release
approved by the site:

```bash
version=v0.3.0
gh release verify "$version" --repo ibadukefan/AutomateSTIG
gh release download "$version" --repo ibadukefan/AutomateSTIG \
  --pattern install.sh --output automatestig-install.sh
sh ./automatestig-install.sh --version "$version"
```

The installer asks no questions. It:

- is cryptographically bound to the tag that published it and rejects a
  different `--version`;
- detects macOS or GNU/Linux and Intel/x86-64 or arm64 automatically;
- downloads the matching CLI, GUI, and recovery-tool archive;
- verifies its one-record SHA-256 checksum and exact tagged-workflow Sigstore
  identity;
- uses an existing Cosign command or temporarily downloads a pinned,
  checksum-verified Cosign verifier;
- rejects links, duplicate names, or any member outside the closed seven-file
  release archive;
- stages and executes the verified CLI before touching an old installation;
- atomically installs or repairs all three entry points in `~/.local/bin`,
  rolling back the entire transaction on a failure; and
- starts the localhost GUI and prints absolute commands for future use.

It never uses `sudo`, edits a shell startup file, disables Gatekeeper, or asks
the user to choose an archive. Python is not required to install, launch, scan,
or verify a handoff. The optional `automatestig-backup-restore` entry point
requires Python 3.10 or newer when it is used.

Until an approved `v0.3.x` release is published, the commands above fail at
release verification and make no installation changes. They never substitute
the legacy `v0.2.x` release.

### Launch, upgrade, repair, and uninstall

The default absolute launch command is:

```bash
"$HOME/.local/bin/automatestig-gui"
```

Adding `~/.local/bin` to `PATH` is optional and remains a site or shell
configuration decision. The installer does not change it.

To upgrade, set `version` to the newly approved tag and repeat the four normal
installation commands. Re-running the same verified release safely repairs
that version. A published installer is tag-bound, so it cannot silently switch
versions.

Install without opening the GUI, or choose another absolute user-owned
destination:

```bash
sh ./automatestig-install.sh --version "$version" --no-launch
sh ./automatestig-install.sh --version "$version" \
  --install-dir "$HOME/Applications/AutomateSTIG/bin"
```

Show all options without installing:

```bash
sh ./automatestig-install.sh --help
```

Remove the three installed entry points while deliberately retaining assessment
state:

```bash
sh ./automatestig-install.sh --uninstall
```

The uninstall leaves `~/.automatestig` intact. Remove that directory only
after following the site's evidence-retention and media-sanitization process.

The old `install-linux.sh` and `install-macos.sh` files are compatibility
wrappers when shipped beside `install.sh`; new installations should use only
the unified installer. `install-windows.ps1` is a no-change explanation of the
unsupported Windows boundary.

## macOS Gatekeeper

The pilot binaries are not notarized. The installer deliberately does not
clear quarantine metadata or bypass Gatekeeper. If an organization blocks the
verified binary, use its approved Gatekeeper exception process or build the
reviewed source. Notarization remains a prerequisite for a genuinely
decision-free general macOS installation.

## Manual archive installation

Use the exact approved release, not the mutable source branch or the legacy
“latest” release. Download these assets for the applicable target:

- `automatestig-<tag>-<target>.tar.gz`
- `automatestig-<tag>-<target>.tar.gz.sha256`
- `automatestig-<tag>-<target>.tar.gz.sigstore.bundle`

Authenticate the immutable release first:

```bash
version=v0.3.0
gh release verify "$version" --repo ibadukefan/AutomateSTIG
gh release download "$version" --repo ibadukefan/AutomateSTIG \
  --pattern 'automatestig-*<target>.tar.gz*'
```

Then verify the exact tagged workflow identity and checksum before extraction:

```bash
archive=automatestig-v0.3.0-<target>.tar.gz
cosign verify-blob \
  --bundle "$archive.sigstore.bundle" \
  --certificate-identity \
    "https://github.com/ibadukefan/AutomateSTIG/.github/workflows/ci.yml@refs/tags/v0.3.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$archive"
sha256sum -c "$archive.sha256"
tar -xzf "$archive"
chmod +x automatestig automatestig-gui automatestig-backup-restore
./automatestig --version
./automatestig-gui
```

On macOS, use `shasum -a 256 -c` if `sha256sum` is unavailable. Manual
installation puts the operator in charge of archive-member review, destination
permissions, atomic replacement, and rollback; the unified installer is the
safer normal path.

## Release provenance

Tagged CI publishes a checksum and keyless Sigstore bundle for the unified
installer and each target archive. The installer is rendered from the reviewed
source with the exact release tag embedded, syntax-checked, attested, signed,
and included in the closed release manifest before publication.

Each target also has:

- `release-equivalence-<target>.json`, binding the tested pre-package CLI, GUI,
  and recovery-tool bytes to the archived bytes;
- a CycloneDX SBOM with locked Cargo dependencies and release-executable
  hashes;
- a Cargo metadata inventory;
- a provenance record binding the archive, commit, workflow run, companions,
  and executable bytes; and
- GitHub attestations plus a signed, checksum-protected
  `release-manifest.json` covering the complete publishable set.

Native release jobs execute the exact extracted CLI and GUI on all four release
targets. The recovery entry point also completes a real backup/restore round
trip. These checks establish artifact identity and executable equivalence; they
do not replace the documented live-device or host-compatibility acceptance
gates.

## Build from source

Source builds are for developers and explicitly reviewed pilot commits. Install
the repository-pinned Rust toolchain and Python 3.10 or newer, then from the
repository root run:

```bash
cargo build --release --workspace
```

The default product binaries are:

- `target/release/automatestig`
- `target/release/automatestig-gui`

Run them with:

```bash
cargo run --release --bin automatestig -- status
cargo run --release --bin automatestig-gui
```

The separately named transition executable is intentionally absent from
analyst release archives. On an applicable controlled host, build it only from
reviewed, version-pinned source:

```bash
cargo build --release --locked --no-default-features \
  --features transition --bin automatestig-transition
```

See [Migration and Transition](migration-transition.md) and
[Handoff Verification](handoff-verification.md) for that protected workflow.

The GUI binds to `127.0.0.1` on a random port, opens a browser, and stores
sensitive local state under `~/.automatestig`. Use the installed
`automatestig-backup-restore` command for a verified recovery unit; from a
source checkout use `python3 scripts/backup-restore.py`.
