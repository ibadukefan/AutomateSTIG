# AutomateSTIG

AutomateSTIG is an offline-capable scanner and evidence producer for selected
difficult-to-scan devices. It supplements STIG Manager; it is not a second
asset, review, governance, or reporting system. Supported release binaries are
published for Linux and macOS. It is a Rust workspace with two binaries:

- `automatestig` - command-line interface
- `automatestig-gui` - local web GUI

STIG Manager remains the system of record for assets, assignments, human
review, governance, dashboards, reports, and long-term history. The
[scanner-first product plan](docs/scanner-product-plan.md) identifies duplicated
features to remove, the non-destructive migration path, and target-specific
comparison gates. AutomateSTIG makes no global or unmeasured “better than
Evaluate-STIG” claim.

AutomateSTIG v0.3 has a deliberately narrow scanner scope: NetApp ONTAP 9.x against the DISA ONTAP DSC STIG, FreeBSD against DISA GPOS, and Cisco IOS-XE Router NDM from an authorized running configuration. ONTAP and FreeBSD use read-only SSH command evidence; IOS-XE does not use remote collection. `collect` emits a native adapter-evidence envelope containing the identity observed from the device, the exact read-only operation plan, per-operation outcomes, the SSH server-key fingerprint, and integrity hashes. Evaluation is deterministic. There is no AI or ML in the evaluation path. The default workflow makes no network calls; STIG Manager integration and remote SSH collection are opt-in connected features.

The shipped profiles contain 54 automated checks and 40 reviewed-manual rules
across a 94-rule reviewed profile and a 274-rule full-benchmark denominator:
ONTAP 15 automated/7 manual/22 reviewed/29 full, FreeBSD 6/24/30/203, and
Cisco IOS-XE 33/9/42/42. These are curated evidence boundaries, not claims of
complete benchmark automation. The profiles remain experimental until their
declared live-device acceptance evidence is attached to a release.

General Linux/AIX/Solaris scanning, Windows scanning, Cisco NX-OS, and Cisco ASA are not v0.3 targets. Importing or converting another benchmark/checklist does not imply scanning support. See the [declared experimental target contract](docs/supported-targets.md).

Windows remains a CI portability-test platform, but Windows release binaries
and operational support are withheld until equivalent Windows filesystem
ownership, ACL, and reparse-point custody controls are implemented. Do not use
a source-built Windows binary for security-sensitive work.

## Features

- Start from immutable release-bundled ONTAP V2R4, FreeBSD/GPOS V3R3, and
  Cisco IOS-XE Router NDM V3R7 scanner profiles; normal users do not manage a
  broad DISA catalog.
- Select a live existing STIG Manager collection, asset, and exact assignment;
  AutomateSTIG never creates the asset or assignment.
- Preview a version-checked, read-only target-adapter plan before collection.
- Evaluate strict plan-bound ONTAP/FreeBSD evidence or a complete IOS-XE
  running configuration with an asset-bound signed organization policy.
- Use the same release-bundled profile resolution, target adapter, evidence
  validation, and deterministic evaluation service from the CLI and GUI.
- Fail closed on missing, denied, timed-out, truncated, malformed, ambiguous,
  stale, or unsupported evidence.
- Preview only scanner-owned reviews while leaving manual, imported,
  answer-file, collection-error, and human-owned reviews untouched. Exact
  remote no-ops can be confirmed directly; create/update proposals use the
  selected-run handoff because the current STIG Manager API has no atomic
  conditional review-write contract.
- Preserve immutable handoff payload digests, verification retry state, conflicts, remote
  receipts, evidence hashes, and evaluation provenance.
- Produce one selected-run handoff for every complete run, including connected
  runs whose changed reviews are safety-gated. The v4 handoff uses
  `sparse-reviews.json` as its tested STIG Manager Review API transport and
  includes digest-bound sparse XCCDF 1.2 and CKLB supplemental projections;
  STIG Manager remains the receiving system of record.
- Use the connected STIG Manager adapter only with the exact retained tested
  server build `1.6.13+1`. Other versions fail closed and use disconnected
  scanning plus a verified selected-run handoff.

## Quick Start

### Release archives

Launching the desktop app starts the local AutomateSTIG GUI and opens it in your browser at a localhost address. The CLI (`automatestig`) is included in every archive and installed on `PATH` by the command-line installers.

- macOS/Linux: download the target-specific `.tar.gz`, verify its checksum and
  Sigstore bundle, extract it, and run `automatestig-gui`.

### Version-pinned command-line installers

Authenticate the immutable GitHub release, download the installer from that
exact tag, and run it with the same pinned version. The installers require
`cosign` and refuse an archive unless its tagged CI workflow identity and exact
checksum both verify:

```bash
# macOS
version=v0.3.0
gh release verify "$version" --repo ibadukefan/AutomateSTIG
curl --proto '=https' --proto-redir '=https' -fsSL \
  "https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/$version/install-macos.sh" \
  -o install-macos.sh
AUTOMATESTIG_VERSION="$version" sh ./install-macos.sh

# Linux
version=v0.3.0
gh release verify "$version" --repo ibadukefan/AutomateSTIG
curl --proto '=https' --proto-redir '=https' -fsSL \
  "https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/$version/install-linux.sh" \
  -o install-linux.sh
AUTOMATESTIG_VERSION="$version" sh ./install-linux.sh
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

The GUI binds to `127.0.0.1` on a random port unless `PORT` is set, opens the
browser automatically, and stores its database, encryption material, trust
stores, and rotating structured logs in `~/.automatestig`. Runnable scanner
content is immutable and release-bundled rather than initialized as a mutable
GUI library.
Installed releases include `automatestig-backup-restore` for a WAL-consistent,
verified recovery unit. From a source checkout, the same tool is
`python3 scripts/backup-restore.py`. A restore deliberately requires STIG
Manager credential re-entry.

Run the CLI:

```bash
cargo run --release --bin automatestig -- --help
cargo run --release --bin automatestig -- status
```

## GUI

The scanner GUI has four workspaces:

- Scan
- Deliveries
- Scanner Content
- Connection

There is no asset-management, finding-editing, assignment, answer-file,
approval, dashboard, or portfolio-reporting workspace. Continue those tasks in
STIG Manager. See [Scanner GUI Guide](docs/gui-guide.md).

## Scanner and preservation CLI examples

The visible product CLI is limited to collection, evaluation, read-only
handoff verification, and status. General checklist
conversion, answer/merge, CKL export, and STIG Manager portfolio commands are
not compiled into the product CLI. Migration and handoff producer-key
operations live only in the separately named, explicitly feature-enabled
`automatestig-transition` binary. Protected content-maintainer operations use
the separate `maintainer` feature. Product release archives intentionally omit
`automatestig-transition`; build it from the same reviewed, version-pinned
source only on the controlled transition or signing host.

```bash
AUTOMATESTIG_SSH_PASSWORD='...' cargo run --release --bin automatestig -- collect --stig NetApp_ONTAP_DSC_9-x_STIG --host filer01 --username scanner --output filer01-evidence.json
cargo run --release --bin automatestig -- evaluate --stig NetApp_ONTAP_DSC_9-x_STIG --evidence filer01-evidence.json --output filer01-result.scanner-result.json
# Optional supplemental projection, only after a complete evaluation:
cargo run --release --bin automatestig -- evaluate --stig NetApp_ONTAP_DSC_9-x_STIG --evidence filer01-evidence.json --output filer01-result.cklb --format cklb
cargo run --release --bin automatestig -- scanner verify-handoff selected-run.zip
cargo run --release --features transition --bin automatestig-transition -- migration inventory --output inventory.json
python3 scripts/validate-scanner-scenarios.py
```

`scanner verify-handoff` validates the current v4 XCCDF result and canonical
run request against the
same scanner-owned reviews, target, and provenance as the other payloads. It
also retains strict verification for already-issued v2 CKLB-only bundles.

## Workspace

```text
crates/
  archive-safety/ Bounded ZIP/archive validation shared by all import paths
  collector/     Shared fail-closed SSH transport and typed collection outcomes
  core/          Shared models, check definitions, custody controls, and contracts
  parsers/       Supplemental CKLB/XCCDF and transition-format parsers
  storage/       SQLite persistence
  stigpack/      .stigpack build, verify, import, manifest, hashes, and Ed25519 signing support
  integrations/  STIG Manager lookup, sparse handoff, and remote no-op verification
  scanner/       Shared GUI/CLI profile, adapter, collection, and evaluation service
  cli/           automatestig binary
  gui/           automatestig-gui local web GUI and HTTP API
  tests/         Workspace integration tests
```

## Documentation

Start with [docs/README.md](docs/README.md) for installation, quickstart, CLI,
GUI, API, security, architecture, integrations, and governance documentation.
Use the [controlled scanner comparison](docs/commercial-scanner-comparison.md)
only for representative-device A/B studies against Evaluate-STIG, Tenable,
Nipper, or another comparator.

## License

MIT
