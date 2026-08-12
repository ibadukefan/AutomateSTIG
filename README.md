# AutomateSTIG

[![CI](https://github.com/ibadukefan/AutomateSTIG/actions/workflows/ci.yml/badge.svg)](https://github.com/ibadukefan/AutomateSTIG/actions/workflows/ci.yml)
[![CodeQL](https://github.com/ibadukefan/AutomateSTIG/actions/workflows/codeql.yml/badge.svg)](https://github.com/ibadukefan/AutomateSTIG/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Status: experimental pilot](https://img.shields.io/badge/status-experimental_pilot-orange.svg)

AutomateSTIG is an offline-capable scanner and evidence producer for selected
difficult-to-scan devices. It supplements STIG Manager; it does not replace
STIG Manager or create a second compliance-management system.

> **Release status:** the scanner-first `v0.3.x` line is an unreleased pilot
> candidate. The public `v0.2.x` release is a legacy application and does not
> implement the workflow documented here. Do not install `v0.2.x` expecting
> the scanner-first product.

## Start here

The [Quickstart](docs/quickstart.md) is the canonical installation, first-open,
training, scan, and handoff guide. For an approved `v0.3.x` release, macOS and
GNU/Linux use the same noninteractive installer:

```bash
version=v0.3.0
gh release verify "$version" --repo ibadukefan/AutomateSTIG
gh release download "$version" --repo ibadukefan/AutomateSTIG \
  --pattern install.sh --output automatestig-install.sh
sh ./automatestig-install.sh --version "$version"
```

The installer detects the operating system and CPU, verifies the archive
checksum and exact tagged-workflow Sigstore identity, installs atomically to
`~/.local/bin`, and opens the local GUI. It asks no questions, uses no `sudo`,
and does not edit shell profiles. Until a gated `v0.3.x` release exists, this
sequence stops without changing the machine.

Windows deployment is unsupported. The Windows build remains a CI portability
check only. Linux release compatibility still needs a published distro/glibc
qualification matrix; before installation the installer executes the verified
staged CLI and leaves the existing installation untouched if it cannot run.

## The analyst flow

1. Collect read-only evidence from an authorized ONTAP or FreeBSD target, or
   evaluate a complete authorized IOS-XE running configuration.
2. Review the deterministic result and download the complete run's verified,
   sparse handoff.
3. Reconcile only scanner-owned reviews with the existing STIG Manager asset
   and assignment, then continue manual review, findings, approvals, and
   reporting in STIG Manager.

On first open, **Open sample result** teaches the result screen without
contacting a device, calling STIG Manager, or saving assessment data.

## Exact pilot scope

| Target | Bundled STIG | Input | Automated | Manual | Full benchmark |
| --- | --- | --- | ---: | ---: | ---: |
| NetApp ONTAP 9.x | ONTAP DSC STIG V2R4 | Plan-bound read-only SSH evidence | 15 | 7 | 29 |
| FreeBSD 13–14 | GPOS V3R3 | Plan-bound read-only SSH evidence | 6 | 24 | 203 |
| Cisco IOS-XE 17 | Router NDM STIG V3R7 | Complete config + signed organization policy | 33 | 9 | 42 |

These are curated evidence boundaries, not claims of full benchmark
automation or production support. The profiles remain experimental until their
declared live-device, receiver, signing, and first-use gates pass. General
Linux, AIX, Solaris, Windows, Cisco NX-OS, and Cisco ASA scanning are not
`v0.3.x` targets. Importing another benchmark does not add scanner support.
See [Supported Targets](docs/supported-targets.md) for the exact contract.

## What AutomateSTIG owns

- Version-checked, read-only collection plans for the supported SSH targets.
- A complete-config evaluation path for the supported IOS-XE target.
- Strict evidence identity, freshness, completeness, and integrity checks.
- Deterministic evaluation with content, policy, evidence, and build
  provenance; no AI or ML is used in the decision path.
- Fail-closed handling of denied, missing, timed-out, truncated, malformed,
  ambiguous, stale, or unsupported evidence.
- A selected-run handoff with sparse JSON, XCCDF 1.2 and CKLB projections,
  source result, evidence/provenance, and integrity manifests.
- Read-only handoff verification and exact remote no-op confirmation.

## What stays in STIG Manager

- Collections, assets, STIG assignments, and review ownership.
- Manual findings, comments, adjudication, approvals, and risk decisions.
- Dashboards, reports, portfolio views, and long-term history.
- Changed-review writes. AutomateSTIG produces a verified sparse handoff; an
  approved receiver performs destination revalidation and semantic readback.

Connected mode is opt-in and currently accepts only the exact retained tested
STIG Manager build `1.6.13+1`. Disconnected scanning remains the default.

## Interfaces and exports

Release archives contain:

- `automatestig-gui` — localhost browser GUI with **Scan**, **Deliveries**,
  **Scanner Content**, and **Connection** workspaces;
- `automatestig` — collection, evaluation, status, and read-only handoff
  verification; and
- `automatestig-backup-restore` — verified protected-state recovery utility.

The normal product surface intentionally excludes asset management, checklist
editing, broad DISA catalog management, answer files, remediation, dashboards,
and portfolio reporting. Maintainer and one-time transition operations are
feature-gated and are not shipped in analyst release archives.

## Security and operations

The GUI binds to `127.0.0.1` on a random port and stores sensitive local state
under `~/.automatestig`. Remote SSH collection and STIG Manager integration are
explicit connected operations; normal evaluation and verification make no
network calls. Review the [Security Model](docs/security-model.md),
[Deployment Hardening](docs/deployment-hardening.md), and
[Handoff Verification](docs/handoff-verification.md) before operational use.

Never attach credentials, device configurations, evidence, private keys,
tokens, or controlled data to a public issue. See [Security](SECURITY.md) and
[Support](SUPPORT.md) for private reporting and safe support paths.

## Develop from source

Builds require the repository-pinned Rust toolchain. Python 3.10 or newer is
needed for recovery and validation tooling, not for ordinary installation or
scanning.

```bash
cargo build --release --workspace
cargo test --workspace
cargo run --release --bin automatestig-gui
```

Start with the [Documentation Index](docs/README.md) for user, target,
security, architecture, integration, and release-governance references. See
[Contributing](CONTRIBUTING.md), the [Changelog](CHANGELOG.md), and the
[controlled comparison protocol](docs/commercial-scanner-comparison.md) before
making product or competitor claims.

## Project status and affiliation

AutomateSTIG is an independent open-source project. It is not affiliated with
or endorsed by DISA, the U.S. Department of Defense, NAVSEA, Evaluate-STIG, or
the STIG Manager maintainers. It makes no global or unmeasured claim to be
“better than Evaluate-STIG.” Comparative claims require the documented
representative-device A/B evidence.

Licensed under the [MIT License](LICENSE).
