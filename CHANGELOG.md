# Changelog

This file records user-visible changes. Release artifacts and source tags on
the [GitHub Releases page](https://github.com/ibadukefan/AutomateSTIG/releases)
remain authoritative.

## v0.3.0 — pilot candidate, not released

- Refocused AutomateSTIG as a difficult-device scanner and evidence producer
  that supplements STIG Manager.
- Replaced the legacy manager-like GUI with Scan, Deliveries, Scanner Content,
  and Connection workspaces.
- Added exact experimental profiles for ONTAP V2R4, FreeBSD/GPOS V3R3, and
  Cisco IOS-XE Router NDM V3R7.
- Added fail-closed collection, deterministic evaluation, decision traces,
  encrypted replay evidence, durable jobs, retention controls, and verified
  selected-run handoffs.
- Removed changed-review writes that cannot atomically protect concurrent human
  work. Exact no-ops can be confirmed; creates and updates use sparse handoff.
- Added v4 handoffs with sparse JSON, XCCDF 1.2, CKLB, native results,
  evidence/provenance, manifests, integrity verification, and protected
  detached signing support.
- Moved migration, producer signing, and maintainer-only content operations out
  of the normal product surface.
- Added a canonical analyst quickstart and one noninteractive macOS/GNU/Linux
  installer with automatic host detection, tag binding, checksum/Sigstore
  verification, transactional rollback, first launch, and safe uninstall.
- Added task-oriented documentation, guided support forms, reviewed release
  notes, community/security policies, and automated documentation validation.
- Added Linux, macOS, and Windows CI coverage; supported release artifacts
  remain Linux and macOS only.

The release remains blocked on the documented human acceptance and independent
release-freeze gates. See [Supported Targets](docs/supported-targets.md) and
[Release Process](docs/release-process.md).

## v0.2.0 — legacy application

The last published release predates the scanner-first product boundary. Its
assets and workflow should not be interpreted as the `v0.3.0` pilot described
by the current documentation.
