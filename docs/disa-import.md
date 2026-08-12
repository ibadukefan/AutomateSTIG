# DISA Import

> **Maintainer/transition tooling:** Normal scanner users receive the exact
> release-bundled ONTAP V2R4, GPOS V3R3, and IOS-XE Router NDM V3R7 profiles.
> Broad XCCDF import and catalog management are not in the scanner-first GUI.

Protected content-maintainer tooling can import DISA STIG content from XCCDF
XML files or ZIP archives. The installed analyst product cannot.

## CLI

```bash
cargo run --release --features maintainer --bin automatestig -- \
  disa-import --input U_STIG.zip
cargo run --release --features maintainer --bin automatestig -- \
  disa-import --input U_STIG-xccdf.xml
```

A ZIP is treated as one import transaction: every selected XCCDF member is
parsed and any eligible generated pack is serialized before the library is
changed. A malformed member, duplicate benchmark ID, storage failure, or ZIP
with no XCCDF members returns nonzero and leaves the batch uncommitted.

## Safety Limits

Legacy CLI import, protected upload, and connected maintainer download use the same
fail-closed archive reader:

- 32 MiB maximum compressed ZIP input and 256 entries.
- 16 MiB maximum actual output for one XCCDF member and 64 MiB across selected members.
- 256 MiB maximum declared uncompressed archive size.
- 100:1 declared compression-ratio screen after a 1 MiB grace threshold.
- 16 MiB maximum for a raw XCCDF XML input.

The reader also rejects unsafe or non-UTF-8 paths, duplicate/case-colliding
names, encrypted entries, links and special files, unsupported compression,
and overlapping member regions. Runtime decompression is capped independently
of ZIP metadata using a limit-plus-one probe.

## Retired GUI/API surface

The former `Standards` workspace and its import, catalog browsing, update, and
fetch actions are historical behavior only. The scanner GUI does not embed or
link that workspace. Every former unversioned content route—including
`/api/library/import-disa`, `/api/disa/available`, `/api/disa/fetch`,
`/api/disa/fetch-all`, and `/api/disa/check-updates`—is an extraction-free
HTTP `410 Gone` tombstone with migration guidance. There is no operational
curl or browser workflow for these routes.

Release maintainers use the protected content pipeline or the explicit
maintainer source build described above. Normal users select an immutable bundled
scanner profile; they do not import or refresh a general DISA catalog. Existing
pre-scanner data can be inventoried and preserved with
`automatestig-transition migration inventory` and
`automatestig-transition migration export` from a protected
transition build without re-enabling the retired
HTTP surface.

## Scanner Scope

Importing a benchmark adds content to the local library; it does not create a
new supported scanner. Automated evaluation is limited to the three curated
packs in `content/supported-targets.json`. Other imported benchmarks remain
useful to the separate transition conversion utility, but are not advertised
as device scanning capability.

Import-time generation is limited to demonstrable Cisco IOS-XE running-config
`config_line` patterns. ONTAP, FreeBSD, and out-of-scope benchmarks generate no
checks; importing a revision that no longer has eligible IOS-XE patterns removes
its stale generated pack transactionally. Generated content does not add a
platform to the supported-target contract.
