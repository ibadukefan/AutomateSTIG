# Content Updates

DISA updates STIGs several times per year (roughly quarterly). AutomateSTIG
never checks, downloads, or imports content on a schedule—air-gapped first is a
core design principle. This page covers how to keep a running installation
current, what happens to existing work when a STIG revision changes, and how
the project itself tracks DISA releases.

## Updating a running installation

### Scanner releases

End-user scanner content is updated with a signed AutomateSTIG release that
contains the exact immutable benchmark subset, check pack, adapter,
compatibility matrix, coverage manifest, and hashes. **Scanner Content** reports
the readiness of profiles in the installed release; it does not check for
updates or browse or fetch the general DISA catalog.

### Historical connected catalog behavior

Earlier releases could fetch content directly from DISA. Every initial URL and redirect was
parsed and validated against the exact HTTPS host allowlist
(`public.cyber.mil`, `dl.dod.cyber.mil`, and `cyber.mil`); lookalike hosts,
credentials, non-default ports, fragments, and non-ZIP paths are rejected.
Downloaded bodies are counted while streaming and capped at 32 MiB rather than
trusting `Content-Length`.

The former unversioned `/api/disa/check-updates`, `/api/disa/fetch`, and
`/api/disa/fetch-all` routes now return extraction-free HTTP `410 Gone` and do
no work. Connected maintainers use the repository corpus pipeline described
below; the retired routes are not a transition workflow.

There is no scheduled/background catalog update in the scanner GUI. All
maintainer catalog checks and downloads use the explicit repository pipeline.

### Air-gapped environments (the default posture)

Updates are manual by design:

1. On a connected machine, download the STIG ZIPs from https://public.cyber.mil/stigs/downloads/.
2. Transfer them across the boundary.
3. Use the maintainer generator/release process to rebuild and validate the
   exact scanner profile. Do not install raw XCCDF through the end-user GUI.

The protected maintainer import surfaces share the
bounded parser and atomic batch commit described in [DISA Import](disa-import.md).

For curated internal distribution, build signed `.stigpack` files (see [STIG Pack Files](stigpack.md)). Field systems refuse unsigned packs unless `AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1` is set explicitly for lab use; trusted Ed25519 public keys go in `AUTOMATESTIG_TRUSTED_KEYS_DIR`.

Raw catalog checking is not an end-user scanner feature.

## What happens to existing work when a revision changes

A new DISA revision does not automatically replace a scanner profile. The
maintainer classifies every changed rule, updates the exact benchmark subset,
check pack, coverage, adapter bindings, and hashes, then repeats negative,
live-device, delivery, and interchange gates. Until a signed release reports
the new revision ready, the old exact profile remains visible and a mismatched
STIG Manager assignment cannot run.

Legacy checklists and answer files remain stored during the migration window
and may be exported, but they are not merged into a new scanner delivery.
Reviewers preserve applicable human determinations in STIG Manager. Collect
fresh evidence for the new exact profile; rules without defensible scanner
evidence remain manual or out of scope.

## How the project tracks DISA releases (maintainers)

The repository pins a snapshot of the DISA public catalog and authorized
artifact metadata under `content/disa-corpus/`. This is a research/content
ingestion input, not a scanner coverage claim. The refresh pipeline lives in
`scripts/disa_corpus/`:

1. `index_disa_downloads.py --output current-index.json` — index the live DISA downloads page.
2. `compare_corpus_freshness.py --baseline content/disa-corpus/download-index.json --current current-index.json` — diff against the checked-in baseline; exits non-zero on drift.
3. `fetch_authorized_artifacts.py` — download new ZIPs with SHA-256 manifest verification.
4. For one of the three supported targets, review the new benchmark against the
   curated pack, explicitly classify rules that lack sufficient evidence as
   `manual`, regenerate `current-checkpacks` with
   `scripts/generate-checkpack-coverage.py`, and update
   `content/supported-targets.json` if the release changes. The generator
   preserves existing manual entries and refuses a rule that is simultaneously
   manual and executable; it never promotes a manual rule merely because a
   prose-derived or newly added check exists.
5. Update `download-index.json` and commit; CI validates the exact target matrix,
   the three pack inventories, and all authorized artifact hashes.

The **DISA Content Watch** workflow (`.github/workflows/disa-watch.yml`) runs
steps 1-2 against the live site on a monthly cadence (and on demand via workflow
dispatch) and opens a `disa-drift` issue when the catalog changes. Catalog drift
does not automatically add a target or content to a release.
