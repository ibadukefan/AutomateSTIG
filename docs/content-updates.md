# Content Updates

DISA updates STIGs several times per year (roughly quarterly). AutomateSTIG never updates content automatically unless you explicitly opt in — air-gapped first is a core design principle. This page covers how to keep a running installation current, what happens to existing work when a STIG revision changes, and how the project itself tracks DISA releases.

## Updating a running installation

### Connected environments (GUI)

The GUI can fetch content directly from DISA. Every initial URL and redirect is
parsed and validated against the exact HTTPS host allowlist
(`public.cyber.mil`, `dl.dod.cyber.mil`, and `cyber.mil`); lookalike hosts,
credentials, non-default ports, fragments, and non-ZIP paths are rejected.
Downloaded bodies are counted while streaming and capped at 32 MiB rather than
trusting `Content-Length`.

- **Check for updates**: `GET /api/disa/check-updates` (or the Library page in the GUI) scrapes the DISA downloads catalog and reports new benchmarks and new revisions of benchmarks you already have installed. Nothing is downloaded.
- **Fetch**: `POST /api/disa/fetch` downloads and imports a single STIG; `POST /api/disa/fetch-all` imports everything available.
- **Background checker**: off by default. When enabled in Settings (the `auto_update_enabled` configuration key), the server re-checks the DISA catalog every 24 hours and logs when new or updated content is available. It never downloads automatically.

### Air-gapped environments (the default posture)

Updates are manual by design:

1. On a connected machine, download the STIG ZIPs from https://public.cyber.mil/stigs/downloads/.
2. Transfer them across the boundary.
3. Import the target benchmark, for example `automatestig disa-import --input U_NetApp_ONTAP_DSC_9-x_V2R2_STIG.zip` (accepts DISA ZIPs or raw XCCDF XML), or use the GUI import.

All three import surfaces (CLI, GUI upload, and connected fetch) share the
bounded parser and atomic batch commit described in [DISA Import](disa-import.md).

For curated internal distribution, build signed `.stigpack` files (see [STIG Pack Files](stigpack.md)). Field systems refuse unsigned packs unless `AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1` is set explicitly for lab use; trusted Ed25519 public keys go in `AUTOMATESTIG_TRUSTED_KEYS_DIR`.

Note: update checking is currently GUI-only; the CLI has no `check-updates` subcommand.

## What happens to existing work when a revision changes

Importing a new revision replaces the benchmark in the STIG library. Existing checklists and answer files remain stored; new evidence can be evaluated against the new revision:

- Answer files match on Vuln IDs, which persist across revisions.
- The CLI `--merge <previous.ckl>` option preserves manual determinations and comments where Vuln IDs still match.

After importing a new revision, collect fresh evidence and run `automatestig evaluate`, optionally merging a prior checklist. Review rules that are new or changed in the revision; rules without valid evidence remain `Not_Reviewed`.

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
