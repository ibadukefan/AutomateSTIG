# Content Updates

DISA updates STIGs several times per year (roughly quarterly). AutomateSTIG never updates content automatically unless you explicitly opt in — air-gapped first is a core design principle. This page covers how to keep a running installation current, what happens to existing work when a STIG revision changes, and how the project itself tracks DISA releases.

## Updating a running installation

### Connected environments (GUI)

The GUI can fetch content directly from DISA. Every download URL is validated against an allowlist of DISA domains (public.cyber.mil, dl.dod.cyber.mil); no other hosts are ever contacted.

- **Check for updates**: `GET /api/disa/check-updates` (or the Library page in the GUI) scrapes the DISA downloads catalog and reports new benchmarks and new revisions of benchmarks you already have installed. Nothing is downloaded.
- **Fetch**: `POST /api/disa/fetch` downloads and imports a single STIG; `POST /api/disa/fetch-all` imports everything available.
- **Background checker**: off by default. When enabled in Settings (the `auto_update_enabled` configuration key), the server re-checks the DISA catalog every 24 hours and logs when new or updated content is available. It never downloads automatically.

### Air-gapped environments (the default posture)

Updates are manual by design:

1. On a connected machine, download the STIG ZIPs from https://public.cyber.mil/stigs/downloads/.
2. Transfer them across the boundary.
3. Import: `automatestig disa-import --input U_RHEL_8_V2R8_STIG.zip` (accepts DISA ZIPs or raw XCCDF XML), or use the GUI import.

For curated internal distribution, build signed `.stigpack` files (see [STIG Pack Files](stigpack.md)). Field systems refuse unsigned packs unless `AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1` is set explicitly for lab use; trusted Ed25519 public keys go in `AUTOMATESTIG_TRUSTED_KEYS_DIR`.

Note: update checking is currently GUI-only; the CLI has no `check-updates` subcommand.

## What happens to existing work when a revision changes

Importing a new revision replaces the benchmark in the STIG library. Your existing checklists, scans, and answer files survive re-evaluation against the new revision:

- Scan results are matched by Vuln ID, then Rule ID, then **revision-normalized** Rule ID (`SV-230223r958398_rule` matches `SV-230223r1017087_rule`), then Group ID and legacy IDs — so results recorded against an older revision still land on the right rules.
- Answer files match on Vuln IDs, which persist across revisions.
- Re-evaluation merges the previous checklist, preserving manual determinations and comments.

After importing a new revision, re-run `automatestig evaluate` (or re-evaluate in the GUI) and review rules that are new or changed in the revision — they will surface as Not_Reviewed.

## How the project tracks DISA releases (maintainers)

The repository pins a snapshot of the DISA public catalog and content corpus under `content/disa-corpus/`. The refresh pipeline lives in `scripts/disa_corpus/`:

1. `index_disa_downloads.py --output current-index.json` — index the live DISA downloads page.
2. `compare_corpus_freshness.py --baseline content/disa-corpus/download-index.json --current current-index.json` — diff against the checked-in baseline; exits non-zero on drift.
3. `fetch_authorized_artifacts.py` — download new ZIPs with SHA-256 manifest verification.
4. `generate_all_authoritative_manifests.py`, then `scripts/validate-all-coverage.py` and `scripts/validate-rule-implementations.py` — regenerate authoritative coverage manifests and prove every rule in the new inventory still has an implementation spec.
5. Update `regression-baseline.json` / `download-index.json` and commit; CI validates all manifests and runs the corpus regression tests.

The **DISA Content Watch** workflow (`.github/workflows/disa-watch.yml`) runs steps 1-2 against the live site on a monthly cadence (and on demand via workflow dispatch) and opens a `disa-drift` issue when DISA has published content the corpus does not know about yet.
