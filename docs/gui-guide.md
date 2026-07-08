# GUI Guide

Run the GUI with:

```bash
cargo run --release --bin automatestig-gui
```

The GUI is served locally, opens in the browser automatically, and stores data in `~/.automatestig`.

The five navigation pages are Assessments, Assets, Standards, Findings, and Settings.

## Assessments

Assessments groups checklist workspaces by host. Selecting a row opens checklist detail. If a host has multiple checklists, a picker is shown.

The page includes:

- Run assessment form with asset picker, STIG benchmark, target hostname, and optional scan-results file.
- Batch Evaluate card.
- Remote Scan card for SSH collection.

The asset picker fills the hostname field.

## Assets

Assets is the inventory workspace.

The page includes:

- Inventory table.
- Multi-select bulk actions: Assign STIG, Add tag, Enable, Disable.
- Add Asset dialog with name, address, platform, protocol, and tags.
- STIG-Manager sync/diff actions.

## Standards

Standards shows installed benchmarks with real CAT I, CAT II, and CAT III counts.

Each benchmark row has a Generate Checks action.

Content operations include:

- Fetch from DISA.
- Check updates.
- Browse available.
- Generate offline pack.
- Import benchmark pack or XCCDF ZIP.

DISA fetch and update checks are connected features and require network access.

## Findings

Findings shows open findings across all checklists with severity, asset, standard, and status. Rows open checklist detail.

## Settings

Settings contains:

- STIG-Manager integration using OAuth2/Keycloak.
- Answer Files editor.
- Credentials vault.

## Checklist Detail

Checklist detail opens from Assessments or Findings rows. It is not a navigation page.

It includes:

- Summary tiles.
- Per-severity CAT open counts.
- Findings table with search and status filters.
- Click-to-edit finding editor for status, details, and comments.

Actions:

- Export CKL.
- Export CKLB.
- Push to STIG-Manager.
- Re-evaluate.
- Delete.
