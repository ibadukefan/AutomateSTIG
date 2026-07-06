# GUI Guide

Run the GUI with:

```bash
cargo run --release --bin automatestig-gui
```

The GUI is served locally, opens in the browser automatically, and stores data in `~/.automatestig`.

## Overview

Overview shows:

- Stat tiles for assets in scope, active assessments, open findings, CAT I/High, installed standards, and average compliance.
- Needs attention.
- Recent activity.
- Compliance by standard.
- Next best actions.

## Assessments

Assessments groups checklist workspaces by host. Selecting a row opens checklist detail. If a host has multiple checklists, a picker is shown.

The page includes:

- Run assessment form with asset picker, STIG benchmark, target hostname, and optional scan-results file.
- Batch Evaluate card.
- Remote Scan card for SSH/WinRM collection.

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

## Reports

Reports provides import and export/transfer operations.

Imports:

- Checklist file.
- Benchmark pack.
- DISA XCCDF ZIP.

Exports and transfers:

- Export all ZIP.
- Generate offline pack.
- Push to STIG-Manager.

The page also includes an import workspace with file pickers.

## Settings

Settings contains:

- STIG-Manager integration using OAuth2/Keycloak.
- Answer Files editor.
- Notifications with webhook test.
- Agent Mode settings: enable, interval, alerts, auto-push, webhook, and targets.
- Credentials vault.
- Schedules.

## Checklist Detail

Checklist detail opens from Assessments or Findings rows. It is not a navigation page.

It includes:

- Summary tiles.
- Per-severity CAT open counts.
- Findings table with search and status filters.
- Click-to-edit finding editor for status, details, comments, POA&M milestone, and POA&M date.

Actions:

- Export CKL.
- Export CKLB.
- Export eMASS.
- Trends compliance-over-time chart.
- Drift.
- Remediation, generating PowerShell, Bash, or Ansible scripts for open findings.
- Push to STIG-Manager.
- Re-evaluate.
- Delete.
