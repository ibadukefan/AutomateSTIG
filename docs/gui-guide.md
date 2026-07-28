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

- Run assessment form with asset picker, STIG benchmark, target hostname,
  platform, input type, and evidence/config file. Cisco configuration
  assessments additionally require a signed organization-policy file and its
  detached signature.
- Remote Scan card for SSH collection.

The asset picker fills the hostname field.

Assessment summaries distinguish the pass rate among applicable assessed
controls from coverage of the complete benchmark. `NotApplicable` and
`NotReviewed` are excluded from the pass-rate denominator, while a defensible
`NotApplicable` determination still counts toward coverage. Any `NotReviewed` controls keep the
assessment in a needs-review state even when every assessed control passes.
Imported, incomplete, unsafe, or otherwise unverified results are shown
neutrally as **Unverified** whenever the API withholds their score fields.
Their pass-rate and coverage grades are unavailable, even when every imported
finding says `NotAFinding`.

The benchmark selector is limited to ONTAP, FreeBSD, and Cisco IOS-XE Router
NDM; the platform and input type are derived from that benchmark. ONTAP and
FreeBSD accept evidence v2 transcripts; IOS-XE accepts a running configuration.
IOS-XE verifies the policy/signature pair against the dedicated offline-policy
trust anchors before evaluation. The Remote Scan card is available only for
ONTAP and FreeBSD.

## Assets

Assets is the inventory workspace.

The page includes:

- Inventory table.
- Multi-select bulk actions: Assign STIG, Add tag, Enable, Disable.
- Add Asset dialog with name, address, platform, and tags.
- STIG-Manager sync/diff actions.

## Standards

Standards shows installed benchmarks with real CAT I, CAT II, and CAT III counts.

The GUI does not generate executable checks from imported XCCDF prose. Standards
provide reference content; executable extensions require a trusted signed
`.stigpack` and are stored separately from legacy generated files.

Content operations include:

- Fetch from DISA.
- Check updates.
- Browse available.
- Generate an offline pack only when an operator has explicitly configured an
  external signing key outside application data; the default action is disabled.
- Import benchmark pack or XCCDF ZIP.

DISA fetch and update checks are connected features and require network access.
For normal air-gap distribution, build and sign packs with the CLI on an
offline signing workstation instead of making the GUI process handle a private
key.

## Findings

Findings shows open findings across all checklists with severity, asset, standard, and status. Rows open checklist detail.

## Settings

Settings contains:

- STIG-Manager integration using OAuth2/Keycloak.
- Answer Files editor.

## Checklist Detail

Checklist detail opens from Assessments or Findings rows. It is not a navigation page.

It includes:

- Summary tiles for assessed pass rate and full-benchmark coverage. Unverified
  imports never receive a green score or a **Fully assessed** status.
- Per-severity CAT open counts.
- Findings table with search and status filters.
- Click-to-edit finding editor for status, details, and comments.

Actions:

- Export CKL.
- Export CKLB.
- Push to STIG-Manager.
- Delete.
