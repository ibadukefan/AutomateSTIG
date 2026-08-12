# AutomateSTIG Documentation

AutomateSTIG is an experimental scanner and evidence producer for selected
difficult-to-scan devices. It supplements STIG Manager; STIG Manager remains
authoritative for assets, assignments, human review, governance, dashboards,
reports, and long-term history.

## I want to use the app

1. Follow the [Quickstart](quickstart.md). It is the canonical install,
   first-launch, training, scan, and handoff path.
2. Check [Supported Targets](supported-targets.md) before preparing credentials
   or evidence.
3. Use [Troubleshooting](troubleshooting.md) if installation, localhost,
   preflight, collection, or handoff verification stops.

The scanner-first `v0.3.0` build is still a pilot candidate. If GitHub Releases
shows only `v0.2.x`, the new scanner has not been published; do not install the
legacy release expecting this workflow.

## Analyst and manager guides

- [Installation](installation.md) - supported platforms, simple installer,
  upgrades, removal, manual verification, source builds, and local data.
- [GUI Guide](gui-guide.md) - Scan, Deliveries, Scanner Content, and Connection.
- [Scanner Operations](scanner-operations.md) - connected and disconnected
  flows, sparse reviews, retention, and operational ownership.
- [CLI Reference](cli-reference.md) - collection, evaluation, verification, and
  status commands.
- [Handoff Verification](handoff-verification.md) - integrity, sparse ownership,
  replay, and optional protected producer signatures.
- [STIG Manager Integration](integrations.md) - exact destination binding and
  the no-overwrite boundary.
- [Transaction Recovery](transaction-recovery.md) - backup, restore, and crash
  recovery.

## Target guides

- [NetApp ONTAP Collection](ontap-collection.md)
- [FreeBSD Collection](bsd-collection.md)
- [Cisco IOS-XE Router NDM Evaluation](cisco-ios-xe.md)
- [Field Calibration](field-calibration.md)

## Security and deployment

- [Security Model](security-model.md)
- [Connected-Mode Threat Model](connected-mode-threat-model.md)
- [Deployment Hardening](deployment-hardening.md)
- [Key Management and Signing Ceremony](key-management.md)
- [Operational Ownership](operational-ownership.md)
- [Release Hardening](release-hardening.md)

## Developer And Operator Reference

- [API Reference](api-reference.md)
- [Architecture](architecture.md)
- [Check Packs](check-packs.md)
- [Evaluation Workflow](evaluation-workflow.md)
- [Target Adapter Development](adapter-tooling.md)
- [Content Updates](content-updates.md)
- [STIG Pack Files](stigpack.md)
- [DISA Import](disa-import.md) - maintainer reference; not a normal
  scanner workflow.
- [Answer Files](answer-files.md) - legacy preservation reference; human
  determinations belong in STIG Manager.
- [Migration and Transition](migration-transition.md)

## Governance And Validation

- [Scanner-First Product Plan](scanner-product-plan.md)
- [Coverage Policy](coverage-policy.md)
- [Audit Exceptions](audit-exceptions.md)
- [Live External Acceptance](live-external-acceptance.md)
- [Evaluate-STIG Comparison](evaluatestig-comparison.md)
- [Controlled Scanner Comparison](commercial-scanner-comparison.md)
- [First-Use UX Release Study](first-use-ux-study.md)
- [2026-08-08 Scanner Validation](scanner-validation-2026-08-08.md) - historical
  validation record, not a live-device acceptance claim.
- [Release Hardening](release-hardening.md)
- [Release Process And Feature Freeze](release-process.md)
- [v0.3.0 Candidate Release Notes](releases/v0.3.0.md)
- [v0.2.0 Legacy Release Notice](releases/v0.2.0.md)
