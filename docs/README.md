# AutomateSTIG Documentation

This directory contains task-oriented user and developer documentation for AutomateSTIG, plus governance and validation material already maintained in the repository.

AutomateSTIG is being refocused as a specialized scanner and evidence producer for hard-to-scan devices. STIG Manager remains the authoritative system for assets, assignments, human review, governance, and reporting. AutomateSTIG currently performs deterministic, offline-capable evaluation for NetApp ONTAP 9.x, FreeBSD/GPOS, and Cisco IOS-XE Router NDM running configurations. The [scanner-first product plan](scanner-product-plan.md) defines the removal of duplicated manager features, verified selected-run handoff, and exact remote no-op verification workflows.

Start here:

- [Installation](installation.md) - prerequisites, build, GUI, CLI, and data directory.
- [Quickstart](quickstart.md) - a short GUI path and equivalent CLI path.
- [Declared Scanner Targets](supported-targets.md) - the exact experimental v0.3 scanner boundary and evidence modes.
- [Scanner Operations](scanner-operations.md) - connected/disconnected analyst and manager flows, sparse reviews, migration, retention, and limitations.
- [Handoff Verification](handoff-verification.md) - offline integrity, sparse-ownership, retained-evidence replay, and protected detached producer signatures.
- [Scanner-First Product Plan](scanner-product-plan.md) - product ownership, feature removals, migration, UX, and target-specific release gates.
- [Evaluate-STIG Comparison](evaluatestig-comparison.md) - the measured, target-specific protocol and claims policy.
- [Controlled Scanner Comparison](commercial-scanner-comparison.md) - the runnable A/B harness for Evaluate-STIG, Tenable, Nipper, or another comparator.
- [2026-08-08 Scanner Validation](scanner-validation-2026-08-08.md) - localhost artifacts, real STIG Manager handoff round-trip, export assessment, and current verdict.

## User Guides

- [GUI Guide](gui-guide.md)
- [CLI Reference](cli-reference.md)
- [Evaluation Workflow](evaluation-workflow.md)
- [Answer Files](answer-files.md) - legacy/transition and maintainer reference; not a scanner GUI workflow.
- [DISA Import](disa-import.md) - content-maintainer and transition reference; normal scans use release-bundled profiles.
- [NetApp ONTAP Collection](ontap-collection.md)
- [FreeBSD Collection](bsd-collection.md)
- [Cisco IOS-XE Router NDM Evaluation](cisco-ios-xe.md)
- [Field Calibration](field-calibration.md)
- [Content Updates](content-updates.md)
- [STIG Pack Files](stigpack.md)
- [Integrations](integrations.md)
- [Troubleshooting](troubleshooting.md)

## Developer And Operator Reference

- [API Reference](api-reference.md)
- [Architecture](architecture.md)
- [Check Packs](check-packs.md)
- [Security Model](security-model.md)
- [Deployment Hardening](deployment-hardening.md)
- [Key Management And Signing Ceremony](key-management.md)
- [Transaction Recovery](transaction-recovery.md)
- [Operational Ownership](operational-ownership.md)

## Governance And Validation

- [Coverage Policy](coverage-policy.md)
- [Audit Exceptions](audit-exceptions.md)
- [Live External Acceptance](live-external-acceptance.md)
- [Controlled Scanner Comparison](commercial-scanner-comparison.md)
- [First-Use UX Release Study](first-use-ux-study.md)
- [2026-08-08 Scanner Validation](scanner-validation-2026-08-08.md)
- [Release Hardening](release-hardening.md)
- [Release Process And Feature Freeze](release-process.md)
