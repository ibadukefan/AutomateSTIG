# AutomateSTIG Documentation

This directory contains task-oriented user and developer documentation for AutomateSTIG, plus governance and validation material already maintained in the repository.

AutomateSTIG is for teams that need deterministic, offline-capable STIG evaluation for three hard-to-scan targets: NetApp ONTAP 9.x, FreeBSD/GPOS, and Cisco IOS-XE Router NDM running configurations. It also handles checklist/content transfer and delivers results to STIG Manager through API push or CKL/CKLB file import.

Start here:

- [Installation](installation.md) - prerequisites, build, GUI, CLI, and data directory.
- [Quickstart](quickstart.md) - a short GUI path and equivalent CLI path.
- [Supported Targets](supported-targets.md) - the exact v0.3 scanner boundary and evidence modes.

## User Guides

- [GUI Guide](gui-guide.md)
- [CLI Reference](cli-reference.md)
- [Evaluation Workflow](evaluation-workflow.md)
- [Answer Files](answer-files.md)
- [DISA Import](disa-import.md)
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
- [Release Hardening](release-hardening.md)
- [Release Process And Feature Freeze](release-process.md)
