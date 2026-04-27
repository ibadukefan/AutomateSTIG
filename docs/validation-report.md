# AutomateSTIG Replacement Validation Report

Status: **not production replacement-ready yet**.

This report is the gate for claiming that AutomateSTIG is a better full replacement for Evaluate-STIG. Current committed evidence is intentionally limited to sanitized fixtures and scaffolding.

## Current validation evidence

- Sanitized DISA-style XCCDF benchmark fixture parses successfully.
- Sanitized SCC and OpenSCAP XCCDF result fixtures parse successfully and preserve pass/fail result evidence.
- Sanitized CKL and CKLB fixtures parse successfully.
- Example coverage manifests exist for Windows Server 2022 and RHEL 8, both marked `experimental`.
- Full experimental coverage inventory manifests now enumerate every rule represented in the current Windows Server 2022 and RHEL 8 check packs.
- An authorized-fixture manifest harness validates fixture existence, safe paths, and SHA-256 digests.
- STIG Manager and eMASS golden export fixtures are regression-tested for stable payload shape.
- Release build CI emits checksums plus SBOM/provenance scaffolds for each platform artifact.

## Required before replacement-ready claims

1. Authorized real DISA benchmark fixtures for each claimed platform.
2. SCC and OpenSCAP result fixtures from representative systems.
3. CKL and CKLB round-trip tests against real-world reviewer workflows.
4. Production coverage manifests backed by the authorized fixture corpus, not only current check-pack inventory.
5. Signed release artifacts, standard SBOMs, and cryptographic provenance/attestations beyond the current CI scaffolds.

## First flagship targets

- Windows Server 2022
- RHEL 8

Strategic rule: **narrow and complete first; broad later.**
