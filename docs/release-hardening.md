# Release Hardening

AutomateSTIG release artifacts are not production-trustworthy until release integrity and provenance controls are in place and verified in CI.

## Current CI controls

The CI release build job now:

- runs only after formatting, clippy, tests, frontend syntax checks, coverage manifest validation, and dependency audit gates pass;
- uses least-privilege default workflow permissions (`contents: read`);
- builds Linux, Windows, and macOS CLI artifacts;
- emits a SHA-256 checksum beside each uploaded artifact;
- fails upload if an expected artifact or checksum is missing;
- limits transient CI artifact retention to 14 days.

## Not yet sufficient for production release claims

Before AutomateSTIG claims production-ready replacement releases, add and validate:

1. signed release artifacts using a documented signing identity;
2. SLSA/in-toto provenance or an equivalent attestation mechanism;
3. SBOM generation and publication for each release artifact;
4. SHA-pinned third-party GitHub Actions or an approved dependency-pinning policy;
5. release workflow permissions scoped per job rather than only top-level read-only defaults;
6. documented release verification instructions for operators in disconnected or DoD/STIG-adjacent environments;
7. a release checklist tying each artifact to the exact commit, CI run, checksum, signature, SBOM, and provenance bundle.

## Operator verification baseline

Until full signing/provenance is implemented, operators should at minimum verify the uploaded SHA-256 checksum before testing a CI artifact:

```bash
sha256sum -c automatestig.sha256
```

For Windows PowerShell:

```powershell
Get-FileHash .\automatestig.exe -Algorithm SHA256
Get-Content .\automatestig.exe.sha256
```

The checksum alone proves artifact integrity relative to the CI upload, not publisher identity or supply-chain provenance.
