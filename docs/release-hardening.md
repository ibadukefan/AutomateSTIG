# Release Hardening

AutomateSTIG publishes only the artifacts produced by the fully gated CI run;
there is no independent rebuild-and-publish workflow.

## Enforced controls

- Feature freeze and protected review boundaries are defined in
  `.github/release-freeze.json`, `CODEOWNERS`, and the pull-request template.
- Every external GitHub Action reference is pinned to a full commit SHA and
  `scripts/validate-workflow-pins.py` prevents a mutable tag from returning.
- Formatting, clippy with warnings denied, cross-platform tests, end-to-end
  acceptance, frontend syntax, exact supported-target/content validation, 100,000 fuzz
  mutations, RustSec audit, and dependency review are required gates.
- Linux, Windows, and macOS archives contain the exact gated CLI/GUI binaries.
- Each archive has a SHA-256 checksum, CycloneDX SBOM, locked Cargo dependency
  inventory, source/run provenance, GitHub OIDC build attestation, and keyless
  Sigstore bundle.
- A tag additionally requires GitHub-bound independent human review, live
  ONTAP, FreeBSD, Cisco IOS-XE, STIG Viewer, and STIG Manager acceptance, a
  recovery drill, and signing-ceremony evidence. The ceremony's JSON, raw
  public key, and signed test pack are byte-bound to a successful protected
  workflow and independently re-hashed; skips do not pass.
- Security-extended CodeQL analyzes Actions, JavaScript/TypeScript, Python, and
  Rust on pull requests, `main`, and a weekly schedule.
- Publication verifies every companion and emits a hash-complete
  signed `release-manifest.json` tied to repository, tag, commit, and workflow
  run. The generator rejects missing, nested, symlinked, or undeclared assets;
  the manifest's own checksum and signature bundle are the only bootstrap
  companions not recursively listed in that manifest. The release is assembled
  as a draft and becomes immutable only after every asset is attached.

See [Release Process](release-process.md), [Key Management](key-management.md),
and [Live External Acceptance](live-external-acceptance.md).

## Connected verification

Verify the GitHub attestation against the repository identity, then verify the
Sigstore bundle and checksum before extraction:

```bash
gh attestation verify automatestig-v0.3.0-<target>.tar.gz \
  --repo ibadukefan/AutomateSTIG \
  --cert-identity \
    'https://github.com/ibadukefan/AutomateSTIG/.github/workflows/ci.yml@refs/tags/v0.3.0' \
  --source-ref refs/tags/v0.3.0 \
  --source-digest <full-release-commit-sha>
cosign verify-blob \
  --bundle automatestig-v0.3.0-<target>.tar.gz.sigstore.bundle \
  --certificate-identity \
    'https://github.com/ibadukefan/AutomateSTIG/.github/workflows/ci.yml@refs/tags/v0.3.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  automatestig-v0.3.0-<target>.tar.gz
sha256sum -c automatestig-v0.3.0-<target>.tar.gz.sha256
gh release verify v0.3.0 --repo ibadukefan/AutomateSTIG
```

Use the corresponding `.zip` names on Windows and compare
`Get-FileHash -Algorithm SHA256` with the published checksum.

## Disconnected verification

On the connected transfer station, verify the attestation and Sigstore identity,
then copy the archive, checksum, Sigstore bundle, SBOM, provenance, dependency
inventory, release manifest, and its checksum to approved media. Record all
hashes on the media manifest. On the disconnected side, independently verify
every checksum before import/extraction. Sigstore identity validation requiring
transparency-log/certificate material must be completed on the connected side
and preserved in the transfer record; a bare checksum does not authenticate the
publisher.

No release is described as accredited solely because these controls pass. The
deploying organization owns authorization, configuration, and system-of-record
decisions.
