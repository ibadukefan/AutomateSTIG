# Key Management And Signing Ceremony

AutomateSTIG uses four separate trust domains. Never reuse key material across
them:

- Ed25519 content keys sign `.stigpack` manifests.
- Ed25519 handoff producer keys sign detached selected-run ZIP identities.
- GitHub OIDC/Sigstore identities attest release archives in CI.
- SSH host keys authenticate scanned devices; SSH user keys authenticate the
  least-privileged collector account.

`<data_dir>/secret.key` is local encryption material for the stored STIG Manager
client secret. It is not a signing key and possession of it plus `data.db`
permits decryption.

## Roles

- The key custodian controls offline content-signing media and the ceremony log.
- The content approver confirms the exact pack manifest and hashes.
- The release manager selects the active fingerprint and release evidence.
- A security reviewer verifies separation of duties, trust-store contents, and
  revocation/rotation actions.
- Operators install public keys only from an independently authenticated
  fingerprint.

The custodian and content approver must be different people for release content.

## Content-key ceremony

1. Use a patched, isolated workstation with OS randomness and encrypted,
   access-controlled removable media. Record asset, date, participants, and tool
   version; do not record private bytes.
2. Explicitly generate the key pair, then create a small test pack:

   ```bash
   cargo run --release --features maintainer --bin automatestig -- \
     generate-signing-key \
     --output /secure-media/automatestig-content-2026q3.key

   cargo run --release --features maintainer --bin automatestig -- \
     build-pack --id ceremony-test --name "Ceremony Test" \
     --version 1.0.0 --source ./approved-content \
     --output ceremony-test.stigpack \
     --signing-key /secure-media/automatestig-content-2026q3.key
   ```

   Generation refuses to replace either path and creates a 32-byte Ed25519 seed
   with owner-only permissions plus a sibling `.pub` trust anchor. Pack build
   only loads the existing pair and never creates or replaces it. Files must be
   regular, non-symlink files; unsafe permissions or paths are rejected.
3. Calculate the public-key fingerprint on two independently controlled systems:

   ```bash
   sha256sum /secure-media/automatestig-content-2026q3.pub
   ```

4. Verify the test pack against a trust directory containing only that public
   key. Record the pack hash, public-key fingerprint, participants, approvals,
   and storage media identifiers in the offline ceremony log. Keep the test
   pack below 48,000 bytes so its public bytes fit the protected workflow input.
5. Seal the primary and backup private-key media separately. Copy only the
   public key to distribution media. Never place private keys in the repository,
   ticket system, CI variables, application data directory, or air-gap transfer
   bundle.

## Protected ceremony proof

For each release, the key custodian dispatches
`.github/workflows/content-signing-ceremony.yml` on `main` while `main` is the
exact `approved_commit`. The inputs are the content approver's GitHub login and
base64 encodings of the raw 32-byte public key and the small, already-signed
test pack. These are public artifacts; the private key never reaches GitHub or
the runner.

Register a hardened, preferably ephemeral Linux self-hosted runner with the
custom `automatestig-content-signing` label. Do not place any private signing
key on that runner. A new dispatch, rather than a rerun of an older job, keeps
the run-to-artifact binding unambiguous.

The `content-signing-ceremony` environment must be non-bypassable, allow only
protected branches, prevent self-review, and have exactly one required GitHub
user reviewer: the named content approver. The workflow actor is the key
custodian, and the script rejects the same login in both roles. A successful
job builds the CLI from `approved_commit`, trusts only the supplied public key,
and verifies the signed pack before uploading the fixed
`content-signing-ceremony` artifact. Download that artifact and commit its
three files without renaming them under `release-evidence/artifacts/<tag>/`:

- `content-signing-ceremony.json`
- `content-signing-public-key.pub`
- `content-signing-test-pack.stigpack`

The connected release validator queries the recorded workflow run and protected
environment. It requires the original and triggering run actors and the sole
environment reviewer to match the two recorded roles, recomputes the public-key
fingerprint and pack hashes, and requires all three committed files to be
byte-for-byte identical to the workflow artifact. `--offline` is only a
draft-document check and cannot make a release eligible.

## Distribution and verification

Authenticate a public-key fingerprint over a channel independent of the pack
media. Install approved `.pub` files in `~/.automatestig/trusted_keys` (or the
explicit `AUTOMATESTIG_TRUSTED_KEYS_DIR`) with a unique, dated filename. Verify
the pack before import. An empty trust store, an unknown signer, a malformed
key, or a signature without a trust match fails verification.

## Rotation

1. Generate the successor through a new ceremony.
2. Distribute and authenticate the new public key while the old key remains
   trusted.
3. Sign one transition release with the new key and verify it at every receiving
   enclave.
4. After the published overlap deadline, remove the old `.pub` file from every
   trust store and record confirmation. Retain old public keys and signed
   manifests in the audit archive; do not keep a revoked key active merely to
   open historical packs.

Rotate at least annually, when a custodian leaves, after material algorithm or
platform change, or immediately on suspected compromise.

## Revocation and compromise

Stop pack publication and import, remove the compromised public key from active
trust stores, inventory every pack signed by it, and publish an authenticated
revocation notice containing fingerprint and effective time. Rebuild affected
content from reviewed source with a new key; do not simply re-sign an unverified
old archive. Preserve incident evidence and notify each enclave out of band.

## SSH host and user keys

Prepopulate device fingerprints from the console or another authenticated
channel. Trust-on-first-use is allowed only during a recorded enrollment window
and is disabled afterward. Collector user keys must be dedicated, read-only,
unshared, owner-readable only, and rotated on staff/role change. A changed host
key stops collection until the device owner confirms it out of band.

## Selected-run handoff producer keys

Handoff producer keys are a fourth, independent Ed25519 trust domain. They
authenticate a detached selected-run ZIP sidecar and must not be reused for
STIG packs or organization policies. The protected `automatestig-transition`
binary is built from reviewed source on the signing host; the analyst product
archive deliberately excludes it.

For release qualification, retain only a non-secret custody record with opaque
asset/media references, the approved commit, public-key fingerprint, and exact
ZIP/sidecar hashes. The record must explicitly state that private key material
entered neither CI nor the scanner runtime, that private bytes were not copied
into evidence, and that revocation status was checked. A distinct receiver
approver authenticates the public key out of band and authorizes the protected
receiver verification. See [Handoff Verification](handoff-verification.md) for
the required approved-commit round trip and fixed release artifact contract.
