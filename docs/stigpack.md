# STIG Pack Files

> `.stigpack` build/import is protected maintainer and transition tooling. The
> scanner-first GUI ships exact immutable scanner profiles and does not expose
> general pack import or signing to an everyday analyst.

`.stigpack` files transfer STIG benchmarks, answer templates, curated checks, and generated check packs.

They are intended for air-gapped transfer and policy-controlled import.

## Manifest

Schema: `schemas/stigpack-manifest.schema.json`.

Required manifest fields:

- `format_version`
- `pack_id`
- `name`
- `version`, semver
- `created_at`
- `signing_key_fingerprint` for signed packs
- `files`

Each file entry is keyed by path and includes:

- `path`
- `sha256`
- `size`
- `content_type`, optional

## Build

```bash
cargo run --release --features maintainer --bin automatestig -- generate-signing-key \
  --output /secure-media/site-content.key

cargo run --release --features maintainer --bin automatestig -- build-pack \
  --id site-content \
  --name "Site Content" \
  --version 1.0.0 \
  --source ./content \
  --output site-content.stigpack \
  --signing-key /secure-media/site-content.key
```

Run key generation only during an explicit offline key ceremony. `build-pack`
requires an existing external private key and sibling `.pub` trust anchor; it
never creates or replaces key material. The CLI verifies that the pair matches
and prints its `SHA256:<hex>` fingerprint.

## Verify

```bash
cargo run --release --features maintainer --bin automatestig -- \
  verify --pack site-content.stigpack
```

## Import

CLI:

```bash
cargo run --release --features maintainer --bin automatestig -- \
  import --pack site-content.stigpack
```

The scanner-first GUI has no pack-import action. Use the protected
maintainer/transition CLI only. The former unversioned
`/api/library/import-stigpack` route is an HTTP `410 Gone` tombstone and does
not accept uploads.

## Signing And Trust

`.stigpack` files are Ed25519-signed and verified on import against trusted keys.

Verification reads the bounded manifest (1 MiB maximum) and 64-byte signature
first, establishes trust, then reads content. Only manifest-listed members are
accepted; hashes and declared sizes are verified before parsed benchmark/check
content is committed. ZIP input is limited to 256 MiB compressed, 1,000
entries, 50 MiB per content member, and 256 MiB total actual output. The same
path, duplicate, encryption, link, compression, overlap, and runtime
decompression checks used for DISA archives apply.

Benchmark, generated-check-pack, answer-template, and custom-check files are
validated as a batch and committed through the same locked, journaled library
transaction. Crash recovery preserves backups until commit/rollback cleanup is
durable; see [Transaction Recovery](transaction-recovery.md).

Generated definitions use `auto_check_packs/` inside the signed archive for
format compatibility. After trusted verification they are promoted to
`<library>/reviewed_check_packs/`, the only generated-pack directory read during
evaluation. Legacy local `auto_check_packs/` content is quarantined and ignored.

For every executable custom or reviewed pack, import stores the exact signed
manifest, signature, signer public key, manifest-member mapping, and content
hash in `trusted-executable-content.json`. That catalog and the executable files
commit in one journaled transaction. Runtime re-verifies the signature and
hashes against the current trust directory. Bare files, post-import changes,
modified proof records, missing content, and revoked signing keys fail closed.

Trusted keys are loaded from:

- `~/.automatestig/trusted_keys`
- `AUTOMATESTIG_TRUSTED_KEYS_DIR`, when set

Unsigned import is blocked unless explicitly allowed:

```bash
AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1 automatestig import --pack lab-only.stigpack
```

Use unsigned import only for explicit lab benchmark/template workflows.
Executable custom or generated checks always require a trusted signature, even
when this override is set.

Key custody, two-person ceremonies, fingerprint distribution, overlap rotation,
and compromise revocation are specified in [Key Management](key-management.md).

## Air-Gapped Transfer

Offline signing workstation:

1. Stage the approved library content.
2. Run `build-pack` with an explicit signing key on protected removable media.
3. Authenticate the public-key fingerprint over an independent channel.
4. Transfer only the `.stigpack` and public key by approved media.

The scanner-first GUI exposes no pack-signing workflow. Use the protected
offline CLI workflow with an explicit `--signing-key` path so an online GUI
process never handles private signing material.

Air-gapped side:

1. Compare the received key to the independently approved fingerprint, then
   place it in the trusted key directory.
2. Import the `.stigpack`.
3. Verify the imported content is present in the library.
