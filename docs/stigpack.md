# STIG Pack Files

`.stigpack` files are transfer packs for STIG content, app updates, custom checks, or remediation content.

They are intended for air-gapped transfer and policy-controlled import.

## Manifest

Schema: `schemas/stigpack-manifest.schema.json`.

Required manifest fields:

- `format_version`
- `pack_id`
- `name`
- `version`, semver
- `created_at`
- `pack_type`, one of `stig_content`, `app_update`, `custom_checks`, `remediation`
- `files`

Each file entry is keyed by path and includes:

- `path`
- `sha256`
- `size`
- `content_type`, optional

## Build

```bash
automatestig build-pack \
  --id site-content \
  --name "Site Content" \
  --version 1.0.0 \
  --source ./content \
  --output site-content.stigpack
```

## Verify

```bash
automatestig verify --pack site-content.stigpack
```

## Import

CLI:

```bash
automatestig import --pack site-content.stigpack
```

GUI:

- Use the benchmark pack import flow in `Reports` or `Standards`.

API:

```bash
curl -H "X-Auth-Token: $AUTOMATESTIG_AUTH_TOKEN" \
  -F "file=@site-content.stigpack" \
  http://127.0.0.1:<PORT>/api/library/import-stigpack
```

## Signing And Trust

`.stigpack` files are Ed25519-signed and verified on import against trusted keys.

Trusted keys are loaded from:

- `~/.automatestig/trusted_keys`
- `AUTOMATESTIG_TRUSTED_KEYS_DIR`, when set

Unsigned import is blocked unless explicitly allowed:

```bash
AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1 automatestig import --pack lab-only.stigpack
```

Use unsigned import only for explicit lab workflows.

## Air-Gapped Transfer

Connected side:

1. Import or fetch required content.
2. Generate an offline pack from the GUI or `GET /api/offline-pack`.
3. Transfer the `.stigpack` by approved media.

Air-gapped side:

1. Place trusted Ed25519 public keys in the trusted key directory.
2. Import the `.stigpack`.
3. Verify the imported content is present in the library.
