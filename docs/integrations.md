# Integrations

Connected integrations are opt-in. The default local workflow does not make network calls.

## STIG-Manager

AutomateSTIG integrates with STIG-Manager using OAuth2 client credentials via Keycloak.

Configuration fields:

- API URL.
- Token URL.
- Client ID.
- Client secret.
- Optional default collection.
- `verify_tls`.

Capabilities:

- Test connection.
- List collections.
- List collection assets.
- Sync collection assets.
- Diff assets.
- Push checklist reviews.

Checklist pushes include Result Engine metadata.

The STIG-Manager client secret is encrypted at rest. See [Security Model](security-model.md) for the encryption caveat.

## CLI Export

```bash
automatestig export \
  --input server01.ckl \
  --output stig-manager.json \
  --format stig-manager \
  --collection "Production"
```
