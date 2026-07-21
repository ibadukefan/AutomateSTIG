# Security Model

## Bind And Auth

The GUI defaults to localhost-only bind. API auth is enforced on all `/api/*` routes except `/api/status`.

Accepted auth method:

- `X-Auth-Token` header.

Download endpoints also require `X-Auth-Token`; query-string tokens are not accepted so credentials are not exposed through URL logs, browser history, or referrers.

In loopback desktop mode, the server auto-generates a random per-session token and injects it into the served frontend, so the local browser is authenticated automatically.

For non-loopback binds, `AUTOMATESTIG_AUTH_TOKEN` must be set and must be at least 16 characters. Without it, the server refuses to start.

## Secret Storage

The STIG-Manager client secret and credential vault are encrypted at rest with AES-256-GCM.

The key is derived from:

- A 32-byte CSPRNG value stored in `<data_dir>/secret.key` (mode `0600` on Unix).
- The hostname.
- A compiled application salt.

The key material is outside the database, but possession of both `data.db` and `secret.key` on the host is equivalent to possession of the secret. OS keychain integration is a documented future hardening step.

Secrets encrypted under the previous database-backed key scheme require re-entry after upgrade.

## Remote Transport Hardening

STIG Manager integration accepts HTTPS URLs only and rejects embedded credentials, localhost, cloud metadata hostnames, and private/local/link-local literal IP addresses by default. Private STIG Manager lab endpoints require:

```bash
AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS=1
```

Remote SSH collection validates scan targets before opening outbound connections. Set `AUTOMATESTIG_SSH_TARGET_ALLOWLIST` to a comma-separated list of exact hostnames/IPs or CIDRs to restrict scan destinations. Private/local/link-local literal IP scans are blocked by default unless they match the allowlist or this explicit lab override is set:

```bash
AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN=1
```

SSH rejects unknown host keys unless trust-on-first-use is explicitly enabled:

```bash
AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE=1
```

WinRM refuses plaintext Basic auth unless explicitly allowed:

```bash
AUTOMATESTIG_ALLOW_INSECURE_WINRM=1
```

WinRM refuses TLS verification disablement unless explicitly allowed:

```bash
AUTOMATESTIG_ALLOW_INVALID_WINRM_CERTS=1
```

Use those overrides only for explicit lab deployments.

## Webhooks

Webhook tests and notifications are guarded:

- HTTPS-only.
- No embedded credentials.
- No localhost or private IP targets unless explicitly allowed.

Private targets require:

```bash
AUTOMATESTIG_ALLOW_PRIVATE_WEBHOOKS=1
```

## STIG Pack Trust

`.stigpack` import verifies:

- Ed25519 signature.
- SHA-256 hashes.

Trusted keys are read from `~/.automatestig/trusted_keys` or `AUTOMATESTIG_TRUSTED_KEYS_DIR`.

Unsigned import is blocked unless:

```bash
AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1
```

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `PORT` | GUI port override. |
| `AUTOMATESTIG_AUTH_TOKEN` | Required for non-loopback API auth; must be at least 16 characters. |
| `AUTOMATESTIG_TRUSTED_KEYS_DIR` | Directory containing trusted Ed25519 public keys for `.stigpack` import. |
| `AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK` | Set to `1` to allow unsigned `.stigpack` import for explicit lab workflows. |
| `AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE` | Set to `1` to accept unknown SSH host keys. |
| `AUTOMATESTIG_ALLOW_INSECURE_WINRM` | Set to `1` to allow plaintext WinRM Basic auth. |
| `AUTOMATESTIG_ALLOW_INVALID_WINRM_CERTS` | Set to `1` to allow WinRM with TLS verification disabled. |
| `AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS` | Set to `1` to allow STIG Manager URLs with private/local literal IP hosts for isolated labs. |
| `AUTOMATESTIG_SSH_TARGET_ALLOWLIST` | Comma-separated exact host/IP/CIDR allowlist for SSH scan targets. |
| `AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN` | Set to `1` to allow private/local/link-local literal IP SSH scan targets outside the allowlist for isolated labs. |
| `AUTOMATESTIG_ALLOW_PRIVATE_WEBHOOKS` | Allow webhook URLs resolving to localhost or private IP addresses. |

## SSH host-key verification (trust-on-first-use)

Remote SSH collection verifies the target's host key against a pin file at
`~/.automatestig/known_hosts`. On first contact the key is recorded; on any
later connection a changed key is rejected as a possible man-in-the-middle
(logged at error level). This is trust-on-first-use: the first connection is
unauthenticated, so for high-assurance environments pre-populate
`~/.automatestig/known_hosts` with the expected `host:port fingerprint`
entries out of band before the first scan.

## Concurrency model

The local GUI serializes all database access through a single mutex and is
designed for a single operator on one machine. It is not a multi-tenant
server; do not expose it to shared or multi-user access. For team workflows,
push results to STIG Manager, which is the multi-user system of record.
