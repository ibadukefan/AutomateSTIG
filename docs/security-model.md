# Security Model

## Supported Release Hosts

AutomateSTIG publishes and supports release binaries for Linux and macOS only.
Windows remains in CI as a portability-test platform, but source-built Windows
binaries are not supported for security-sensitive use. The release pipeline
will not build, attest, manifest, or publish a Windows archive until Windows
ACL, ownership, reparse-point, and same-file custody checks protect the same
trust-bearing state as the Unix implementation.

## Bind And Auth

The GUI defaults to localhost-only bind. API auth is enforced on all `/api/*` routes except `/api/status`.

Accepted auth method:

- `X-Auth-Token` header.

Download endpoints also require `X-Auth-Token`; query-string tokens are not accepted so credentials are not exposed through URL logs, browser history, or referrers.

Tokens in URLs are rejected because URLs leak through history, logs, referrers,
and screenshots. In loopback desktop mode, the server auto-generates a
non-empty random per-session token and injects it into the served frontend, so
the local browser is authenticated automatically. Loopback requests also
validate the Host header to prevent a hostile website from using DNS rebinding
to reach the local API.

For non-loopback binds, `AUTOMATESTIG_AUTH_TOKEN` must be set and must be at least 16 characters. Without it, the server refuses to start.

## Secret Storage

The STIG-Manager client secret is encrypted at rest with AES-256-GCM.

The key is derived from:

- A 32-byte CSPRNG value stored in `<data_dir>/secret.key` (mode `0600` on Unix).
- The hostname.
- A compiled application salt.

The key material is outside the database, but possession of both `data.db` and `secret.key` on the host is equivalent to possession of the secret. The key path and parent are required to be real, owner-controlled filesystem objects; symlink and unsafe-permission states fail closed. OS keychain integration remains a defense-in-depth option for managed deployments.

## Remote Transport Hardening

STIG Manager integration accepts HTTPS URLs only and rejects embedded credentials, localhost, cloud metadata hostnames, and non-global special-use/private/local/link-local literal IP addresses by default. Invalid, reserved, multicast, and documentation addresses are always rejected. API and OAuth hostnames are each resolved once when the client is created, every answer is authorized, and separate HTTP clients pin those numeric addresses while retaining the original hostname for Host/SNI and TLS verification. Redirects are disabled. If a target allowlist is configured, unlisted public destinations are also rejected. A non-global special-use/private/local/link-local result requires a matching IP/CIDR entry or an explicit isolated-lab override; an exact hostname entry alone cannot authorize such a DNS answer. Prefer a narrow comma-separated host/IP/CIDR allowlist:

```bash
AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST=stigman.example.mil,keycloak.example.mil,10.20.0.0/16
```

The legacy broad private-destination override remains for isolated labs only:

```bash
AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS=1
```

Remote SSH collection applies the same outbound policy in the shared collector used by both the GUI and CLI. Set `AUTOMATESTIG_SSH_TARGET_ALLOWLIST` to a comma-separated list of exact hostnames/IPs or CIDRs to restrict scan destinations; when it is set, unlisted public targets are rejected too. Non-global special-use/private/local/link-local literal IP scans and DNS results require a matching IP/CIDR entry or this explicit isolated-lab override:

```bash
AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN=1
```

SSH rejects unknown host keys unless trust-on-first-use is explicitly enabled:

```bash
automatestig collect ... --trust-on-first-use
```

The GUI service also recognizes `AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE=1` as a one-shot enrollment arm: a running process can enroll at most one collection before it must be deliberately restarted. Enrolled fingerprints are host-and-port scoped, recorded in `~/.automatestig/known_hosts`, included in evidence when key exchange completes, and a changed key is rejected.

The target is resolved once under the configured timeout, every answer is authorized, and SSH receives only those pinned numeric addresses while retaining the operator-supplied hostname for host-key pinning. Unspecified, multicast, broadcast, reserved/documentation, and unauthorized link-local addresses fail closed, and mixed loopback/private/public/link-local DNS results are rejected. `AUTOMATESTIG_SSH_ALLOW_LINK_LOCAL=1` remains a narrower explicit exception for a scoped link-local device. Private keys must resolve beneath `~/.ssh` or `~/.automatestig/ssh_keys`; other secure roots require an explicit platform-separated `AUTOMATESTIG_SSH_KEY_ROOTS` list. Key files are bounded and must be regular, nonsymlink, current-user-owned files without group/other access; their direct parent and configured root are checked separately.

SSH client authentication and host-key negotiation support Ed25519 and ECDSA
keys. RSA SSH keys are deliberately unsupported: the collector rejects an RSA
private key with an actionable error, and the RSA algorithm is not advertised
during host-key negotiation.

SSH collection keeps stdout, stderr, exit status, timeout, and protocol states separate. Output is bounded to 50 MiB per command and 256 MiB per collection. A failed, missing-status, timed-out, oversized, malformed, or semantically invalid command remains a typed collection error; its diagnostic stdout is never evaluation input. Unaffected rules may evaluate, affected rules become `Not_Reviewed`, and the incomplete operation returns nonzero from the CLI or HTTP 207 from the API.

Evidence v2 is strict JSON bound to the target platform and current collection-plan digest. Duplicate keys, unexpected commands, stale plans, and marker-like target output are rejected. Marker-based v1 evidence is rejected by default; `--allow-legacy-evidence` is an explicitly unsafe CLI-only migration aid.

STIG-Manager API and OAuth endpoints must use HTTPS; HTTP is accepted only for
an explicit loopback test endpoint. Redirects are disabled so bearer tokens and
client credentials are never forwarded to a second endpoint. Changing an
endpoint or client ID requires re-entering the client secret. TLS verification
is enabled by default. `AUTOMATESTIG_ALLOW_INVALID_STIGMAN_CERTS=1` is a
lab-only override.

## STIG Pack Trust

`.stigpack` import verifies:

- Ed25519 signature.
- SHA-256 hashes.

The manifest and signature are bounded and trust is established before bulk
content decompression. Archive metadata is never treated as an output limit:
member and aggregate byte caps are enforced while decompressing, and unsafe
paths, collisions, encrypted/link/special entries, overlaps, and unlisted
members are rejected.

Signed manifests carry the actual Ed25519 public-key fingerprint. Existing
private keys and public anchors must match; a missing private key beside an
existing public anchor or a mismatched anchor fails instead of silently
rotating or overwriting trust. Key and trust paths reject symlinks and unsafe
ownership/permissions.

## Content Import Isolation

DISA ZIP/XML import parses the complete selected batch before changing the
library and never derives executable checks from prose. A library-scoped
operating-system file lock serializes writers across GUI and CLI processes.
Benchmarks, reviewed signed check packs, ancillary content,
the transaction journal, and the future index are staged and synchronized;
artifacts are replaced with backups and the index is replaced last. Startup
recovers abandoned journals before exposing the library. A rollback/cleanup
failure preserves the transaction directory and its backups and stops the
open. See [Transaction Recovery](transaction-recovery.md).

Trusted keys are read from `~/.automatestig/trusted_keys` or `AUTOMATESTIG_TRUSTED_KEYS_DIR`.

Unsigned import is blocked unless:

```bash
AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1
```

The override can import lab benchmark/template content, but cannot install
executable custom or generated checks. Those always require a trusted signature
and are promoted to `reviewed_check_packs/`; legacy `auto_check_packs/` files are
not executable.

Trusted import commits executable bytes and a cryptographic provenance catalog
in one recoverable transaction. Runtime verifies the retained signed manifest,
signature, signer key, member hash, and current trust-anchor membership before
loading either `custom_checks/` or `reviewed_check_packs/`. A bare or modified
file is never executable.

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `PORT` | GUI port override. |
| `AUTOMATESTIG_BIND` | Explicit GUI bind IP; defaults to `127.0.0.1`. |
| `AUTOMATESTIG_AUTH_TOKEN` | Required for non-loopback API auth; must be at least 16 characters. |
| `AUTOMATESTIG_TRUSTED_KEYS_DIR` | Directory containing trusted Ed25519 public keys for `.stigpack` import. |
| `AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR` | Dedicated directory containing trusted Ed25519 public keys for signed Cisco organization policies. It is intentionally separate from executable-content trust. |
| `AUTOMATESTIG_OFFLINE_SIGNING_KEY` | Existing external private key for explicitly enabled GUI offline export. It must be outside application data; unset disables the endpoints. Prefer offline CLI signing. |
| `AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK` | Set to `1` to allow unsigned non-executable `.stigpack` content for explicit lab workflows; executable checks still require trust. |
| `AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE` | GUI/service-only explicit enrollment of an unknown SSH host key; CLI users should prefer `collect --trust-on-first-use`. |
| `AUTOMATESTIG_SSH_ALLOW_LINK_LOCAL` | Set to `1` only to scan an explicitly scoped link-local SSH address. |
| `AUTOMATESTIG_SSH_KEY_ROOTS` | Platform-separated additional secure roots from which SSH private keys may be loaded. |
| `AUTOMATESTIG_SSH_TARGET_ALLOWLIST` | Comma-separated exact host/IP/CIDR allowlist for SSH scan targets. Every non-global special-use, private, local, or link-local answer requires an IP/CIDR entry; hostname-only entries authorize ordinary global-unicast answers only. |
| `AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN` | Set to `1` to allow non-global special-use/private/local/link-local SSH targets outside the allowlist only in an isolated lab. |
| `AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST` | Comma-separated exact host/IP/CIDR allowlist for STIG Manager API and token endpoints. Every non-global special-use, private, local, or link-local answer requires an IP/CIDR entry; hostname-only entries authorize ordinary global-unicast answers only. |
| `AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_DESTINATIONS` | Set to `1` to allow non-global special-use/private/local/link-local STIG Manager DNS results only in an isolated lab. Invalid addresses remain denied. |
| `AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS` | Legacy broad override for non-global special-use/private/local literal IP STIG Manager URLs and resolved destinations; prefer `AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST`. Invalid addresses remain denied. |
| `AUTOMATESTIG_ALLOW_INVALID_STIGMAN_CERTS` | Disable STIG-Manager TLS certificate validation for explicit lab use. |

## SSH host-key verification (trust-on-first-use)

Remote SSH collection verifies the target's host key against a pin file at
`~/.automatestig/known_hosts`. With the explicit trust-on-first-use setting, the first key is recorded; on any
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

See [Deployment Hardening](deployment-hardening.md) for the required host and
network boundary.
