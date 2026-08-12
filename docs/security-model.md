# Security Model

## Supported Release Hosts

AutomateSTIG publishes release binaries for macOS and GNU/Linux, but the pilot
has not published a complete minimum distro/glibc matrix. Do not infer RHEL or
musl compatibility from the presence of a Linux archive. The installer
executes the authenticated staged CLI and changes no installed file if that
binary cannot run on the host.
Windows remains in CI as a portability-test platform, but source-built Windows
binaries are not supported for security-sensitive use. The release pipeline
will not build, attest, manifest, or publish a Windows archive until Windows
ACL, ownership, reparse-point, and same-file custody checks protect the same
trust-bearing state as the Unix implementation.

The shared filesystem-custody layer now opens sensitive Windows paths without
following reparse points, rejects reparse/junction ancestors, validates the
current-user owner SID, and rejects effective write/delete/DACL/owner rights
for `Everyone`, `Authenticated Users`, and `BUILTIN\Users`. Validation and I/O
use the same open handle, with stable volume/file identities available for
same-file comparisons. SSH private keys and the data-root-scoped SSH
`known_hosts`/lock files, the GUI data directory and `secret.key`, managed
SQLite databases, every signing trust-store directory/key, organization-policy
inputs/signing keys, CLI migration library inputs, and CLI artifact staging use
this layer. This is necessary but not sufficient to publish Windows: mutable
library transaction paths beyond the read-only migration boundary still need
equivalent ACL custody, and the ACL/reparse/race suite must pass on a native
Windows runner before Windows packaging can be enabled.

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

For non-loopback binds, `AUTOMATESTIG_AUTH_TOKEN` must be set and must contain
at least 32 visible ASCII characters with no whitespace. Repeated failures
from one network peer are bounded and temporarily rate limited. Without a
token, the server refuses to start. The public HTML
does not contain that configured server secret. Instead, the browser presents
a required token prompt and validates the value against a protected endpoint.
The value is retained only in that tab's JavaScript memory; it is not written
to local or session storage. Because the built-in listener is HTTP, put any
non-loopback deployment behind a trusted TLS-terminating reverse proxy and do
not enter or transmit the token over an untrusted plaintext network. HTML that
contains the auto-generated loopback session token is served with
`Cache-Control: no-store`. The token is inert metadata rather than executable
inline script, allowing a self-only script Content Security Policy. All
responses deny framing and MIME sniffing, suppress referrers and unnecessary
browser permissions, and isolate same-origin resources. Every authenticated
API response is `no-store`, varies on `X-Auth-Token`, and carries legacy
`Pragma: no-cache` protection for intermediaries.

The GUI writes newline-delimited structured logs to the private
`<data_dir>/logs` directory as well as its operator console. Logs rotate daily
and retain at most 14 files. Authentication failures and background-task root
causes are recorded without tokens, device passwords, or client secrets.

## Secret Storage

The STIG-Manager client secret is encrypted at rest with AES-256-GCM.

The key is derived from:

- A 32-byte CSPRNG value stored in `<data_dir>/secret.key` (mode `0600` on Unix).
- The hostname.
- A compiled application salt.

The key material is outside the database, but possession of both `data.db` and `secret.key` on the host is equivalent to possession of the secret. The key path and parent are required to be real, owner-controlled filesystem objects; symlink and unsafe-permission states fail closed. OS keychain integration remains a defense-in-depth option for managed deployments.

The authenticated scanner connection delete action removes the active
STIG-Manager configuration row, including its encrypted client secret. The
former `DELETE /api/stigman/config` route is an extraction-free HTTP `410 Gone`
tombstone. The active scanner-first endpoint is `DELETE
/api/v1/stig-manager/connection`. Deletion does
not remove the shared `<data_dir>/secret.key`, and it cannot erase encrypted
remnants from existing backups or storage snapshots; retire those copies under
the deployment's normal media-sanitization policy when required.

## Scanner data and retention

The scanner stores short-lived operational state: scan steps, immutable
evidence/result metadata, content and plan hashes, the outbound sparse payload,
delivery attempts, conflicts, and the remote receipt. It must not be treated as
an authoritative copy of STIG Manager assets, assignments, human reviews,
labels, workflow, accepted risk, or portfolio history.

Passwords and private-key passphrases are used only for the submitted
preflight/run and are never persisted. Raw command responses and running
configurations can still expose account names, topology, management endpoints,
and security settings; protect the data directory as sensitive assessment
material even when secret redaction succeeds.

Set the raw-artifact retention period from the site's records, incident,
evidence, and media-sanitization requirements with
`AUTOMATESTIG_EVIDENCE_RETENTION_DAYS` (1–365 days; default 30) or the
`scanner.evidence_retention_days` configuration value. The expiry clock starts
when evidence is sealed and is independent of delivery state. Expired replay
evidence is purged at startup, before access, and by the periodic sweeper, so an
operator who needs a retained-evidence handoff must create and archive it before
the displayed expiry time. An explicit, confirmed purge is also one-way.

Evidence is stored separately from the immutable result as AES-256-GCM
ciphertext under a fresh per-artifact data key; that key is wrapped with key
material derived from the owner-only `secret.key`. Purge removes the ciphertext
and wrapped data key while preserving hashes, timestamps, audit events, attempt
history, conflict disposition, and receipts. It cannot remove copies in
backups, snapshots, handoff media, browser downloads, or STIG Manager; govern
those stores separately.

## Legacy assessment and import boundaries

Legacy assessments, imported CKL/CKLB/checklist JSON, answer files, and local
asset records are preserved only for the documented migration inventory and
create-new-export workflow. The scanner-first GUI cannot create, edit, rerun,
merge, or promote them, and the product CLI does not expose the former
assessment, answer-file, conversion, or portfolio commands.

Migration keeps the original source classification and attribution. An
imported or answer-derived determination is never relabeled as an automated
scanner result, and exporting preserved data does not rerun collection or
upgrade its provenance. Historical answer files remain reviewer-decision
inputs rather than device evidence; their presence cannot satisfy a native
adapter-evidence requirement or replace a collection error.

Some legacy parser and model code remains for lossless migration, backwards
compatibility tests, and a non-default maintainer build. Its presence does not
expand the supported scanner surface.

## Remote Transport Hardening

STIG Manager integration accepts HTTPS URLs only and rejects embedded credentials, localhost, cloud metadata hostnames, and non-global special-use/private/local/link-local literal IP addresses by default. Invalid, reserved, multicast, and documentation addresses are always rejected. API and OAuth hostnames are each resolved once when the client is created, every answer is authorized, and separate HTTP clients pin those numeric addresses while retaining the original hostname for Host/SNI and TLS verification. Redirects are disabled. If a target allowlist is configured, unlisted public destinations are also rejected. A non-global special-use/private/local/link-local result requires a matching IP/CIDR entry; an exact hostname entry alone cannot authorize such a DNS answer. Prefer a narrow comma-separated host/IP/CIDR allowlist:

```bash
AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST=stigman.example.mil,keycloak.example.mil,10.20.0.0/16
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

The scanner GUI requires the operator to confirm destination authorization and
host-key prerequisites before a remote scan. In connected mode, the selected
STIG Manager collection, existing asset, and exact assignment are validated
live before collection and again before delivery. The operator-supplied
endpoint must match the authoritative asset identity; checklist hostname text
cannot relabel it. AutomateSTIG never creates an asset or assignment. The exact
profile determines ONTAP or FreeBSD collection; Cisco remains config-file only.

The target is resolved once under the configured timeout, every answer is authorized, and SSH receives only those pinned numeric addresses while retaining the operator-supplied hostname for host-key pinning. Unspecified, multicast, broadcast, reserved/documentation, and unauthorized link-local addresses fail closed, and mixed loopback/private/public/link-local DNS results are rejected. `AUTOMATESTIG_SSH_ALLOW_LINK_LOCAL=1` remains a narrower explicit exception for a scoped link-local device. Private keys must resolve beneath the absolute-path equivalents of `~/.ssh` or `~/.automatestig/ssh_keys`; other secure roots require an explicit platform-separated `AUTOMATESTIG_SSH_KEY_ROOTS` list. GUI submissions must use an absolute key path because the collector does not expand `~` and resolves relative paths from the process working directory. Key files are bounded and must be regular, nonsymlink, current-user-owned files without group/other access; their direct parent and configured root are checked separately.

SSH client authentication and host-key negotiation support Ed25519 and ECDSA
keys. The GUI can use a per-scan password or a secure private-key path with an
optional passphrase; these credential values are not persisted. RSA SSH keys
are deliberately unsupported: the collector rejects an RSA private key with an
actionable error, and the RSA algorithm is not advertised during host-key
negotiation.

SSH collection keeps stdout, stderr, exit status, timeout, and protocol states separate. Output is bounded to 50 MiB per command and 256 MiB per collection. A failed, missing-status, timed-out, oversized, malformed, or semantically invalid command remains a typed collection error; its diagnostic stdout is never evaluation input. Unaffected rules may evaluate, affected rules become `Not_Reviewed`, and the incomplete operation returns nonzero from the CLI or HTTP 207 from the API.

Evidence v2 is strict JSON bound to the target platform and current collection-plan digest. Duplicate keys, unexpected commands, stale plans, and marker-like target output are rejected. Marker-based v1 evidence is rejected by the product CLI, GUI, and API with no unsafe override.

STIG-Manager API and OAuth endpoints must use HTTPS; there is no HTTP exception.
Redirects are disabled so bearer tokens and client credentials are never
forwarded to a second endpoint. **Test and save connection** first exercises
the values currently in the form; it persists them only after the live test
succeeds. A blank secret may reuse the stored secret only when the API URL,
token URL, and client ID are unchanged; changing any of those requires
re-entering the secret. TLS verification is mandatory. The scanner has no
invalid-certificate override; install the correct CA trust before configuring
the connection.

## STIG Pack Trust

An ordinary DISA XCCDF `.xml` or `.zip` is imported through the DISA/XCCDF
path as benchmark reference content. It is not a `.stigpack` and does not need
a content-pack signature. A `.stigpack` is an AutomateSTIG distribution format
for curated benchmarks, answer templates, and potentially executable content;
it uses the separate trust process below.

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
operating-system file lock serializes protected maintainer writers.
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

## Cisco Organization-Policy Trust

Cisco IOS-XE evaluation consumes a complete operator-captured running
configuration plus an organization-policy JSON and its detached 64-byte
Ed25519 signature. The policy is bound to the exact supported STIG release and
the configuration's hostname, and its effective/expiry window must include the
evaluation time. A policy for another asset or release fails closed.

Organization-policy public keys are loaded only from
`~/.automatestig/organization_policy_keys` or
`AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR`. This trust store is intentionally
separate from `.stigpack` executable-content trust. The checklist provenance
records the policy identifier, version, SHA-256, signer fingerprint, verified
signature state, and the benchmark/check-pack/evaluation-plan bindings. The
private signing key does not belong on the evaluation host.

## Selected-Run Handoff Producer Trust

The GUI emits an unsigned handoff v4 ZIP and has no producer-signing key or
signing endpoint. A protected CLI host may first fully verify that ZIP and then
create a detached signature sidecar with a dedicated external Ed25519 key. The
domain-separated signed statement binds the exact compressed ZIP SHA-256,
handoff schema, run UUID, and producer-key fingerprint. The sidecar is strict,
bounded, create-new, and never supplies its own trust anchor.

Receiving workstations load approved public keys only from the dedicated
handoff trust directory. They verify the signature and exact ZIP digest before
decompressing evidence, then repeat all structural, provenance, sparse-
ownership, CKLB, and replay checks. Content-pack keys and organization-policy
keys are separate trust domains and must not be reused as handoff producer
keys. A successful signature proves control of a currently trusted producer
key, not a trusted signing time or possession by the GUI process; key custody,
producer assignment, rotation, and revocation remain operational controls.

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `PORT` | GUI port override. |
| `AUTOMATESTIG_BIND` | Explicit GUI bind IP; defaults to `127.0.0.1`. |
| `AUTOMATESTIG_DATA_DIR` | Explicit shared state root for GUI, CLI, collector SSH host trust, database, secret key, and default trust stores. Defaults to `~/.automatestig`. |
| `AUTOMATESTIG_AUTH_TOKEN` | Required for non-loopback API auth; must contain at least 32 visible ASCII characters with no whitespace. Loopback-only explicit tokens retain a 16-character minimum. |
| `AUTOMATESTIG_TRUSTED_KEYS_DIR` | Directory containing trusted Ed25519 public keys for `.stigpack` import. |
| `AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR` | Dedicated directory containing trusted Ed25519 public keys for signed Cisco organization policies. It is intentionally separate from executable-content trust. |
| `AUTOMATESTIG_HANDOFF_TRUSTED_KEYS_DIR` | Dedicated directory containing trusted Ed25519 public keys for detached selected-run handoff producer signatures. Defaults to `~/.automatestig/handoff_trusted_keys`; never place private keys here. |
| `AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK` | Set to `1` to allow unsigned non-executable `.stigpack` content for explicit lab workflows; executable checks still require trust. |
| `AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE` | GUI/service-only explicit enrollment of an unknown SSH host key; CLI users should prefer `collect --trust-on-first-use`. |
| `AUTOMATESTIG_SSH_ALLOW_LINK_LOCAL` | Set to `1` only to scan an explicitly scoped link-local SSH address. |
| `AUTOMATESTIG_SSH_KEY_ROOTS` | Platform-separated additional secure roots from which SSH private keys may be loaded. |
| `AUTOMATESTIG_SSH_TARGET_ALLOWLIST` | Comma-separated exact host/IP/CIDR allowlist for SSH scan targets. Every non-global special-use, private, local, or link-local answer requires an IP/CIDR entry; hostname-only entries authorize ordinary global-unicast answers only. |
| `AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN` | Set to `1` to allow non-global special-use/private/local/link-local SSH targets outside the allowlist only in an isolated lab. |
| `AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST` | Comma-separated exact host/IP/CIDR allowlist for STIG Manager API and token endpoints. Every non-global special-use, private, local, or link-local answer requires an IP/CIDR entry; hostname-only entries authorize ordinary global-unicast answers only. |

## SSH host-key verification (trust-on-first-use)

Remote SSH collection verifies the target's host key against a pin file at
`<data_dir>/known_hosts` (`~/.automatestig/known_hosts` by default). The GUI,
CLI, and collector all honor `AUTOMATESTIG_DATA_DIR` for this state root. With
the explicit trust-on-first-use setting, the first key is recorded; on any
later connection a changed key is rejected as a possible man-in-the-middle
(logged at error level). This is trust-on-first-use: the first connection is
unauthenticated, so for high-assurance environments pre-populate
`<data_dir>/known_hosts` with the expected `host:port fingerprint`
entries out of band before the first scan.

## Concurrency model

The local GUI serializes all database access through a single mutex and is
designed for a single operator on one machine. It is not a multi-tenant
server; do not expose it to shared or multi-user access. For team workflows,
verify the selected-run handoff and map only its sparse JSON reviews through an
approved receiver to the exact existing STIG Manager assignment; STIG Manager
remains the multi-user system of record. Supplemental XCCDF/CKLB members are
not additional review sets.

See [Deployment Hardening](deployment-hardening.md) for the required host and
network boundary.
