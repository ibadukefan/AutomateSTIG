# Deployment Hardening

AutomateSTIG is a single-operator scanner and evidence workstation. It is not a
multi-tenant web service or the enterprise audit system of record. Use STIG
Manager for shared review and workflow.

Supported release deployments use Linux or macOS. Windows is a CI
portability-test platform only; do not deploy a source-built Windows binary for
security-sensitive work.

## Host baseline

- Use a dedicated, patched OS account and encrypted disk. Do not share its home
  directory or application data directory.
- Restrict `<data_dir>`, `data.db`, `secret.key`, SSH keys, `known_hosts`, and
  trust stores to the service account and approved backup agent. Keep content
  signing private keys on separately controlled offline media.
- Deny symlinks and network/shared filesystems for mutable application state.
- Enable host EDR, time synchronization, secure boot where available, and
  centralized OS/service logs. Exclude collected evidence from broad telemetry
  if it may contain sensitive configuration.
- Back up the database, library, trust store, and `secret.key` as one protected
  recovery set. Keep content-signing private keys outside this set.

## Network boundary

Loopback (`127.0.0.1`) is the default and preferred bind. The API accepts the
`X-Auth-Token` header only; never place a token in a URL. The desktop session
uses a generated, non-empty random token and rejects unexpected Host headers.

If a controlled service deployment requires a non-loopback bind:

- set a random `AUTOMATESTIG_AUTH_TOKEN` of at least 32 bytes;
- place a managed TLS reverse proxy and source-IP allowlist in front of it;
- restrict host firewall ingress and outbound SSH/STIG Manager/DISA destinations;
- use split credentials and an environment-specific STIG Manager OAuth client;
- terminate the process if the proxy/auth boundary is unavailable;
- do not expose it directly to the internet or a shared user network.

The lab-only unsigned-pack, invalid-STIG-Manager-certificate, legacy-evidence,
and SSH trust-on-first-use overrides are prohibited in production launch
configuration. Treat their presence as a deployment failure.

Leave `AUTOMATESTIG_OFFLINE_SIGNING_KEY` unset on ordinary GUI/service hosts.
GUI pack export is disabled without it. Prefer the explicit `build-pack`
workflow on an offline signing workstation.

## Device access

Use dedicated read-only accounts and device command authorization. Restrict
targets to the approved management network and validate every hostname/address
against the site inventory before a scan. Private key files must be regular,
owner-controlled files from approved key directories; never accept a path from
an untrusted API caller. Pre-pin SSH host keys.

## Operation and shutdown

Run the startup status check, verify the expected bind address, and review
security warnings before scanning. Export results to the approved staging STIG
Manager only. On shutdown, confirm no import is active, preserve failed
transaction directories for recovery, and never delete them manually before a
recovery drill or incident review.

The protected live-acceptance workflow depends on a dedicated self-hosted lab
runner. Leave runner auto-update enabled, or patch a deliberately immutable
runner within 30 days of every Actions runner release. Treat a stale/offline
runner as a failed acceptance gate, keep its labels exclusive to the authorized
device lab, and never attach it to an untrusted public-repository workflow.

See [Operational Ownership](operational-ownership.md), [Key Management](key-management.md),
and [Transaction Recovery](transaction-recovery.md).
