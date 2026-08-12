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
- Set `AUTOMATESTIG_EVIDENCE_RETENTION_DAYS` to the approved 1–365 day
  replay-evidence period (default 30). The timer starts when evidence is sealed;
  delivery does not postpone it. Protect any retained-evidence handoff and
  backups under the same assessment-data policy.

Use the repository's bounded backup tool instead of copying a live SQLite file:

```bash
automatestig-backup-restore backup \
  --data-dir ~/.automatestig --output /protected/automatestig-2026-08-11.zip
automatestig-backup-restore restore \
  --input /protected/automatestig-2026-08-11.zip \
  --data-dir /new/private/path/.automatestig
```

The recovery entrypoint requires Python 3.10 or newer. Data, archive, output,
and restore paths must be real paths: the utility rejects a symlink, junction,
or other reparse point in the target or any existing ancestor. Choose an
owner-controlled real directory rather than relying on a filesystem alias.

Stop GUI and transition-CLI writers while creating the recovery unit so any
preserved legacy library and trust/key files represent the same operational
point. SQLite's online backup
API still handles committed WAL frames safely and avoids a raw live-file copy.

The backup uses SQLite's online backup API, so committed WAL frames are part of
the database snapshot. It includes `secret.key`, any preserved transition
library, SSH host
trust, and the three public-key trust domains; it excludes logs and transient
SQLite sidecars. The archive is create-new and owner-only, but it is not
encrypted—put it only on approved encrypted media. Restore verifies the exact
manifest and every SHA-256 digest, refuses an existing destination, checkpoints
the database, and deletes `stigman_config` so the OAuth secret must be re-entered
and tested. Device passwords and key passphrases are never backup inputs.

## Network boundary

Loopback (`127.0.0.1`) is the default and preferred bind. The API accepts the
`X-Auth-Token` header only; never place a token in a URL. The desktop session
uses a generated, non-empty random token and rejects unexpected Host headers.

If a controlled service deployment requires a non-loopback bind:

- set a random `AUTOMATESTIG_AUTH_TOKEN` of at least 32 visible ASCII characters with no whitespace;
- place a managed TLS reverse proxy and source-IP allowlist in front of it;
- restrict host firewall ingress and outbound SSH/STIG Manager/DISA destinations;
- use split credentials and an environment-specific STIG Manager OAuth client;
- terminate the process if the proxy/auth boundary is unavailable;
- monitor authentication-failure and temporary-rate-limit warnings;
- do not expose it directly to the internet or a shared user network.

Collect the daily JSON-lines files from `<data_dir>/logs` with the site's
approved log shipper. The local writer retains at most 14 files; downstream
retention and access control remain an operator responsibility.

The lab-only unsigned-pack and SSH trust-on-first-use overrides are prohibited
in production launch configuration. Treat their presence as a deployment
failure. STIG Manager TLS verification has no bypass.

The scanner-first GUI exposes no signing workflow. Run the explicit protected
CLI command with its `--signing-key` argument only on an offline signing
workstation; never place that private key on an ordinary GUI/service host.

Likewise, never place a selected-run handoff producer private key on an
ordinary GUI/service host. Use the protected
`automatestig-transition scanner sign-handoff` CLI
ceremony, distribute only its public key out of band, and keep those public
keys in the dedicated handoff trust domain rather than the content or
organization-policy trust stores.

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
