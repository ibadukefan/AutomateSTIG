# Security Policy

AutomateSTIG processes security-assessment evidence. Do not report suspected
vulnerabilities, credentials, private keys, device configurations, or
controlled data in a public issue.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/ibadukefan/AutomateSTIG/security/advisories/new).
Include only the minimum sanitized information needed to reproduce the issue:

- the exact AutomateSTIG release or commit;
- the affected platform and scanner profile;
- the trust boundary or security property affected;
- sanitized reproduction steps; and
- hashes in place of operational artifacts whenever possible.

Maintainers aim to acknowledge a report within five business days. No
remediation date is promised until the report is reproduced and its impact is
understood.

## Supported versions

| Version | Status |
| --- | --- |
| `v0.3.x` | Pilot candidate; not supported until an approved release is published |
| `v0.2.x` | Legacy; security reports accepted on a best-effort basis |
| Earlier | Unsupported |

Source snapshots and pull request builds are development artifacts, not
production support commitments. The
[GitHub Releases page](https://github.com/ibadukefan/AutomateSTIG/releases) is
authoritative for published binaries.

## Operational data

Assume evidence, logs, handoffs, database backups, running configurations, and
organization-policy files are sensitive. Before sharing a diagnostic:

1. reproduce with synthetic data when possible;
2. remove device names, addresses, account names, tokens, and configuration
   content;
3. retain only non-secret run IDs, error codes, and digests; and
4. use an approved protected transfer when sanitized metadata is insufficient.

See the [security model](docs/security-model.md) and
[deployment hardening guide](docs/deployment-hardening.md) for operating
requirements.
