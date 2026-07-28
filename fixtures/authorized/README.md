# Authorized Fixture Corpus

This directory defines how AutomateSTIG proves compatibility with authorized DISA, CKL/CKLB, device-evidence, and STIG-Manager artifacts without committing sensitive system output by accident.

## Required production process

1. Place authorized fixtures under `fixtures/authorized/<corpus-name>/`.
2. Strip or tokenize hostnames, IPs, usernames, command output that identifies a real system, and any credentials/secrets.
3. Record each file in a manifest with:
   - fixture `id`;
   - `kind` (`disa-xccdf`, `device-evidence`, `network-config`, `ckl`, `cklb`, or `stig-manager`);
   - repo-relative `path`;
   - lowercase SHA-256 digest;
   - source/authorization notes;
   - classification (`sanitized`, `authorized_public`, or approved internal handling label).
4. Validate the manifest before making coverage claims:

```bash
python3 scripts/validate-authorized-fixtures.py fixtures/authorized/manifest.example.json --repo-root .
```

The included `manifest.example.json` records sanitized format fixtures and
official public DISA Cyber Exchange ZIPs used for content/format testing and the
three scoped scanner targets: ONTAP, FreeBSD/GPOS, and Cisco IOS-XE Router NDM.
The Windows and RHEL artifacts exercise ingestion and conversion only; they do
not add scanner targets. Sanitized fixtures remain test harness inputs rather
than production evidence from representative targets.

## Production claim rule

A platform may not move to `production` coverage status until its coverage manifest references a validated authorized fixture corpus and acceptance records document the exact fixture manifest, hashes, STIG release, device/software versions, and golden export payloads used.
