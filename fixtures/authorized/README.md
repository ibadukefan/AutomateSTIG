# Authorized Fixture Corpus

This directory defines how AutomateSTIG proves compatibility with real DISA/SCC/OpenSCAP/CKL/CKLB artifacts without committing sensitive system output by accident.

## Required production process

1. Place authorized fixtures under `fixtures/authorized/<corpus-name>/`.
2. Strip or tokenize hostnames, IPs, usernames, command output that identifies a real system, and any credentials/secrets.
3. Record each file in a manifest with:
   - fixture `id`;
   - `kind` (`disa-xccdf`, `scc-results`, `openscap-results`, `ckl`, `cklb`, `stig-manager`, `emass`);
   - repo-relative `path`;
   - lowercase SHA-256 digest;
   - source/authorization notes;
   - classification (`sanitized`, `authorized_public`, or approved internal handling label).
4. Validate the manifest before making replacement-readiness claims:

```bash
python3 scripts/validate-authorized-fixtures.py fixtures/authorized/manifest.example.json --repo-root .
```

The included `manifest.example.json` records the current sanitized scaffold fixtures only. It is useful for testing the harness, but it is **not** evidence of production replacement readiness.

## Production claim rule

A platform may not move to `production` coverage status until its coverage manifest references a validated authorized fixture corpus and the validation report documents the exact fixture manifest, hashes, STIG release, scanner versions, and golden export payloads used.
