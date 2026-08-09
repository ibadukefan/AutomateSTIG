# Scanner-First Local Data Transition

AutomateSTIG keeps legacy local data for one transition release, but the scanner GUI no longer owns STIG Manager inventory, assignments, human reviews, or reporting. A separate maintainer CLI inventories and preserves that local data without restoring those duplicate features.

Stop the AutomateSTIG GUI before taking a snapshot. If the database predates the current release, start the GUI once so its normal schema migration can finish, stop it, and then run:

```bash
automatestig --db ~/.automatestig/data.db \
  --library ~/.automatestig/library \
  migration inventory --output ./automatestig-migration-inventory.json

automatestig --db ~/.automatestig/data.db \
  --library ~/.automatestig/library \
  migration export --output ./automatestig-transition-2026-08-08.zip
```

Use `migration inventory --output -` (or omit `--output`) for JSON on standard output. The database is opened with SQLite read-only and query-only enforcement. Inventory and export do not create or update local records, connect to STIG Manager, or mutate any STIG Manager object. The ZIP export refuses to replace an existing file and must be written outside AutomateSTIG-managed data, library, and trust-store paths.

The inventory separates completed scanner output, incomplete/audit-only attempts, imported/unverified data, manually edited data, and answer-file-derived data. Categories can overlap for a mixed checklist. Exact per-finding source counts remain visible, and `Manual`, `Imported`, and `AnswerFile` findings are never relabeled as automated.

The private transition ZIP includes:

- immutable scanner run request/result records, with complete and bound runs separated from audit-only runs;
- attributed checklist JSON plus CKL/CKLB interoperability files when external export is allowed;
- an attribution sidecar beside every parsed checklist because CKL and CKLB do not encode AutomateSTIG finding-source provenance;
- exact answer-template bytes and the retained legacy answer-file registry;
- evaluation history, append-only audit events, incomplete-attempt events, and raw malformed checklist JSON when necessary;
- the preserved local asset inventory and scanner delivery destination bindings;
- delivery records and receipts used to identify runs that have a verified remote receipt;
- a sanitized STIG Manager connection description with `client_secret` excluded;
- a manifest and SHA-256 checksum list.

Treat the ZIP as sensitive assessment material: scanner evidence and device configuration can contain operational details. The CLI writes the output privately on Unix, but storage, transfer, and eventual destruction remain the operator's responsibility.

The report's `retention_cleanup_eligible` flag is advisory and requires both a complete, bound scanner result and a delivered remote receipt. This transition command never deletes local artifacts. It also cannot prove the behavior of an external device from database hashes alone; “verified” here means the retained run JSON and scanner evidence/provenance bindings are internally consistent. Live target validity remains subject to the scanner preflight and collection controls.
