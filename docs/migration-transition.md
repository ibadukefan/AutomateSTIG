# Scanner-First Local Data Transition

AutomateSTIG keeps legacy local data for one transition release, but the
scanner GUI no longer owns STIG Manager inventory, assignments, human reviews,
or reporting. The separately named `automatestig-transition` executable
inventories and preserves that local data without restoring those duplicate
features to the analyst product.

The protected executable is deliberately absent from normal product release
archives. Build it from the reviewed, version-pinned source on a controlled
transition workstation:

```bash
cargo build --release --locked --no-default-features \
  --features transition --bin automatestig-transition
```

Stop the AutomateSTIG GUI before taking a snapshot. If the database predates
the current release, start the matching GUI release once so its normal schema
migration can finish, stop it, and then run:

```bash
./target/release/automatestig-transition --db ~/.automatestig/data.db \
  --library ~/.automatestig/library \
  migration inventory --output ./automatestig-migration-inventory.json

./target/release/automatestig-transition --db ~/.automatestig/data.db \
  --library ~/.automatestig/library \
  migration export --output ./automatestig-transition-YYYY-MM-DD.zip
```

Use `migration inventory --output -` (or omit `--output`) for JSON on standard output. The database is opened with SQLite read-only and query-only enforcement. Inventory and export do not create or update local records, connect to STIG Manager, or mutate any STIG Manager object. The ZIP export refuses to replace an existing file and must be written outside AutomateSTIG-managed data, library, and trust-store paths.

The preservation reader does not apply retention expiry while the read-only
snapshot is open. It captures every stored custody row or fails the export; it
never silently drops an expired checkpoint, a purged-evidence metadata row, or
an integrity-mismatched encrypted artifact.

The inventory separates completed scanner output, incomplete/audit-only attempts, imported/unverified data, manually edited data, and answer-file-derived data. Categories can overlap for a mixed checklist. Exact per-finding source counts remain visible, and `Manual`, `Imported`, and `AnswerFile` findings are never relabeled as automated.

The private transition ZIP includes:

- immutable scanner run request/result records, with complete and bound runs separated from audit-only runs;
- retained replay-evidence lifecycle metadata and, where still retained, the
  exact ciphertext and wrapped data-encryption key (never decrypted evidence);
- durable scan jobs, their complete append-only transition histories, thin
  target connection profiles, and encrypted operation-checkpoint custody;
- exact reconciliation receipt documents and detached signatures, plus the
  append-only operational purge tombstone ledger;
- the exact configured scanner evidence and operational retention values;
- attributed checklist JSON plus CKL/CKLB interoperability files when external export is allowed;
- an attribution sidecar beside every parsed checklist because CKL and CKLB do not encode AutomateSTIG finding-source provenance;
- exact answer-template bytes and the retained legacy answer-file registry;
- evaluation history, append-only audit events, incomplete-attempt events, and raw malformed checklist JSON when necessary;
- the preserved local asset inventory and scanner delivery destination bindings;
- delivery records and receipts used to identify runs that have a verified remote receipt;
- a sanitized STIG Manager connection description, including the configured
  GUI base URL, with `client_secret` excluded;
- a manifest and SHA-256 checksum list.

Treat the ZIP as sensitive assessment material: scanner evidence and device
configuration can contain operational details. Replay evidence and operation
checkpoints remain encrypted in the archive, and can be restored or opened
only with the matching external key-provider/master-key custody identified by
their metadata. Ephemeral target credentials and the saved STIG Manager client
secret are not exported. Every custody metadata, ciphertext, wrapped-key,
receipt, and signature member is covered by the manifest and checksum list.
The CLI writes the output privately on Unix, but storage, transfer, key
custody, and eventual destruction remain the operator's responsibility.

The report's `retention_cleanup_eligible` flag is advisory and requires both a
complete, bound scanner result and a delivered remote receipt. These transition
commands never delete local artifacts. They also cannot prove the behavior of
an external device from database hashes alone; “verified” here means the
retained run JSON and scanner evidence/provenance bindings are internally
consistent. Live target validity remains subject to the scanner preflight and
collection controls.

## Bind one retained run to an exact STIG Manager destination

`migration bind-run` is the only state-changing migration command. Use it only
after the inventory identifies an eligible retained run and an operator has
selected the exact existing STIG Manager collection and asset. It reads the
selected asset and its assignments through the tested STIG Manager
`1.6.13+1` API adapter, requires an unambiguous exact STIG/revision and device
identity match, and appends one immutable local mapping. It does not create or
change a remote asset, assignment, review, or collection, and a run cannot be
remapped.

Provide the OAuth client secret through a named environment variable, never a
command-line argument:

```bash
export AUTOMATESTIG_STIGMAN_CLIENT_SECRET='REDACTED'
./target/release/automatestig-transition \
  --db ~/.automatestig/data.db \
  --library ~/.automatestig/library \
  migration bind-run \
  --run-id '<retained-run-uuid>' \
  --api-url 'https://stig-manager.example.mil/api' \
  --token-url 'https://identity.example.mil/<approved-token-path>' \
  --client-id 'automatestig-transition' \
  --destination-allowlist 'stig-manager.example.mil,identity.example.mil' \
  --collection-id '<collection-id>' \
  --asset-id '<asset-id>' \
  --operator-source '<change-or-ticket-id>' \
  --output './retained-run-binding-receipt.json'
unset AUTOMATESTIG_STIGMAN_CLIENT_SECRET
```

The API and token destinations must use HTTPS and appear in the explicit
allowlist. The secret is not serialized, logged, or persisted. The optional
JSON receipt uses create-new semantics; if receipt output fails after the
append-only mapping commits, the command reports that distinction and the
mapping remains available in subsequent inventory/export output.
