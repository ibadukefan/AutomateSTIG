# CLI Reference

Binary: `automatestig`.

The end-user CLI is a difficult-device collection, deterministic evaluation,
selected-run handoff verification, and transition-data preservation surface. It
does not manage STIG Manager assets, assignments, human reviews, acceptance,
reporting, or portfolio history.

When running from source, put arguments after `--`:

```bash
cargo run --release --bin automatestig -- status
```

## Product commands

| Command | Purpose |
| --- | --- |
| `collect` | Collect plan-bound evidence from an ONTAP or FreeBSD target over SSH. |
| `evaluate` | Deterministically evaluate native evidence or a Cisco running configuration. |
| `scanner verify-handoff` | Verify a selected-run handoff without importing or changing state. |
| `migration inventory` | Report preserved pre-scanner records and their provenance, read-only. |
| `migration export` | Create a private one-time transition bundle without changing state. |
| `status` | Show the application version and scanner-content state. |

Global `--db` and `--library` options select non-default transition state.
`--verbose` enables diagnostic logging. Artifact outputs use a private atomic
writer and cannot alias consumed inputs, the database or sidecars, the managed
library, SSH trust, or signing-trust paths.

## `collect`

```bash
AUTOMATESTIG_SSH_PASSWORD='...' automatestig collect \
  --stig NetApp_ONTAP_DSC_9-x_STIG \
  --host filer.example.mil --username scanner \
  --output filer-evidence.json
```

Required inputs are `--stig`, `--host`, `--username`, and `--output`. Optional
inputs include `--hostname` as a corroborating equality check, `--port`
(default 22), `--key`, password/passphrase environment-variable names,
`--timeout-secs`, and explicit `--trust-on-first-use` enrollment.

Collection resolves and authorizes the target once, pins the numeric addresses,
verifies the SSH host key, and executes only the check pack's disclosed
read-only plan. Any required command failure produces `complete=false` evidence
and a nonzero exit; failed output remains diagnostic and is not evaluated as a
passing observation. Use least-privilege accounts and pre-pin host keys for
high-assurance operation.

## `evaluate`

```bash
automatestig evaluate \
  --stig NetApp_ONTAP_DSC_9-x_STIG \
  --evidence filer-evidence.json \
  --output filer-result.cklb --format cklb
```

Supply exactly one of `--evidence` or `--config`. Cisco configuration input also
requires a signed organization-policy document and detached signature when the
profile contains organization-defined controls. `--host` may corroborate, but
cannot relabel, the evidence-bound identity. Output may be CKLB, CKL, or JSON;
the selected-run handoff from the GUI/API remains the preferred transfer
artifact because it binds the sparse result to evidence and provenance.

Legacy answer-file, previous-checklist merge, and marker-evidence switches are
hidden transition compatibility options. They are not part of the scanner
workflow, cannot repair incomplete collection, and must not be used to create
or overwrite human determinations that belong in STIG Manager.

## `scanner verify-handoff`

```bash
automatestig scanner verify-handoff automatestig-run-<RUN_ID>.zip

automatestig scanner verify-handoff automatestig-run-<RUN_ID>.zip \
  --signature automatestig-run-<RUN_ID>.zip.signature.json \
  --trust-dir /approved/automatestig-handoff-keys
```

The verifier accepts current v3 handoffs and the exact legacy v2 contract for
already-issued bundles, in both retained-evidence and purged result-only
states. It fails closed on unsafe or undeclared ZIP members, validates all
hashes and run/content/evidence bindings, enforces sparse ownership safety,
checks the CKLB projection, validates the v3 XCCDF 1.2 projection and its
target/rule/provenance bindings, and replays retained adapter evidence. With no
sidecar, success proves internal integrity but not producer identity. With
`--signature`, verification requires a matching key from the dedicated
handoff trust domain and authenticates the exact ZIP before decompression. The
default trust directory is `~/.automatestig/handoff_trusted_keys`, overridable
with `AUTOMATESTIG_HANDOFF_TRUSTED_KEYS_DIR` or `--trust-dir`.

XCCDF validation proves the supplemental member is internally consistent with
the handoff. It does not prove that a particular downstream GUI imported the
file; the staged STIG Manager transport is the explicit sparse-review-to-Review
API mapping.

## `scanner generate-signing-key` and `scanner sign-handoff`

```bash
automatestig scanner generate-signing-key \
  --output /protected/handoff-producer.key
automatestig scanner sign-handoff automatestig-run-<RUN_ID>.zip \
  --signing-key /protected/handoff-producer.key \
  --output automatestig-run-<RUN_ID>.zip.signature.json
```

These protected-host commands are the only handoff-signing surface. Signing
performs full semantic verification first, never changes the handoff ZIP, never
overwrites an output, and never stores a private key in the GUI. See [Verify a
Selected-Run Handoff](handoff-verification.md) for key custody and trust
semantics.

## `migration`

```bash
automatestig migration inventory --output inventory.json
automatestig migration export --output transition.zip
```

These commands exist to avoid deleting pre-scanner local data. Inventory is
read-only. Export uses create-new semantics and preserves source attribution;
it never relabels manual, imported, or answer-derived findings as automated.
See [Migration and Transition](migration-transition.md).

## Hidden transition and maintainer compatibility

The binary temporarily retains hidden commands for signed content maintenance
and one-release legacy data conversion. They do not appear in product help and
are not supported as an end-user compliance-management workflow. General
library administration, answer templates, checklist summaries/conversion,
STIG Manager JSON export, and broad DISA import are owned by STIG Manager or by
the protected release pipeline. New automation must not depend on these hidden
commands; use `migration export` for preservation and the selected-run handoff
for scanner results.

## `status`

```bash
automatestig status
```

Status is diagnostic. It does not report enterprise compliance or replace STIG
Manager dashboards.
