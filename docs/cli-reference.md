# CLI Reference

Binary: `automatestig`.

The end-user CLI is a difficult-device collection, deterministic evaluation,
and read-only selected-run handoff verification surface. It
does not manage STIG Manager assets, assignments, human reviews, acceptance,
reporting, or portfolio history.

When running from source, put arguments after `--`:

```bash
cargo run --release --bin automatestig -- status
```

## Product commands

| Command | Purpose |
| --- | --- |
| `collect` | Collect a native, plan-bound adapter-evidence envelope from an ONTAP or FreeBSD target over SSH. |
| `evaluate` | Deterministically evaluate native evidence or a Cisco running configuration. |
| `scanner verify-handoff` | Verify a selected-run handoff without importing or changing state. |
| `status` | Show the application version and scanner-content state. |

Global `--db` and `--library` options select non-default preservation or
maintainer state; collection and evaluation never load runtime scanner content
from that library. `--verbose` enables diagnostic logging. Artifact outputs use
a private atomic writer and cannot alias consumed inputs, the database or
sidecars, preserved library, SSH trust, or signing-trust paths.

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

Collection resolves the immutable bundled profile before reading credentials,
pins the numeric addresses, verifies the SSH host key, and runs the adapter's
read-only identity preflight. The identity observed from the device—not
`--host`—supplies hostname, vendor, product family, and software version.
Optional `--hostname` is only a corroborating equality check and cannot relabel
that identity. New collection emits an `automatestig-adapter-evidence/v2`
envelope and v2 device/plan contract; verification retains the exact v1 hash
path for pre-upgrade evidence. The envelope binds
the fingerprint, adapter/profile/check-pack/plan digests, transport identity,
and typed per-operation outcomes. Any required operation failure produces
`complete=false` evidence and a nonzero exit; failed output remains diagnostic
and cannot become a passing observation. Use least-privilege accounts and
pre-pin host keys for high-assurance operation.

The product offers only a one-time password or an absolute private-key path for
SSH. It does not offer a managed credential reference or persist a device
credential.

## `evaluate`

```bash
automatestig evaluate \
  --stig NetApp_ONTAP_DSC_9-x_STIG \
  --evidence filer-evidence.json
```

Supply exactly one of `--evidence` or `--config`. `--evidence` accepts only a
native adapter-evidence envelope produced by `collect`; `--config` accepts an
authorized complete IOS-XE running configuration. Cisco configuration input
also requires a signed organization-policy document and detached signature.
`--host` may corroborate, but cannot relabel, the input-bound identity.

The default output is native `ScannerEvaluation` JSON named
`<hostname>_<STIG-ID>.scanner-result.json`. Use `--output` to select another
path. `--format json` writes that native result explicitly. `--format cklb`
writes a supplemental CKLB projection only when collection and evaluation are
complete; an incomplete evaluation may write diagnostic native JSON but
returns nonzero and produces no deliverable reviews. If `--format` is omitted,
the explicit output extension selects `json` or `cklb`; the generated default
path is JSON. There is no CKL output mode.
The selected-run handoff from the GUI/API remains the transfer artifact because
it binds sparse reviews to evidence, target, content, and provenance.
Every automated determination in native JSON also has a versioned sanitized
decision trace. The trace retains exact content/build/device/evidence and
operation bindings, parser/predicate identity, typed transport outcomes, and a
safe expected/observed representation. Raw command/configuration output,
diagnostics, error text, and credentials remain outside result JSON.

Legacy evidence, answer-file application, previous-checklist merge, and
marker-evidence switches are not compiled into the product CLI. CLI evaluation
writes only the requested artifact; it does not save a checklist, findings, or
evaluation record into the legacy SQLite schema. Incomplete collection must be
recollected; human determinations belong in STIG Manager.

## `scanner verify-handoff`

```bash
automatestig scanner verify-handoff automatestig-run-<RUN_ID>.zip

automatestig scanner verify-handoff automatestig-run-<RUN_ID>.zip \
  --signature automatestig-run-<RUN_ID>.zip.signature.json \
  --trust-dir /approved/automatestig-handoff-keys
```

The verifier accepts current v4 handoffs and the exact legacy v2/v3 contracts for
already-issued bundles, in both retained-evidence and purged result-only
states. It fails closed on unsafe or undeclared ZIP members, validates all
hashes and run/content/evidence bindings, enforces sparse ownership safety,
checks the CKLB projection, validates the v3 XCCDF 1.2 projection and its
target/rule/provenance bindings, and deterministically re-evaluates retained
adapter evidence. Fresh traces and sparse reviews must exactly match the
immutable result; CKLB and XCCDF are compared to that fresh result. A purged
v3 package remains integrity/projection-verifiable but is explicitly reported
as not replayed. With no
sidecar, success proves internal integrity but not producer identity. With
`--signature`, verification requires a matching key from the dedicated
handoff trust domain and authenticates the exact ZIP before decompression. The
default trust directory is `~/.automatestig/handoff_trusted_keys`, overridable
with `AUTOMATESTIG_HANDOFF_TRUSTED_KEYS_DIR` or `--trust-dir`.

XCCDF validation proves the supplemental member is internally consistent with
the handoff. It does not prove that a particular downstream GUI imported the
file; the staged STIG Manager transport is the explicit sparse-review-to-Review
API mapping.

## Protected transition binary

Migration and producer-key operations are not compiled into `automatestig`.
They require the separately named `automatestig-transition` binary and its
explicit non-default `transition` feature. The protected executable is absent
from the normal analyst product archive and must be built from the same
reviewed, version-pinned source on the controlled transition/signing host:

```bash
cargo run --release --features transition --bin automatestig-transition -- --help
```

### `scanner generate-signing-key` and `scanner sign-handoff`

```bash
cargo run --release --features transition --bin automatestig-transition -- \
  scanner generate-signing-key \
  --output /protected/handoff-producer.key
cargo run --release --features transition --bin automatestig-transition -- \
  scanner sign-handoff automatestig-run-<RUN_ID>.zip \
  --signing-key /protected/handoff-producer.key \
  --output automatestig-run-<RUN_ID>.zip.signature.json
```

These protected-host commands are the only handoff-signing surface. Signing
performs full semantic verification first, never changes the handoff ZIP, never
overwrites an output, and never stores a private key in the GUI. See [Verify a
Selected-Run Handoff](handoff-verification.md) for key custody and trust
semantics.

### `migration`

```bash
cargo run --release --features transition --bin automatestig-transition -- \
  migration inventory --output inventory.json
cargo run --release --features transition --bin automatestig-transition -- \
  migration export --output transition.zip
cargo run --release --features transition --bin automatestig-transition -- \
  migration bind-run --help
```

These commands exist to avoid deleting pre-scanner local data. Inventory is
read-only. Export uses create-new semantics and preserves source attribution;
it never relabels manual, imported, or answer-derived findings as automated.
`bind-run` performs exact-version, read-only destination validation and then
appends one immutable local retained-run mapping; it never writes a remote
STIG Manager object and never permits remapping. Its OAuth secret is accepted
only through the named environment variable. Use `bind-run --help` for the
required explicit API/token destinations, allowlist, collection, asset, run,
and operator-source arguments.
See [Migration and Transition](migration-transition.md).

## Maintainer boundary

The normal product binary does not compile transition migration, handoff
signing/key generation, protected content import, library,
pack-building, organization-policy signing, broad DISA import, or coverage
maintenance commands. Migration and handoff producer-signing require the
separate `transition` binary; protected content preparation requires the
`maintainer` feature. General answer templates, checklist
summaries/conversion, and STIG Manager portfolio export are absent from product
scanning and the supported transition path. Use `automatestig-transition
migration export` for preservation and the selected-run handoff for scanner
results.

## `status`

```bash
automatestig status
```

Status is diagnostic. It does not report enterprise compliance or replace STIG
Manager dashboards.
