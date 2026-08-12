# Verify A Selected-Run Handoff

Use the read-only verifier on the receiving workstation before reconciling a
scanner result with the existing exact STIG Manager assignment:

```bash
automatestig scanner verify-handoff automatestig-run-<RUN_ID>.zip
```

That command performs integrity, projection, and—when replay evidence is
retained—deterministic evaluation verification. It does not authenticate the
producer unless the detached-signature option below is also used.

The command makes no database, checklist, or STIG Manager changes. It exits
nonzero unless all of these checks pass:

- the ZIP has canonical, non-duplicated paths, bounded sizes and decompression,
  and exactly the members declared by its v2, v3, or v4 handoff contract;
- `integrity.json`, the manifest, and every payload SHA-256 match;
- the reconstructed immutable result digest and manifest run bindings agree;
- checklist provenance binds the exact STIG revision, evidence, benchmark,
  check pack, collection plan, and evaluation plan;
- `sparse-reviews.json` is exactly the projection of completed scanner-owned
  findings, with no duplicate or `NotReviewed` result;
- current `scanner-run.json` contains one strict
  `automatestig.decision-trace.v2` record for every automated determination.
  Legacy v3 bundles retain their exact v1 trace contract.
  Each trace binds the exact device, STIG/rule, adapter, profile, check pack,
  evaluator build, parser/predicate versions, evidence/operation digests,
  transport, privilege, timing, status, truncation, and safe expected/observed
  representation without copying raw output, diagnostics, or secrets;
- `fallback.cklb` contains exactly those reviewed scanner-owned rows—never
  manual, unreviewed, or outside-profile rows; and
- for v3/v4, `results.xccdf.xml` uses the expected XCCDF 1.2 and extension
  namespaces and has an exact sparse Rule/rule-result set, target identity,
  STIG Manager detail/comment fields, DISA V-/SV- identifiers, and
  benchmark/run/content provenance that agrees with the other payloads; and
- when retained replay evidence is included, the verifier evaluates the exact
  bundled profile again and requires the regenerated decision traces and
  sparse reviews to match byte-for-byte, then compares the CKLB and XCCDF
  projections against that fresh result. Any mismatch fails closed; and
- Cisco handoffs retain the exact signed organization-policy bytes, detached
  signature, and signer public key needed for replay. The verifier rechecks the
  policy digest, signature, signer fingerprint, asset/STIG scope, and original
  verification instant. No private key is present.

Handoff v4 deliberately supports two retention states. A `retained` package
contains `evidence-envelope.json` and the verifier replays it. A `purged`
package is a result-only handoff: it must omit that file and retain a valid
purge timestamp and reason in the manifest. The command can still prove ZIP
integrity, immutable result/trace bindings, sparse ownership, and projection
equivalence, but it explicitly reports that deterministic evaluation replay
was not performed. It never upgrades result-only verification into a replay
claim.

The current producer emits `automatestig.selected-run-handoff.v4`, including
the sanitized canonical `run-request.json`. The verifier recalculates its
`request_sha256` and cross-checks its mode, destination, endpoint, device,
profile, collection-plan, and source-artifact bindings against the immutable
scanner result and decision traces. The verifier also accepts the exact legacy
v2 and v3 member sets for already-issued bundles; it does not silently
reinterpret them as a newer schema or allow undeclared members.

## XCCDF supplemental result artifact

`results.xccdf.xml` is a digest-bound, standards-based supplemental current result
artifact. It is an XCCDF 1.2 `Benchmark` containing one `TestResult` and only
the completed rules owned by this scanner run. XCCDF IDs use the DISA/STIG
Manager-compatible prefixes, while the exact source `V-*` and `SV-*_rule`
values are retained in rule identity metadata. Omitted rules are deliberately
unowned and must not be cleared, reset, or marked Not Reviewed.

The result mapping is `NotAFinding` to `pass`, `Open` to `fail`, and
`NotApplicable` to `notapplicable`. XCCDF also defines `notchecked` and `error`,
but AutomateSTIG refuses a selected-run handoff when a selected scanner result
is unresolved, collection-errored, or the run is incomplete.

The tested STIG Manager transport is not a server-side XCCDF upload. The
receiving workflow maps the verified `sparse-reviews.json` rows to STIG
Manager's Review API for the existing asset and exact assigned benchmark. The
local STIG Manager client source includes a browser-side XCCDF parser that can
translate a selected file into review writes, but AutomateSTIG's staging rig
does not exercise that import wizard. Do not claim native XCCDF file-import
compatibility until a supported-version GUI import and semantic readback gate
passes. `fallback.cklb` has the same supplemental ownership-safe scope.

The verifier performs bounded structural, namespace, identity, provenance, and
cross-payload checks; it is not a complete XCCDF schema validator. Any release
claim about XSD conformance requires a separate generated-fixture validation
against the applicable XCCDF 1.2 schema bundle.

## Protected Producer-Signature Workflow

The everyday GUI never loads or generates a handoff-signing key and emits the
exact unsigned v4 ZIP. Create a dedicated producer key only on a
protected signing host:

```bash
cargo run --release --features transition --bin automatestig-transition -- \
  scanner generate-signing-key \
  --output /protected/automatestig-handoff-producer.key
```

Keep the private key off GUI/service hosts. Distribute the adjacent
`automatestig-handoff-producer.pub` file independently to the receiving
workstation's dedicated handoff trust store. Do not reuse the executable
content or organization-policy trust stores.

After downloading a handoff, sign it on the protected host:

```bash
cargo run --release --features transition --bin automatestig-transition -- \
  scanner sign-handoff automatestig-run-<RUN_ID>.zip \
  --signing-key /protected/automatestig-handoff-producer.key \
  --output automatestig-run-<RUN_ID>.zip.signature.json
```

Signing first performs the complete semantic handoff verification described
above. It refuses malformed, incomplete, unsafe, or ownership-invalid input.
The output is create-new and symlink-safe. The detached signature uses a
strict v1 sidecar schema and a domain-separated Ed25519/SHA-256 statement that
binds the exact compressed ZIP SHA-256, handoff schema, canonical run UUID,
and signing-key fingerprint. It does not modify or repackage the handoff ZIP.

On the receiving workstation, verify with the detached sidecar:

```bash
automatestig scanner verify-handoff automatestig-run-<RUN_ID>.zip \
  --signature automatestig-run-<RUN_ID>.zip.signature.json \
  --trust-dir /approved/automatestig-handoff-keys
```

If `--trust-dir` is omitted, the dedicated default is
`~/.automatestig/handoff_trusted_keys`, overridable with
`AUTOMATESTIG_HANDOFF_TRUSTED_KEYS_DIR`. Signed verification fails closed when
the sidecar is absent, malformed, oversized, rebound to another ZIP or run,
signed by an untrusted key, or disagrees with the trusted key fingerprint. It
hashes and authenticates the compressed ZIP before decompressing evidence,
then performs all semantic and replay checks. Success prints the local trusted
key label and independently calculated `SHA256:` fingerprint.

## Unsigned Integrity Is Not Producer Authenticity

Without `--signature`, handoff hashes detect accidental corruption and inconsistent
or selectively modified content, but someone able to replace the entire
package can calculate new hashes. Integrity-only success therefore does
**not** prove which producer created the ZIP, and the CLI retains a prominent
unsigned warning. Transfer unsigned bundles through an authenticated channel
and verify their run ID against the origin system or an independently conveyed
receipt.

A trusted detached signature proves control of the approved producer key at
signing time; it is not a trusted timestamp or proof that a particular GUI
process held the key. Assign keys to producers, protect the signing ceremony,
record fingerprints out of band, and govern key rotation/revocation. Never
trust a public key merely because it accompanies the handoff or sidecar.

## Release qualification round trip

Ordinary signed verification is necessary but not sufficient for a supported
release claim. Release qualification uses two protected workflows and one
external signing operation:

1. `.github/workflows/stigman-staging.yml` produces a bounded exact
   `producer-handoff.zip` beside its STIG Manager acceptance JSON at the
   reviewed `approved_commit`.
2. A key custodian downloads that exact ZIP, builds the source-only
   `automatestig-transition` binary from the same reviewed commit on the
   protected signing host, runs `scanner sign-handoff`, and completes a
   non-secret custody record conforming to
   `schemas/handoff-key-custody-ceremony.schema.json`. The private key must not
   enter GitHub, CI, the scanner GUI/service host, or the evidence record.
3. The custodian dispatches
   `.github/workflows/handoff-receiver-ceremony.yml` with only public material.
   A distinct protected-environment receiver approver authorizes an identified
   receiver runner. That runner builds the unprivileged product verifier from
   `approved_commit`, installs only the independently conveyed trust anchor,
   and verifies the exact ZIP and sidecar before producing the five-file
   release artifact.

The connected release validator re-downloads that sole workflow artifact,
checks byte identity and every commit/run/digest/fingerprint/participant
binding, and verifies that the STIG Manager staging artifact contained the same
ZIP. The ceremony workflow intentionally cannot generate a key or create a
signature. Until the external custodian and independent receiver approver
complete the round trip, `producer_authenticated_handoff` is absent and release
readiness remains unmet.

The custodian record contains the exact public-key, ZIP, and sidecar SHA-256
values; the two participant logins; signing time; distinct opaque references
for the signing host, primary key media, and backup media; `true` for
`revocation_status_checked`; and `false` for
`private_key_entered_ci`, `private_key_entered_scanner_runtime`, and
`private_key_material_recorded`. References identify controlled assets without
including paths, credentials, private bytes, or recovery secrets. The receiver
script rejects extra JSON members, stale timestamps, reused references, role
collisions, and any digest mismatch before invoking the product verifier.

Current v4 handoffs contain the sanitized canonical run-request bytes, so the
verifier independently recalculates `request_sha256`. Legacy v2/v3 packages
retain their historical limitation: the verifier can check that digest's shape
but cannot reconstruct the omitted request bytes.
