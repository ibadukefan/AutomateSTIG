# Controlled Scanner Comparison

AutomateSTIG can now produce a reproducible, fail-closed scorecard against
Evaluate-STIG, Tenable, Nipper, or another scanner. The harness compares
already collected results; it does not install licensed products, connect to
devices, or manufacture a score when a comparator cannot run.

This is deliberately separate from normal scanning. STIG Manager remains the
system of record, and the comparison harness does not create assets,
assignments, reviews, dashboards, or compliance history.

## What the harness accepts

Keep every comparison in a protected working directory outside the repository.
The directory contains:

- one draft or completed manifest conforming to
  `schemas/scanner-comparison-manifest.schema.json`;
- every target, benchmark, source-state, tool package, tool content, result,
  and failure-evidence artifact named by a relative path in that manifest;
- the independently adjudicated compliant, noncompliant, permission-denied,
  transport-failure, truncated-output, ambiguous-output, and
  unsupported-version cases;
- each tool's exact retained result export;
- when a product has no usable XCCDF export, its original proprietary report
  plus a decision record conforming to
  `schemas/normalized-scanner-decisions.schema.json`; and
- for every row claimed as evidence-traceable, a separate record conforming to
  `schemas/scanner-row-traceability.schema.json`.

Prefer native XCCDF 1.2. AutomateSTIG's selected-run handoff includes
`results.xccdf.xml`; every complete AutomateSTIG run must use that exact member
and cannot substitute a normalized record. A Tenable XCCDF export can be used
directly. A Nipper HTML/PDF/XML report, Evaluate-STIG checklist, or other
proprietary result must retain its original bytes and SHA-256 and be normalized
by two people who did not adjudicate the ground truth and could not see the
oracle. The normalized record binds the original export and the reviewed
mapping procedure by SHA-256.

A result export proves that a tool emitted a status; it does not, by itself,
prove how that status was derived. Native XCCDF therefore receives no automatic
traceability credit. Each credited V-ID needs a retained row trace that binds:

- the exact result status and result SHA-256;
- the exact raw-evidence regular file and SHA-256;
- a distinct retained collection-operation descriptor whose
  schema is `automatestig-scanner-operation-binding/v1`, whose ID and request
  digest match the row, and whose `raw_evidence_sha256` matches those evidence
  bytes;
- distinct retained parser and predicate artifacts, with stable IDs and
  verified SHA-256 digests;
- the run's oracle source-state SHA-256;
- the declared tool build/package and content SHA-256 digests; and
- the effective benchmark-model SHA-256.

The trace document itself is retained by relative path and SHA-256 in the run's
`result.traceability` member. Supporting evidence may serve multiple rules in
one run, but raw-evidence files cannot be reused across runs. Every supplied
path must stay below the manifest directory and every byte digest is verified.
A malformed, tampered, mismatched, or extra trace row rejects the comparison.
A trace document may cover a strict subset of result rows; uncovered rows are
reported as not supplied and receive no credit.

The parser accepts only an XCCDF 1.2 `Benchmark` in the exact
`http://checklists.nist.gov/xccdf/1.2` namespace. The manifest declares the
exact Benchmark ID and release, and each XCCDF result declaration names the
one expected TestResult ID. A different namespace, Benchmark ID, release,
TestResult ID, nested/duplicate TestResult, or empty determined result is not a
usable result. Determined `pass`, `fail`, and `notapplicable` rows are mapped
through exact V-/SV- identity. The loader also rejects duplicates, unmapped
determined rows, DTDs, entities, oversized files, symlinks in any path
component, path traversal, and digest changes.

## Freeze the protocol before scanning

At least two people establish ground truth from the DISA check text and
captured device state without seeing any product output. Both are cybersecurity
SMEs, and at least one also holds the test-owner role. These roles approve the
exact test protocol; they are not inferred from tool output.

The manifest binds the exact representative device, model, software, virtual
or HA context, privilege profile, network path, site policy, DISA artifact,
effective benchmark model, every captured case state, scanner binary/package,
and scanner content by both a relative artifact path and SHA-256. The harness
opens each regular non-symlink artifact below the manifest directory and
verifies its bytes before accepting the protocol. A digest string without the
retained artifact is not evidence. `representative_authorized_device` must be
`true` and `synthetic` must be `false`; repository fixtures cannot pass this
protocol.

The path/digest pairs are explicit:

- target: `hardware_identity_path`, `privilege_profile_path`,
  `network_path_artifact_path`, and `site_policy_path`, each beside its existing
  `*_sha256` member;
- benchmark: `source_path`/`source_sha256` and
  `effective_model_path`/`effective_model_sha256`;
- oracle case: `source_state_path`/`source_state_sha256`; and
- tool: `artifact_path`/`artifact_sha256` and
  `content_path`/`content_sha256`.

All paths are relative to the manifest directory. Archive a directory-shaped
installer or content set into one retained regular file before hashing it.

Record every exclusion or procedural deviation in the manifest. Every oracle
adjudicator approves each entry and classifies its impact. A deviation marked
`invalidates_claim` remains visible in the report and fails the protocol gate;
it cannot be hidden to improve a score.

Every ordinary case repeats the exact baseline software version. The required
unsupported-version case names its different observed version explicitly, so a
tool cannot be credited for failing closed on an unidentified target.

Include at least three repetitions for every tool and case. The
`sha256-order-v1` schedule is committed by a random seed before execution. To
measure setup fairly, each tool entry also contains at least three
clean-workstation setup trials with elapsed time and analyst actions. To
create the header with schema
`automatestig-scanner-comparison-draft/v1` and an empty `runs` array, then
expand it into the exact run sheet:

```bash
python3 scripts/compare-commercial-scanners.py comparison-header.json \
  --prepare-schedule-out comparison-run-sheet.json
```

The generated `null` fields are intentional. For each run, restore the exact
case state, verify its source-state digest, run only the scheduled tool, and
record:

- whether collection was complete;
- the relative result path and exact digest, or `null` when there was no result;
- for XCCDF, the exact retained TestResult ID;
- the optional traceability-record path and digest for rows with a validated
  evidence-to-decision chain (omit it or use `null` when the tool did not
  supply that data);
- for every incomplete run, a structured failure stage, code, detail, and the
  relative path and digest of retained diagnostic evidence;
- wall-clock milliseconds;
- analyst actions; and
- reviewed lines of external target-specific script.

Do not reorder the run sheet. Do not reuse one result file for multiple runs.
The harness rejects a run whose source-state digest differs from the oracle or
whose sequence differs from the committed schedule.

The draft contract deliberately permits the generated null observation fields.
After filling every run, change `schema` to
`automatestig-scanner-comparison/v2`. The completed contract requires typed
measurements, a retained nonempty result for every run marked complete, and a
bound structured failure for every run marked incomplete. Legacy
`automatestig-scanner-comparison/v1` manifests recorded unverified digest
strings without artifact paths and are rejected; rebuild their bindings under
the draft/v1 or completed/v2 contract rather than relabeling them.

## Generate the scorecard

After every `null` run field is replaced with an observed value:

```bash
python3 scripts/compare-commercial-scanners.py comparison-complete.json \
  --json-out comparison-report.json \
  --markdown-out comparison-report.md \
  --require-comparison-gate
```

The report publishes numerators and denominators for collection success,
precision, recall, automation depth, manual tail, false passes, false failures,
incomplete-result leakage, evidence traceability, runtime, analyst action, and
external script burden. The false-pass denominator separately exposes
ground-truth noncompliant rows and unobservable determined rows. A missing or
failed comparator run remains a failed or
incomplete attempt with its reason visible; it is never silently removed or
converted into a fabricated rule score.

Evidence traceability is validation coverage, not an inference from result
format. The report counts only V-IDs with a valid row-trace chain. It labels
partial coverage as `validated_partial`; when no trace was supplied it reports
`not_supplied`, a `null` rate, and the exact number of unvalidated rows instead
of manufacturing 100%. Runs with no determined rows are `not_applicable`. Each
tool's JSON `row_traceability` array identifies the run, case, repetition, and
V-ID separately; a validated row carries the retained trace-record digest and
an unsubstantiated row carries `null`.

`--require-technical-gate` exits with status 2 if AutomateSTIG reports a false
pass, produces any status mismatch, emits a determined row from
incomplete/unobservable evidence, claims a complete collection for an expected
failure case, or emits a rule that was not in the oracle. Invalid, missing,
reordered, duplicated, or tampered inputs exit with status 1.

`--require-comparison-gate` applies that safety gate and also exits with status
2 when an approved deviation invalidates the protocol or any declared tool
lacks a usable determined result covering at least one oracle-adjudicated rule
for any compliant/noncompliant repetition. It also requires complete validated
row traceability for the SUT and every comparator. Missing trace data does not
invalidate accuracy measurements, but it fails the claim-evidence gate and
sets the claim status to `validated_traceability_required`.
Thus a licensed comparator that was never run, failed export, or returned only
undetermined rows cannot produce a passing comparison gate. Its failed runs
remain in the JSON and Markdown with their structured reasons and diagnostic
digests, and the report suppresses advantage deltas for that comparator rather
than treating missing output as a score. Use the combined gate for retained
release or claim evidence; the narrower technical gate is useful while
diagnosing AutomateSTIG itself.

Completed v2 manifests remain readable when their result objects omit
`traceability`; those legacy observations are reported honestly as not
supplied. Reports generated by the corrected harness use
`automatestig-scanner-comparison-report/v3` because the old report calculation
incorrectly treated every determined result row as traceable.

## Interpreting the result

The JSON and Markdown identify observed target-specific deltas. They never
automatically authorize “better than” language. Before publishing a measured
advantage, the cybersecurity SME and test owner must review retained raw
artifacts, deviations, sample size, and run-to-run variation and approve the
exact scoped wording. A safety-gate failure blocks the claim even if
AutomateSTIG is faster or automates more rules.

Run a separate manifest for every target/revision/device-version combination.
For the current scanner focus that normally means separate controlled studies
for Cisco IOS-XE Router NDM, FreeBSD/GPOS, and NetApp ONTAP. A new STIG release,
firmware boundary, adapter change, or comparator content update invalidates the
old claim scope and requires a new comparison.

## What remains external

This repository cannot provide licensed Tenable/Nipper binaries, authorized
Evaluate-STIG packages, representative production-like devices, or independent
SME adjudication. Until those inputs are supplied and the controlled reports
pass, comparisons remain engineering hypotheses. Synthetic scenario fixtures
prove AutomateSTIG's own fail-closed behavior; they are not commercial product
scores.
