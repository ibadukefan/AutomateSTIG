# Evaluation Workflow

AutomateSTIG evaluation is deterministic. The same release-bundled scanner
profile and accepted evidence or configuration produce the same evaluation
outcome.

> The scanner-first workflow uses an immutable release-bundled profile,
> native target-adapter evidence, and no legacy evidence, answer-file, or
> prior-checklist merge path.
> The GUI persists a short-lived scanner run and verified sparse handoff; the
> CLI writes a standalone native result without legacy database state. Changed
> scanner reviews use the handoff, while human and manual work remains in STIG
> Manager. See [Scanner Operations](scanner-operations.md).

## Data Flow

1. A release-bundled profile binds the exact benchmark, check pack, coverage,
   adapter, and compatibility contract.
2. A native `AdapterEvidenceEnvelope` or an authorized IOS-XE running
   configuration provides collected device state and observed identity.
3. The scanner application service shared by the CLI and GUI validates the
   exact profile/adapter/plan bindings, initializes every benchmark rule, and
   applies only evidence-backed scanner checks.
4. Missing or incomplete evidence stays `Not_Reviewed` and blocks handoff.
5. The service returns a native scanner result. A complete GUI/API run can
   produce a sparse selected-run handoff; supplemental XCCDF and CKLB
   projections remain bound to that same scanner-owned result.

## Benchmarks

Runnable benchmarks are compiled into the signed application release as exact
scanner profiles. A normal installation does not initialize or manage a local
STIG catalog. Broad DISA content administration remains outside the end-user
scanner workflow.

## Check Packs

Reviewed check packs are compiled into the executable and validated against the
profile's exact benchmark, coverage counts, and digests before use. The process
working directory and mutable legacy library are never searched for runtime
scanner content. Raw command checks are limited to the product's reviewed
read-only capability set; shell control, mutation, and network-capable commands
are rejected.

## Inputs

The shared scanner service accepts these target-appropriate sources:

- A native `automatestig-adapter-evidence/v2` envelope from `collect` or a
  scanner run for ONTAP or FreeBSD.
- Live remote SSH collection for ONTAP and FreeBSD through the CLI, GUI, or
  API; it produces that same native envelope before evaluation.
- Operator-supplied IOS-XE running configurations used by curated `ConfigLine`
  checks; AutomateSTIG does not SSH to IOS-XE in v0.3.

CLI `evaluate` requires exactly one of `--evidence` or `--config` and rejects a
source that does not match the selected profile.

## Statuses

Findings use these statuses:

- `NotAFinding`
- `Open`
- `Not_Applicable`
- `Not_Reviewed`

Automated check execution maps a successfully observed compliant state to `NotAFinding`, a successfully observed noncompliant state to `Open`, and collection/evaluation errors to `Not_Reviewed`. A transport failure, nonaccepted exit status, missing exit status, timeout, output limit, invalid UTF-8, command mismatch, or semantic-output error can never satisfy a positive or negative check predicate.

## Local Evaluation

Local evaluation uses release-bundled scanner content and one evidence source.
Native scanner-result JSON is the default artifact:

```bash
automatestig evaluate --stig NetApp_ONTAP_DSC_9-x_STIG \
  --evidence filer01-evidence.json
```

The default path is
`<hostname>_<STIG-ID>.scanner-result.json`. The JSON retains the checklist
projection, completeness/errors, content and evidence digests, coverage
summary, complete-only sparse reviews, and one sanitized versioned decision
trace for every automated check (including fail-closed errors). Traces bind the
raw artifact/envelope by digest and retain typed operation, parser, predicate,
device, policy, content, and build provenance without copying raw output or
secrets. A supplemental CKLB may be requested
with `--output filer01.cklb --format cklb`, but only a complete evaluation can
produce it. CKL, answer-file, and prior-checklist merge output paths do not
exist in the product CLI.

## Remote Collection

Remote SSH collection is an opt-in connected feature. The CLI resolves the
exact release-bundled profile before reading credentials, observes and
validates device identity during a read-only preflight, and records the exact
adapter operation plan in native evidence:

```bash
AUTOMATESTIG_SSH_PASSWORD='...' automatestig collect \
  --stig <STIG_ID> --host device01 --username scanner \
  --output device01-evidence.json
```

Use `--key <PRIVATE_KEY>` instead of the password environment variable for key authentication. Unknown SSH server keys are rejected by default. `--trust-on-first-use` performs explicit enrollment; later key changes are rejected.

`collect` emits strict `automatestig-adapter-evidence/v2` JSON. Its
`DeviceFingerprint` uses `automatestig.device-fingerprint.v2` and explicitly
records hostname, vendor, product family, software version, operating context,
and typed HA role. Unknown context/role is serialized as
`unknown_or_unsupported`; an adapter that requires either value fails before
evaluation rather than guessing. The envelope binds that identity to the adapter, profile,
check pack, operation plan, SSH transport identity, collection time, typed
per-operation status/duration/response, completeness, and evidence digest.
Duplicate keys, truncated JSON, foreign targets, stale plans, unexpected
operations, and marker-like target output cannot alter the operation structure.

The verifier retains exact legacy v1 envelope, operation-plan, and schema-less
fingerprint DTOs. It recomputes their historical canonical hashes without
injecting v2 defaults and rejects any v1/v2 cross-version rebinding.

Each preflight operation declares expected and maximum duration, and the plan
declares its total expected duration. Those values are shown in the GUI and
covered by the plan digest. The plan digest also binds the evaluation predicates and output-validation
policy, not only command strings. A supplied evidence/config file is retained
as evidence provenance rather than claimed as a live observation; only a live
SSH session collected within the scanner run can be marked `automated` for a
STIG Manager `autoResult`. The scanner workflow has no checklist-upload or
finding-edit path.

Collection is per operation. Successfully collected observations can still be
diagnosed when another operation fails, while every dependent rule remains
`Not_Reviewed`. `collect` writes the incomplete native envelope and returns
nonzero. CLI `evaluate` can write diagnostic native scanner-result JSON and
then returns nonzero; it does not save a checklist, finding, or evaluation to
the legacy database. An incomplete GUI/API run remains diagnostic and cannot
create a handoff or deliverable sparse review set.

Collection provenance is bound to every completed native scanner result and
persisted GUI scanner run. Incomplete evaluations cannot be projected as CKLB
or handed to STIG Manager. Recollect the target before making a compliance
decision.

ONTAP collection rejects an anchored CLI `Error:` even when SSH reports exit
status zero. Its structured table checks require canonical headers and terminal
row-count summaries, reject pagination/truncation, and evaluate every applicable
row. FreeBSD automation is limited to six defensible rules: the `auditd`
service state, four OpenBSM event-class selections bound to reviewed system-file
digests, and the live PF state.
`service auditd onestatus` exit status 1 is an accepted observation of a stopped
service and therefore evaluates `Open`, while a transport or permission failure
remains `Not_Reviewed`.

Cisco running configurations must be nonempty, unpaginated, free of recognized
CLI errors, and terminate with the platform's `end` marker. Empty or truncated
configuration text therefore cannot satisfy a forbidden-line absence check.

Legacy transcripts cannot prove the native adapter, observed identity, and
operation-plan bindings and are rejected. The product CLI, GUI, and API provide
no unsafe override.

Validating the success path requires reachable hosts, credentials, network access, and working SSH collectors.

## Preserving previous local data

The retired conversion, summary, answer-generation, and general export commands
are not compiled into the product CLI. Use `automatestig-transition migration
inventory` and `automatestig-transition migration export` from an explicit
`transition` build to preserve prior local data without
relabeling it, then continue human review and reporting in STIG Manager.
