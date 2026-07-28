# Evaluation Workflow

AutomateSTIG evaluation is deterministic. The same benchmark, evidence/config input, answer files, check packs, and merge input produce the same evaluation outcome.

## Data Flow

1. Benchmarks define the STIG rules.
2. Check packs define structured checks for rules that can be evaluated automatically.
3. Plan-bound evidence v2 documents or running configurations provide collected device state; answer files provide reviewer decisions.
4. The engine initializes findings, applies structured check results, applies answer files, and optionally merges prior checklist entries.
5. Results are exported as CKL, CKLB, JSON, or STIG-Manager payloads.

## Benchmarks

Benchmarks are installed in the local library. They can be imported from DISA XCCDF XML or ZIP content, imported through `.stigpack`, fetched from DISA as an opt-in connected feature, or transferred in an offline pack.

## Check Packs

Check packs are JSON definitions for automated checks. They can be installed from:

- `<library>/custom_checks`
- `<library>/reviewed_check_packs` (trusted signed imports only)

Reviewed curated packs are compiled into the executable. The process working
directory is never searched for executable check content. Raw command checks
are limited to the product's read-only inspection capability set; shell
control, mutation, and network-capable commands are rejected during pack load.

DISA/XCCDF import installs reference benchmarks only and removes stale legacy
prose-generated packs. It never creates executable decisions. Reviewed curated
packs are embedded; additional custom/generated definitions must be explicitly
imported in a trusted signed `.stigpack`.

Signed import is not a one-time trust shortcut. Executable library files retain
their signed-manifest proof and content hash in the same journaled transaction,
and every evaluation re-verifies that proof against the current trust anchors.
Bare files, post-import changes, and content signed by a removed key fail closed.

## Inputs

Evaluation can use:

- Evidence v2 JSON from `collect`, GUI SSH scan, or the GUI Run assessment form.
- Answer files with `evaluate --answer <FILE>`.
- Previous checklist merge input with `evaluate --merge <FILE>`.
- Cisco IOS-XE running-configuration files.
- Remote SSH collection for ONTAP and FreeBSD through the CLI, GUI, or API.
- Operator-supplied IOS-XE running configurations used by curated `ConfigLine`
  checks; AutomateSTIG does not SSH to IOS-XE in v0.3.

## Statuses

Findings use these statuses:

- `NotAFinding`
- `Open`
- `Not_Applicable`
- `Not_Reviewed`

Automated check execution maps a successfully observed compliant state to `NotAFinding`, a successfully observed noncompliant state to `Open`, and collection/evaluation errors to `Not_Reviewed`. A transport failure, nonaccepted exit status, missing exit status, timeout, output limit, invalid UTF-8, command mismatch, or semantic-output error can never satisfy a positive or negative check predicate.

## Local Evaluation

Local evaluation uses installed library content, local files, and answer files.

```bash
automatestig evaluate --stig NetApp_ONTAP_DSC_9-x_STIG --evidence filer01-evidence.json --answer answers.yaml --output filer01.ckl --format ckl
```

## Remote Collection

Remote SSH collection is an opt-in connected feature. The CLI derives the smallest command plan from the installed check pack and records the exact plan digest in evidence:

```bash
AUTOMATESTIG_SSH_PASSWORD='...' automatestig collect \
  --stig <STIG_ID> --host device01 --username scanner \
  --output device01-evidence.json
```

Use `--key <PRIVATE_KEY>` instead of the password environment variable for key authentication. Unknown SSH server keys are rejected by default. `--trust-on-first-use` performs explicit enrollment; later key changes are rejected.

Evidence v2 is strict JSON (`schemas/evidence-v2.schema.json`). It separates stdout and stderr, retains the remote exit status and duration, identifies the target platform and collector version, and binds the document to the current plan. Duplicate keys, truncated JSON, foreign platforms, stale plans, unexpected commands, and marker-like target output cannot alter the command structure.

The plan digest also binds the evaluation predicates and output-validation
policy, not only command strings. A supplied evidence/config file is retained
as `evidence` provenance rather than claimed as a live AutomateSTIG observation;
only an SSH session collected by the running process is marked `automated` for
STIG Manager `autoResult`. Uploaded checklist JSON is normalized to `imported`,
and any GUI finding edit is normalized to `manual`.

Collection is per command. Successfully collected observations can still be
diagnosed when another command fails, while every dependent rule remains
`Not_Reviewed`. `collect` retains the typed evidence document and returns
nonzero. `evaluate` records an append-only `evaluation.incomplete` event but
does not write or save a checklist. The HTTP API returns `207 Multi-Status`
with `collection_complete=false`, `persisted=false`, a null checklist ID and
compliance score, and keyed `collection_errors`.

Collection provenance is stored with every completed evaluation checklist.
Incomplete or unsafe evaluations cannot be changed by answer files or merge
input, exported, or pushed to STIG Manager. Recollect the target before making
a compliance decision.

ONTAP collection rejects an anchored CLI `Error:` even when SSH reports exit
status zero. Its structured table checks require canonical headers and terminal
row-count summaries, reject pagination/truncation, and evaluate every applicable
row. FreeBSD automation is limited to three direct effective-state observations:
the `auditd` service state, the configured timezone, and the 64-bit ASLR sysctl.
`service auditd onestatus` exit status 1 is an accepted observation of a stopped
service and therefore evaluates `Open`, while a transport or permission failure
remains `Not_Reviewed`.

Cisco running configurations must be nonempty, unpaginated, free of recognized
CLI errors, and terminate with the platform's `end` marker. Empty or truncated
configuration text therefore cannot satisfy a forbidden-line absence check.

Marker-based v1 transcripts cannot prove command success and are rejected by default. The CLI-only `--allow-legacy-evidence` option can parse controlled legacy fixtures for migration diagnostics, but the resulting attempt is unsafe and cannot produce or save a checklist. The GUI/API has no legacy override.

Validating the success path requires reachable hosts, credentials, network access, and working SSH collectors.

## Export

Use the GUI checklist detail actions or CLI commands:

```bash
automatestig convert --input server01.ckl --output server01.cklb --format cklb
automatestig export --input server01.ckl --output stigman.json --format stig-manager --collection "Production"
```

CKL/CKLB conversion preserves the modeled checklist fields and retained rule-level extensions, but it is not advertised as byte-for-byte or universally lossless conversion. A CKLB containing multiple STIGs is rejected instead of silently dropping all but the first. Validate generated files with the exact STIG Viewer/STIG Manager versions used by the deployment.
