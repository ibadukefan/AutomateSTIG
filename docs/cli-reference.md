# CLI Reference

Binary: `automatestig`.

When running from source, put CLI arguments after `--`:

```bash
cargo run --release --bin automatestig -- status
```

## Global Options

| Option | Purpose |
| --- | --- |
| `-v`, `--verbose` | Enable verbose output. |
| `--db <PATH>` | Use a database path other than the default `~/.automatestig/data.db`. |
| `--library <PATH>` | Use a library path other than the default `~/.automatestig/library`. |

## `evaluate`

Evaluate a STIG against a collected evidence transcript or Cisco running configuration.

| Option | Purpose |
| --- | --- |
| `-s`, `--stig <ID>` | Required STIG benchmark ID. |
| `--evidence <FILE>` | Plan-bound evidence v2 JSON. Mutually exclusive with `--config`; exactly one primary input is required. |
| `--allow-legacy-evidence` | Unsafely assume marker-based v1 command sections succeeded; migration/testing only and valid only with `--evidence`. |
| `--config <FILE>` | Cisco running configuration. Mutually exclusive with `--evidence`; exactly one primary input is required. |
| `-a`, `--answer <FILE>` | Answer file. Repeatable. |
| `--host <NAME>` | Target hostname. |
| `-o`, `--output <FILE>` | Output file. |
| `-f`, `--format <ckl|cklb|json>` | Output format. |
| `--merge <FILE>` | Merge with a previous checklist. |

```bash
automatestig evaluate --stig <STIG_ID> --evidence device01-evidence.json --answer answers.yaml --output device01.ckl --format ckl
```

Evidence v2 must match the installed check pack's platform and collection-plan digest. Missing, failed, or semantically invalid command evidence makes the evaluation incomplete. AutomateSTIG appends an `evaluation.incomplete` audit event, writes no checklist, saves no checklist row, and exits nonzero. Answer files and `--merge` cannot convert a collection error into a result.

Summary output reports two separate values: the pass rate among applicable
assessed controls (`NotApplicable` and `NotReviewed` are excluded) and benchmark
coverage. A 100% assessed pass rate is not presented as
full benchmark compliance when any control remains `NotReviewed`, and partial
coverage is never given a green grade.

For Cisco configuration input, the evaluator derives the asset identity from
the single top-level `hostname` command. If `--host` is supplied, it must match
that value case-insensitively; a mismatch or ambiguous hostname fails closed.

## `collect`

Collect evidence v2 from a remote device with the same SSH implementation used by the GUI.

| Option | Purpose |
| --- | --- |
| `-s`, `--stig <ID>` | Required STIG benchmark whose installed check pack defines the plan. |
| `--host <HOST>` | Required remote hostname or address. |
| `--hostname <NAME>` | Optional hostname recorded in evidence; defaults to `--host`. |
| `-u`, `--username <USER>` | Required SSH username. |
| `--port <PORT>` | SSH port; default `22`. |
| `--key <FILE>` | Private-key file under `~/.ssh` or `~/.automatestig/ssh_keys`. Without it, password authentication is used. |
| `--password-env <NAME>` | Password environment variable; default `AUTOMATESTIG_SSH_PASSWORD`. |
| `--passphrase-env <NAME>` | Key-passphrase environment variable; default `AUTOMATESTIG_SSH_KEY_PASSPHRASE`. |
| `--timeout-secs <SECONDS>` | DNS, connection, authentication, key-loading, and per-command timeout; default `30`. |
| `-o`, `--output <FILE|->` | Required evidence destination; `-` writes JSON to stdout. |
| `--trust-on-first-use` | Explicitly enroll an unknown server key for this run. |

```bash
AUTOMATESTIG_SSH_PASSWORD='...' automatestig collect \
  --stig NetApp_ONTAP_DSC_9-x_STIG \
  --host filer.example.mil --username scanner \
  --output filer-evidence.json

automatestig collect \
  --stig General_Purpose_Operating_System \
  --host bsd.example.mil --username scanner --key ~/.ssh/id_ed25519 \
  --output bsd-evidence.json
```

Collection always writes a complete diagnostic document when it can determine the plan. If any required command fails, the document has `complete=false` and the command has a typed failure status; the process then exits nonzero. Failed stdout is retained only as diagnostics and is never exposed to check predicates.

Collection resolves the target once and connects to that numeric address while retaining the supplied hostname for host-key pinning. Unspecified, multicast, broadcast, and link-local targets are rejected, as are DNS answers spanning loopback, private, public, or link-local trust classes. An explicitly scoped link-local device requires `AUTOMATESTIG_SSH_ALLOW_LINK_LOCAL=1`. Private keys outside the two default roots require a secure root listed in `AUTOMATESTIG_SSH_KEY_ROOTS` (using the platform path-list separator); key files, their direct parent, and the selected root must pass ownership, type, symlink, size, and permission checks.

## `import`

Import a `.stigpack`.

| Option | Purpose |
| --- | --- |
| `-p`, `--pack <FILE>` | Required `.stigpack` file. |

```bash
automatestig import --pack content.stigpack
```

## `verify`

Verify a `.stigpack` signature and hashes without importing.

| Option | Purpose |
| --- | --- |
| `-p`, `--pack <FILE>` | Required `.stigpack` file. |

```bash
automatestig verify --pack content.stigpack
```

## `library`

Manage the local STIG library.

| Command | Purpose |
| --- | --- |
| `library list` | List installed benchmarks. |
| `library show <ID>` | Show a benchmark. |
| `library init` | Initialize the library. |

```bash
automatestig library init
automatestig library list
automatestig library show <STIG_ID>
```

## `convert`

Convert between checklist formats.

| Option | Purpose |
| --- | --- |
| `-i`, `--input <FILE>` | Required input file. |
| `-o`, `--output <FILE>` | Required output file. |
| `-f`, `--format <ckl|cklb|json|stig-manager>` | Output format. |

```bash
automatestig convert --input server01.ckl --output server01.cklb --format cklb
```

## `summary`

Show a checklist or scan summary.

| Option | Purpose |
| --- | --- |
| `-i`, `--input <FILE>` | Required input file. |
| `--open-only` | Show only open findings. |
| `--severity <high|medium|low>` | Filter by severity. |

```bash
automatestig summary --input server01.ckl --open-only --severity high
```

## `gen-answer`

Generate an answer file template from a checklist.

| Option | Purpose |
| --- | --- |
| `-i`, `--input <FILE>` | Required input checklist. |
| `-o`, `--output <.json|.yaml>` | Required output answer file. |
| `--include-unreviewed` | Include `Not_Reviewed` findings. |

```bash
automatestig gen-answer --input server01.ckl --output answers.yaml --include-unreviewed
```

## `export`

Export a checklist to an external format.

| Option | Purpose |
| --- | --- |
| `-i`, `--input <FILE>` | Required input checklist. |
| `-o`, `--output <FILE>` | Required output file. |
| `-f`, `--format <stig-manager>` | Required output format. |
| `--collection <NAME>` | STIG-Manager collection name. |

```bash
automatestig export --input server01.ckl --output stigman.json --format stig-manager --collection "Production"
```

## `build-pack`

Build a `.stigpack`.

| Option | Purpose |
| --- | --- |
| `--id <ID>` | Required pack ID. |
| `--name <NAME>` | Required pack name. |
| `--version <VERSION>` | Required semver pack version. |
| `-s`, `--source <DIR>` | Required source directory. |
| `-o`, `--output <FILE>` | Required output file. |
| `--signing-key <FILE>` | Required existing external raw Ed25519 private key; a matching sibling `.pub` file is required. |

```bash
automatestig generate-signing-key --output /secure-media/site-content.key
automatestig build-pack --id site-content --name "Site Content" --version 1.0.0 \
  --source ./content --output site-content.stigpack \
  --signing-key /secure-media/site-content.key
```

`generate-signing-key` is an explicit offline ceremony command and refuses to
replace existing key material. `build-pack` never creates keys.

## `disa-import`

Import DISA STIG reference content directly from XCCDF XML files or ZIP archives.
This never derives executable checks from prose and removes a stale legacy
generated pack for the imported benchmark. Executable extensions require a
trusted signed `.stigpack`.

| Option | Purpose |
| --- | --- |
| `-i`, `--input <XCCDF-XML|ZIP>` | Required DISA XCCDF XML or ZIP. |

```bash
automatestig disa-import --input U_STIG.zip
```

## `coverage validate`

Validate a coverage manifest JSON file.

| Option | Purpose |
| --- | --- |
| `-m`, `--manifest <JSON>` | Required coverage manifest. |

```bash
automatestig coverage validate --manifest content/coverage/current-checkpacks/netapp_ontap9.current.json
```

## `status`

Show application version and library status.

```bash
automatestig status
```
