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

Evaluate a STIG against scan results and answer files.

| Option | Purpose |
| --- | --- |
| `-s`, `--stig <ID>` | Required STIG benchmark ID. |
| `-S`, `--scan <FILE>` | Scan result file. |
| `-a`, `--answer <FILE>` | Answer file. Repeatable. |
| `--host <NAME>` | Target hostname. |
| `-o`, `--output <FILE>` | Output file. |
| `-f`, `--format <ckl|cklb|json>` | Output format. |
| `--merge <FILE>` | Merge with a previous checklist. |

```bash
automatestig evaluate --stig <STIG_ID> --scan results.xml --answer answers.yaml --host server01 --output server01.ckl --format ckl
```

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

```bash
automatestig build-pack --id site-content --name "Site Content" --version 1.0.0 --source ./content --output site-content.stigpack
```

## `disa-import`

Import DISA STIG content directly from XCCDF XML files or ZIP archives. This also generates and persists auto check packs to `<library>/auto_check_packs/<stig>.json` and reports the auto-check count.

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
automatestig coverage validate --manifest content/coverage/windows_server_2022.disa-v2r8.json
```

## `status`

Show application version and library status.

```bash
automatestig status
```
