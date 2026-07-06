# Evaluation Workflow

AutomateSTIG evaluation is deterministic. The same benchmark, scan inputs, answer files, check packs, and merge inputs produce the same evaluation outcome.

## Data Flow

1. Benchmarks define the STIG rules.
2. Check packs define structured checks for rules that can be evaluated automatically.
3. Scan results and answer files provide evidence and reviewer decisions.
4. The engine initializes findings, applies available automated and imported evidence, applies answer files, and optionally merges prior checklist entries.
5. Results are exported as CKL, CKLB, JSON, STIG-Manager payloads, eMASS CSV, reports, or remediation plans.

## Benchmarks

Benchmarks are installed in the local library. They can be imported from DISA XCCDF XML or ZIP content, imported through `.stigpack`, fetched from DISA as an opt-in connected feature, or transferred in an offline pack.

## Check Packs

Check packs are JSON definitions for automated checks. They can be installed from:

- `<data_dir>/plugins`
- `content/check_packs`
- `<library>/auto_check_packs`

DISA import auto-generates check packs from structured check-content where supported. Unstructured or manual-review controls remain manual review.

## Inputs

Evaluation can use:

- Scan results with `evaluate --scan <FILE>` or the GUI Run assessment form.
- Answer files with `evaluate --answer <FILE>`.
- Previous checklist merge input with `evaluate --merge <FILE>`.
- Remote SSH/WinRM collection through the GUI or API.

## Statuses

Findings use these statuses:

- `NotAFinding`
- `Open`
- `Not_Applicable`
- `Not_Reviewed`

Automated check execution maps passing checks to `NotAFinding`, failing checks to `Open`, and execution errors to `Not_Reviewed`.

## Local Evaluation

Local evaluation uses installed library content, local files, and answer files.

```bash
automatestig evaluate --stig <STIG_ID> --scan results.xml --answer answers.yaml --host server01 --output server01.ckl --format ckl
```

## Remote Collection

Remote SSH and WinRM scanning are connected features. They collect live host data and feed evaluation.

Validating the success path requires reachable hosts, credentials, network access, and working collectors. WinRM's WS-Man lifecycle is implemented, but it needs validation against a live Windows listener.

## Export

Use the GUI checklist detail actions or CLI commands:

```bash
automatestig convert --input server01.ckl --output server01.cklb --format cklb
automatestig export --input server01.ckl --output emass.csv --format emass-csv
automatestig report --input server01.ckl --output report.html --title "Compliance Report"
```
