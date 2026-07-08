# Quickstart

This path assumes you already have a DISA STIG XCCDF XML or ZIP file and, for automated evaluation, scan results or answer files that match the benchmark.

## GUI: 5 Minute Path

1. Start the GUI.

   ```bash
   cargo run --release --bin automatestig-gui
   ```

2. Import a DISA STIG.

   Open `Standards`, then import a DISA XCCDF XML or ZIP. DISA fetch is also available from `Standards` as an opt-in connected operation.

3. Add an asset.

   Open `Assets`, choose `Add Asset`, and enter name, address, platform, protocol, and tags.

4. Run an assessment.

   Open `Assessments`, use the Run assessment form, select the asset, choose the STIG benchmark, set the target hostname, and optionally attach a scan-results file.

5. Triage findings.

   Open the assessment row or a finding row to enter checklist detail. Use search and status filters, then edit finding status, details, and comments.

6. Export or push results.

   In checklist detail, choose `Export CKL`, `Export CKLB`, or `Push to STIG-Manager`.

## CLI Path

Import benchmark content:

```bash
cargo run --release --bin automatestig -- disa-import --input U_STIG.zip
```

List installed benchmarks and choose the benchmark ID:

```bash
cargo run --release --bin automatestig -- library list
```

Run an evaluation:

```bash
cargo run --release --bin automatestig -- evaluate \
  --stig <STIG_ID> \
  --scan results.xml \
  --host server01 \
  --output server01.ckl \
  --format ckl
```

Summarize open findings:

```bash
cargo run --release --bin automatestig -- summary --input server01.ckl --open-only
```

Convert or export when needed:

```bash
cargo run --release --bin automatestig -- convert --input server01.ckl --output server01.cklb --format cklb
cargo run --release --bin automatestig -- export --input server01.ckl --output stigman.json --format stig-manager --collection "Production"
```
