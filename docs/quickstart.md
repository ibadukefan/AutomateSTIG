# Quickstart

This path assumes you have the matching DISA benchmark plus plan-bound ONTAP/FreeBSD evidence or an authorized Cisco IOS-XE Router NDM running configuration. See [Supported Targets](supported-targets.md).

## GUI: 5 Minute Path

1. Start the GUI.

   ```bash
   cargo run --release --bin automatestig-gui
   ```

2. Import a DISA STIG.

   Open `Standards`, then import a DISA XCCDF XML or ZIP. DISA fetch is also available from `Standards` as an opt-in connected operation.

3. Add an asset.

   Open `Assets`, choose `Add Asset`, and select ONTAP, FreeBSD, or Cisco IOS-XE Router NDM.

4. Run an assessment.

   Open `Assessments`, use the Run assessment form, select the asset, choose the STIG benchmark and platform, then attach an evidence transcript or running configuration.

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

Collect and evaluate SSH evidence:

```bash
AUTOMATESTIG_SSH_PASSWORD='...' cargo run --release --bin automatestig -- collect \
  --stig NetApp_ONTAP_DSC_9-x_STIG --host filer01 --username scanner \
  --output filer01-evidence.json

cargo run --release --bin automatestig -- evaluate \
  --stig NetApp_ONTAP_DSC_9-x_STIG \
  --evidence filer01-evidence.json \
  --output filer01.ckl \
  --format ckl
```

Summarize open findings:

```bash
cargo run --release --bin automatestig -- summary --input filer01.ckl --open-only
```

Convert or export when needed:

```bash
cargo run --release --bin automatestig -- convert --input filer01.ckl --output filer01.cklb --format cklb
cargo run --release --bin automatestig -- export --input filer01.ckl --output stigman.json --format stig-manager --collection "Production"
```
