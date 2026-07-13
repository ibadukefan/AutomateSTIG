# NetApp ONTAP Collection and Evaluation

AutomateSTIG evaluates NetApp ONTAP filers from read-only CLI evidence transcripts. ONTAP filers cannot run scanner scripts, so the workflow is to collect command output and evaluate it against the DISA NetApp ONTAP DSC 9.x STIG.

The `netapp_ontap9` check pack targets DISA NetApp ONTAP DSC 9.x STIG V2R2. That release contains 29 rules:

- 22 rules automated by the `netapp_ontap9` check pack.
- 7 rules requiring manual review: `V-246927`, `V-246930`, `V-246933`, `V-246939`, `V-246945`, `V-246946`, and `V-246949`.

## Collecting Evidence

Use one of these collection paths.

### Connected GUI Scan

On the `Assessments` page, start a GUI SSH scan with `Platform = NetApp ONTAP`.

The GUI connects over SSH, runs the ONTAP collection commands, and stores the transcript as assessment evidence.

### Air-Gapped Transcript

From any host with SSH access to the cluster management LIF, run:

```bash
scripts/collectors/ontap-collect.sh admin@filer > filer-evidence.txt
```

Transfer `filer-evidence.txt` into the AutomateSTIG environment.

Two read-only commands require ONTAP advanced privilege:

- `system configuration backup show`
- `security config show`

The collector wraps those commands with:

```text
set -privilege advanced -confirmations off
```

The evidence transcript is plain text. Each command section starts with a delimiter:

```text
### automatestig:command <command>
```

If automated collection is not available, you can capture the same format manually in a recorded terminal session.

## Evaluating

Import the DISA STIG once:

```bash
automatestig disa-import --input U_NetApp_ONTAP_DSC_9-x_V2R2_STIG.zip
```

Then evaluate the filer transcript:

```bash
automatestig evaluate \
  --stig NetApp_ONTAP_DSC_9-x_STIG \
  --evidence filer-evidence.txt \
  --host <filer-hostname> \
  --output filer.ckl \
  --format ckl
```

Results merge with answer files as usual. Completed results can be pushed to STIG Manager or imported as CKL.

## Accuracy Note

The `netapp_ontap9` check pack matches canonical ONTAP 9 CLI output. The pack is marked experimental, and unusual formatting from custom CLI sessions or truncated columns should be verified against the manual STIG before relying on automated results.

Manual-review rules always appear as `Not_Reviewed`.

## Chain of Custody

Every checklist evaluated from an evidence transcript or config file records the SHA-256 of the exact input bytes in each finding's comments (`Automated evaluation provenance: ... SHA-256: <hex>`). A reviewer can independently confirm the checklist came from a specific artifact with `sha256sum evidence.txt` (or `shasum -a 256`). If the evidence is altered by a single byte, the digest no longer matches — this is the audit anchor binding results to collected evidence.
