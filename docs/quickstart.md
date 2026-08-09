# Scanner Quickstart

AutomateSTIG scans selected difficult-device targets and produces a verified
sparse handoff for an existing STIG Manager asset and assignment. It does not
replace STIG Manager's inventory, human review, submission, dashboard, or
reporting workflows.

The release already contains the exact scanner profiles; a normal user does
not import a general DISA catalog before the first scan. Confirm the target is
one of the exact profiles in [Supported Targets](supported-targets.md).

## Before you start

For a connected run, obtain:

- the HTTPS STIG Manager API and OAuth token URLs;
- a least-privilege client ID/secret able to read the chosen collection,
  assets, assignments, and reviews; AutomateSTIG does not use it to write a
  changed review;
- an existing asset with the exact supported STIG revision assigned; and
- an authorized device credential and verified SSH host-key fingerprint for
  ONTAP/FreeBSD, or a complete IOS-XE running configuration with a trusted
  signed organization policy.

Configure the destination and SSH IP/CIDR allowlists described in
[Security Model](security-model.md). Prefer out-of-band host-key enrollment to
trust on first use.

## Connected first scan

1. Start the GUI.

   ```bash
   cargo run --release --bin automatestig-gui
   ```

2. Choose **Connect to STIG Manager**, enter the connection, and select **Test
   these values**. Confirm server identity, version, capabilities, and
   privileges, then save. The UI must never echo the client secret.

3. Open **Scan**. Select the live collection, existing asset, and exact assigned
   STIG. If an assignment is unsupported, read its reason; do not work around a
   revision or target mismatch.

4. Choose the collection method:

   - ONTAP V2R4: read-only SSH or strict matching evidence;
   - FreeBSD/GPOS V3R3: read-only SSH or strict matching evidence; or
   - IOS-XE Router NDM V3R7: complete running configuration, organization-policy
     JSON, and its detached trusted signature.

5. Select **Preflight**. Verify the device identity, observed version,
   destination binding, privilege, content hashes, and every read-only
   operation. Secrets remain in memory only through run submission.

6. Start the run. A permission failure, timeout, truncation, unsupported
   version, malformed output, missing configuration section, or failed policy
   validation produces an incomplete diagnostic run. Recollect; no handoff is
   available for it.

7. For a complete run, inspect the read-only sparse preview. Check create and
   update proposals, unchanged reviews, conflicts, evidence references, and
   the manual/out-of-scope count that remains untouched. The coverage panel
   distinguishes automated, reviewed-profile, and full-benchmark denominators.

8. Follow the preview. If every proposed review is unchanged, confirm the
   remote no-op and retain its receipt. If any row is a create or update,
   download and verify the selected-run handoff; AutomateSTIG blocks the direct write
   because the current STIG Manager API cannot atomically protect human work.
   Use the approved receiver to map `sparse-reviews.json` to the exact
   assignment, then choose **Open in STIG Manager** to review the result.

9. Complete manual reviews, comments, submission, validation, findings
   analysis, and reports in STIG Manager.

## Retry after an outage

Open **Deliveries** and select the affected run. Confirm the collection, asset,
assignment, and payload digest. A recheck reads current remote state. An
identical result becomes a safe no-op; a new human-owned review becomes a
conflict; a create/update remains handoff-only.

Never resolve a human conflict by overwriting it from AutomateSTIG. Open the
remote review, establish ownership in STIG Manager, refresh, and deliberately
recheck. Use the selected-run handoff for any resulting create or update.

## Disconnected scan

1. On first open, choose **Run disconnected**.
2. Select the exact profile and provide the authorized endpoint/evidence or
   IOS-XE configuration and signed policy.
3. Verify the same preflight identity, compatibility, and operation plan.
4. Run collection/evaluation and review evidence completeness.
5. For a complete run, download one selected-run integrity handoff.
6. On the connected side, verify it before receiver mapping:

   ```bash
   automatestig scanner verify-handoff automatestig-run-<RUN_ID>.zip
   ```

7. Map only the verified `sparse-reviews.json` rows to the existing STIG Manager
   asset and exact assignment. Treat XCCDF and CKLB as supplemental artifacts,
   not additional review sets.

An incomplete run has no handoff. The handoff is not a local portfolio and
does not replace STIG Manager. A passing v2 integrity verification does not
prove producer authenticity. When the protected producer-signing workflow is
in use, supply its detached sidecar and dedicated trust directory:

```bash
automatestig scanner verify-handoff automatestig-run-<RUN_ID>.zip \
  --signature automatestig-run-<RUN_ID>.zip.signature.json \
  --trust-dir /approved/automatestig-handoff-keys
```

Otherwise use an authenticated transfer and independently confirm the run ID.

## Safe synthetic scenarios

The repository includes synthetic analyst/manager flows for compliant,
noncompliant, incomplete, unchanged, conflict, retry, and disconnected cases:

```bash
python3 scripts/validate-scanner-scenarios.py
```

The validator confirms exact profile/release bindings, input hashes, existing
synthetic assignments, sparse counts, conflict safety, retry digest stability,
and absence of checked-in secrets. These fixtures are development data, not
live-device or Evaluate-STIG acceptance evidence. See
[`fixtures/scanner_scenarios`](../fixtures/scanner_scenarios/README.md).

## Legacy CLI during migration

Existing collection, evaluation, conversion, and one-time export commands
remain available during the transition. They must preserve source attribution
and cannot turn imported, manual, answer-file, or incomplete results into
scanner-owned reviews. The scanner-first GUI is the normal user flow; broad
content import, historical checklist conversion, and migration exports move to
separate maintainer/transition tooling.
