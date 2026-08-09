# Scanner Validation Report — 2026-08-08

> Historical evidence snapshot: the coverage and bundle counts below describe
> the 2026-08-08 validation run. Current scanner profiles and handoff schema may
> be newer; use [Supported Targets](supported-targets.md) and rerun the current
> gates rather than treating this report as current release evidence.

## Decision

AutomateSTIG now has a coherent scanner-first product boundary and a useful
handoff for difficult-device results. It does not duplicate STIG Manager's
asset, assignment, human-review, approval, reporting, or portfolio workflows.
Changed reviews are never written directly by AutomateSTIG; an exact remote
no-op can be verified, while changed results use a selected-run handoff.

The current evidence supports a **credible pilot** verdict. It does not support
a global claim that AutomateSTIG is better than Evaluate-STIG. A controlled A/B
run with the current authorized Evaluate-STIG package, equivalent target state,
and independent rule ground truth is still required.

## Exact scanner scope

| Profile | STIG | Automated | Reviewed manual | Reviewed profile | Full benchmark | Executable/full |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| NetApp ONTAP 9.x | V2R4 | 15 | 7 | 22 | 29 | 51.7% |
| FreeBSD / GPOS | V3R3 | 3 | 27 | 30 | 203 | 1.5% |
| Cisco IOS-XE Router NDM | V3R7 | 21 | 13 | 34 | 42 | 50.0% |
| **Total** | | **39** | **47** | **86** | **274** | **14.2%** |

These percentages are scanner depth against the full benchmark denominator,
not compliance grades. Manual and outside-profile controls remain STIG Manager
work.

## Scenarios exercised

The checked-in nine-scenario matrix covers pass, finding, and incomplete
outcomes for all three profiles. It additionally covers disconnected handoff,
create/update preview with zero writes, human conflict, exact remote no-op,
transient retry, and incomplete evidence with no delivery or handoff.

A fresh release-binary localhost run generated six native ONTAP/FreeBSD
evidence envelopes and persisted three immutable runs:

| Run | Outcome | Sparse reviews | Handoff |
| --- | --- | ---: | --- |
| `808cb993-7671-4fe6-b6a9-b84178ea3bb3` | FreeBSD complete/pass | 3 | Retained-evidence v2; verified |
| `5f4d8714-ca78-49ec-a9d6-cb02241318ee` | ONTAP complete/pass | 15 | Retained v2 and post-purge result-only v2; both verified |
| `fb83893a-99a5-4e00-8b95-c904c7bd3776` | ONTAP incomplete transport | 0 | Correctly unavailable |

The incomplete run preserved seven collection errors and created no delivery
record, no sparse reviews, and no handoff.

The final scanner-first end-to-end gate passed 62/62 checks. The complete Rust
workspace suite, 102 Python governance/workflow tests, 11 served-frontend
contract tests, the nine-scenario catalog validator, and 18 detached-handoff
security tests also passed. Negative security tests intentionally emitted
rejection messages while still passing.

The real container acceptance ran against STIG Manager 1.6.13+1 and passed
23/23 checks. The rig administrator created the collection, asset, and exact
Cisco V3R7 assignment before AutomateSTIG ran. AutomateSTIG then operated
disconnected and made zero STIG Manager review writes. Its handoff verifier
accepted 21 sparse scanner reviews; a separate receiving operator imported
those reviews into the existing 42-rule assignment. STIG Manager returned a
42/42 full CKL, while the fallback CKLB remained sparse at 21 reviewed rows.
The retired direct-push route returned HTTP 410.

## Export assessment

| Artifact | Assessment | Value | Limitation |
| --- | --- | --- | --- |
| Selected-run handoff v2 with evidence | Strong pilot artifact | Binds the run, exact STIG/content/plan/evidence hashes, sparse reviews, fallback CKLB, and replayable native evidence. Offline verifier checks bounded ZIP safety, integrity, provenance, ownership, CKLB projection, and evidence replay. A detached signature can authenticate the exact ZIP against a dedicated handoff trust store. | The GUI deliberately holds no producer key. Production still needs governed key custody and a protected signing/receiving ceremony. |
| Sparse fallback CKLB | Good receiving fallback | Contains only scanner-owned reviewed rows, so it does not blank manual or outside-profile work. It round-tripped successfully into the real STIG Manager rig. | Intentionally not a full assessment and should not be presented as one. |
| Result-only post-purge handoff | Useful audit fallback | Preserves immutable result, hashes, sparse reviews, CKLB, purge time, and purge reason after replay evidence is destroyed. | Original evidence can no longer be replayed. |
| STIG Manager CKL after reconcile | Authoritative downstream export | Preserved the full 42-rule Cisco assignment: 21 received reviews and 21 untouched rows. | Produced and governed by STIG Manager, not AutomateSTIG. |

The retained localhost ZIPs had six declared members; the result-only ZIP had
five. Every file and manifest digest verified. The tested artifact hashes are:

- FreeBSD retained handoff:
  `12b08f600117e6214b54433590c36ca9031b05c2a66bd27fbdfe6c5227e077cd`
- ONTAP retained handoff:
  `4b931f6dc0112d922948f03612d6cc0e771c3984576a30bcc812d9f78cf53eb5`
- ONTAP result-only handoff:
  `b7cccc4dfbbb79ac8227c1b5abc786584e1cd5bfdd5595467f75b3e783b8d140`

All three were then signed on a separate protected CLI path and verified
against the independently populated lab handoff trust store before evidence
decompression. The lab producer fingerprint was
`SHA256:55c2ae0dc948da75162ec993cf3bf7684c81fa52d285f399d3d3c5ad89f55c27`.
The detached-signature SHA-256 values, in the same order, were
`f06be66485aff2c488c77ededeb4d17c10d2a23602e24bfb90c018bb67c2328c`,
`abf1115573bfdb70a5b2f61a54780911aac33c6f1484b39de5f8da5986245a06`,
and `b0c3abd6e86465c15d3be7717a4083bd1854305b58102d958c12f0cdd94cc301`.
This demonstrates the mechanism, not production identity governance; the lab
private key was kept outside the review-artifact directory.

## Evidence retention and security observations

The fresh database used schema v6. FreeBSD replay evidence was present only as
1,967 bytes of authenticated ciphertext plus a 60-byte wrapped data key. The
tested raw strings `auditd is running as pid 812.` and
`kern.elf64.aslr.enable: 1` were absent from database string extraction. The
explicit ONTAP purge nulled both ciphertext and wrapped key, retained the digest
and timestamps, recorded `operator_requested`, and left the SQLite WAL at zero
bytes. Retention was set to 30 days; the supported policy range is 1–365 days.

## UX assessment

The served GUI exposes only four workspaces: Scan, Deliveries, Scanner Content,
and Connection. First open asks the user to connect to STIG Manager or run
disconnected and states that STIG Manager remains the system of record. The
connected flow requires a live collection, existing asset, and exact assigned
STIG revision before collection. Preflight discloses the read-only plan;
incomplete evidence fails closed; delivery preview distinguishes automated,
reviewed-manual, outside-profile, and full-benchmark counts.

Automated keyboard/accessibility, responsive-layout, task-language, secret
handling, and first-use contracts passed. The localhost instance was started
for hands-on review, but the installed browser-control backend was unavailable
to this test session, so an independent visual/usability walkthrough by
representative analysts is still required. The release gate remains at least
80% unaided first-task completion in that study.

## Evaluate-STIG comparison verdict

The exports are valuable and more evidence-rich than a bare checklist because
they preserve scanner provenance, sparse ownership, retention state, and
offline verification. That is a product advantage in traceability, not yet a
measured advantage over Evaluate-STIG. No authorized current Evaluate-STIG
package hash, equivalent device corpus, repetition set, or independent ground
truth was available for this run. Per the claims policy, the comparison result
is therefore **unknown / not directly comparable**, never zero for
Evaluate-STIG.

The next evidence needed for a target-specific “better” claim is:

1. current authorized Evaluate-STIG package version and SHA-256;
2. equivalent ONTAP, FreeBSD, or Cisco target state and privileges;
3. blinded SME ground truth for compliant, noncompliant, denied, truncated,
   ambiguous, and unsupported-version cases;
4. repeated randomized A/B runs measuring false passes first, then collection
   success, automation depth, intervention, runtime, and script burden; and
5. production key custody plus signed current-consumer round-trip acceptance
   for the selected-run handoff.

See [Evaluate-STIG Comparison](evaluatestig-comparison.md) for the complete
protocol and [Scanner-First Product Plan](scanner-product-plan.md) for the
remaining release gates.
