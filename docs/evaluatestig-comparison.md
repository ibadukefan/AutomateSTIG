# Evaluate-STIG Comparison

AutomateSTIG is not intended to replace Evaluate-STIG globally. Its goal is to
perform selected difficult-device scans more reliably, safely, or efficiently
than the current authorized Evaluate-STIG package or the site scripts needed to
fill its gaps. Every superiority statement must name a target, exact STIG
revision, device version, test dimension, and dated comparison artifact.

## Claims policy

Use one of these forms:

- **Measured advantage:** “For ONTAP version X and STIG VnRm in this test
  corpus, AutomateSTIG had N/N successful collections versus M/N, with zero
  false passes for both tools.”
- **Equivalent:** report the same measured outcome and prefer neither tool.
- **Not directly comparable:** use this when Evaluate-STIG has no target path,
  its required package is unavailable, the revisions differ, or equivalent
  privilege/device state cannot be established.
- **Unknown:** use this for missing evidence or inconclusive results.

Do not turn absent public documentation, a gated package, an unsupported
workflow, or a tool error into a zero score. Do not claim “better than
Evaluate-STIG” without a controlled overlapping-target result.

## Required inputs

Before an A/B run, record:

1. the authorized Evaluate-STIG package version and SHA-256;
2. the AutomateSTIG build, profile, benchmark, check-pack, and plan hashes;
3. identical hardware or VM identity, firmware, HA/virtual context, benchmark
   revision, credential privilege, network path, and site-policy inputs;
4. a frozen device-state snapshot or reproducible lab-state recipe;
5. two named SMEs who establish blinded rule ground truth from the STIG check
   text and captured device state; and
6. exclusions, unavailable features, deviations, and the reason for each.

If these prerequisites cannot be met, publish a capability observation or
engineering hypothesis instead of a comparison score.

## Test corpus

For every rule classified as technically automatable, include:

- one compliant state;
- one deliberate noncompliant state;
- permission denial;
- authentication or transport failure where applicable;
- timeout and response truncation;
- malformed or semantically ambiguous output;
- stale or partial configuration;
- unsupported target version;
- relevant HA, tenant, VDOM, virtual-context, or failover state; and
- every organization-defined parameter boundary used by the rule.

Run the same number of repetitions for both tools in randomized order after
restoring the frozen state. Retain raw outputs, timestamps, tool logs, hashes,
and the comparison manifest. Synthetic fixtures are development oracles, not a
substitute for representative authorized devices.

## Metrics and denominators

Publish the raw numerator and denominator for every measure.

| Measure | Definition |
| --- | --- |
| False passes | Ground-truth noncompliant or unobservable cases reported compliant. This is the primary safety measure. |
| False failures | Ground-truth compliant cases reported noncompliant. |
| Precision | True noncompliant findings divided by all noncompliant findings emitted. |
| Recall | True noncompliant findings divided by all ground-truth noncompliant cases. |
| Collection success | Complete, version-bound collections divided by authorized attempts. |
| Automation depth | Correct automated decisions divided by the SME-classified technically automatable rules, not total benchmark rules. |
| Manual tail | Rules left `NotReviewed` or requiring analyst transcription after valid collection. |
| Evidence traceability | Automated decisions resolving to raw evidence, collection operation, parser/predicate, content, policy, target, and build hashes. |
| Setup time | Median hands-on time from clean workstation to ready-to-scan state. |
| Runtime | Median wall-clock collection plus evaluation time under the same network/device state. |
| Analyst intervention | Median manual steps, prompts, remediations, and transcription actions per completed target. |
| Script burden | Target-specific scripts/modules and reviewed lines required outside the shipped tool. Report language and counting method. |
| Revision adaptation | Engineering and validation time from new STIG receipt to a gated target profile. |
| Delivery integrity | Initial delivery, identical re-delivery, interrupted retry, and human-conflict outcomes against the same STIG Manager version. Mark not applicable when a tool has no comparable delivery function. |
| Interchange integrity | Rule identity, status, details, comments, and provenance preserved through the supported CKLB/CKL consumer round trip. |

Also publish total benchmark rules, classified reviewed rules, technically
automatable rules, implemented rules, manual rules, excluded rules, and
collection-error rules. A percentage without these denominators is not an
acceptable comparison.

## Decision gates

A target-specific AutomateSTIG advantage can be published only when:

- both tools were measured on an equivalent overlapping target, or the claim
  is explicitly limited to completing a workflow the other package reports as
  unsupported;
- AutomateSTIG produced zero false passes in the maintained negative and error
  corpus;
- any claimed improvement exceeds run-to-run variation and includes sample
  size and repetitions;
- every AutomateSTIG machine decision has traceable evidence and provenance;
- unsupported versions and incomplete evidence fail closed;
- exclusions and tool failures are visible rather than silently removed; and
- the report is independently reviewed by a cybersecurity SME and test owner.

A failure in a safety gate blocks the claim even when setup time, runtime, or
automation depth is better. Results are scoped to the tested profile and
firmware; a new STIG revision or material adapter change requires a new
comparison.

## Analyst and manager value study

The technical A/B test should be followed by a blinded operational pilot.
Analysts attempt the same prepared cases with both tools and no author help.
Measure task completion, time to identify collection errors, time to understand
why a rule passed or failed, manual transcription, and support requests.

Managers evaluate whether the output arrives at the exact existing STIG
Manager assignment, leaves human work untouched, exposes retry/conflict state,
and provides a useful receipt and evidence trail. They should not score
AutomateSTIG on dashboards, approvals, or portfolio reports because those
remain intentionally owned by STIG Manager.

The first-use UX gate is at least 80% of representative lab users completing a
prepared scan without external documentation. Record participant experience,
task failures, assistance, and version information alongside the result.

## Report template

Every published target scorecard should contain:

```text
Comparison ID / date:
Target family, model, firmware, context:
STIG ID and revision:
Evaluate-STIG package version / SHA-256:
AutomateSTIG build / profile / content hashes:
Ground-truth owners and review date:
Cases and repetitions:
Deviations and exclusions:

Metric                    AutomateSTIG   Evaluate-STIG   Delta   Denominator
False passes
False failures
Precision / recall
Collection success
Automation depth
Manual tail
Evidence traceability
Setup time / runtime
Analyst intervention
External script burden
Delivery / interchange

Claim permitted: yes / no / not directly comparable
Exact permitted wording:
Open defects and unknowns:
Independent approvals:
Artifact manifest SHA-256:
```

The scenario fixtures in `fixtures/scanner_scenarios` validate product
semantics such as incomplete runs, sparse reviews, conflicts, and retries. They
must never be presented as Evaluate-STIG comparison data.

Use the [controlled scanner comparison harness](commercial-scanner-comparison.md)
to freeze a deterministic run schedule, verify exact source/result hashes,
consume XCCDF or independently normalized proprietary exports, calculate the
metrics above, and enforce the false-pass/incomplete-evidence safety gate. The
harness works for Evaluate-STIG and private-sector comparators but never
automatically authorizes a superiority claim.
