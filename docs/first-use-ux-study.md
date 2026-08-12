# First-Use UX Release Study

AutomateSTIG does not claim that its scanner-first GUI is ready for a supported
release from automated UI tests alone. A supported release requires a real,
protected first-use study in which at least 80 percent of the complete cohort
finishes the prepared scan without external documentation or assistance.

## Cohort and task

Recruit 5 to 100 people who have not used AutomateSTIG before. The cohort must
include at least two cybersecurity analysts, at least two cybersecurity
managers, and at least two role-experience bands. Do not remove a participant
after the task begins because they failed, needed help, or consulted external
documentation.

Every participant uses the same prepared scan fixture, task definition,
AutomateSTIG GUI bytes, product version, scanner profile, and lab conditions.
Record the SHA-256 of both the fixture and task definition. The task ends when
the participant either completes the prepared scan or reaches the study's
predeclared time limit. The task definition must say what counts as completion
and must not explain the UI interaction sequence.

The facilitator may give neutral study instructions but no product help. If a
participant receives any product help or uses documentation outside the GUI,
record it. That participant remains in the denominator and cannot enter the
numerator even if the scan later completes.

## Roles and independence

The study record names three distinct people by GitHub login:

- a facilitator who administers the sessions;
- an independent observer who verifies each recorded outcome and dispatches
  the protected workflow; and
- an independent approver who reviews the completed record through the
  `first-use-ux-study` protected environment.

The observer and approver cannot be the same person. Configure the environment
with exactly the recorded approver as its required reviewer, prevent self
review, disable administrator bypass, and restrict it to protected branches.
The protected job must run on one identified Linux x64 self-hosted runner with
the `automatestig-first-use-study` label.

## Evidence format

Start from `release-evidence/templates/first-use-ux-study.json` and validate it
against `schemas/first-use-ux-study.schema.json`. The template is deliberately
a failed, stale placeholder and cannot satisfy a release. Replace every
placeholder from the real study. Use pseudonymous participant IDs;
do not store names, credentials, target addresses, free-form device output, or
other sensitive operational data. `outcome_notes` should describe only the
observable task result or failure point.

The denominator is the exact number of participant rows. The numerator is
recomputed from rows where all three conditions hold:

1. `completed_prepared_scan` is `true`;
2. `external_documentation_used` is `false`; and
3. `assistance_received` is `false`.

The validator recomputes the ratio using integer arithmetic. `passed` must be
`true` exactly when `numerator / denominator >= 0.80`; therefore a failed study
is an honest, valid study record, not a pass or waiver.

## Protected workflow

After the observer has reviewed the complete redacted record, dispatch
`.github/workflows/first-use-ux-study.yml` from the exact approved commit. Supply
the absolute runner path to the JSON and the intended semantic-version tag.
The workflow builds the default-feature-free GUI, verifies its SHA-256 against
the study record, validates and normalizes the record, and uploads it before
enforcing the threshold. A below-threshold study therefore leaves a retained
failure artifact but the workflow concludes unsuccessfully.

Before dispatch, replace the template repository, approved source commit,
intended product version, GUI SHA-256, scenario values, study identities,
participant rows, and exact metrics. The protected workflow replaces only the
placeholder `workflow_run_id` with its own immutable run ID; it does not invent
participants, outcomes, commit identity, product identity, or a pass.

For a passing study, copy the uploaded `first-use-ux-study.json` unchanged to
`release-evidence/artifacts/<tag>/`, hash it, and reference it from the required
`first_use_ux` gate in `release-evidence/<tag>.json`. The connected release
validator verifies the exact commit, tag, GUI digest, scenario, complete cohort,
numerator and denominator, independent identities, protected workflow,
artifact bytes, and 90-day freshness. A missing, stale, assisted, undersized,
unrepresentative, or below-threshold study blocks the supported release.

This gate proves only the prepared first-use task on the tested version and
scenario. It is not a general usability certification and must be repeated for
a materially changed first-run flow or release candidate.
