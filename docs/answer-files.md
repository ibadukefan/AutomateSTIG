# Answer Files

> **Transition-only:** Answer files are not part of the scanner-first GUI or
> verified selected-run handoff. Human determinations, comments, overrides, and
> manual-rule completion belong in STIG Manager. This page documents legacy
> evaluation, one-time export, and maintainer compatibility for the
> non-destructive migration window.

Answer files are JSON or YAML files that apply reviewer decisions during evaluation. Format is auto-detected from `.json`, `.yaml`, or `.yml`.

Schema: `schemas/answer-file.schema.json`.

They are inputs to a new evaluation, not result files. Selecting an answer file
does not import a checklist and does not contact or collect from a device by
itself.

## Shape

Top-level required fields:

- `name`
- `version`
- `entries`

Top-level optional fields:

- `description`
- `stig_id`, where `null` means any STIG.

Each entry requires:

- `vuln_id`, matching `^V-\d+$`
- `status`, one of `NotAFinding`, `Open`, `Not_Applicable`, `Not_Reviewed`

Each entry may include:

- `finding_details`
- `comments`
- `severity_override`, one of `high`, `medium`, `low`
- `severity_override_justification`, required when `severity_override` is set
- `force_override`, default `false`

With `force_override: false`, an entry can fill an otherwise `Not_Reviewed` or
manual result, but a later status established by device evidence wins.
Set `force_override: true` only for a specifically approved decision that is
intended to replace an automated/evidence result. Answer files never replace a
typed collection error. Review every applied entry in the resulting checklist.

## Historical GUI behavior

Earlier releases exposed answer-file editing and selection under `Settings`
and `Assessments`. Those workspaces are not embedded in the scanner GUI, and
the former unversioned answer-file and assessment HTTP routes return `410 Gone`.
They must not be used to create new reviewer decisions.

Existing answer-file bytes and their source attribution remain preservable for
the non-destructive migration window through `automatestig-transition migration
inventory` and `automatestig-transition migration export`. Human determinations, overrides, comments,
and manual-rule completion continue in STIG Manager. The format material below
is retained only to interpret preserved files; it is not an operational GUI or
product-CLI procedure.

## JSON Example

```json
{
  "name": "ONTAP site answers",
  "description": "Site-reviewed answers for an ONTAP assessment",
  "stig_id": "NetApp_ONTAP_DSC_9-x_STIG",
  "version": "1.0.0",
  "entries": [
    {
      "vuln_id": "V-246927",
      "status": "NotAFinding",
      "finding_details": "Validated by site evidence.",
      "comments": "Reviewed by ISSO.",
      "force_override": false
    },
    {
      "vuln_id": "V-246930",
      "status": "Open",
      "finding_details": "Control is not implemented.",
      "comments": "Tracked for follow-up.",
      "severity_override": "medium",
      "severity_override_justification": "Approved site-specific risk adjustment.",
      "force_override": true
    }
  ]
}
```

## YAML Example

```yaml
name: ONTAP site answers
description: Site-reviewed answers for an ONTAP assessment
stig_id: NetApp_ONTAP_DSC_9-x_STIG
version: 1.0.0
entries:
  - vuln_id: V-246927
    status: NotAFinding
    finding_details: Validated by site evidence.
    comments: Reviewed by ISSO.
    force_override: false
  - vuln_id: V-246930
    status: Open
    finding_details: Control is not implemented.
    comments: Tracked for follow-up.
    severity_override: medium
    severity_override_justification: Approved site-specific risk adjustment.
    force_override: true
```

## Preservation only

The former `gen-answer` command and `evaluate --answer` option are retired and
are not compiled into the scanner product. Use `automatestig-transition migration export`
to preserve historical answer-file bytes and attribution. Create and complete
human determinations in STIG Manager; they are never converted into
AutomateSTIG scanner results.
