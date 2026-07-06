# Answer Files

Answer files are JSON or YAML files that apply reviewer decisions during evaluation. Format is auto-detected from `.json`, `.yaml`, or `.yml`.

Schema: `schemas/answer-file.schema.json`.

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

## JSON Example

```json
{
  "name": "Server baseline answers",
  "description": "Site-reviewed answers for a server baseline",
  "stig_id": "MS_Windows_Server_2022_STIG",
  "version": "1.0.0",
  "entries": [
    {
      "vuln_id": "V-254239",
      "status": "NotAFinding",
      "finding_details": "Validated by site evidence.",
      "comments": "Reviewed by ISSO.",
      "force_override": false
    },
    {
      "vuln_id": "V-254240",
      "status": "Open",
      "finding_details": "Control is not implemented.",
      "comments": "Tracked for remediation.",
      "severity_override": "medium",
      "severity_override_justification": "Approved site-specific risk adjustment.",
      "force_override": true
    }
  ]
}
```

## YAML Example

```yaml
name: Server baseline answers
description: Site-reviewed answers for a server baseline
stig_id: MS_Windows_Server_2022_STIG
version: 1.0.0
entries:
  - vuln_id: V-254239
    status: NotAFinding
    finding_details: Validated by site evidence.
    comments: Reviewed by ISSO.
    force_override: false
  - vuln_id: V-254240
    status: Open
    finding_details: Control is not implemented.
    comments: Tracked for remediation.
    severity_override: medium
    severity_override_justification: Approved site-specific risk adjustment.
    force_override: true
```

## Generate A Template

Generate a template from a checklist:

```bash
automatestig gen-answer --input server01.ckl --output answers.yaml
```

Include `Not_Reviewed` findings:

```bash
automatestig gen-answer --input server01.ckl --output answers.yaml --include-unreviewed
```

Use the answer file during evaluation:

```bash
automatestig evaluate --stig <STIG_ID> --scan results.xml --answer answers.yaml --host server01 --output server01.ckl --format ckl
```
