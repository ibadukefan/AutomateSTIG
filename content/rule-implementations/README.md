# Rule Implementations

Each JSON file under this tree describes how one authoritative DISA rule is or will be handled by AutomateSTIG. Production status requires every authoritative rule to have a valid implementation spec and zero `unsupported` coverage entries.

See `schemas/rule-implementation.schema.json`.

## Current generated backlog

`generated/` is produced from `content/coverage/disa-authoritative/` by:

```bash
python3 scripts/disa_corpus/generate_rule_implementation_specs.py \
  --coverage-root content/coverage/disa-authoritative \
  --implementation-root content/rule-implementations/generated \
  --repo-root .
```

Candidate check packs can be generated from specs that contain conservative `candidate_check` templates:

```bash
python3 scripts/disa_corpus/generate_candidate_check_packs.py \
  --implementation-root content/rule-implementations/generated \
  --out content/check_packs/generated-candidates
```

Current generated backlog summary is in `status.json`:

- planned implementation specs: 1,037
- planned automated implementations: 951
- planned manual-evidence workflows: 86
- candidate executable checks awaiting fixture validation: 96
  - registry: 94
  - windows_feature: 2
- collector families:
  - linux_collector: 543
  - windows_collector: 407
  - manual_evidence_workflow: 86
  - platform_collector: 1

These specs and generated candidate check packs are **not** a production-readiness claim. They are the machine-readable burn-down queue for reducing `unsupported` authoritative DISA rules to zero. A candidate becomes replacement evidence only after pass/fail/NA fixtures and export/live workflow acceptance validate it.
