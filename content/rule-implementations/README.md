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

- authorized public DISA artifacts tracked: 10
- authoritative rules tracked: 2,944
- generated implementation specs: 2,690
- implemented fixture-backed candidate specs: 451
- remaining planned specs: 2,239
- planned automated implementations: 2,051
- planned manual-evidence workflows: 188
- candidate executable checks with deterministic fixture evidence: 451
  - registry: 286
  - windows_feature: 7
  - sysctl: 49
  - package: 38
  - file_content: 71

These specs and generated candidate check packs are **not** a production-readiness claim. They are the machine-readable burn-down queue for reducing `unsupported` authoritative DISA rules to zero. A candidate becomes replacement evidence only after pass/fail/NA fixtures and export/live workflow acceptance validate it.
