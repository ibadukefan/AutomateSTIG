# Coverage Manifests

This directory contains the reviewed candidate inventories that govern curated
checks for AutomateSTIG's three v0.3 scanner targets.

Each current manifest answers three questions for every rule in its reviewed
candidate inventory:

1. Does AutomateSTIG automate it from supported device evidence or require manual review?
2. Where is the implementation or evidence mapping?
3. What tests prove the behavior?

CI rejects a shipped check pack without an exact matching manifest, and rejects
any pack not listed by `content/supported-targets.json`.

`current-checkpacks/*.current.json` retains both executable rules and rules
removed from execution because the supported evidence cannot prove the full
requirement. The current boundary is:

- ONTAP: 22 reviewed, 16 automated, 6 manual.
- FreeBSD/GPOS: 30 reviewed, 3 automated, 27 manual.
- Cisco IOS-XE Router NDM: 34 reviewed, 18 automated, 16 manual.
- Total: 86 reviewed candidate rules, 37 automated and 49 manual.

Regenerate all three inventories after a reviewed pack change:

```bash
python3 scripts/generate-checkpack-coverage.py --repo-root .
python3 scripts/validate-check-packs.py
```

The checked-in manifests are reviewed candidate inventories, not comprehensive
ONTAP or GPOS benchmark manifests. They do not establish full-benchmark
automation, external acceptance, accreditation, or suitability as an audit
system of record.
