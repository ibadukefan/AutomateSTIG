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

- ONTAP V2R4: 15 automated, 7 manual, 22 reviewed, 29 full-benchmark rules.
- FreeBSD/GPOS V3R3: 6 automated, 24 manual, 30 reviewed, 203 full-benchmark rules.
- Cisco IOS-XE Router NDM V3R7: 33 automated, 9 manual, 42 reviewed, 42 full-benchmark rules.
- Total: 54 automated, 40 manual, 94 reviewed, 274 full-benchmark rules.

Regenerate all three inventories after a reviewed pack change:

```bash
python3 scripts/generate-checkpack-coverage.py --repo-root .
python3 scripts/validate-check-packs.py
```

The checked-in coverage manifests are reviewed candidate inventories, not
claims that every full-benchmark rule was classified or assessed. The bundled
benchmark models provide the full denominators above. The difference between
the reviewed and full counts remains outside the scanner profile and must be
completed in STIG Manager; it does not establish external acceptance,
accreditation, or suitability as an audit system of record.
