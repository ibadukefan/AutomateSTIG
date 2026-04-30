#!/usr/bin/env python3
"""Emit candidate AutomateSTIG check packs from rule implementation specs.

Candidate packs are scaffolding only: they compile inferred rule templates into the
same JSON shape consumed by AutomateSTIG check packs, but rules remain planned
until fixtures validate them and coverage manifests are regenerated.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path


def slug(value: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '_', value.strip().lower()).strip('._-') or 'unknown'


def load_candidate_specs(spec_root: Path) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for path in sorted(spec_root.rglob('*.json')):
        if path.name == 'status.json':
            continue
        spec = json.loads(path.read_text())
        candidate = spec.get('candidate_check')
        if not candidate:
            continue
        stig_id = spec.get('stig_id') or 'unknown'
        check = {
            'vuln_id': candidate.get('vuln_id') or spec.get('vuln_id', ''),
            'platform': candidate.get('platform', 'generic'),
            'check': candidate['check'],
            'expected': candidate['expected'],
            'description': candidate.get('description') or spec.get('title', ''),
        }
        grouped[stig_id].append(check)
    return grouped


def choose_platform(checks: list[dict]) -> str:
    platforms = {check.get('platform', 'generic') for check in checks}
    if len(platforms) == 1:
        return next(iter(platforms))
    if 'windows' in platforms and platforms <= {'windows', 'generic'}:
        return 'windows'
    if 'linux' in platforms and platforms <= {'linux', 'generic'}:
        return 'linux'
    return 'generic'


def generate_candidate_packs(spec_root: Path, out_root: Path) -> int:
    written = 0
    for stig_id, checks in sorted(load_candidate_specs(spec_root).items()):
        checks = sorted(checks, key=lambda item: item.get('vuln_id', ''))
        pack = {
            'stig_id': stig_id,
            'platform': choose_platform(checks),
            'version': 'candidate-planned',
            'checks': checks,
        }
        out_root.mkdir(parents=True, exist_ok=True)
        (out_root / f'{slug(stig_id)}.candidates.json').write_text(json.dumps(pack, indent=2, sort_keys=True) + '\n')
        written += 1
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--implementation-root', default='content/rule-implementations')
    parser.add_argument('--out', default='content/check_packs/generated-candidates')
    args = parser.parse_args(argv)
    written = generate_candidate_packs(Path(args.implementation_root), Path(args.out))
    print(f'Generated {written} candidate check packs')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
