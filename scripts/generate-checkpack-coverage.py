#!/usr/bin/env python3
"""Generate coverage manifests for every current AutomateSTIG check pack.

These manifests prove 100% *current check-pack inventory* coverage: every rule
that exists in `content/check_packs/*.json` is represented as an automated
AutomateSTIG check. They are intentionally separate from authoritative DISA
benchmark manifests, which can contain many rules that are not yet implemented
as native checks.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path


def load_pack(path: Path) -> dict:
    with path.open('r', encoding='utf-8') as f:
        return json.load(f)


def manifest_for_pack(pack_path: Path, repo_root: Path) -> dict:
    pack = load_pack(pack_path)
    checks = pack.get('checks', [])
    check_pack_name = pack_path.stem
    generated_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    rules = []
    for idx, check in enumerate(checks, 1):
        vuln_id = str(check.get('vuln_id', '')).strip()
        if not vuln_id:
            raise SystemExit(f'{pack_path}: check #{idx} is missing vuln_id')
        description = str(check.get('description', '')).strip() or f'Automated check for {vuln_id}'
        rules.append({
            'vuln_id': vuln_id,
            'rule_id': check.get('rule_id') or f'{vuln_id}_automatestig_check',
            'classification': 'automated',
            'reason': description,
            'check_pack': check_pack_name,
            'check_id': vuln_id,
            'evidence_required': True,
            'validated_by': [
                f'content/check_packs/{pack_path.name}',
                'cargo test --workspace',
            ],
        })
    return {
        'stig_id': pack.get('stig_id') or check_pack_name,
        'version': str(pack.get('version', 'unknown')),
        'source': f'AutomateSTIG current check pack: content/check_packs/{pack_path.name}',
        'status': 'experimental',
        'generated_at': generated_at,
        'generated_from': f'content/check_packs/{pack_path.name}',
        'total_rules': len(rules),
        'rules': rules,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-root', default='.')
    ap.add_argument('--output-dir', default='content/coverage/current-checkpacks')
    args = ap.parse_args()
    repo = Path(args.repo_root).resolve()
    out = repo / args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    count = 0
    total_rules = 0
    for pack_path in sorted((repo / 'content/check_packs').glob('*.json')):
        manifest = manifest_for_pack(pack_path, repo)
        target = out / f'{pack_path.stem}.current.json'
        target.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        count += 1
        total_rules += manifest['total_rules']
    print(f'Generated {count} current-checkpack manifests covering {total_rules} automated checks')


if __name__ == '__main__':
    main()
