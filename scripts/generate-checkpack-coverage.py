#!/usr/bin/env python3
"""Refresh mixed automated/manual inventories for shipped check packs.

Every executable check is regenerated as ``automated``. Existing ``manual``
entries are preserved verbatim so a refresh cannot silently turn an explicitly
de-automated, evidence-insufficient rule back into a compliance decision.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path


def load_pack(path: Path) -> dict:
    with path.open('r', encoding='utf-8') as f:
        return json.load(f)


def manifest_for_pack(
    pack_path: Path,
    repo_root: Path,
    existing_manifest: dict | None = None,
) -> dict:
    pack = load_pack(pack_path)
    checks = pack.get('checks', [])
    check_pack_name = pack_path.stem
    generated_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    automated_rules = []
    for idx, check in enumerate(checks, 1):
        vuln_id = str(check.get('vuln_id', '')).strip()
        if not vuln_id:
            raise SystemExit(f'{pack_path}: check #{idx} is missing vuln_id')
        description = str(check.get('description', '')).strip() or f'Automated check for {vuln_id}'
        automated_rules.append({
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

    automated_by_id = {rule['vuln_id']: rule for rule in automated_rules}
    manual_rules = []
    existing_order = []
    if existing_manifest is not None:
        existing_rules = existing_manifest.get('rules')
        if not isinstance(existing_rules, list):
            raise SystemExit(f'{pack_path}: existing coverage rules must be an array')
        for rule in existing_rules:
            if not isinstance(rule, dict) or not isinstance(rule.get('vuln_id'), str):
                raise SystemExit(f'{pack_path}: existing coverage contains an invalid rule')
            vuln_id = rule['vuln_id']
            existing_order.append(vuln_id)
            if rule.get('classification') == 'manual':
                if vuln_id in automated_by_id:
                    raise SystemExit(
                        f'{pack_path}: {vuln_id} is both executable and explicitly manual'
                    )
                manual_rules.append(rule)
            elif rule.get('classification') != 'automated':
                raise SystemExit(
                    f'{pack_path}: {vuln_id} has an unsupported existing classification'
                )

    manual_by_id = {rule['vuln_id']: rule for rule in manual_rules}
    if len(manual_by_id) != len(manual_rules):
        raise SystemExit(f'{pack_path}: existing coverage contains duplicate manual IDs')
    combined = {**manual_by_id, **automated_by_id}
    rules = [combined.pop(vuln_id) for vuln_id in existing_order if vuln_id in combined]
    rules.extend(automated_by_id[vuln_id] for vuln_id in automated_by_id if vuln_id in combined)
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
    automated_rules = 0
    for pack_path in sorted((repo / 'content/check_packs').glob('*.json')):
        target = out / f'{pack_path.stem}.current.json'
        existing = load_pack(target) if target.exists() else None
        manifest = manifest_for_pack(pack_path, repo, existing)
        target.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        count += 1
        total_rules += manifest['total_rules']
        automated_rules += sum(
            rule['classification'] == 'automated' for rule in manifest['rules']
        )
    print(
        f'Refreshed {count} current-checkpack manifests covering '
        f'{total_rules} reviewed rules ({automated_rules} automated)'
    )


if __name__ == '__main__':
    main()
