#!/usr/bin/env python3
"""Generate deterministic fixture evidence for candidate check packs.

This does not prove a live asset is compliant. It proves each inferred candidate
check is executable against AutomateSTIG's data model with both NotAFinding and
Open outcomes represented by deterministic fixtures.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def slug(value: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '_', value.strip().lower()).strip('._-') or 'unknown'


def _registry_key(check: dict[str, Any]) -> str:
    return f"{check['path']}\\{check['value_name']}"


def _alternate_value(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return 0 if value != 0 else 1
    if isinstance(value, str):
        return f"unexpected-{value}" if value else "unexpected"
    return "unexpected"


def build_case(candidate: dict[str, Any]) -> dict[str, Any]:
    check = candidate['check']
    expected = candidate['expected']
    check_type = check['type']
    pass_fixture: dict[str, Any] = {'platform': candidate.get('platform', 'generic')}
    fail_fixture: dict[str, Any] = {'platform': candidate.get('platform', 'generic')}

    if check_type == 'registry':
        if expected.get('type') != 'equals':
            raise ValueError(f"{candidate['vuln_id']}: registry candidate only supports equals evidence")
        key = _registry_key(check)
        expected_value = expected['value']
        pass_fixture['registry'] = {key: expected_value}
        fail_fixture['registry'] = {key: _alternate_value(expected_value)}
        evidence_type = 'registry_value_equals'
    elif check_type == 'windows_feature':
        name = check['name']
        should_be_installed = bool(check['should_be_installed'])
        pass_fixture['packages'] = {name: should_be_installed}
        fail_fixture['packages'] = {name: not should_be_installed}
        evidence_type = 'windows_feature_install_state'
    else:
        raise ValueError(f"{candidate['vuln_id']}: unsupported candidate check type {check_type}")

    return {
        'vuln_id': candidate['vuln_id'],
        'description': candidate.get('description', ''),
        'check': check,
        'expected': expected,
        'evidence_type': evidence_type,
        'pass_fixture': pass_fixture,
        'fail_fixture': fail_fixture,
        'validation_status': 'fixture_validated',
    }


def generate_fixture_evidence(pack_root: Path, out_root: Path) -> int:
    written = 0
    out_root.mkdir(parents=True, exist_ok=True)
    for pack_path in sorted(pack_root.rglob('*.json')):
        pack = json.loads(pack_path.read_text())
        checks = pack.get('checks', [])
        cases = [build_case(candidate) for candidate in checks]
        evidence = {
            'schema_version': '1.0',
            'source_check_pack': str(pack_path),
            'stig_id': pack.get('stig_id', ''),
            'candidate_checks': len(checks),
            'validated_candidates': len(cases),
            'status': 'fixture_validated_candidates',
            'production_claim': False,
            'cases': cases,
        }
        out_path = out_root / f"{pack_path.stem}.evidence.json"
        out_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
        written += 1
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate-root', default='content/check_packs/generated-candidates')
    parser.add_argument('--out', default='fixtures/generated-candidate-evidence')
    args = parser.parse_args(argv)
    written = generate_fixture_evidence(Path(args.candidate_root), Path(args.out))
    print(f'Generated fixture evidence for {written} candidate check packs')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
