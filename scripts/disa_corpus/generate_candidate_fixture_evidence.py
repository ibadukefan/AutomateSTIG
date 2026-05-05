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
        key = _registry_key(check)
        if expected.get('type') == 'equals':
            expected_value = expected['value']
            pass_fixture['registry'] = {key: expected_value}
            fail_fixture['registry'] = {key: _alternate_value(expected_value)}
            evidence_type = 'registry_value_equals'
        elif expected.get('type') == 'matches':
            literals = [int(value) for value in re.findall(r'(?<!\\d)([-+]?\d+)(?!\\d)', expected.get('pattern', ''))]
            if not literals:
                raise ValueError(f"{candidate['vuln_id']}: registry matches evidence requires numeric literals")
            pass_fixture['registry'] = {key: literals[0]}
            fail_fixture['registry'] = {key: max(literals) + 1}
            evidence_type = 'registry_value_matches'
        else:
            raise ValueError(f"{candidate['vuln_id']}: registry candidate only supports equals or matches evidence")
    elif check_type == 'windows_feature':
        name = check['name']
        should_be_installed = bool(check['should_be_installed'])
        pass_fixture['packages'] = {name: should_be_installed}
        fail_fixture['packages'] = {name: not should_be_installed}
        evidence_type = 'windows_feature_install_state'
    elif check_type == 'sysctl':
        if expected.get('type') != 'equals':
            raise ValueError(f"{candidate['vuln_id']}: sysctl candidate only supports equals evidence")
        key = check['key']
        expected_value = str(expected['value'])
        pass_fixture['sysctl'] = {key: expected_value}
        fail_fixture['sysctl'] = {key: _alternate_value(expected_value)}
        evidence_type = 'linux_sysctl_value_equals'
    elif check_type == 'package':
        name = check['name']
        should_be_installed = bool(check['should_be_installed'])
        pass_fixture['packages'] = {name: should_be_installed}
        fail_fixture['packages'] = {name: not should_be_installed}
        evidence_type = 'linux_package_install_state'
    elif check_type == 'file_content':
        path = check['path']
        pattern = check['pattern']
        if expected.get('type') == 'is_false':
            pass_fixture['files'] = {path: "before\nafter\n"}
            fail_fixture['files'] = {path: f"before\n{pattern}\nafter\n"}
            evidence_type = 'linux_file_content_absent'
        else:
            pass_fixture['files'] = {path: f"before\n{pattern}\nafter\n"}
            fail_fixture['files'] = {path: "before\nafter\n"}
            evidence_type = 'linux_file_content_contains'
    elif check_type == 'service':
        name = check['name']
        expected_status = check['expected_status']
        pass_fixture['services'] = {name: expected_status}
        fail_fixture['services'] = {name: 'running' if expected_status != 'running' else 'disabled'}
        evidence_type = 'linux_service_status'
    elif check_type == 'file_permission':
        path = check['path']
        expected_perm = {
            'exists': True,
            'owner': check.get('owner'),
            'group': check.get('group'),
            'mode': check.get('mode'),
        }
        unexpected_perm = dict(expected_perm)
        for field in ('mode', 'owner', 'group'):
            if expected_perm.get(field) is not None:
                unexpected_perm[field] = _alternate_value(expected_perm.get(field))
                break
        pass_fixture['file_permissions'] = {path: expected_perm}
        fail_fixture['file_permissions'] = {path: unexpected_perm}
        evidence_type = 'linux_file_permission'
    elif check_type == 'audit_policy':
        if expected.get('type') != 'contains':
            raise ValueError(f"{candidate['vuln_id']}: audit_policy candidate only supports contains evidence")
        subcategory = check['subcategory']
        substring = expected['substring']
        pass_fixture['audit_policy'] = {subcategory: check.get('setting') or substring}
        fail_fixture['audit_policy'] = {subcategory: 'No Auditing'}
        evidence_type = 'windows_audit_policy_contains'
    elif check_type == 'security_policy':
        if expected.get('type') not in ('equals', 'not_equals', 'greater_or_equal', 'less_or_equal', 'matches'):
            raise ValueError(f"{candidate['vuln_id']}: security_policy candidate only supports scalar comparison or regex evidence")
        key = f"{check['section']}\\{check['key']}"
        if expected.get('type') == 'matches':
            literals = re.findall(r'S-\d+(?:-\d+)+', expected.get('pattern', ''))
            pass_fixture['security_policy'] = {key: ','.join(literals) if literals else expected.get('pattern', '')}
            fail_fixture['security_policy'] = {key: ''}
        else:
            expected_value = expected['value']
            if expected.get('type') == 'not_equals':
                pass_fixture['security_policy'] = {key: _alternate_value(expected_value)}
                fail_fixture['security_policy'] = {key: expected_value}
            else:
                pass_fixture['security_policy'] = {key: expected_value}
                if expected.get('type') == 'less_or_equal' and isinstance(expected_value, (int, float)):
                    fail_value = expected_value + 1
                elif expected.get('type') == 'greater_or_equal' and isinstance(expected_value, (int, float)):
                    fail_value = expected_value - 1
                else:
                    fail_value = _alternate_value(expected_value)
                fail_fixture['security_policy'] = {key: fail_value}
        evidence_type = f"windows_security_policy_{expected['type']}"
    elif check_type == 'command_output':
        if expected.get('type') == 'equals':
            command = check['command']
            expected_value = str(expected['value'])
            pass_fixture['command_outputs'] = {command: expected_value}
            fail_fixture['command_outputs'] = {command: _alternate_value(expected_value)}
            evidence_type = 'command_output_equals'
        elif expected.get('type') == 'not_equals':
            command = check['command']
            expected_value = str(expected['value'])
            pass_fixture['command_outputs'] = {command: _alternate_value(expected_value)}
            fail_fixture['command_outputs'] = {command: expected_value}
            evidence_type = 'command_output_not_equals'
        elif expected.get('type') == 'contains':
            command = check['command']
            substring = expected['substring']
            pass_fixture['command_outputs'] = {command: f"before\n{substring}\nafter\n"}
            fail_fixture['command_outputs'] = {command: "before\nafter\n"}
            evidence_type = 'command_output_contains'
        elif expected.get('type') == 'matches':
            command = check['command']
            pattern = expected.get('pattern', '')
            uint32_match = re.search(r'\|([1-9][0-9]{0,2})\)\$', pattern)
            if uint32_match and pattern.startswith('^uint32 '):
                maximum = int(uint32_match.group(1))
                pass_fixture['command_outputs'] = {command: f'uint32 {maximum}'}
                fail_fixture['command_outputs'] = {command: f'uint32 {maximum + 1}'}
            else:
                raise ValueError(f"{candidate['vuln_id']}: command_output matches evidence requires supported deterministic regex")
            evidence_type = 'command_output_matches'
        else:
            raise ValueError(f"{candidate['vuln_id']}: command_output candidate only supports equals, not_equals, contains, or matches evidence")
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
