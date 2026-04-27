#!/usr/bin/env python3
"""Generate planned implementation specs for unsupported authoritative DISA rules."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import extract_xccdf_inventory

MANUAL_HINTS = (
    'document', 'documented', 'documentation', 'approval', 'approve', 'policy',
    'procedure', 'procedures', 'process', 'reviewed', 'organization-defined',
    'system owner', 'isso', 'issm', 'authorizing official', 'written',
)
WINDOWS_HINTS = ('windows', 'registry', 'powershell', 'group policy', 'audit policy', 'event log')
LINUX_HINTS = ('rhel', 'linux', 'sshd', 'systemd', 'rpm', 'yum', 'dnf', 'auditd', 'sysctl')
NETWORK_HINTS = ('router', 'switch', 'firewall', 'cisco', 'interface', 'acl', 'snmp')


def slug(value: str) -> str:
    value = re.sub(r'[^A-Za-z0-9._-]+', '_', value.strip().lower()).strip('._-')
    return value or 'unknown'


def classify_rule(title: str) -> tuple[str, str]:
    lower = title.lower()
    if any(hint in lower for hint in MANUAL_HINTS):
        return 'manual', 'manual_evidence_workflow'
    if any(hint in lower for hint in WINDOWS_HINTS):
        return 'automated', 'windows_collector'
    if any(hint in lower for hint in LINUX_HINTS):
        return 'automated', 'linux_collector'
    if any(hint in lower for hint in NETWORK_HINTS):
        return 'automated', 'network_config_collector'
    return 'automated', 'platform_collector'


def _registry_hive_abbrev(hive: str) -> str:
    normalized = re.sub(r'[^A-Z_]', '', hive.upper())
    return {
        'HKEY_LOCAL_MACHINE': 'HKLM',
        'HKLM': 'HKLM',
        'HKEY_CURRENT_USER': 'HKCU',
        'HKCU': 'HKCU',
        'HKEY_CLASSES_ROOT': 'HKCR',
        'HKCR': 'HKCR',
        'HKEY_USERS': 'HKU',
        'HKU': 'HKU',
        'HKEY_CURRENT_CONFIG': 'HKCC',
        'HKCC': 'HKCC',
    }.get(normalized, hive.strip())


def _registry_value(check_content: str):
    match = re.search(r'^\s*Value\s*:\s*(0x[0-9a-fA-F]+|[-+]?\d+)\s*(?:\(([-+]?\d+)\))?', check_content, re.MULTILINE)
    if not match:
        return None
    raw = match.group(2) or match.group(1)
    try:
        return int(raw, 16) if raw.lower().startswith('0x') else int(raw)
    except ValueError:
        return raw


def infer_candidate_check(rule: dict, stig_id: str) -> dict | None:
    """Infer a conservative executable check candidate from DISA prose.

    Candidates are not marked validated; they are scaffolds requiring fixture proof
    before a rule can be promoted from planned to implemented/validated.
    """
    content = rule.get('check_content', '') or ''
    hive = re.search(r'Registry\s+Hive:\s*([^\n\r]+)', content, re.IGNORECASE)
    path = re.search(r'Registry\s+Path:\s*([^\n\r]+)', content, re.IGNORECASE)
    value_name = re.search(r'Value\s+Name:\s*([^\n\r]+)', content, re.IGNORECASE)
    if hive and path and value_name:
        reg_path = path.group(1).strip().strip('\\/')
        expected_value = _registry_value(content)
        if expected_value is not None:
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows' if 'windows' in stig_id.lower() or 'win' in stig_id.lower() else 'generic',
                'check': {
                    'type': 'registry',
                    'path': f"{_registry_hive_abbrev(hive.group(1))}\\{reg_path}",
                    'value_name': value_name.group(1).strip(),
                },
                'expected': {'type': 'equals', 'value': expected_value},
                'description': rule.get('title', ''),
            }

    feature = re.search(r'Get-WindowsFeature\s*\|\s*Where\s+Name\s+-eq\s+([A-Za-z0-9_.-]+)', content, re.IGNORECASE)
    if feature and re.search(r'Installed[^\n.]+is[^\n.]+finding|If[^\n.]+Installed[^\n.]+finding', content, re.IGNORECASE):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'windows',
            'check': {'type': 'windows_feature', 'name': feature.group(1), 'should_be_installed': False},
            'expected': {'type': 'is_false'},
            'description': rule.get('title', ''),
        }
    return None


def spec_from_rule(manifest_path: Path, manifest: dict, rule: dict) -> dict:
    classification, collector = classify_rule(rule.get('title', ''))
    spec = {
        'vuln_id': rule.get('vuln_id', ''),
        'rule_id': rule.get('rule_id', ''),
        'stig_id': manifest.get('stig_id', manifest.get('benchmark', 'unknown')),
        'title': rule.get('title', ''),
        'severity': rule.get('severity', ''),
        'classification': classification,
        'implementation_status': 'planned',
        'source_coverage_manifest': str(manifest_path),
        'source_benchmark': manifest.get('benchmark', ''),
        'source_version': manifest.get('version', ''),
        'collector_type': collector,
        'collector_commands': [],
        'normalizer': 'planned',
        'evaluator': 'planned',
        'expected_values': {},
        'evidence_fields': ['rule_id', 'vuln_id', 'status', 'evidence', 'source_artifact'],
        'na_conditions': [],
        'remediation': 'planned',
        'fixtures': [],
        'external_acceptance_refs': [],
        'tracking_issue': rule.get('tracking_issue', '') or f"TODO-{rule.get('vuln_id', rule.get('rule_id', 'UNKNOWN'))}",
    }
    if rule.get('check_content'):
        spec['check_content_excerpt'] = rule.get('check_content', '')[:4000]
    if rule.get('fix_text'):
        spec['fix_text_excerpt'] = rule.get('fix_text', '')[:4000]
    candidate = infer_candidate_check(rule, spec['stig_id'])
    if candidate:
        spec['candidate_check'] = candidate
        spec['normalizer'] = candidate['check']['type']
        spec['evaluator'] = 'candidate_template'
        spec['expected_values'] = candidate['expected']
    return spec


def _artifact_rule_map(manifest: dict, repo_root: Path, cache: dict[Path, dict]) -> dict:
    merged = {}
    refs = []
    for key in ('generated_from', 'benchmark_path'):
        if manifest.get(key):
            refs.append(manifest[key])
    refs.extend(manifest.get('generated_from_refs', []))
    refs.extend(manifest.get('validated_by', []))
    for raw_ref in refs:
        ref = str(raw_ref)
        if not ref.lower().endswith(('.zip', '.xml', '.xccdf')):
            continue
        path = Path(ref)
        if not path.is_absolute():
            path = repo_root / path
        if not path.exists():
            continue
        if path not in cache:
            try:
                inv = extract_xccdf_inventory.extract(path)
                cache[path] = {rule.get('vuln_id') or rule.get('rule_id'): rule for rule in inv.get('rules', [])}
            except Exception:
                cache[path] = {}
        merged.update(cache[path])
    return merged


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n')


def generate_specs(coverage_root: Path, implementation_root: Path, repo_root: Path | None = None) -> int:
    repo_root = repo_root or Path.cwd()
    artifact_cache: dict[Path, dict] = {}
    count = 0
    for manifest_path in sorted(coverage_root.rglob('*.json')):
        manifest = json.loads(manifest_path.read_text())
        artifact_rules = _artifact_rule_map(manifest, repo_root, artifact_cache)
        stig_slug = slug(manifest.get('stig_id') or manifest.get('benchmark') or manifest_path.parent.name)
        for rule in manifest.get('rules', []):
            if rule.get('classification') != 'unsupported':
                continue
            enriched = dict(rule)
            enriched.update({k: v for k, v in artifact_rules.get(rule.get('vuln_id') or rule.get('rule_id'), {}).items() if v})
            vuln = enriched.get('vuln_id') or enriched.get('rule_id') or 'unknown'
            out = implementation_root / stig_slug / f'{slug(vuln)}.json'
            write_json(out, spec_from_rule(manifest_path, manifest, enriched))
            count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--coverage-root', default='content/coverage/disa-authoritative')
    parser.add_argument('--implementation-root', default='content/rule-implementations')
    parser.add_argument('--repo-root', default='.')
    args = parser.parse_args(argv)
    count = generate_specs(Path(args.coverage_root), Path(args.implementation_root), Path(args.repo_root))
    print(f'Generated {count} planned rule implementation specs')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
