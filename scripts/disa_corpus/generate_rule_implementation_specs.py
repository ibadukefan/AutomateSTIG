#!/usr/bin/env python3
"""Generate planned implementation specs for unsupported authoritative DISA rules."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

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


def spec_from_rule(manifest_path: Path, manifest: dict, rule: dict) -> dict:
    classification, collector = classify_rule(rule.get('title', ''))
    return {
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


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n')


def generate_specs(coverage_root: Path, implementation_root: Path) -> int:
    count = 0
    for manifest_path in sorted(coverage_root.rglob('*.json')):
        manifest = json.loads(manifest_path.read_text())
        stig_slug = slug(manifest.get('stig_id') or manifest.get('benchmark') or manifest_path.parent.name)
        for rule in manifest.get('rules', []):
            if rule.get('classification') != 'unsupported':
                continue
            vuln = rule.get('vuln_id') or rule.get('rule_id') or 'unknown'
            out = implementation_root / stig_slug / f'{slug(vuln)}.json'
            write_json(out, spec_from_rule(manifest_path, manifest, rule))
            count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--coverage-root', default='content/coverage/disa-authoritative')
    parser.add_argument('--implementation-root', default='content/rule-implementations')
    args = parser.parse_args(argv)
    count = generate_specs(Path(args.coverage_root), Path(args.implementation_root))
    print(f'Generated {count} planned rule implementation specs')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
