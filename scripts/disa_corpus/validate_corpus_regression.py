#!/usr/bin/env python3
"""Fail CI when tracked DISA corpus or mapped coverage regresses.

This is a ratchet, not a production-readiness claim. Update the committed
baseline intentionally after verified corpus expansion or coverage burn-down.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

DEFAULT_BASELINE = Path('content/disa-corpus/regression-baseline.json')


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8'))


def collect_metrics(repo_root: Path) -> dict[str, int]:
    coverage_root = repo_root / 'content' / 'coverage' / 'disa-authoritative'
    artifact_manifest = repo_root / 'content' / 'disa-corpus' / 'artifacts.manifest.json'

    if not coverage_root.exists():
        raise SystemExit(f'missing authoritative coverage root: {coverage_root}')
    if not artifact_manifest.exists():
        raise SystemExit(f'missing DISA artifact manifest: {artifact_manifest}')

    classifications: Counter[str] = Counter()
    manifests = 0
    for path in sorted(coverage_root.rglob('*.json')):
        doc = _load_json(path)
        rules = doc.get('rules')
        if not isinstance(rules, list):
            raise SystemExit(f'{path}: expected rules array')
        manifests += 1
        for rule in rules:
            classifications[str(rule.get('classification'))] += 1

    artifacts = _load_json(artifact_manifest).get('fixtures', [])
    if not isinstance(artifacts, list):
        raise SystemExit(f'{artifact_manifest}: expected fixtures array')

    automated = classifications['automated'] + classifications['scanner_import'] + classifications['manual_evidence'] + classifications['not_applicable']
    # Today generated authoritative manifests use 'automated' and 'unsupported'.
    # The extra non-unsupported classes above make the ratchet forward-compatible
    # with the documented 100%-coverage definition.
    total = sum(classifications.values())
    unsupported = classifications['unsupported']

    return {
        'public_disa_artifacts': len(artifacts),
        'authoritative_manifests': manifests,
        'authoritative_rules': total,
        'automated_or_mapped_rules': automated,
        'unsupported_rules': unsupported,
    }


def _check_min(metrics: dict[str, int], baseline: dict[str, Any], baseline_key: str, metric_key: str, failures: list[str]) -> None:
    expected = int(baseline[baseline_key])
    actual = metrics[metric_key]
    if actual < expected:
        failures.append(f'{metric_key} regressed: actual {actual} < floor {expected}')


def _check_max(metrics: dict[str, int], baseline: dict[str, Any], baseline_key: str, metric_key: str, failures: list[str]) -> None:
    expected = int(baseline[baseline_key])
    actual = metrics[metric_key]
    if actual > expected:
        failures.append(f'{metric_key} regressed: actual {actual} > ceiling {expected}')


def validate(repo_root: Path, baseline_path: Path) -> dict[str, int]:
    repo_root = repo_root.resolve()
    if not baseline_path.is_absolute():
        baseline_path = repo_root / baseline_path
    baseline = _load_json(baseline_path)
    required = {
        'min_public_disa_artifacts',
        'min_authoritative_manifests',
        'min_authoritative_rules',
        'min_automated_or_mapped_rules',
        'max_unsupported_rules',
    }
    missing = sorted(required - baseline.keys())
    if missing:
        raise SystemExit(f'{baseline_path}: missing regression floor fields: {missing}')

    metrics = collect_metrics(repo_root)
    failures: list[str] = []
    _check_min(metrics, baseline, 'min_public_disa_artifacts', 'public_disa_artifacts', failures)
    _check_min(metrics, baseline, 'min_authoritative_manifests', 'authoritative_manifests', failures)
    _check_min(metrics, baseline, 'min_authoritative_rules', 'authoritative_rules', failures)
    _check_min(metrics, baseline, 'min_automated_or_mapped_rules', 'automated_or_mapped_rules', failures)
    _check_max(metrics, baseline, 'max_unsupported_rules', 'unsupported_rules', failures)

    if failures:
        details = '\n'.join(f'- {failure}' for failure in failures)
        raise SystemExit(f'DISA corpus regression guard failed:\n{details}')
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo-root', default='.')
    parser.add_argument('--baseline', default=str(DEFAULT_BASELINE))
    parser.add_argument('--json', action='store_true', help='Print collected metrics as JSON')
    args = parser.parse_args()

    metrics = validate(Path(args.repo_root), Path(args.baseline))
    if args.json:
        print(json.dumps(metrics, indent=2, sort_keys=True))
    else:
        print(
            'DISA corpus regression guard passed: '
            f"artifacts={metrics['public_disa_artifacts']} "
            f"manifests={metrics['authoritative_manifests']} "
            f"rules={metrics['authoritative_rules']} "
            f"automated_or_mapped={metrics['automated_or_mapped_rules']} "
            f"unsupported={metrics['unsupported_rules']}"
        )


if __name__ == '__main__':
    main()
