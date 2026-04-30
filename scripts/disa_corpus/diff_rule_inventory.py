#!/usr/bin/env python3
"""Diff two coverage/rule inventory manifests by vuln_id/rule_id."""
from __future__ import annotations
import argparse
import json
from pathlib import Path


def rules(path: str):
    data = json.loads(Path(path).read_text())
    return {(rule.get('vuln_id'), rule.get('rule_id')): rule for rule in data.get('rules', [])}


def main(argv=None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--old', required=True)
    parser.add_argument('--new', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)

    old_rules = rules(args.old)
    new_rules = rules(args.new)
    added = sorted(
        [{'vuln_id': key[0], 'rule_id': key[1]} for key in new_rules.keys() - old_rules.keys()],
        key=lambda item: (item['vuln_id'] or '', item['rule_id'] or ''),
    )
    removed = sorted(
        [{'vuln_id': key[0], 'rule_id': key[1]} for key in old_rules.keys() - new_rules.keys()],
        key=lambda item: (item['vuln_id'] or '', item['rule_id'] or ''),
    )
    changed = []
    for key in old_rules.keys() & new_rules.keys():
        old_projection = {field: old_rules[key].get(field) for field in ['title', 'severity', 'classification']}
        new_projection = {field: new_rules[key].get(field) for field in ['title', 'severity', 'classification']}
        if old_projection != new_projection:
            changed.append({'vuln_id': key[0], 'rule_id': key[1]})
    out = {'added': added, 'removed': removed, 'changed': changed, 'summary': {'added': len(added), 'removed': len(removed), 'changed': len(changed)}}
    Path(args.output).write_text(json.dumps(out, indent=2, sort_keys=True) + '\n')
    print(json.dumps(out['summary'], sort_keys=True))


if __name__ == '__main__':
    main()
