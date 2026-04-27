#!/usr/bin/env python3
"""Validate that DISA coverage rules have implementation specs when required."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ALLOWED={'automated','scanner_import','manual','not_applicable'}
def load_specs(root):
    specs={}
    if not root.exists(): return specs
    for p in root.rglob('*.json'):
        d=json.loads(p.read_text()); key=(d.get('vuln_id'),d.get('rule_id')); specs[key]=p
        if d.get('classification') not in ALLOWED: raise SystemExit(f'{p}: invalid classification {d.get("classification")}')
        for f in d.get('fixtures',[]):
            if f and not Path(f).exists(): raise SystemExit(f'{p}: missing fixture {f}')
    return specs
def main(argv=None):
    ap=argparse.ArgumentParser(); ap.add_argument('--coverage-root',required=True); ap.add_argument('--implementation-root',required=True); ap.add_argument('--require-production',action='store_true')
    args=ap.parse_args(argv); specs=load_specs(Path(args.implementation_root)); missing=[]; unsupported=[]; total=0
    for p in Path(args.coverage_root).rglob('*.json'):
        d=json.loads(p.read_text())
        for r in d.get('rules',[]):
            total+=1
            if r.get('classification')=='unsupported': unsupported.append((p,r.get('vuln_id'),r.get('rule_id')))
            if args.require_production and (r.get('vuln_id'),r.get('rule_id')) not in specs: missing.append((p,r.get('vuln_id'),r.get('rule_id')))
    if args.require_production and (missing or unsupported):
        for item in missing[:20]: print('MISSING_SPEC', *item, file=sys.stderr)
        for item in unsupported[:20]: print('UNSUPPORTED', *item, file=sys.stderr)
        raise SystemExit(f'production validation failed: missing_specs={len(missing)} unsupported={len(unsupported)}')
    print(f'Validated implementation specs={len(specs)} coverage_rules={total} unsupported={len(unsupported)}')
if __name__=='__main__': main()
