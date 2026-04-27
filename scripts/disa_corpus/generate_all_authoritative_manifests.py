#!/usr/bin/env python3
"""Generate authoritative coverage manifests from a DISA artifact manifest."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_xccdf_inventory import extract

def norm(s): return re.sub(r'[^a-z0-9]+','_',s.lower()).strip('_') or 'unknown'
def load_check_ids(repo):
    ids={}
    for p in (repo/'content/check_packs').glob('*.json'):
        data=json.loads(p.read_text())
        for c in data.get('checks',[]):
            check_id = c.get('id') or c.get('vuln_id') or ''
            if check_id:
                ids.setdefault(check_id, p.stem)
    return ids

def manifest_from_inventory(inv, fixture_path, check_ids):
    rules=[]
    for r in inv['rules']:
        vuln=r['vuln_id']; pack=check_ids.get(vuln)
        if pack:
            cls='automated'; reason='Mapped to existing AutomateSTIG check definition.'; validated=[f'content/check_packs/{pack}.json', fixture_path]
            check_pack=pack; check_id=vuln; issue=''
        else:
            cls='unsupported'; reason='Authoritative DISA rule inventory item pending automation classification and implementation.'; validated=[fixture_path]
            check_pack=''; check_id=''; issue=f'TODO-{vuln}'
        rules.append({'vuln_id':vuln,'rule_id':r['rule_id'],'title':r['title'],'severity':r['severity'],'classification':cls,'reason':reason,'check_pack':check_pack,'check_id':check_id,'evidence_required':True,'validated_by':validated,'tracking_issue':issue})
    stig=inv.get('benchmark_id') or inv.get('title') or 'unknown'
    return {'stig_id':stig,'version':Path(fixture_path).name,'source':'DISA XCCDF benchmark','status':'experimental','total_rules':len(rules),'generated_from':fixture_path,'rules':rules}

def main(argv=None):
    ap=argparse.ArgumentParser(); ap.add_argument('--corpus',required=True); ap.add_argument('--out',required=True); ap.add_argument('--repo-root',default='.')
    args=ap.parse_args(argv); repo=Path(args.repo_root); out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    corpus=json.loads(Path(args.corpus).read_text()); check_ids=load_check_ids(repo); count=0
    for e in corpus.get('fixtures',[]):
        path=e.get('path')
        if not path or not Path(path).exists() or e.get('kind') not in {'manual_stig_zip','scap_benchmark_zip','disa-xccdf'}: continue
        try: inv=extract(path)
        except Exception as ex: print(f'WARN: failed inventory for {path}: {ex}', file=sys.stderr); continue
        if not inv['rules']: continue
        m=manifest_from_inventory(inv, path.replace('\\','/'), check_ids)
        dest=out/norm(m['stig_id'])/(norm(Path(path).stem)+'.json'); dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(json.dumps(m,indent=2,sort_keys=True)+'\n'); count+=1
    print(f'Generated {count} authoritative manifests')
if __name__=='__main__': main()
