#!/usr/bin/env python3
"""Extract deterministic rule inventory from XCCDF XML or ZIP artifacts."""
from __future__ import annotations
import argparse, json, re, zipfile, xml.etree.ElementTree as ET
from pathlib import Path

def local(tag): return tag.rsplit('}',1)[-1]
def text_of(elem,name):
    for c in list(elem):
        if local(c.tag)==name and c.text: return c.text.strip()
    return ''
def all_text(elem,name):
    vals=[]
    for c in elem.iter():
        if local(c.tag)==name and c.text and c.text.strip(): vals.append(c.text.strip())
    return vals

def read_xml(path, member=None):
    p=Path(path)
    if zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            names=[n for n in z.namelist() if n.lower().endswith(('.xml','.xccdf'))]
            chosen=member or next((n for n in names if 'xccdf' in n.lower() or 'benchmark' in n.lower()), names[0])
            return z.read(chosen), chosen
    return p.read_bytes(), p.name

def extract(path, member=None):
    raw, source_member=read_xml(path, member)
    root=ET.fromstring(raw)
    benchmark_id=root.attrib.get('id','')
    title=text_of(root,'title')
    rules=[]
    for group in root.iter():
        if local(group.tag)!='Group': continue
        group_id=group.attrib.get('id','')
        for rule in list(group):
            if local(rule.tag)!='Rule': continue
            rid=rule.attrib.get('id','')
            stigid=text_of(rule,'version') or group_id
            rules.append({
              'vuln_id': group_id, 'rule_id': rid, 'stigid': stigid, 'title': text_of(rule,'title'),
              'severity': rule.attrib.get('severity',''), 'cci': sorted(set(all_text(rule,'ident'))),
              'check_content': '\n'.join(all_text(rule,'check-content'))[:4000], 'fix_text': '\n'.join(all_text(rule,'fixtext'))[:4000]
            })
    return {'source':str(path),'source_member':source_member,'benchmark_id':benchmark_id,'title':title,'total_rules':len(rules),'rules':rules}

def main(argv=None):
    ap=argparse.ArgumentParser(); ap.add_argument('--artifact',required=True); ap.add_argument('--member'); ap.add_argument('--output',required=True)
    args=ap.parse_args(argv); inv=extract(args.artifact,args.member)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True); Path(args.output).write_text(json.dumps(inv,indent=2,sort_keys=True)+'\n')
    print(f'Extracted {inv["total_rules"]} rules from {inv["source_member"]}')
if __name__=='__main__': main()
