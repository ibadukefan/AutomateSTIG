#!/usr/bin/env python3
"""Index public DISA Cyber Exchange STIG downloads.

The Cyber Exchange download page is partly dynamic. This script supports two
inputs:
1. fetching/parsing static HTML when links are present;
2. a repository seed list of known public DISA URLs so CI remains deterministic.
"""
from __future__ import annotations
import argparse, datetime as dt, json, re, sys, urllib.request
from html import unescape
from pathlib import Path
from urllib.parse import urljoin

DEFAULT_SOURCE='https://public.cyber.mil/stigs/downloads/'
ZIP_RE=re.compile(r'https?://[^\s"\']+?\.zip|href=["\']([^"\']+?\.zip)["\']', re.I)
TITLE_RE=re.compile(r'title=["\']([^"\']+)["\']', re.I)
SEED_DOWNLOADS=[
 {'title':'Microsoft Windows Server 2022 STIG V2R8','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R8_STIG.zip'},
 {'title':'Microsoft Windows Server 2022 STIG SCAP 1.3 Benchmark V2R8','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R8_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Microsoft Windows Server 2019 STIG V3R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2019_V3R4_STIG.zip'},
 {'title':'Microsoft Windows Server 2019 STIG SCAP 1.3 Benchmark V3R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2019_V3R4_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Microsoft Windows 11 STIG V2R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R4_STIG.zip'},
 {'title':'Microsoft Windows 11 STIG SCAP 1.3 Benchmark V2R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R4_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Red Hat Enterprise Linux 8 STIG V2R7','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V2R7_STIG.zip'},
 {'title':'Red Hat Enterprise Linux 8 STIG SCAP 1.3 Benchmark V2R7','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V2R7_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Red Hat Enterprise Linux 9 STIG V2R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R4_STIG.zip'},
 {'title':'Red Hat Enterprise Linux 9 STIG SCAP 1.3 Benchmark V2R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R4_STIG_SCAP_1-3_Benchmark.zip'},
]

def classify(title,url):
    text=(title+' '+url).lower()
    if 'scap' in text or 'benchmark' in text: return 'scap_benchmark_zip'
    if 'stig' in text and url.lower().endswith('.zip'): return 'manual_stig_zip'
    if 'scc' in text: return 'scc_content'
    return 'other'

def release_from(text):
    m=re.search(r'V\d+R\d+', text, re.I)
    return m.group(0).upper() if m else ''

def platform_from(title):
    t=re.sub(r'\b(STIG|SCAP|Benchmark|ZIP|V\d+R\d+)\b',' ',title,flags=re.I)
    return re.sub(r'\s+',' ',t).strip()

def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read().decode('utf-8','replace')

def parse_html(html, base_url):
    out=[]
    for m in ZIP_RE.finditer(html):
        raw=m.group(1) or m.group(0)
        raw=raw.replace('href=','').strip('"\' ')
        url=urljoin(base_url, unescape(raw))
        window=html[max(0,m.start()-300):m.end()+300]
        tm=TITLE_RE.search(window)
        title=unescape(tm.group(1)) if tm else Path(url).name.replace('_',' ')
        out.append({'title':title,'url':url})
    return out

def normalize(items):
    seen={}
    for item in items:
        url=item['url'].strip()
        title=item.get('title') or Path(url).name
        seen[url]={
          'title': title,
          'url': url,
          'artifact_type': classify(title,url),
          'release': release_from(title+' '+url),
          'platform': platform_from(title),
          'category': 'stig'
        }
    return sorted(seen.values(), key=lambda x:(x['platform'].lower(), x['artifact_type'], x['url']))

def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('--source', default=DEFAULT_SOURCE)
    ap.add_argument('--output', required=True)
    ap.add_argument('--seed-only', action='store_true')
    args=ap.parse_args(argv)
    items=list(SEED_DOWNLOADS)
    if not args.seed_only:
        try: items.extend(parse_html(fetch(args.source), args.source))
        except Exception as e: print(f'WARN: failed to fetch {args.source}: {e}', file=sys.stderr)
    data={'generated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'source':args.source,'downloads':normalize(items)}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(data, indent=2, sort_keys=True)+'\n')
    print(f'Indexed {len(data["downloads"])} DISA downloads')
if __name__=='__main__': main()
