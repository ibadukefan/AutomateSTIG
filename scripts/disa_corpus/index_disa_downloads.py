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
DATA_LINK_RE=re.compile(r'data-link=["\']([^"\']+?\.zip)["\']', re.I)
TITLE_RE=re.compile(r'title=["\']([^"\']+)["\']', re.I)
ARIA_LABEL_RE=re.compile(r'aria-label=["\'](?:Download\s+)?([^"\']+)["\']', re.I)
SEED_DOWNLOADS=[
 {'title':'Microsoft Windows Server 2022 STIG V2R8','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R8_STIG.zip'},
 {'title':'Microsoft Windows Server 2022 STIG SCAP 1.3 Benchmark V2R8','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R8_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Microsoft Windows Server 2019 STIG V3R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2019_V3R4_STIG.zip'},
 {'title':'Microsoft Windows Server 2019 STIG SCAP 1.3 Benchmark V3R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2019_V3R4_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Microsoft Windows 11 STIG V2R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R4_STIG.zip'},
 {'title':'Microsoft Windows 11 STIG SCAP 1.3 Benchmark V2R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R4_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Microsoft Windows 10 STIG V3R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_10_V3R4_STIG.zip'},
 {'title':'Microsoft Windows 10 STIG SCAP 1.3 Benchmark V3R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_10_V3R4_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Red Hat Enterprise Linux 7 STIG V3R15','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_7_V3R15_STIG.zip'},
 {'title':'Red Hat Enterprise Linux 7 STIG SCAP 1.3 Benchmark V3R15','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_7_V3R15_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Red Hat Enterprise Linux 8 STIG V2R7','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V2R7_STIG.zip'},
 {'title':'Red Hat Enterprise Linux 8 STIG SCAP 1.3 Benchmark V2R7','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V2R7_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Red Hat Enterprise Linux 9 STIG V2R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R4_STIG.zip'},
 {'title':'Red Hat Enterprise Linux 9 STIG SCAP 1.3 Benchmark V2R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R4_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Canonical Ubuntu 20.04 LTS STIG V2R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_20-04_LTS_V2R4_STIG.zip'},
 {'title':'Canonical Ubuntu 20.04 LTS STIG SCAP 1.3 Benchmark V2R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_20-04_LTS_V2R4_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Canonical Ubuntu 24.04 LTS STIG V1R1','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_24-04_LTS_V1R1_STIG.zip'},
 {'title':'Canonical Ubuntu 24.04 LTS STIG SCAP 1.3 Benchmark V1R1','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_24-04_LTS_V1R1_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Oracle Linux 8 STIG V2R5','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Oracle_Linux_8_V2R5_STIG.zip'},
 {'title':'Oracle Linux 8 STIG SCAP 1.3 Benchmark V2R5','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Oracle_Linux_8_V2R5_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Google Chrome STIG V2R11','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Google_Chrome_V2R11_STIG.zip'},
 {'title':'Google Chrome STIG SCAP 1.3 Benchmark V2R11','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Google_Chrome_V2R11_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Canonical Ubuntu 22.04 LTS STIG V2R6','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R6_STIG.zip'},
 {'title':'Canonical Ubuntu 22.04 LTS STIG SCAP 1.3 Benchmark V2R6','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R6_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Oracle Linux 9 STIG V1R3','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Oracle_Linux_9_V1R3_STIG.zip'},
 {'title':'Oracle Linux 9 STIG SCAP 1.3 Benchmark V1R3','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Oracle_Linux_9_V1R3_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Microsoft Edge STIG V2R5','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Edge_V2R5_STIG.zip'},
 {'title':'Microsoft Edge STIG SCAP 1.3 Benchmark V2R5','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Edge_V2R5_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Cisco NX OS Switch STIG Y26M04','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Cisco_NX-OS_Switch_Y26M04_STIG.zip'},
 {'title':'Apache Server 2.4 Windows STIG Y26M04','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Apache_Server_2-4_Windows_Y26M04_STIG.zip'},
 {'title':'Apache Tomcat Application Server 9 STIG V3R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Apache_Tomcat_Application_Server_9_V3R4_STIG.zip'},
 {'title':'Apple macOS 15 STIG V1R7','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Apple_macOS_15_V1R7_STIG.zip'},
 {'title':'Microsoft Windows Server 2025 STIG V1R1','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2025_V1R1_STIG.zip'},
 {'title':'Microsoft SQL Server 2022 STIG Y26M04','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_SQL_Server_2022_Y26M04_STIG.zip'},
 {'title':'Microsoft IIS 10.0 STIG Y26M04','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_IIS_10-0_Y26M04_STIG.zip'},
 {'title':'Microsoft Office 365 ProPlus STIG V3R5','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Office_365_ProPlus_V3R5_STIG.zip'},
 {'title':'Microsoft Office 365 ProPlus STIG SCAP 1.3 Benchmark V3R8','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Office_365_ProPlus_V3R8_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Mozilla Firefox STIG V6R7','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MOZ_Firefox_V6R7_STIG.zip'},
 {'title':'Mozilla Firefox for Windows STIG SCAP 1.3 Benchmark V6R7','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MOZ_Firefox_Windows_V6R7_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Mozilla Firefox for Linux STIG SCAP 1.3 Benchmark V6R6','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MOZ_Firefox_Linux_V6R6_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Adobe Acrobat Professional DC Continuous Track STIG V2R1','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Adobe_Acrobat_Pro_DC_Continuous_V2R1_STIG.zip'},
 {'title':'Adobe Acrobat Professional DC Continuous Track STIG SCAP 1.3 Benchmark V2R1','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Adobe_Acrobat_Pro_DC_Continuous_V2R1_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'Adobe Acrobat Reader DC Continuous Track STIG V2R1','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Adobe_Acrobat_Reader_DC_Continuous_V2R1_STIG.zip'},
 {'title':'Adobe Acrobat Reader DC Continuous Track STIG SCAP 1.3 Benchmark V2R4','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Adobe_Acrobat_Reader_DC_Continuous_V2R4_STIG_SCAP_1-3_Benchmark.zip'},
 {'title':'SUSE Linux Enterprise Server 15 STIG V2R7','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SLES_15_V2R7_STIG.zip'},
 {'title':'SUSE Linux Enterprise Server 15 STIG SCAP 1.3 Benchmark V2R8','url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SLES_15_V2R8_STIG_SCAP_1-3_Benchmark.zip'},
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
    seen=set()
    for m in DATA_LINK_RE.finditer(html):
        url=urljoin(base_url, unescape(m.group(1)))
        window=html[max(0,m.start()-300):m.end()+300]
        tm=ARIA_LABEL_RE.search(window) or TITLE_RE.search(window)
        title=unescape(tm.group(1)) if tm else Path(url).name.replace('_',' ')
        out.append({'title':title,'url':url})
        seen.add(url)
    for m in ZIP_RE.finditer(html):
        raw=m.group(1) or m.group(0)
        raw=raw.replace('href=','').strip('"\' ')
        url=urljoin(base_url, unescape(raw))
        if url in seen:
            continue
        window=html[max(0,m.start()-300):m.end()+300]
        tm=TITLE_RE.search(window) or ARIA_LABEL_RE.search(window)
        title=unescape(tm.group(1)) if tm else Path(url).name.replace('_',' ')
        out.append({'title':title,'url':url})
        seen.add(url)
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
