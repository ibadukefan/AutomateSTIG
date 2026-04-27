#!/usr/bin/env python3
"""Fetch or metadata-track authorized DISA artifacts from a download index."""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, urllib.request
from pathlib import Path
from urllib.parse import urlparse

def safe_name(url):
    name=Path(urlparse(url).path).name
    if not name or name in {'.','..'} or '/' in name or '\\' in name or '\x00' in name: raise ValueError(f'unsafe artifact filename: {name!r}')
    if not name.lower().endswith('.zip'): raise ValueError(f'unexpected artifact type: {name}')
    return name

def sha256_bytes(b): return hashlib.sha256(b).hexdigest()
def head_or_get(url):
    req=urllib.request.Request(url, method='HEAD')
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return int(r.headers.get('content-length') or 0), None
    except Exception: return 0, None

def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('--index', required=True)
    ap.add_argument('--output', required=True)
    ap.add_argument('--cache-dir', default='content/disa-corpus/artifacts')
    ap.add_argument('--metadata-only', action='store_true')
    args=ap.parse_args(argv)
    index=json.loads(Path(args.index).read_text())
    entries=[]
    for d in index.get('downloads',[]):
        url=d['url']; name=safe_name(url)
        size=0; sha='metadata-only'
        path=''
        if args.metadata_only:
            size,_=head_or_get(url)
        else:
            with urllib.request.urlopen(url, timeout=120) as r: data=r.read()
            sha=sha256_bytes(data); size=len(data)
            dest=Path(args.cache_dir)/sha/name; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(data); path=str(dest)
        entries.append({
          'id': name.rsplit('.',1)[0], 'kind': d.get('artifact_type','other'), 'path': path,
          'sha256': sha, 'size_bytes': size, 'source': url, 'authorization': 'public DISA Cyber Exchange download metadata',
          'classification': 'public', 'retrieved_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'notes': d.get('title','')
        })
    out={'version':1,'generated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'fixtures':entries}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, indent=2, sort_keys=True)+'\n')
    print(f'Wrote {len(entries)} artifact metadata entries')
if __name__=='__main__': main()
