#!/usr/bin/env python3
"""Compare a fresh DISA download index with a checked-in baseline."""
from __future__ import annotations
import argparse, json
from pathlib import Path


def urls(path: str) -> set[str]:
    data = json.loads(Path(path).read_text())
    return {item['url'] for item in data.get('downloads', [])}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--current', required=True)
    parser.add_argument('--allow-new', action='store_true')
    args = parser.parse_args()
    baseline = urls(args.baseline)
    current = urls(args.current)
    added = sorted(current - baseline)
    removed = sorted(baseline - current)
    print(json.dumps({'added': added, 'removed': removed, 'summary': {'added': len(added), 'removed': len(removed)}}, indent=2))
    if (added or removed) and not args.allow_new:
        raise SystemExit('DISA corpus index drift detected')


if __name__ == '__main__':
    main()
