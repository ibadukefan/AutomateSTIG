#!/usr/bin/env python3
"""Validate every coverage manifest in the repository."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-root', default='.')
    args = ap.parse_args()
    repo = Path(args.repo_root).resolve()
    manifests = sorted((repo / 'content/coverage').glob('**/*.json'))
    if not manifests:
        raise SystemExit('No coverage manifests found')
    failures = []
    for manifest in manifests:
        rel = manifest.relative_to(repo)
        result = subprocess.run(
            ['cargo', 'run', '-q', '-p', 'automatestig', '--', 'coverage', 'validate', '--manifest', str(rel)],
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if result.returncode != 0:
            failures.append((str(rel), result.stdout))
        else:
            print(f'validated {rel}')
    if failures:
        for rel, output in failures:
            print(f'FAILED {rel}\n{output}', file=sys.stderr)
        raise SystemExit(1)
    print(f'Validated {len(manifests)} coverage manifests')


if __name__ == '__main__':
    main()
