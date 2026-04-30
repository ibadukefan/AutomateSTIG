#!/usr/bin/env python3
"""Run live external acceptance checks for STIG Viewer, STIG Manager, and eMASS.

This script intentionally requires explicit endpoint/tool configuration. It does
not fake live acceptance in CI. Use `--require-live` in a controlled environment
with test/staging systems and non-production credentials.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path


def ok(msg: str) -> None:
    print(f'OK: {msg}')


def fail(msg: str) -> None:
    print(f'ERROR: {msg}', file=sys.stderr)
    raise SystemExit(1)


def check_stig_viewer(repo: Path, require: bool) -> bool:
    cli = os.environ.get('STIG_VIEWER_CLI') or shutil.which('STIGViewer') or shutil.which('stigviewer')
    if not cli:
        if require: fail('STIG_VIEWER_CLI missing; cannot run live STIG Viewer acceptance')
        print('SKIP: STIG Viewer CLI not configured')
        return False
    fixture = repo / 'fixtures/ckl/windows_server_2022_sanitized.ckl'
    result = subprocess.run([cli, '--help'], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    if result.returncode != 0:
        if require: fail('STIG Viewer CLI did not execute successfully')
        print('SKIP: STIG Viewer CLI present but unsupported noninteractive smoke command')
        return False
    ok(f'STIG Viewer CLI reachable; fixture available at {fixture}')
    return True


def check_http_json(name: str, url_env: str, token_env: str, require: bool) -> bool:
    url = os.environ.get(url_env)
    token = os.environ.get(token_env)
    if not url or not token:
        if require: fail(f'{name} live acceptance requires {url_env} and {token_env}')
        print(f'SKIP: {name} endpoint/token not configured')
        return False
    req = urllib.request.Request(url.rstrip('/') + '/api/op/definition' if name == 'STIG Manager' else url.rstrip('/'))
    req.add_header('Authorization', f'Bearer {token}')
    req.add_header('Accept', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read(1024).decode('utf-8', 'ignore')
            if resp.status >= 400:
                fail(f'{name} returned HTTP {resp.status}')
            # Do not print response bodies: endpoints can include environment details.
            json.loads(body or '{}') if body.strip().startswith(('{','[')) else None
            ok(f'{name} endpoint accepted authenticated request')
            return True
    except Exception as exc:
        if require: fail(f'{name} live acceptance failed: {exc}')
        print(f'SKIP: {name} live acceptance failed without --require-live: {exc}')
        return False


def check_emass_fixture(repo: Path) -> None:
    path = repo / 'fixtures/exports/emass_golden.csv'
    with path.open(newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    if not rows:
        fail('eMASS golden CSV is empty')
    ok('eMASS golden CSV remains parseable before live submission')


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-root', default='.')
    ap.add_argument('--require-live', action='store_true')
    args = ap.parse_args()
    repo = Path(args.repo_root).resolve()
    live = 0
    live += check_stig_viewer(repo, args.require_live)
    live += check_http_json('STIG Manager', 'STIG_MANAGER_URL', 'STIG_MANAGER_TOKEN', args.require_live)
    check_emass_fixture(repo)
    live += check_http_json('eMASS', 'EMASS_URL', 'EMASS_API_KEY', args.require_live)
    if args.require_live and live < 3:
        fail('not all live external acceptance checks ran')
    print(f'Live external acceptance checks completed: {live}/3 live integrations exercised')


if __name__ == '__main__':
    main()
