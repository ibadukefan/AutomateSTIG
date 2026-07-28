#!/usr/bin/env python3
"""Run live external acceptance checks for STIG Viewer and STIG Manager.

This script intentionally requires explicit endpoint/tool configuration. It does
not fake live acceptance in CI. Use `--require-live` in a controlled environment
with test/staging systems and non-production credentials.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


def ok(msg: str) -> None:
    print(f'OK: {msg}')


def fail(msg: str) -> None:
    print(f'ERROR: {msg}', file=sys.stderr)
    raise SystemExit(1)


VIEWER_CONFIGURATION = {
    'binary': 'STIG_VIEWER_AUTOMATESTIG_BINARY',
    'ckl_source': 'STIG_VIEWER_CKL_SOURCE',
    'ckl_roundtrip': 'STIG_VIEWER_CKL_ROUNDTRIP',
    'cklb_source': 'STIG_VIEWER_CKLB_SOURCE',
    'cklb_roundtrip': 'STIG_VIEWER_CKLB_ROUNDTRIP',
    'product_version': 'STIG_VIEWER_PRODUCT_VERSION',
    'platform': 'STIG_VIEWER_PLATFORM',
    'operator': 'STIG_VIEWER_OPERATOR',
}


def check_stig_viewer(repo: Path, require: bool) -> bool:
    if os.environ.get('STIG_VIEWER_ACCEPTANCE_EVIDENCE'):
        fail(
            'STIG_VIEWER_ACCEPTANCE_EVIDENCE is no longer trusted; configure the raw '
            'STIG Viewer source/round-trip paths so the hardened verifier runs now'
        )
    configured = {
        argument: os.environ.get(variable)
        for argument, variable in VIEWER_CONFIGURATION.items()
    }
    present = {argument for argument, value in configured.items() if value}
    if not present:
        if require:
            fail(
                'real STIG Viewer acceptance requires: '
                + ', '.join(VIEWER_CONFIGURATION.values())
            )
        print('SKIP: STIG Viewer raw source/round-trip paths are not configured')
        return False
    if len(present) != len(configured):
        missing = [
            variable
            for argument, variable in VIEWER_CONFIGURATION.items()
            if argument not in present
        ]
        fail(f'incomplete STIG Viewer configuration; missing: {", ".join(missing)}')

    configured_output = os.environ.get('STIG_VIEWER_EVIDENCE_OUTPUT')
    with tempfile.TemporaryDirectory(prefix='automatestig-live-viewer-') as temporary:
        output = (
            Path(configured_output)
            if configured_output
            else Path(temporary) / 'evidence.json'
        )
        if not output.is_absolute():
            output = repo / output
        command = [
            sys.executable,
            str(repo / 'scripts/run-stig-viewer-acceptance.py'),
            '--repo-root',
            str(repo),
            '--binary',
            configured['binary'],
            '--ckl-source',
            configured['ckl_source'],
            '--ckl-roundtrip',
            configured['ckl_roundtrip'],
            '--cklb-source',
            configured['cklb_source'],
            '--cklb-roundtrip',
            configured['cklb_roundtrip'],
            '--product-version',
            configured['product_version'],
            '--platform',
            configured['platform'],
            '--operator',
            configured['operator'],
            '--output',
            str(output),
        ]
        try:
            result = subprocess.run(
                command,
                cwd=repo,
                text=True,
                capture_output=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            fail('hardened STIG Viewer acceptance exceeded its five-minute timeout')
        if result.returncode:
            fail(
                'hardened STIG Viewer acceptance failed: '
                + (result.stderr or result.stdout)[-1000:]
            )
        try:
            evidence = json.loads(output.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as exc:
            fail(f'hardened STIG Viewer verifier did not produce valid evidence: {exc}')
        cases = evidence.get('cases') or []
        if evidence.get('passed') is not True or {
            case.get('format')
            for case in cases
            if case.get('status') == 'passed'
        } != {'ckl', 'cklb'}:
            fail('hardened STIG Viewer verifier returned incomplete evidence')
    ok('STIG Viewer GUI preserved exact raw and first-parse CKL/CKLB semantics')
    return True


def check_http_json(name: str, url_env: str, token_env: str, require: bool) -> bool:
    url = os.environ.get(url_env)
    token = os.environ.get(token_env)
    if not url or not token:
        if require:
            fail(f'{name} live acceptance requires {url_env} and {token_env}')
        print(f'SKIP: {name} endpoint/token not configured')
        return False
    endpoint = (
        url.rstrip('/') + '/api/op/definition'
        if name == 'STIG Manager'
        else url.rstrip('/')
    )
    req = urllib.request.Request(endpoint)
    req.add_header('Authorization', f'Bearer {token}')
    req.add_header('Accept', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode('utf-8', 'ignore')
            if resp.status >= 400:
                fail(f'{name} returned HTTP {resp.status}')
            # Do not print response bodies: endpoints can include environment details.
            json.loads(body or '{}') if body.strip().startswith(('{', '[')) else None
            ok(f'{name} endpoint accepted authenticated request')
            return True
    except Exception as exc:
        if require:
            fail(f'{name} live acceptance failed: {exc}')
        print(f'SKIP: {name} live acceptance failed without --require-live: {exc}')
        return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-root', default='.')
    ap.add_argument('--require-live', action='store_true')
    args = ap.parse_args()
    repo = Path(args.repo_root).resolve()
    live = 0
    live += check_stig_viewer(repo, args.require_live)
    live += check_http_json(
        'STIG Manager', 'STIG_MANAGER_URL', 'STIG_MANAGER_TOKEN', args.require_live
    )
    if args.require_live and live < 2:
        fail('not all live external acceptance checks ran')
    print(
        f'Live external acceptance checks completed: '
        f'{live}/2 live integrations exercised'
    )


if __name__ == '__main__':
    main()
