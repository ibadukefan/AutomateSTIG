#!/usr/bin/env python3
"""Validate an AutomateSTIG authorized fixture corpus manifest.

This validator is intentionally dependency-free so it can run in disconnected
CI. It verifies that every fixture listed in the manifest exists under the repo
root, stays within the repo root, and matches the recorded SHA-256 digest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REQUIRED_TOP_LEVEL = {"schema_version", "corpus", "status", "fixtures"}
REQUIRED_FIXTURE_FIELDS = {
    "id",
    "kind",
    "path",
    "sha256",
    "source",
    "authorization",
    "classification",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def safe_fixture_path(repo_root: Path, relative: str) -> Path:
    if not relative or relative.strip() != relative:
        fail(f"invalid fixture path spacing: {relative!r}")
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        fail(f"fixture path must be repo-relative and non-traversing: {relative}")
    resolved = (repo_root / rel).resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError:
        fail(f"fixture path escapes repo root: {relative}")
    return resolved


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(manifest_path: Path, repo_root: Path) -> None:
    try:
        manifest = json.loads(manifest_path.read_text())
    except Exception as exc:  # noqa: BLE001 - CLI reports clean error text
        fail(f"failed to parse manifest JSON: {exc}")

    missing = REQUIRED_TOP_LEVEL - set(manifest)
    if missing:
        fail(f"manifest missing required fields: {sorted(missing)}")

    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        fail("manifest fixtures must be a non-empty array")

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for index, fixture in enumerate(fixtures):
        if not isinstance(fixture, dict):
            fail(f"fixtures[{index}] must be an object")
        missing_fixture = REQUIRED_FIXTURE_FIELDS - set(fixture)
        if missing_fixture:
            fail(f"fixtures[{index}] missing fields: {sorted(missing_fixture)}")

        fixture_id = str(fixture["id"]).strip()
        if not fixture_id:
            fail(f"fixtures[{index}].id is blank")
        if fixture_id in seen_ids:
            fail(f"duplicate fixture id: {fixture_id}")
        seen_ids.add(fixture_id)

        rel_path = str(fixture["path"])
        if rel_path in seen_paths:
            fail(f"duplicate fixture path: {rel_path}")
        seen_paths.add(rel_path)

        path = safe_fixture_path(repo_root, rel_path)
        if not path.is_file():
            fail(f"fixture file does not exist: {rel_path}")

        expected = str(fixture["sha256"]).lower()
        if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
            fail(f"fixtures[{index}].sha256 must be lowercase hex SHA-256")
        actual = sha256(path)
        if actual != expected:
            fail(f"sha256 mismatch for {rel_path}: expected {expected}, got {actual}")

    print(f"Validated {len(fixtures)} fixture entries from {manifest_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    validate(args.manifest, args.repo_root)


if __name__ == "__main__":
    main()
