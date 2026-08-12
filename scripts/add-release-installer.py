#!/usr/bin/env python3
"""Validate and append the tag-bound installer to a generated release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def load_unique_json(path: Path) -> dict:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member: {key}")
            result[key] = value
        return result

    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        fail(f"cannot read release manifest: {error}")
    if not isinstance(document, dict):
        fail("release manifest must contain a JSON object")
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()

    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", args.tag):
        fail("tag is not a semantic version tag")

    root = args.artifact_dir.resolve()
    manifest_path = args.manifest.resolve()
    if manifest_path.parent != root:
        fail("release manifest must be a direct child of the artifact directory")

    document = load_unique_json(manifest_path)
    if (
        document.get("schema") != "automatestig-release-manifest/v1"
        or document.get("tag") != args.tag
        or not isinstance(document.get("artifacts"), list)
        or "installer" in document
    ):
        fail("release manifest is not the expected unextended tag manifest")

    required = {
        "script": root / "install.sh",
        "checksum": root / "install.sh.sha256",
        "sigstore_bundle": root / "install.sh.sigstore.bundle",
    }
    for role, path in required.items():
        if path.is_symlink() or not path.is_file():
            fail(f"installer {role} is missing or not a regular file: {path.name}")

    script = required["script"].read_text(encoding="utf-8")
    expected_binding = f'SCRIPT_RELEASE_TAG="{args.tag}"'
    if expected_binding not in script or "@AUTOMATESTIG_RELEASE_TAG@" in script:
        fail("installer is not bound exclusively to the release tag")

    checksum_fields = required["checksum"].read_text(encoding="utf-8").strip().split()
    script_digest = digest(required["script"])
    if checksum_fields != [script_digest, "install.sh"]:
        fail("installer checksum does not bind install.sh")

    document["installer"] = {
        role: {"name": path.name, "sha256": digest(path)}
        for role, path in required.items()
    }
    manifest_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Validated and recorded tag-bound installer for {args.tag}")


if __name__ == "__main__":
    main()
