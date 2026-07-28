#!/usr/bin/env python3
"""Verify release companions and emit a hash-complete publication manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

TARGETS = {
    "x86_64-unknown-linux-gnu": "tar.gz",
    "aarch64-unknown-linux-gnu": "tar.gz",
    "x86_64-pc-windows-msvc": "zip",
    "x86_64-apple-darwin": "tar.gz",
    "aarch64-apple-darwin": "tar.gz",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def load_json(path: Path, description: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {description} {path.name}: {error}")
    if not isinstance(value, dict):
        fail(f"{description} {path.name} must contain a JSON object")
    return value


def validate_sbom(path: Path, target: str, expected_version: str) -> None:
    sbom = load_json(path, "SBOM")
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        fail(f"{path.name} is not a CycloneDX 1.5 SBOM")
    component = (sbom.get("metadata") or {}).get("component") or {}
    if (
        component.get("name") != "automatestig"
        or component.get("version") != expected_version
    ):
        fail(f"{path.name} does not identify AutomateSTIG {expected_version}")
    properties = component.get("properties") or []
    if not any(
        item.get("name") == "target" and item.get("value") == target
        for item in properties
        if isinstance(item, dict)
    ):
        fail(f"{path.name} is not bound to target {target}")
    if not isinstance(sbom.get("components"), list) or not sbom["components"]:
        fail(f"{path.name} contains no dependency components")


def validate_inventory(path: Path) -> str:
    inventory = load_json(path, "Cargo dependency inventory")
    packages = inventory.get("packages")
    members = set(inventory.get("workspace_members") or [])
    if not isinstance(packages, list) or not packages or not members:
        fail(f"{path.name} has no packages or workspace members")
    application = next(
        (
            package
            for package in packages
            if isinstance(package, dict)
            and package.get("name") == "automatestig"
            and package.get("id") in members
        ),
        None,
    )
    if application is None or not isinstance(application.get("version"), str):
        fail(f"{path.name} does not identify the workspace AutomateSTIG package")
    return application["version"]


def validate_provenance(
    path: Path,
    *,
    package: Path,
    target: str,
    repository: str,
    tag: str,
    commit: str,
    run_id: str,
) -> None:
    provenance = load_json(path, "provenance")
    expected = {
        "artifact": package.name,
        "target": target,
        "repository": repository,
        "ref": f"refs/tags/{tag}",
        "sha": commit,
        "workflow": "CI",
        "run_id": str(run_id),
        "sbom": f"automatestig-{target}.cdx.json",
    }
    mismatches = [name for name, value in expected.items() if provenance.get(name) != value]
    if mismatches:
        fail(f"{path.name} has mismatched release fields: {mismatches}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", args.tag):
        fail("tag is not a semantic version tag")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        fail("commit must be a full lowercase Git SHA")
    version = args.tag[1:].split("+", 1)[0].split("-", 1)[0]

    root = args.artifact_dir.resolve()
    output = args.output.resolve()
    if output.parent != root:
        fail("release manifest output must be a direct child of the artifact directory")
    if output.exists() or output.is_symlink():
        fail("refusing to replace an existing release manifest")

    required_by_target = {}
    expected_files = set()
    for target, extension in TARGETS.items():
        package = root / f"automatestig-{args.tag}-{target}.{extension}"
        required = {
            "archive": package,
            "checksum": Path(f"{package}.sha256"),
            "sigstore_bundle": Path(f"{package}.sigstore.bundle"),
            "sbom": root / f"automatestig-{target}.cdx.json",
            "provenance": root / f"provenance-{target}.json",
            "dependency_inventory": root / f"cargo-metadata-{target}.json",
        }
        required_by_target[target] = required
        expected_files.update(path.name for path in required.values())

    observed = set()
    try:
        entries = list(root.iterdir())
    except OSError as error:
        fail(f"cannot inspect release artifact directory: {error}")
    for path in entries:
        if path.is_symlink() or not path.is_file():
            fail(f"release artifact directory contains a non-regular entry: {path.name}")
        observed.add(path.name)
    if observed != expected_files:
        fail(
            "release artifact set is not closed: "
            f"missing={sorted(expected_files - observed)} "
            f"unexpected={sorted(observed - expected_files)}"
        )

    records = []
    for target, extension in TARGETS.items():
        required = required_by_target[target]
        package = required["archive"]
        missing = [str(path) for path in required.values() if not path.is_file()]
        if missing:
            fail(f"{target} is missing release companions: {missing}")
        archive_digest = digest(package)
        checksum_text = required["checksum"].read_text(encoding="utf-8").strip().split()
        checksum_name = checksum_text[1].lstrip("*") if len(checksum_text) == 2 else ""
        if checksum_text[:1] != [archive_digest] or checksum_name != package.name:
            fail(f"checksum companion does not match {package.name}")
        inventory_version = validate_inventory(required["dependency_inventory"])
        if inventory_version != version:
            fail(
                f"{required['dependency_inventory'].name} version {inventory_version} "
                f"does not match tag {args.tag}"
            )
        validate_sbom(required["sbom"], target, version)
        validate_provenance(
            required["provenance"],
            package=package,
            target=target,
            repository=args.repository,
            tag=args.tag,
            commit=args.commit,
            run_id=str(args.run_id),
        )
        records.append(
            {
                "target": target,
                "files": {
                    role: {"name": path.name, "sha256": digest(path)}
                    for role, path in required.items()
                },
            }
        )
    manifest = {
        "schema": "automatestig-release-manifest/v1",
        "tag": args.tag,
        "repository": args.repository,
        "commit": args.commit,
        "workflow_run_id": str(args.run_id),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "artifacts": records,
    }
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Verified and recorded {len(records)} release targets in {output}")


if __name__ == "__main__":
    main()
