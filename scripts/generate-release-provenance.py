#!/usr/bin/env python3
"""Generate provenance that byte-binds one archive, its binaries, SBOM, and inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path


SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def strict_json_loads(raw: str) -> object:
    return json.loads(raw, object_pairs_hook=unique_json_object)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def regular(path: Path, description: str) -> Path:
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
        raise ValueError(f"{description} must be a non-empty regular nonsymlink file")
    return path.resolve()


def load_equivalence(path: Path) -> dict:
    document = strict_json_loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or document.get("schema") != "automatestig-release-artifact-equivalence/v1"
        or not isinstance(document.get("archive"), dict)
        or not isinstance(document.get("binaries"), dict)
        or not isinstance(document.get("operational_tools"), dict)
    ):
        raise ValueError("equivalence manifest is invalid")
    return document


def generate(
    *,
    archive: Path,
    equivalence_manifest: Path,
    sbom: Path,
    inventory: Path,
    target: str,
    repository: str,
    ref: str,
    commit: str,
    workflow: str,
    run_id: str,
    run_attempt: str,
    output: Path,
) -> dict:
    archive = regular(archive, "release archive")
    equivalence_manifest = regular(equivalence_manifest, "equivalence manifest")
    sbom = regular(sbom, "SBOM")
    inventory = regular(inventory, "dependency inventory")
    equivalence = load_equivalence(equivalence_manifest)
    archive_record = equivalence["archive"]
    if (
        equivalence.get("target") != target
        or equivalence.get("source_commit") != commit
        or archive_record.get("name") != archive.name
        or archive_record.get("sha256") != digest(archive)
        or archive_record.get("size") != archive.stat().st_size
    ):
        raise ValueError("archive/equivalence provenance inputs do not agree")
    if not GIT_SHA.fullmatch(commit):
        raise ValueError("commit must be a full lowercase Git SHA")
    for label, value in {
        "repository": repository,
        "ref": ref,
        "workflow": workflow,
        "run_id": run_id,
        "run_attempt": run_attempt,
    }.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} is required")
    binaries = {}
    for role in ("cli", "gui"):
        record = equivalence["binaries"].get(role)
        if (
            not isinstance(record, dict)
            or record.get("pre_package_sha256") != record.get("archive_member_sha256")
            or not isinstance(record.get("archive_member_sha256"), str)
            or not SHA256.fullmatch(record["archive_member_sha256"])
        ):
            raise ValueError(f"equivalence manifest {role} binding is invalid")
        binaries[role] = {
            "name": record.get("name"),
            "sha256": record["archive_member_sha256"],
            "size": record.get("size"),
        }
    tools = {}
    for role, record in equivalence["operational_tools"].items():
        if (
            role != "backup_restore"
            or not isinstance(record, dict)
            or record.get("name") != "automatestig-backup-restore"
            or record.get("pre_package_sha256")
            != record.get("archive_member_sha256")
            or not isinstance(record.get("archive_member_sha256"), str)
            or not SHA256.fullmatch(record["archive_member_sha256"])
        ):
            raise ValueError("equivalence manifest backup/restore binding is invalid")
        tools[role] = {
            "name": record["name"],
            "sha256": record["archive_member_sha256"],
            "size": record.get("size"),
        }
    if set(tools) != {"backup_restore"}:
        raise ValueError("equivalence manifest must bind the backup/restore utility")
    document = {
        "schema": "automatestig-release-provenance/v1",
        "target": target,
        "version": equivalence.get("version"),
        "repository": repository,
        "ref": ref,
        "sha": commit,
        "workflow": workflow,
        "run_id": str(run_id),
        "run_attempt": str(run_attempt),
        "artifact": {
            "name": archive.name,
            "sha256": digest(archive),
            "size": archive.stat().st_size,
        },
        "binary_equivalence_manifest": {
            "name": equivalence_manifest.name,
            "sha256": digest(equivalence_manifest),
        },
        "binaries": binaries,
        "operational_tools": tools,
        "sbom": {"name": sbom.name, "sha256": digest(sbom)},
        "dependency_inventory": {
            "name": inventory.name,
            "sha256": digest(inventory),
        },
    }
    if output.exists() or output.is_symlink():
        raise ValueError(f"refusing to replace existing provenance: {output}")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--equivalence-manifest", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        document = generate(
            archive=args.archive,
            equivalence_manifest=args.equivalence_manifest,
            sbom=args.sbom,
            inventory=args.inventory,
            target=args.target,
            repository=args.repository,
            ref=args.ref,
            commit=args.commit,
            workflow=args.workflow,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            output=args.output,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(
        f"Bound {document['artifact']['name']} and both binaries into release provenance"
    )


if __name__ == "__main__":
    main()
