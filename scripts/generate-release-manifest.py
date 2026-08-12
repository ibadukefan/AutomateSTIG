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

# Closed supported-release set. Windows is portability-tested in CI but is not
# accepted into a release manifest until its filesystem custody boundary is
# equivalent to the Unix implementation.
TARGETS = {
    "x86_64-unknown-linux-gnu": "tar.gz",
    "aarch64-unknown-linux-gnu": "tar.gz",
    "x86_64-apple-darwin": "tar.gz",
    "aarch64-apple-darwin": "tar.gz",
}


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def strict_json_loads(raw: str) -> object:
    return json.loads(raw, object_pairs_hook=unique_json_object)


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
        value = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        fail(f"cannot read {description} {path.name}: {error}")
    if not isinstance(value, dict):
        fail(f"{description} {path.name} must contain a JSON object")
    return value


def validate_equivalence(
    path: Path,
    *,
    package: Path,
    target: str,
    expected_version: str,
    commit: str,
) -> dict:
    document = load_json(path, "binary equivalence manifest")
    archive = document.get("archive")
    binaries = document.get("binaries")
    operational_tools = document.get("operational_tools")
    if (
        document.get("schema")
        != "automatestig-release-artifact-equivalence/v1"
        or document.get("target") != target
        or document.get("version") != expected_version
        or document.get("source_commit") != commit
        or not isinstance(archive, dict)
        or archive.get("name") != package.name
        or archive.get("sha256") != digest(package)
        or archive.get("size") != package.stat().st_size
        or archive.get("format") != "tar.gz"
        or not isinstance(binaries, dict)
        or set(binaries) != {"cli", "gui"}
        or not isinstance(operational_tools, dict)
        or set(operational_tools) != {"backup_restore"}
    ):
        fail(f"{path.name} does not bind the expected target/archive")
    expected_names = {"cli": "automatestig", "gui": "automatestig-gui"}
    for role, name in expected_names.items():
        record = binaries.get(role)
        if (
            not isinstance(record, dict)
            or record.get("name") != name
            or record.get("pre_package_sha256")
            != record.get("archive_member_sha256")
            or not isinstance(record.get("archive_member_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["archive_member_sha256"])
            or not isinstance(record.get("size"), int)
            or record["size"] <= 0
        ):
            fail(f"{path.name} has an invalid {role} byte binding")
    backup = operational_tools["backup_restore"]
    if (
        not isinstance(backup, dict)
        or backup.get("name") != "automatestig-backup-restore"
        or backup.get("pre_package_sha256")
        != backup.get("archive_member_sha256")
        or not isinstance(backup.get("archive_member_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", backup["archive_member_sha256"])
        or not isinstance(backup.get("size"), int)
        or backup["size"] <= 0
    ):
        fail(f"{path.name} has an invalid backup/restore byte binding")
    return document


def validate_sbom(
    path: Path,
    target: str,
    expected_version: str,
    package: Path,
    equivalence_path: Path,
    equivalence: dict,
) -> None:
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
    properties_by_name = {
        item.get("name"): item.get("value")
        for item in properties
        if isinstance(item, dict)
    }
    expected_properties = {
        "automatestig:release-archive": package.name,
        "automatestig:release-archive-sha256": digest(package),
        "automatestig:binary-equivalence-manifest": equivalence_path.name,
        "automatestig:binary-equivalence-manifest-sha256": digest(
            equivalence_path
        ),
        "automatestig:release-scope": "analyst-product",
        "automatestig:transition-cli-included": "false",
    }
    if any(
        properties_by_name.get(name) != value
        for name, value in expected_properties.items()
    ):
        fail(f"{path.name} is not byte-bound to the archive/equivalence manifest")
    if not isinstance(sbom.get("components"), list) or not sbom["components"]:
        fail(f"{path.name} contains no dependency components")
    release_components = {
        item.get("bom-ref"): item
        for item in sbom["components"]
        if isinstance(item, dict)
    }
    for role in ("cli", "gui"):
        component = release_components.get(
            f"urn:automatestig:release-binary:{target}:{role}"
        )
        expected_hash = equivalence["binaries"][role]["archive_member_sha256"]
        if (
            not isinstance(component, dict)
            or component.get("version") != expected_version
            or {"alg": "SHA-256", "content": expected_hash}
            not in (component.get("hashes") or [])
        ):
            fail(f"{path.name} does not bind the exact {role} executable")
    recovery = release_components.get(
        f"urn:automatestig:release-tool:{target}:backup_restore"
    )
    expected_recovery_hash = equivalence["operational_tools"]["backup_restore"][
        "archive_member_sha256"
    ]
    if (
        not isinstance(recovery, dict)
        or recovery.get("name") != "automatestig-backup-restore"
        or recovery.get("version") != expected_version
        or {"alg": "SHA-256", "content": expected_recovery_hash}
        not in (recovery.get("hashes") or [])
    ):
        fail(f"{path.name} does not bind the exact backup/restore utility")


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
    equivalence_path: Path,
    equivalence: dict,
    sbom_path: Path,
    inventory_path: Path,
) -> None:
    provenance = load_json(path, "provenance")
    expected = {
        "schema": "automatestig-release-provenance/v1",
        "target": target,
        "version": equivalence["version"],
        "repository": repository,
        "ref": f"refs/tags/{tag}",
        "sha": commit,
        "workflow": "CI",
        "run_id": str(run_id),
    }
    mismatches = [name for name, value in expected.items() if provenance.get(name) != value]
    if mismatches:
        fail(f"{path.name} has mismatched release fields: {mismatches}")
    expected_records = {
        "artifact": {
            "name": package.name,
            "sha256": digest(package),
            "size": package.stat().st_size,
        },
        "binary_equivalence_manifest": {
            "name": equivalence_path.name,
            "sha256": digest(equivalence_path),
        },
        "binaries": {
            role: {
                "name": equivalence["binaries"][role]["name"],
                "sha256": equivalence["binaries"][role][
                    "archive_member_sha256"
                ],
                "size": equivalence["binaries"][role]["size"],
            }
            for role in ("cli", "gui")
        },
        "operational_tools": {
            "backup_restore": {
                "name": equivalence["operational_tools"]["backup_restore"][
                    "name"
                ],
                "sha256": equivalence["operational_tools"]["backup_restore"][
                    "archive_member_sha256"
                ],
                "size": equivalence["operational_tools"]["backup_restore"][
                    "size"
                ],
            }
        },
        "sbom": {"name": sbom_path.name, "sha256": digest(sbom_path)},
        "dependency_inventory": {
            "name": inventory_path.name,
            "sha256": digest(inventory_path),
        },
    }
    mismatched_records = [
        name
        for name, value in expected_records.items()
        if provenance.get(name) != value
    ]
    if mismatched_records:
        fail(
            f"{path.name} has mismatched byte-bound records: "
            f"{mismatched_records}"
        )


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
            "binary_equivalence_manifest": root
            / f"release-equivalence-{target}.json",
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
        equivalence = validate_equivalence(
            required["binary_equivalence_manifest"],
            package=package,
            target=target,
            expected_version=version,
            commit=args.commit,
        )
        validate_sbom(
            required["sbom"],
            target,
            version,
            package,
            required["binary_equivalence_manifest"],
            equivalence,
        )
        validate_provenance(
            required["provenance"],
            package=package,
            target=target,
            repository=args.repository,
            tag=args.tag,
            commit=args.commit,
            run_id=str(args.run_id),
            equivalence_path=required["binary_equivalence_manifest"],
            equivalence=equivalence,
            sbom_path=required["sbom"],
            inventory_path=required["dependency_inventory"],
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
