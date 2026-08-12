#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM from locked `cargo metadata` JSON."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import tomllib
import uuid
from pathlib import Path


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def strict_json_loads(raw: str) -> object:
    return json.loads(raw, object_pairs_hook=unique_json_object)


def load_json_file(path: Path, description: str) -> object:
    try:
        return strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"cannot read {description}: {error}") from error


def purl(pkg: dict) -> str:
    name = pkg.get("name", "unknown")
    version = pkg.get("version", "0")
    return f"pkg:cargo/{name}@{version}"


def file_sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def release_bindings(
    equivalence_path: Path | None,
    archive_path: Path | None,
    target: str,
    version: str,
) -> tuple[list[dict], list[dict]]:
    """Bind the SBOM to every executable/tool byte shipped in the product."""
    if (equivalence_path is None) != (archive_path is None):
        raise SystemExit("--equivalence-manifest and --archive must be supplied together")
    if equivalence_path is None or archive_path is None:
        return [], []
    if equivalence_path.is_symlink() or not equivalence_path.is_file():
        raise SystemExit("release equivalence manifest must be a regular nonsymlink file")
    if archive_path.is_symlink() or not archive_path.is_file():
        raise SystemExit("release archive must be a regular nonsymlink file")
    equivalence = load_json_file(
        equivalence_path, "release equivalence manifest"
    )
    archive = equivalence.get("archive") if isinstance(equivalence, dict) else None
    binaries = equivalence.get("binaries") if isinstance(equivalence, dict) else None
    operational_tools = (
        equivalence.get("operational_tools")
        if isinstance(equivalence, dict)
        else None
    )
    if (
        not isinstance(equivalence, dict)
        or equivalence.get("schema")
        != "automatestig-release-artifact-equivalence/v1"
        or equivalence.get("target") != target
        or equivalence.get("version") != version
        or not isinstance(archive, dict)
        or archive.get("name") != archive_path.name
        or archive.get("sha256") != file_sha256(archive_path)
        or archive.get("size") != archive_path.stat().st_size
        or not isinstance(binaries, dict)
        or set(binaries) != {"cli", "gui"}
        or not isinstance(operational_tools, dict)
        or set(operational_tools) != {"backup_restore"}
    ):
        raise SystemExit("release equivalence manifest does not match this SBOM target/archive")
    components = []
    expected_names = {"cli": "automatestig", "gui": "automatestig-gui"}
    for role, name in expected_names.items():
        record = binaries.get(role)
        if (
            not isinstance(record, dict)
            or record.get("name") != name
            or record.get("pre_package_sha256")
            != record.get("archive_member_sha256")
            or not isinstance(record.get("archive_member_sha256"), str)
            or len(record["archive_member_sha256"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in record["archive_member_sha256"]
            )
        ):
            raise SystemExit(f"release equivalence manifest has an invalid {role} binding")
        components.append(
            {
                "type": "application",
                "bom-ref": f"urn:automatestig:release-binary:{target}:{role}",
                "name": name,
                "version": version,
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": record["archive_member_sha256"],
                    }
                ],
                "properties": [
                    {"name": "automatestig:release-role", "value": role},
                    {"name": "automatestig:target", "value": target},
                    {
                        "name": "automatestig:archive-member-size",
                        "value": str(record.get("size")),
                    },
                ],
            }
        )
    backup = operational_tools["backup_restore"]
    if (
        not isinstance(backup, dict)
        or backup.get("name") != "automatestig-backup-restore"
        or backup.get("pre_package_sha256")
        != backup.get("archive_member_sha256")
        or not isinstance(backup.get("archive_member_sha256"), str)
        or len(backup["archive_member_sha256"]) != 64
        or any(
            character not in "0123456789abcdef"
            for character in backup["archive_member_sha256"]
        )
        or not isinstance(backup.get("size"), int)
        or backup["size"] <= 0
    ):
        raise SystemExit(
            "release equivalence manifest has an invalid backup/restore binding"
        )
    components.append(
        {
            "type": "file",
            "bom-ref": f"urn:automatestig:release-tool:{target}:backup_restore",
            "name": backup["name"],
            "version": version,
            "hashes": [
                {
                    "alg": "SHA-256",
                    "content": backup["archive_member_sha256"],
                }
            ],
            "properties": [
                {
                    "name": "automatestig:release-role",
                    "value": "backup_restore",
                },
                {"name": "automatestig:target", "value": target},
                {
                    "name": "automatestig:archive-member-size",
                    "value": str(backup["size"]),
                },
            ],
        }
    )
    properties = [
        {"name": "automatestig:release-archive", "value": archive_path.name},
        {
            "name": "automatestig:release-archive-sha256",
            "value": archive["sha256"],
        },
        {
            "name": "automatestig:binary-equivalence-manifest",
            "value": equivalence_path.name,
        },
        {
            "name": "automatestig:binary-equivalence-manifest-sha256",
            "value": file_sha256(equivalence_path),
        },
        {
            "name": "automatestig:release-scope",
            "value": "analyst-product",
        },
        {
            "name": "automatestig:transition-cli-included",
            "value": "false",
        },
    ]
    return components, properties


def bom_ref(pkg: dict) -> str:
    """Return a stable, collision-resistant reference for one Cargo package."""
    identity = pkg.get("id")
    if not isinstance(identity, str) or not identity:
        raise SystemExit("cargo metadata package is missing its package id")
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"urn:automatestig:cargo-package:{digest}"


def load_locked_checksums(
    metadata: dict, lockfile: Path | None
) -> dict[tuple[str, str, str], str]:
    """Read registry package checksums from the lockfile bound to the metadata."""
    if lockfile is None:
        workspace_root = metadata.get("workspace_root")
        if isinstance(workspace_root, str) and workspace_root:
            lockfile = Path(workspace_root) / "Cargo.lock"
    if lockfile is None or not lockfile.is_file():
        return {}
    try:
        document = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise SystemExit(
            f"cannot read locked Cargo checksums from {lockfile}: {error}"
        ) from error

    checksums = {}
    for package in document.get("package", []):
        checksum = package.get("checksum")
        source = package.get("source")
        if isinstance(checksum, str) and isinstance(source, str):
            key = (package.get("name"), package.get("version"), source)
            checksums[key] = checksum
    return checksums


def component_hashes(
    pkg: dict, locked_checksums: dict[tuple[str, str, str], str]
) -> list[dict]:
    """Expose the registry archive checksum bound by Cargo.lock."""
    checksum = pkg.get("checksum")
    source = pkg.get("source")
    if checksum is None and isinstance(source, str):
        checksum = locked_checksums.get((pkg.get("name"), pkg.get("version"), source))
    if checksum is None:
        if isinstance(source, str) and source.startswith("registry+"):
            raise SystemExit(
                f"locked Cargo checksum is missing for {pkg.get('name')} {pkg.get('version')}"
            )
        return []
    if (
        not isinstance(checksum, str)
        or len(checksum) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in checksum)
    ):
        raise SystemExit(f"cargo metadata contains an invalid checksum for {pkg.get('name')}")
    return [{"alg": "SHA-256", "content": checksum.lower()}]


def source_references(pkg: dict) -> tuple[list[dict], list[dict]]:
    """Preserve the locked Cargo source and human-facing source repository."""
    references = []
    properties = []
    source = pkg.get("source")
    if isinstance(source, str) and source:
        properties.append({"name": "cargo:source", "value": source})
        if "+" in source:
            source_kind, source_url = source.split("+", 1)
            reference_type = "vcs" if source_kind == "git" else "distribution"
            references.append({"type": reference_type, "url": source_url})
    else:
        properties.append({"name": "cargo:source", "value": "workspace-or-path"})

    repository = pkg.get("repository")
    if isinstance(repository, str) and repository:
        candidate = {"type": "vcs", "url": repository}
        if candidate not in references:
            references.append(candidate)
    return references, properties


def package_component(
    pkg: dict, locked_checksums: dict[tuple[str, str, str], str]
) -> dict:
    references, properties = source_references(pkg)
    component = {
        "type": "library",
        "bom-ref": bom_ref(pkg),
        "name": pkg.get("name", "unknown"),
        "version": pkg.get("version", "0"),
        "purl": purl(pkg),
        "properties": properties,
    }
    if pkg.get("license"):
        component["licenses"] = [{"expression": pkg["license"]}]
    hashes = component_hashes(pkg, locked_checksums)
    if hashes:
        component["hashes"] = hashes
    if references:
        component["externalReferences"] = references
    return component


def dependency_graph(metadata: dict, references: dict[str, str]) -> list[dict]:
    """Translate Cargo resolve nodes into CycloneDX dependency relationships."""
    dependencies_by_id = {package_id: set() for package_id in references}
    resolve = metadata.get("resolve")
    nodes = resolve.get("nodes") if isinstance(resolve, dict) else None
    if not isinstance(nodes, list):
        raise SystemExit("cargo metadata does not contain a locked dependency graph")
    node_ids = {
        node.get("id") for node in nodes if isinstance(node, dict) and node.get("id")
    }
    missing_nodes = sorted(set(references) - node_ids)
    if missing_nodes:
        raise SystemExit(
            "cargo metadata dependency graph is missing package nodes: "
            + ", ".join(missing_nodes)
        )
    for node in nodes:
        package_id = node.get("id")
        if package_id not in references:
            continue
        rich_dependencies = node.get("deps")
        if isinstance(rich_dependencies, list):
            dependency_ids = [dependency.get("pkg") for dependency in rich_dependencies]
        else:
            dependency_ids = node.get("dependencies") or []
        dependencies_by_id[package_id].update(
            references[dependency_id]
            for dependency_id in dependency_ids
            if dependency_id in references
        )
    return [
        {
            "ref": references[package_id],
            "dependsOn": sorted(dependencies_by_id[package_id]),
        }
        for package_id in sorted(references, key=lambda item: references[item])
    ]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--metadata", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--target", required=True)
    ap.add_argument("--lockfile", type=Path)
    ap.add_argument("--equivalence-manifest", type=Path)
    ap.add_argument("--archive", type=Path)
    args = ap.parse_args()

    metadata = load_json_file(args.metadata, "Cargo metadata")
    if not isinstance(metadata, dict):
        raise SystemExit("Cargo metadata must contain a JSON object")
    packages = metadata.get("packages", [])
    workspace_members = set(metadata.get("workspace_members", []))
    application = next(
        (
            package
            for package in packages
            if package.get("name") == "automatestig"
            and package.get("id") in workspace_members
        ),
        None,
    )
    if application is None:
        raise SystemExit("cargo metadata does not contain the workspace automatestig package")

    sorted_packages = sorted(
        packages,
        key=lambda package: (
            package.get("name", ""),
            package.get("version", ""),
            package.get("id", ""),
        ),
    )
    locked_checksums = load_locked_checksums(metadata, args.lockfile)
    application_component = package_component(application, locked_checksums)
    application_component["type"] = "application"
    application_component["properties"].append(
        {"name": "target", "value": args.target}
    )
    release_components, release_properties = release_bindings(
        args.equivalence_manifest,
        args.archive,
        args.target,
        application["version"],
    )
    application_component["properties"].extend(release_properties)
    components = [
        package_component(package, locked_checksums)
        for package in sorted_packages
        if package.get("id") != application.get("id")
    ]
    components.extend(release_components)
    references = {package["id"]: bom_ref(package) for package in sorted_packages}
    if len(references) != len(sorted_packages):
        raise SystemExit("cargo metadata contains duplicate package ids")
    dependencies = dependency_graph(metadata, references)
    if release_components:
        application_ref = references[application["id"]]
        application_dependencies = next(
            item for item in dependencies if item["ref"] == application_ref
        )
        application_dependencies["dependsOn"].extend(
            component["bom-ref"] for component in release_components
        )
        application_dependencies["dependsOn"].sort()
        dependencies.extend(
            {"ref": component["bom-ref"], "dependsOn": []}
            for component in release_components
        )
        dependencies.sort(key=lambda item: item["ref"])

    graph_identity = hashlib.sha256(
        json.dumps(
            {
                "application": application_component,
                "components": components,
                "dependencies": dependencies,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"https://github.com/ibadukefan/AutomateSTIG/{application['version']}/{args.target}/{graph_identity}",
    )
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "tools": [
                {
                    "vendor": "AutomateSTIG",
                    "name": "generate-cyclonedx-sbom.py",
                    "version": "2",
                }
            ],
            "component": application_component,
        },
        "components": components,
        "dependencies": dependencies,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bom, indent=2) + "\n")
    print(f"Wrote {args.output} with {len(components)} components")


if __name__ == "__main__":
    main()
