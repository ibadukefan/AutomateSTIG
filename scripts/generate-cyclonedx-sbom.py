#!/usr/bin/env python3
"""Generate a minimal CycloneDX 1.5 SBOM from `cargo metadata` JSON."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import uuid
from pathlib import Path


def purl(pkg: dict) -> str:
    name = pkg.get("name", "unknown")
    version = pkg.get("version", "0")
    return f"pkg:cargo/{name}@{version}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--metadata", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--target", required=True)
    args = ap.parse_args()

    metadata = json.loads(args.metadata.read_text())
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

    components = []
    for pkg in sorted(packages, key=lambda p: (p.get("name", ""), p.get("version", ""))):
        component = {
            "type": "library",
            "bom-ref": purl(pkg),
            "name": pkg.get("name", "unknown"),
            "version": pkg.get("version", "0"),
            "purl": purl(pkg),
        }
        if pkg.get("license"):
            component["licenses"] = [{"license": {"id": pkg["license"]}}]
        components.append(component)

    graph_identity = hashlib.sha256(
        json.dumps(
            [(item["name"], item["version"], item["purl"]) for item in components],
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
            "tools": [{"vendor": "AutomateSTIG", "name": "generate-cyclonedx-sbom.py", "version": "1"}],
            "component": {
                "type": "application",
                "name": "automatestig",
                "version": application["version"],
                "purl": purl(application),
                "properties": [{"name": "target", "value": args.target}],
            },
        },
        "components": components,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bom, indent=2) + "\n")
    print(f"Wrote {args.output} with {len(components)} components")


if __name__ == "__main__":
    main()
