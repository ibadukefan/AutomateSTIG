#!/usr/bin/env python3
"""Generate a minimal CycloneDX 1.5 SBOM from `cargo metadata` JSON."""
from __future__ import annotations

import argparse
import datetime as dt
import json
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
    components = []
    for pkg in sorted(metadata.get("packages", []), key=lambda p: (p.get("name", ""), p.get("version", ""))):
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

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "tools": [{"vendor": "AutomateSTIG", "name": "generate-cyclonedx-sbom.py", "version": "1"}],
            "component": {"type": "application", "name": "automatestig", "version": "0.1.0", "properties": [{"name": "target", "value": args.target}]},
        },
        "components": components,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bom, indent=2) + "\n")
    print(f"Wrote {args.output} with {len(components)} components")


if __name__ == "__main__":
    main()
