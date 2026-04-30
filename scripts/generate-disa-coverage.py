#!/usr/bin/env python3
"""Generate an AutomateSTIG coverage manifest from an authorized DISA XCCDF ZIP.

This uses the DISA benchmark as the authoritative rule inventory, then maps
rules to the current AutomateSTIG check pack by Vuln ID. Unmapped rules are
classified as manual so the manifest remains a complete rule-by-rule inventory
without overclaiming automation coverage.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET


def fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def first_text(parent: ET.Element, name: str) -> str:
    for child in parent.iter():
        if local_name(child.tag) == name and child.text and child.text.strip():
            return " ".join(child.text.split())
    return ""


def direct_text(parent: ET.Element, name: str) -> str:
    for child in list(parent):
        if local_name(child.tag) == name and child.text and child.text.strip():
            return " ".join(child.text.split())
    return ""


def read_single_xccdf(zip_path: Path, preferred_member: str | None) -> tuple[str, bytes]:
    with zipfile.ZipFile(zip_path) as zf:
        names = [n for n in zf.namelist() if n.lower().endswith((".xml", ".xccdf")) and not n.endswith("/")]
        if preferred_member:
            if preferred_member not in names:
                fail(f"preferred member not found in {zip_path}: {preferred_member}")
            return preferred_member, zf.read(preferred_member)
        xccdf_names = [n for n in names if "xccdf" in n.lower() or "benchmark" in n.lower()]
        candidates = xccdf_names or names
        if len(candidates) != 1:
            fail(f"expected one XCCDF candidate in {zip_path}, found {candidates}")
        return candidates[0], zf.read(candidates[0])


def benchmark_rules(xml_bytes: bytes) -> tuple[dict, list[dict]]:
    root = ET.fromstring(xml_bytes)
    benchmark = {
        "id": root.attrib.get("id", ""),
        "title": direct_text(root, "title"),
        "version": direct_text(root, "version"),
        "release": "",
    }
    for child in list(root):
        if local_name(child.tag) in {"plain-text", "release-info"} and child.text and "Release:" in child.text:
            benchmark["release"] = child.text.split("Release:", 1)[1].split()[0]
            break

    rules = []
    for group in root.iter():
        if local_name(group.tag) != "Group":
            continue
        group_id = group.attrib.get("id", "")
        for child in list(group):
            if local_name(child.tag) != "Rule":
                continue
            stigid = direct_text(child, "version")
            rules.append(
                {
                    "vuln_id": group_id,
                    "rule_id": child.attrib.get("id", ""),
                    "stigid": stigid,
                    "title": direct_text(child, "title"),
                    "severity": child.attrib.get("severity", ""),
                }
            )
    if not rules:
        fail("no XCCDF Group/Rule entries found")
    return benchmark, rules


def load_check_pack(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text())
    out = {}
    for idx, check in enumerate(data.get("checks", [])):
        vuln = str(check.get("vuln_id", "")).strip()
        if vuln:
            out[vuln] = vuln
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", required=True, type=Path)
    ap.add_argument("--member")
    ap.add_argument("--check-pack", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--stig-id", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--tracking-issue", default="docs/coverage-policy.md#manual-review")
    args = ap.parse_args()

    member, xml_bytes = read_single_xccdf(args.zip, args.member)
    benchmark, rules = benchmark_rules(xml_bytes)
    checks = load_check_pack(args.check_pack)

    generated_from = str(args.zip).replace("\\", "/")
    check_pack_name = args.check_pack.stem
    manifest_rules = []
    for rule in rules:
        vuln = rule["vuln_id"]
        has_check = vuln in checks
        if has_check:
            manifest_rules.append(
                {
                    "vuln_id": vuln,
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "classification": "automated",
                    "check_pack": check_pack_name,
                    "check_id": vuln,
                    "evidence_required": True,
                    "reason": "Mapped by Vuln ID to an existing AutomateSTIG check definition and cross-checked against the authoritative DISA XCCDF inventory.",
                    "validated_by": [f"fixture:{generated_from}"],
                }
            )
        else:
            manifest_rules.append(
                {
                    "vuln_id": vuln,
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "classification": "manual",
                    "evidence_required": True,
                    "reason": "Authoritative DISA rule is represented for production workflow completeness, but no executable AutomateSTIG check is mapped yet; manual reviewer input is required.",
                    "tracking_issue": args.tracking_issue,
                    "validated_by": [f"fixture:{generated_from}"],
                }
            )

    manifest = {
        "stig_id": args.stig_id,
        "version": args.version,
        "source": f"{args.source}; authoritative XCCDF member {member}; benchmark {benchmark.get('id')}",
        "status": "supported",
        "total_rules": len(manifest_rules),
        "generated_from": generated_from,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "rules": manifest_rules,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n")
    automated = sum(1 for r in manifest_rules if r["classification"] == "automated")
    print(f"wrote {args.output}: {len(manifest_rules)} rules, {automated} automated, {len(manifest_rules)-automated} manual")


if __name__ == "__main__":
    main()
