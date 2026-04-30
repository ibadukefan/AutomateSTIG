#!/usr/bin/env python3
"""Validate external workflow acceptance fixtures without external credentials.

This is an offline contract harness for artifacts exchanged with STIG Viewer,
STIG Manager, and eMASS. It deliberately does not assert that a remote service
accepted the payload unless an operator supplies an endpoint/token in a private
run. CI uses the offline mode to prevent payload/schema drift.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_ckl(path: Path) -> None:
    root = ET.parse(path).getroot()
    if root.tag != "CHECKLIST":
        fail(f"{path} is not a STIG Viewer CKL CHECKLIST document")
    if root.find("STIGS/iSTIG") is None:
        fail(f"{path} does not contain STIGS/iSTIG")
    vulns = root.findall(".//VULN")
    if not vulns:
        fail(f"{path} contains no VULN entries")


def validate_cklb(path: Path) -> None:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        fail(f"{path} is not a CKLB JSON object")
    stigs = data.get("stigs") or data.get("STIGS")
    if not stigs:
        fail(f"{path} contains no stigs collection")
    text = json.dumps(data)
    if "V-" not in text or "SV-" not in text:
        fail(f"{path} does not include Vuln/Rule identifiers")


def validate_stig_manager(path: Path) -> None:
    data = json.loads(path.read_text())
    for key in ["collection", "assets"]:
        if key not in data:
            fail(f"{path} missing STIG Manager key: {key}")
    if not isinstance(data["assets"], list) or not data["assets"]:
        fail(f"{path} contains no STIG Manager assets")
    stigs = data["assets"][0].get("stigs") or []
    if not stigs:
        fail(f"{path} contains no asset STIG assignments")
    reviews = stigs[0].get("reviews") or []
    if not reviews:
        fail(f"{path} contains no STIG Manager reviews")
    required_review_keys = {"ruleId", "result", "detail", "comment"}
    missing = required_review_keys - set(reviews[0])
    if missing:
        fail(f"{path} STIG Manager review missing keys: {sorted(missing)}")


def validate_emass(path: Path) -> None:
    with path.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        fail(f"{path} contains no eMASS rows")
    normalized = {column.lower().strip(): column for column in rows[0]}
    required = {"cci", "result", "result comment", "stig reference", "severity", "system name", "assessment date"}
    missing = required - set(normalized)
    if missing:
        fail(f"{path} eMASS CSV missing columns: {sorted(missing)}")


def validate_disa_zip(path: Path) -> None:
    with zipfile.ZipFile(path) as zf:
        xml_members = [n for n in zf.namelist() if n.lower().endswith(".xml")]
        if not xml_members:
            fail(f"{path} contains no XCCDF/XML member")
        # Parse at least one XML member to catch corrupt downloads.
        ET.fromstring(zf.read(xml_members[0]))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".", type=Path)
    args = ap.parse_args()
    root = args.repo_root

    checks = [
        (validate_ckl, root / "fixtures/ckl/windows_server_2022_sanitized.ckl"),
        (validate_cklb, root / "fixtures/cklb/windows_server_2022_sanitized.cklb"),
        (validate_stig_manager, root / "fixtures/exports/stig_manager_golden.json"),
        (validate_emass, root / "fixtures/exports/emass_golden.csv"),
        (validate_disa_zip, root / "fixtures/authorized/disa-public-2026-04/U_MS_Windows_Server_2022_V2R8_STIG.zip"),
        (validate_disa_zip, root / "fixtures/authorized/disa-public-2026-04/U_RHEL_8_V2R7_STIG.zip"),
    ]
    for fn, path in checks:
        if not path.is_file():
            fail(f"missing fixture: {path}")
        fn(path)
    print(f"Validated {len(checks)} external workflow acceptance fixtures")


if __name__ == "__main__":
    main()
