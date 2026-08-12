#!/usr/bin/env python3
"""Validate external workflow acceptance fixtures without external credentials.

This is an offline contract harness for CKL, CKLB, and DISA XCCDF artifacts.
CI uses the offline mode to prevent payload/schema drift. STIG Manager scanner
handoff is covered by the selected-run verifier and staging acceptance gate,
not by a duplicate portfolio-import format.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

SCRIPTS_ROOT = Path(__file__).resolve().parent
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from bounded_xccdf import BoundedXccdfArchive, BoundedXccdfError


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


def validate_disa_zip(path: Path) -> None:
    try:
        with BoundedXccdfArchive(path) as archive:
            xml_members = [n for n in archive.names if n.lower().endswith(".xml")]
            if not xml_members:
                fail(f"{path} contains no XCCDF/XML member")
            # Parse at least one XML member to catch corrupt downloads.
            ET.fromstring(archive.read_member(xml_members[0]))
    except BoundedXccdfError as error:
        fail(f"unsafe DISA ZIP {path}: {error}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".", type=Path)
    args = ap.parse_args()
    root = args.repo_root

    checks = [
        (validate_ckl, root / "fixtures/ckl/windows_server_2022_sanitized.ckl"),
        (validate_cklb, root / "fixtures/cklb/windows_server_2022_sanitized.cklb"),
        (validate_disa_zip, root / "fixtures/authorized/disa-public-2026-07/U_Cisco_IOS-XE_Router_Y26M04_STIG.zip"),
        (validate_disa_zip, root / "fixtures/authorized/disa-public-2026-07/U_NetApp_ONTAP_DSC_9-x_V2R4_STIG.zip"),
    ]
    for fn, path in checks:
        if not path.is_file():
            fail(f"missing fixture: {path}")
        fn(path)
    print(f"Validated {len(checks)} external workflow acceptance fixtures")


if __name__ == "__main__":
    main()
