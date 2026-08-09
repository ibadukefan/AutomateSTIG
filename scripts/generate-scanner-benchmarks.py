#!/usr/bin/env python3
"""Generate the exact, release-bundled benchmark subset for scanner profiles.

This is a maintainer tool, not an end-user content downloader. Each source
archive is pinned by SHA-256 and every emitted rule must already be declared in
the reviewed coverage manifest. The runtime never performs these downloads.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "content" / "scanner_profiles"

PROFILES = (
    {
        "target_key": "netapp_ontap9",
        "url": "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_NetApp_ONTAP_DSC_9-x_V2R4_STIG.zip",
        "archive_sha256": "5e596bb9d6faa6c5f0762f4b0b6ca43b03a3f10a8c4fff658183eb901f5e39cc",
        "member": "U_NetApp_ONTAP_DSC_9-x_V2R4_Manual_STIG/U_NetApp_ONTAP_DSC_9-x_STIG_V2R4_Manual-xccdf.xml",
        "coverage": "content/coverage/current-checkpacks/netapp_ontap9.current.json",
        "stig_id": "NetApp_ONTAP_DSC_9-x_STIG",
        "revision": "V2R4",
        "platform_family": "network",
        "platform_name": "NetApp ONTAP 9.x",
    },
    {
        "target_key": "freebsd_gpos",
        "url": "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_GPOS_V3R3_SRG.zip",
        "archive_sha256": "97026655bce18d91e12c9c0a9fd54288989f0b483d3b92ec615e2dc0544e6f24",
        "member": "U_GPOS_V3R3_Manual_SRG/U_GPOS_SRG_V3R3_Manual-xccdf.xml",
        "coverage": "content/coverage/current-checkpacks/freebsd_gpos.current.json",
        "stig_id": "General_Purpose_Operating_System",
        "revision": "V3R3",
        "platform_family": "operating_system",
        "platform_name": "FreeBSD / DISA GPOS",
    },
    {
        "target_key": "cisco_ios_xe_router_ndm",
        "url": "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Cisco_IOS-XE_Router_Y26M04_STIG.zip",
        "archive_sha256": "01900ad03d8972698160db7c1fdfc71b64a3c7188ee53c4f1047fc827986f36d",
        "member": "U_Cisco_IOS-XE_Router_NDM_V3R7_Manual_STIG/U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml",
        "coverage": "content/coverage/current-checkpacks/cisco_ios_xe_router_ndm.current.json",
        "stig_id": "Cisco_IOS-XE_Router_NDM_STIG",
        "revision": "V3R7",
        "platform_family": "network",
        "platform_name": "Cisco IOS-XE Router NDM",
    },
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return "".join(element.itertext()).strip()


def embedded_field(value: str, name: str) -> str:
    if not value:
        return ""
    try:
        wrapper = ET.fromstring(f"<root>{value}</root>")
    except ET.ParseError:
        return value.strip() if name == "VulnDiscussion" else ""
    return text(wrapper.find(name))


def generate(profile: dict[str, str]) -> tuple[dict, dict]:
    request = urllib.request.Request(
        profile["url"], headers={"User-Agent": "AutomateSTIG scanner-profile maintainer"}
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        archive = response.read()
    actual_archive_sha256 = sha256(archive)
    if actual_archive_sha256 != profile["archive_sha256"]:
        raise RuntimeError(
            f"{profile['target_key']}: DISA archive digest changed: "
            f"expected {profile['archive_sha256']}, got {actual_archive_sha256}"
        )

    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        xccdf = bundle.read(profile["member"])
    root = ET.fromstring(xccdf)
    namespace = root.tag.partition("}")[0].lstrip("{")
    ns = {"x": namespace}

    coverage_path = ROOT / profile["coverage"]
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    if coverage["stig_id"] != profile["stig_id"] or coverage["version"] != profile["revision"]:
        raise RuntimeError(f"{profile['target_key']}: coverage identity drift")
    coverage_by_vuln = {rule["vuln_id"]: rule for rule in coverage["rules"]}

    emitted = {}
    for group in root.findall("x:Group", ns):
        vuln_id = group.get("id", "")
        if vuln_id not in coverage_by_vuln:
            continue
        rule = group.find("x:Rule", ns)
        if rule is None:
            raise RuntimeError(f"{profile['target_key']}: {vuln_id} has no Rule")
        description = text(rule.find("x:description", ns))
        check = rule.find("x:check", ns)
        severity = rule.get("severity", "").lower()
        if severity not in {"high", "medium", "low"}:
            raise RuntimeError(f"{profile['target_key']}: invalid severity for {vuln_id}")
        classification = coverage_by_vuln[vuln_id]["classification"]
        emitted[vuln_id] = {
            "vuln_id": vuln_id,
            "rule_id": rule.get("id", ""),
            "group_id": vuln_id,
            "group_title": text(group.find("x:title", ns)),
            "title": text(rule.find("x:title", ns)),
            "rule_version": text(rule.find("x:version", ns)),
            "discussion": embedded_field(description, "VulnDiscussion"),
            "severity": severity,
            "check_content": text(check.find("x:check-content", ns)) if check is not None else "",
            "fix_text": text(rule.find("x:fixtext", ns)),
            "cci_refs": [text(item) for item in rule.findall("x:ident", ns) if text(item)],
            "legacy_ids": [],
            "stig_ref": f"{text(root.find('x:title', ns))} :: {profile['revision']}",
            "weight": float(rule.get("weight", "0")),
            "automatable": "full" if classification == "automated" else "manual",
        }
        if not emitted[vuln_id]["rule_id"].startswith("SV-"):
            raise RuntimeError(f"{profile['target_key']}: non-official rule ID for {vuln_id}")

    missing = set(coverage_by_vuln) - set(emitted)
    extra = set(emitted) - set(coverage_by_vuln)
    if missing or extra:
        raise RuntimeError(
            f"{profile['target_key']}: source/coverage mismatch; missing={sorted(missing)}, extra={sorted(extra)}"
        )

    match = re.fullmatch(r"V(\d+)R(\d+)", profile["revision"])
    if not match:
        raise RuntimeError(f"invalid revision {profile['revision']}")
    version, release = match.groups()
    status = root.find("x:status", ns)
    benchmark = {
        "id": root.get("id", ""),
        "title": text(root.find("x:title", ns)),
        "description": text(root.find("x:description", ns)),
        "version": version,
        "release": release,
        "release_date": status.get("date") if status is not None else None,
        "xccdf_id": root.get("id"),
        "platform": {
            "family": profile["platform_family"],
            "name": profile["platform_name"],
            "cpe": [],
        },
        "rules": [emitted[item["vuln_id"]] for item in coverage["rules"]],
    }
    if benchmark["id"] != profile["stig_id"]:
        raise RuntimeError(
            f"{profile['target_key']}: XCCDF id {benchmark['id']} did not match {profile['stig_id']}"
        )
    source = {
        "schema_version": 1,
        "target_key": profile["target_key"],
        "stig_id": profile["stig_id"],
        "stig_revision": profile["revision"],
        "source_url": profile["url"],
        "source_archive_sha256": actual_archive_sha256,
        "source_member": profile["member"],
        "source_xccdf_sha256": sha256(xccdf),
        "coverage_manifest": profile["coverage"],
        "coverage_manifest_sha256": sha256(coverage_path.read_bytes()),
        "rule_count": len(benchmark["rules"]),
    }
    return benchmark, source


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for profile in PROFILES:
        benchmark, source = generate(profile)
        target_key = profile["target_key"]
        benchmark_bytes = (json.dumps(benchmark, ensure_ascii=False, indent=2) + "\n").encode()
        source["benchmark_model_sha256"] = sha256(benchmark_bytes)
        source_bytes = (json.dumps(source, ensure_ascii=False, indent=2) + "\n").encode()
        (OUTPUT_DIR / f"{target_key}.benchmark.json").write_bytes(benchmark_bytes)
        (OUTPUT_DIR / f"{target_key}.source.json").write_bytes(source_bytes)
        print(
            f"{target_key}: {len(benchmark['rules'])} rules, "
            f"benchmark {source['benchmark_model_sha256']}"
        )


if __name__ == "__main__":
    main()
