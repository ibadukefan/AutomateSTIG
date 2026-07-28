#!/usr/bin/env python3
"""Verify CKL and CKLB files round-tripped through the real STIG Viewer GUI."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


MAX_CHECKLIST_BYTES = 16 * 1024 * 1024
PLACEHOLDER_VALUE = re.compile(
    r"(?:^|[^a-z0-9])(?:placeholder|fabricated|dummy|fake|example|sample|todo|tbd|"
    r"changeme|replace[ _-]?me)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)
PLACEHOLDER_EXACT = {
    "n/a",
    "na",
    "none",
    "null",
    "test",
    "tester",
    "testing",
    "unknown",
    "unspecified",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def validate_attestation_metadata(name: str, value: str) -> str:
    normalized = " ".join(value.strip().split())
    folded = normalized.casefold()
    if (
        not normalized
        or folded in PLACEHOLDER_EXACT
        or PLACEHOLDER_VALUE.search(normalized)
        or (normalized.startswith("<") and normalized.endswith(">"))
        or "${{" in normalized
    ):
        fail(f"--{name.replace('_', '-')} must be a real, non-placeholder value")
    if name != "product_version" and not any(
        character.isalpha() for character in normalized
    ):
        fail(f"--{name.replace('_', '-')} must contain descriptive text")
    if name in {"product_version", "platform"} and not any(
        character.isdigit() for character in normalized
    ):
        fail(f"--{name.replace('_', '-')} must include the exact version")
    return normalized


def normalized_status(value: object) -> str:
    return "".join(character for character in str(value).lower() if character.isalpha())


def normalized_severity(value: object) -> str:
    normalized = " ".join(str(value or "medium").strip().lower().split())
    return {
        "cat i": "high",
        "cat ii": "medium",
        "cat iii": "low",
    }.get(normalized, normalized)


def normalized_classification(value: object) -> str:
    normalized = str(value or "").strip().upper()
    return (
        normalized
        if normalized in {"CUI", "CONFIDENTIAL", "SECRET", "TOP SECRET"}
        else "UNCLASSIFIED"
    )


def normalized_technology_area(value: object) -> str | None:
    if value is None:
        return None
    normalized = " ".join(str(value).strip().lower().split())
    values = {
        "": "",
        "none": "",
        "application review": "Application Review",
        "boundary security": "Boundary Security",
        "cds admin review": "CDS Admin Review",
        "cds technical review": "CDS Technical Review",
        "database review": "Database Review",
        "domain name system (dns)": "Domain Name System (DNS)",
        "exchange server": "Exchange Server",
        "host based system security (hbss)": "Host Based System Security (HBSS)",
        "internal network": "Internal Network",
        "mobility": "Mobility",
        "releasable networks (rel)": "Releasable Networks (REL)",
        "traditional security": "Traditional Security",
        "unix os": "Unix OS",
        "vvoip review": "VVOIP Review",
        "other review": "Other Review",
        "web review": "Web Review",
        "windows os": "Windows OS",
        "workstation": "Workstation",
        "member server": "Member Server",
        "domain controller": "Domain Controller",
    }
    return values.get(normalized, str(value).strip())


def normalized_role(value: object) -> str:
    normalized = str(value or "").strip()
    return (
        normalized
        if normalized in {"Workstation", "Member Server", "Domain Controller"}
        else "None"
    )


def optional_text(element: ET.Element | None) -> str | None:
    if element is None or element.text is None or not element.text.strip():
        return None
    return element.text.strip()


def required_single(items: list, description: str):
    if len(items) != 1:
        fail(f"{description} must occur exactly once; found {len(items)}")
    return items[0]


def read_bounded(path: pathlib.Path) -> str:
    if path.stat().st_size > MAX_CHECKLIST_BYTES:
        fail(f"checklist exceeds {MAX_CHECKLIST_BYTES} bytes: {path}")
    return path.read_text(encoding="utf-8")


def release_projection(value: object) -> tuple[str, str | None]:
    text = str(value or "")
    release = "0"
    release_marker = "Release:"
    date_marker = "Benchmark Date:"
    if release_marker in text:
        remainder = text.split(release_marker, 1)[1].strip()
        if remainder:
            release = remainder.split()[0]
    date = text.split(date_marker, 1)[1].strip() if date_marker in text else None
    return release, date or None


def load_with_automatestig(
    binary: pathlib.Path, source: pathlib.Path, destination: pathlib.Path
) -> dict:
    result = subprocess.run(
        [
            str(binary),
            "convert",
            "--input",
            str(source),
            "--output",
            str(destination),
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        timeout=60,
    )
    if result.returncode:
        fail(
            f"AutomateSTIG could not parse {source}: "
            f"{(result.stderr or result.stdout)[-500:]}"
        )
    try:
        return json.loads(destination.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"AutomateSTIG produced invalid normalized JSON for {source}: {error}")


def finding_projection(finding: dict) -> dict:
    metadata = finding.get("format_metadata") or {}
    attributes = metadata.get("attributes") or {}
    return {
        "vuln_id": finding.get("vuln_id")
        or metadata.get("vuln_num")
        or attributes.get("Vuln_Num")
        or "",
        "rule_id": finding.get("rule_id")
        or metadata.get("rule_id")
        or attributes.get("Rule_ID")
        or "",
        "group_id": finding.get("group_id") or metadata.get("group_id") or "",
        "group_title": finding.get("group_title") or metadata.get("group_title") or "",
        "rule_title": finding.get("rule_title")
        or metadata.get("rule_title")
        or attributes.get("Rule_Title")
        or "",
        "rule_version": finding.get("rule_version") or metadata.get("rule_version") or "",
        "severity": normalized_severity(
            finding.get("severity") or metadata.get("severity") or attributes.get("Severity")
        ),
        "weight": float(finding.get("weight") or 0),
        "status": normalized_status(finding.get("status")),
        "finding_details": finding.get("finding_details") or "",
        "comments": finding.get("comments") or "",
        "discussion": finding.get("discussion") or metadata.get("discussion") or "",
        "check_content": finding.get("check_content") or metadata.get("check_content") or "",
        "fix_text": finding.get("fix_text") or metadata.get("fix_text") or "",
        "stig_ref": finding.get("stig_ref"),
        "cci_refs": sorted(finding.get("cci_refs") or []),
        "legacy_ids": sorted(finding.get("legacy_ids") or []),
        "severity_override": (
            normalized_severity(finding.get("severity_override"))
            if finding.get("severity_override")
            else None
        ),
        "severity_override_justification": finding.get("severity_override_justification"),
    }


def projection(document: dict, kind: str | None = None) -> dict:
    findings = [finding_projection(item) for item in document.get("findings") or []]
    findings.sort(key=lambda item: (item["rule_id"], item["vuln_id"]))
    if not findings or any(not item["rule_id"] for item in findings):
        fail("normalized checklist has missing findings or Rule IDs")
    if len({item["rule_id"] for item in findings}) != len(findings):
        fail("normalized checklist contains duplicate Rule IDs")
    asset = document.get("asset") or {}
    stig = document.get("stig_info") or {}
    asset_projection = {
        name: asset.get(name)
        for name in (
            "hostname",
            "ip_address",
            "mac_address",
            "fqdn",
            "target_comment",
            "role",
            "asset_type",
            "os",
            "technology_area",
            "web_or_database",
            "is_active",
            "web_db_site",
            "web_db_instance",
        )
    }
    stig_projection = {
        name: stig.get(name)
        for name in (
            "stig_id",
            "title",
            "version",
            "release",
            "release_date",
            "uuid",
        )
    }
    # quick-xml can surface explicit empty elements written by this process as
    # empty strings, while an independent XML parser represents the same CKL
    # elements as absent text. Treat those two XML spellings identically.
    if kind == "ckl":
        for name in (
            "ip_address",
            "mac_address",
            "fqdn",
            "target_comment",
            "os",
            "technology_area",
            "web_db_site",
            "web_db_instance",
        ):
            if asset_projection[name] == "":
                asset_projection[name] = None
        if stig_projection["uuid"] == "":
            stig_projection["uuid"] = None
    return {
        "asset": asset_projection,
        "stig_info": stig_projection,
        "classification": document.get("classification"),
        "findings": findings,
    }


def ckl_raw_projection(path: pathlib.Path) -> dict:
    xml = read_bounded(path)
    if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        fail(f"CKL acceptance input must not contain DTD/entity declarations: {path}")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as error:
        fail(f"invalid raw CKL XML {path}: {error}")
    if root.tag != "CHECKLIST":
        fail(f"raw CKL root must be CHECKLIST: {path}")
    asset_node = required_single(root.findall("./ASSET"), f"{path} ASSET")
    istig = required_single(root.findall("./STIGS/iSTIG"), f"{path} iSTIG")

    asset_values = {child.tag: optional_text(child) for child in asset_node}
    web_value = asset_values.get("WEB_OR_DATABASE")
    if web_value is not None:
        web_value = web_value.lower()
        if web_value not in {"true", "false"}:
            fail(f"raw CKL has invalid WEB_OR_DATABASE value: {web_value!r}")
    technology_area = normalized_technology_area(asset_values.get("TECH_AREA"))
    if technology_area == "":
        technology_area = None
    asset = {
        "hostname": asset_values.get("HOST_NAME") or "Unknown",
        "ip_address": asset_values.get("HOST_IP"),
        "mac_address": asset_values.get("HOST_MAC"),
        "fqdn": asset_values.get("HOST_FQDN"),
        "target_comment": asset_values.get("TARGET_COMMENT"),
        "role": normalized_role(asset_values.get("ROLE")),
        "asset_type": (
            "Non-Computing"
            if asset_values.get("ASSET_TYPE") == "Non-Computing"
            else "Computing"
        ),
        "os": None,
        "technology_area": technology_area,
        "web_or_database": web_value,
        "is_active": True,
        "web_db_site": asset_values.get("WEB_DB_SITE"),
        "web_db_instance": asset_values.get("WEB_DB_INSTANCE"),
    }

    stig_info_values: dict[str, str] = {}
    for item in istig.findall("./STIG_INFO/SI_DATA"):
        name = optional_text(item.find("./SID_NAME"))
        value = optional_text(item.find("./SID_DATA"))
        if name and value is not None:
            stig_info_values[name] = value
    release, release_date = release_projection(stig_info_values.get("releaseinfo"))
    stig_info = {
        "stig_id": stig_info_values.get("stigid", ""),
        "title": stig_info_values.get("title", ""),
        "version": stig_info_values.get("version", ""),
        "release": release,
        "release_date": release_date,
        "uuid": stig_info_values.get("uuid"),
    }

    findings = []
    for vuln in istig.findall("./VULN"):
        attributes: dict[str, str] = {}
        ccis: list[str] = []
        legacy_ids: list[str] = []
        for item in vuln.findall("./STIG_DATA"):
            name = optional_text(item.find("./VULN_ATTRIBUTE"))
            value = optional_text(item.find("./ATTRIBUTE_DATA")) or ""
            if name == "CCI_REF":
                if value:
                    ccis.append(value)
            elif name == "LEGACY_ID":
                if value:
                    legacy_ids.append(value)
            elif name:
                attributes[name] = value
        severity = normalized_severity(attributes.get("Severity"))
        weight_value = attributes.get("Weight")
        default_weight = {"high": 10.0, "medium": 8.0, "low": 2.0}.get(severity, 8.0)
        try:
            weight = float(weight_value) if weight_value else default_weight
        except ValueError:
            fail(f"raw CKL has invalid Weight {weight_value!r}")
        severity_override = optional_text(vuln.find("./SEVERITY_OVERRIDE"))
        findings.append({
            "vuln_id": attributes.get("Vuln_Num", ""),
            "rule_id": attributes.get("Rule_ID", ""),
            "group_id": attributes.get("Vuln_Num", ""),
            "group_title": attributes.get("Group_Title", ""),
            "rule_title": attributes.get("Rule_Title", ""),
            "rule_version": attributes.get("Rule_Ver", ""),
            "severity": severity,
            "weight": weight,
            "status": normalized_status(optional_text(vuln.find("./STATUS")) or "NotReviewed"),
            "finding_details": optional_text(vuln.find("./FINDING_DETAILS")) or "",
            "comments": optional_text(vuln.find("./COMMENTS")) or "",
            "discussion": attributes.get("Vuln_Discuss", ""),
            "check_content": attributes.get("Check_Content", ""),
            "fix_text": attributes.get("Fix_Text", ""),
            "stig_ref": attributes.get("STIGRef") or None,
            "cci_refs": sorted(ccis),
            "legacy_ids": sorted(legacy_ids),
            "severity_override": (
                normalized_severity(severity_override) if severity_override else None
            ),
            "severity_override_justification": optional_text(
                vuln.find("./SEVERITY_JUSTIFICATION")
            ),
        })
    findings.sort(key=lambda item: (item["rule_id"], item["vuln_id"]))
    validate_rule_set(findings, f"raw CKL {path}")
    return {
        "asset": asset,
        "stig_info": stig_info,
        "classification": normalized_classification(asset_values.get("MARKING")),
        "findings": findings,
    }


def first_present(document: dict, *names: str, default=None):
    for name in names:
        if name in document and document[name] is not None:
            return document[name]
    return default


def cklb_raw_projection(path: pathlib.Path) -> dict:
    try:
        document = json.loads(read_bounded(path))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid raw CKLB JSON {path}: {error}")
    if not isinstance(document, dict):
        fail(f"raw CKLB root must be an object: {path}")
    stigs = document.get("stigs")
    if not isinstance(stigs, list):
        fail(f"raw CKLB stigs must be an array: {path}")
    stig = required_single(stigs, f"{path} STIG")
    if not isinstance(stig, dict):
        fail(f"raw CKLB STIG must be an object: {path}")
    target = document.get("target_data")
    if not isinstance(target, dict):
        fail(f"raw CKLB target_data must be an object: {path}")
    web_database = target.get("is_web_database")
    if web_database is not None and not isinstance(web_database, bool):
        fail(f"raw CKLB is_web_database must be boolean: {path}")
    asset = {
        "hostname": target.get("host_name") or "",
        "ip_address": target.get("ip_address"),
        "mac_address": target.get("mac_address"),
        "fqdn": target.get("fqdn"),
        "target_comment": target.get("comments"),
        "role": normalized_role(target.get("role")),
        "asset_type": (
            "Non-Computing"
            if target.get("target_type") == "Non-Computing"
            else "Computing"
        ),
        "os": first_present(target, "os", "operating_system"),
        "technology_area": normalized_technology_area(target.get("technology_area")),
        "web_or_database": str(web_database).lower() if web_database is not None else None,
        "is_active": document.get("active") if isinstance(document.get("active"), bool) else True,
        "web_db_site": target.get("web_db_site"),
        "web_db_instance": target.get("web_db_instance"),
    }
    release, release_date = release_projection(stig.get("release_info"))
    stig_info = {
        "stig_id": stig.get("stig_id") or "",
        "title": first_present(stig, "stig_name", "display_name", default="") or "",
        "version": str(stig["version"]) if stig.get("version") is not None else "",
        "release": release,
        "release_date": release_date,
        "uuid": stig.get("uuid"),
    }
    rules = stig.get("rules")
    if not isinstance(rules, list):
        fail(f"raw CKLB rules must be an array: {path}")
    findings = []
    for rule in rules:
        if not isinstance(rule, dict):
            fail(f"raw CKLB rule must be an object: {path}")
        severity = normalized_severity(rule.get("severity"))
        weight_value = rule.get("weight")
        try:
            weight = (
                float(weight_value)
                if weight_value not in (None, "")
                else {"high": 10.0, "medium": 8.0, "low": 2.0}.get(severity, 8.0)
            )
        except (TypeError, ValueError):
            fail(f"raw CKLB has invalid weight {weight_value!r}")
        severity_override = rule.get("severity_override")
        findings.append({
            "vuln_id": first_present(rule, "group_id_v", "group_id", "vuln_num", default="") or "",
            "rule_id": first_present(rule, "rule_id_src", "rule_id", default="") or "",
            "group_id": rule.get("group_id") or "",
            "group_title": first_present(
                rule, "group_title", default=rule.get("group_id", "")
            ),
            "rule_title": rule.get("rule_title") or "",
            "rule_version": rule.get("rule_version") or "",
            "severity": severity,
            "weight": weight,
            "status": normalized_status(rule.get("status") or "NotReviewed"),
            "finding_details": first_present(rule, "finding_details", "detail", default="") or "",
            "comments": first_present(rule, "comments", "comment", default="") or "",
            "discussion": rule.get("discussion") or "",
            "check_content": rule.get("check_content") or "",
            "fix_text": rule.get("fix_text") or "",
            "stig_ref": rule.get("srg_id") or None,
            "cci_refs": sorted(rule.get("ccis") or []),
            "legacy_ids": sorted(rule.get("legacy_ids") or []),
            "severity_override": (
                normalized_severity(severity_override) if severity_override else None
            ),
            "severity_override_justification": rule.get("severity_justification"),
        })
    findings.sort(key=lambda item: (item["rule_id"], item["vuln_id"]))
    validate_rule_set(findings, f"raw CKLB {path}")
    return {
        "asset": asset,
        "stig_info": stig_info,
        "classification": normalized_classification(target.get("classification")),
        "findings": findings,
    }


def validate_rule_set(findings: list[dict], description: str) -> None:
    if not findings or any(not item["rule_id"] for item in findings):
        fail(f"{description} has missing findings or Rule IDs")
    if len({item["rule_id"] for item in findings}) != len(findings):
        fail(f"{description} contains duplicate Rule IDs")


def raw_projection(kind: str, path: pathlib.Path) -> dict:
    if kind == "ckl":
        return ckl_raw_projection(path)
    if kind == "cklb":
        return cklb_raw_projection(path)
    fail(f"unsupported Viewer acceptance format: {kind}")


def require_non_default_exercise(kind: str, document: dict) -> None:
    asset = document["asset"]
    required = {
        "technology_area": asset.get("technology_area"),
        "web_db_site": asset.get("web_db_site"),
        "web_db_instance": asset.get("web_db_instance"),
    }
    if kind == "cklb":
        required["os"] = asset.get("os")
    missing = sorted(name for name, value in required.items() if value in (None, ""))
    if asset.get("web_or_database") != "true":
        missing.append("web_or_database=true")
    if missing:
        fail(f"{kind.upper()} source does not exercise non-default target metadata: {missing}")
    if not any(
        finding["group_title"]
        and finding["rule_version"]
        and finding["discussion"]
        and finding["check_content"]
        and finding["fix_text"]
        and len(finding["cci_refs"]) > 1
        and len(finding["legacy_ids"]) > 1
        for finding in document["findings"]
    ):
        fail(
            f"{kind.upper()} source must exercise content fields plus repeated CCI and legacy IDs"
        )


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def run_case(
    binary: pathlib.Path,
    kind: str,
    source: pathlib.Path,
    roundtrip: pathlib.Path,
    root: pathlib.Path,
) -> dict:
    if source.resolve() == roundtrip.resolve():
        fail(f"{kind} source and round-trip paths must be different files")
    for path in (source, roundtrip):
        if not path.is_file() or path.suffix.lower() != f".{kind}":
            fail(f"{kind} acceptance input is missing or has the wrong extension: {path}")
    source_sha256 = sha256(source)
    roundtrip_sha256 = sha256(roundtrip)
    if source_sha256 == roundtrip_sha256:
        fail(
            f"{kind.upper()} source and round-trip are byte-identical; "
            "provide the file actually saved/exported by STIG Viewer"
        )
    raw_before = raw_projection(kind, source)
    require_non_default_exercise(kind, raw_before)
    before = projection(
        load_with_automatestig(binary, source, root / f"{kind}-source.json"), kind
    )
    if raw_before != before:
        fail(
            f"AutomateSTIG's first {kind.upper()} parse lost or changed modeled source fields; "
            f"raw={canonical_sha256(raw_before)} normalized={canonical_sha256(before)}"
        )
    raw_after = raw_projection(kind, roundtrip)
    after = projection(
        load_with_automatestig(binary, roundtrip, root / f"{kind}-roundtrip.json"), kind
    )
    if raw_after != after:
        fail(
            f"AutomateSTIG's first parse of the Viewer {kind.upper()} output lost modeled fields; "
            f"raw={canonical_sha256(raw_after)} normalized={canonical_sha256(after)}"
        )
    if raw_before != raw_after:
        fail(f"STIG Viewer changed raw modeled {kind.upper()} semantics")
    if before != after:
        before_findings = {item["rule_id"]: item for item in before["findings"]}
        after_findings = {item["rule_id"]: item for item in after["findings"]}
        changed = sorted(
            rule for rule in set(before_findings) | set(after_findings)
            if before_findings.get(rule) != after_findings.get(rule)
        )
        fail(
            f"{kind.upper()} changed modeled checklist semantics in STIG Viewer round-trip; "
            f"changed Rule IDs: {changed[:10]}"
        )
    return {
        "format": kind,
        "status": "passed",
        "source_sha256": source_sha256,
        "roundtrip_sha256": roundtrip_sha256,
        "semantic_sha256": canonical_sha256(before),
        "rule_set_sha256": canonical_sha256([item["rule_id"] for item in before["findings"]]),
        "finding_count": len(before["findings"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--ckl-source", type=pathlib.Path, required=True)
    parser.add_argument("--ckl-roundtrip", type=pathlib.Path, required=True)
    parser.add_argument("--cklb-source", type=pathlib.Path, required=True)
    parser.add_argument("--cklb-roundtrip", type=pathlib.Path, required=True)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_file():
        fail(f"AutomateSTIG CLI binary does not exist: {args.binary}")
    for name in ("product_version", "platform", "operator"):
        setattr(
            args,
            name,
            validate_attestation_metadata(name, getattr(args, name)),
        )
    with tempfile.TemporaryDirectory(prefix="automatestig-stig-viewer-") as temporary:
        root = pathlib.Path(temporary)
        cases = [
            run_case(args.binary, "ckl", args.ckl_source, args.ckl_roundtrip, root),
            run_case(args.binary, "cklb", args.cklb_source, args.cklb_roundtrip, root),
        ]
    evidence = {
        "schema": "automatestig-stig-viewer-acceptance/v1",
        "passed": True,
        "tested_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "product": "DoD STIG Viewer",
        "product_version": args.product_version,
        "platform": args.platform,
        "operator": args.operator,
        "automatestig_cli_sha256": sha256(args.binary),
        "source_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=args.repo_root.resolve(),
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip(),
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "protected_environment": os.environ.get("AUTOMATESTIG_PROTECTED_ENVIRONMENT"),
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "PASS: submitted STIG Viewer round trips preserved CKL and CKLB semantics; "
        f"evidence={args.output}"
    )


if __name__ == "__main__":
    main()
