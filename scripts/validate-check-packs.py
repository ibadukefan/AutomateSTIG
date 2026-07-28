#!/usr/bin/env python3
"""Validate the exact v0.3 target set and its shipped check-pack content.

The supported-target manifest is the release boundary. CI rejects unlisted packs,
missing coverage, target metadata drift, and rule/check mismatches so experimental
or future content cannot become a product claim merely by landing in a directory.
Dependency-free by design.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


REPO = Path(
    os.environ.get("REPO_ROOT", Path(__file__).resolve().parent.parent)
).resolve()
TARGET_MANIFEST = Path("content/supported-targets.json")

EXPECTED_TARGETS: dict[str, dict[str, Any]] = {
    "netapp_ontap9": {
        "display_name": "NetApp ONTAP 9.x",
        "stig_id": "NetApp_ONTAP_DSC_9-x_STIG",
        "stig_release": "V2R2",
        "platform": "ontap",
        "evidence_mode": "ssh_transcript",
        "expected_automated_checks": 16,
        "expected_reviewed_rules": 22,
        "check_pack": "content/check_packs/netapp_ontap9.json",
        "coverage_manifest": "content/coverage/current-checkpacks/netapp_ontap9.current.json",
        "acceptance_gate": "ontap",
    },
    "freebsd_gpos": {
        "display_name": "FreeBSD / DISA GPOS",
        "stig_id": "General_Purpose_Operating_System",
        "stig_release": "V3R3",
        "platform": "bsd",
        "evidence_mode": "ssh_transcript",
        "expected_automated_checks": 3,
        "expected_reviewed_rules": 30,
        "check_pack": "content/check_packs/freebsd_gpos.json",
        "coverage_manifest": "content/coverage/current-checkpacks/freebsd_gpos.current.json",
        "acceptance_gate": "freebsd",
    },
    "cisco_ios_xe_router_ndm": {
        "display_name": "Cisco IOS-XE Router NDM",
        "stig_id": "Cisco_IOS-XE_Router_NDM_STIG",
        "stig_release": "V3R7",
        "platform": "cisco_ios",
        "evidence_mode": "running_configuration",
        "expected_automated_checks": 21,
        "expected_reviewed_rules": 34,
        "check_pack": "content/check_packs/cisco_ios_xe_router_ndm.json",
        "coverage_manifest": "content/coverage/current-checkpacks/cisco_ios_xe_router_ndm.current.json",
        "acceptance_gate": "cisco_ios_xe",
    },
}

TYPED_CISCO_CHECKS = {
    "cisco_vty_session_limit": "V-215807",
    "cisco_logging_buffer_capacity": "V-215836",
    "cisco_logging_trap_severity": "V-215837",
}
KNOWN_CHECK_TYPES = {"command", "config_line", "all", "any", *TYPED_CISCO_CHECKS}
KNOWN_EXPECTED_TYPES = {"matches", "not_contains", "is_true", "match_count_at_least"}


def _rel(path: Path, repo: Path) -> str:
    return path.relative_to(repo).as_posix()


def _load_json(path: Path, repo: Path, errors: list[str]) -> dict[str, Any] | None:
    name = _rel(path, repo) if path.is_relative_to(repo) else str(path)
    if path.is_symlink() or not path.is_file():
        errors.append(f"{name}: must be a regular, non-symlink file")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{name}: not valid JSON: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append(f"{name}: top-level JSON value must be an object")
        return None
    return value


def _validate_check(
    pack: str,
    vuln_id: str,
    check: Any,
    errors: list[str],
    *,
    top_level: bool = True,
) -> None:
    if not isinstance(check, dict):
        errors.append(f"{pack}: {vuln_id}: check must be an object")
        return
    check_type = check.get("type")
    if check_type not in KNOWN_CHECK_TYPES:
        errors.append(f"{pack}: {vuln_id}: unsupported v0.3 check type {check_type!r}")
        return
    if check_type == "config_line":
        pattern = check.get("pattern")
        if not isinstance(pattern, str) or not pattern.strip():
            errors.append(f"{pack}: {vuln_id}: config_line needs a non-empty pattern")
        elif pattern != pattern.strip():
            errors.append(
                f"{pack}: {vuln_id}: config_line pattern has leading/trailing whitespace"
            )
        if not isinstance(check.get("should_exist"), bool):
            errors.append(f"{pack}: {vuln_id}: config_line needs boolean should_exist")
    elif check_type == "command":
        command = check.get("command")
        if not isinstance(command, str) or not command.strip():
            errors.append(f"{pack}: {vuln_id}: command check needs a non-empty command")
        if "pattern" in check and not isinstance(check["pattern"], str):
            errors.append(f"{pack}: {vuln_id}: command pattern must be a string")
        if "is_regex" in check and not isinstance(check["is_regex"], bool):
            errors.append(f"{pack}: {vuln_id}: command is_regex must be a boolean")
    elif check_type in {"all", "any"}:
        children = check.get("checks")
        if not isinstance(children, list) or not children:
            errors.append(f"{pack}: {vuln_id}: {check_type} needs non-empty checks[]")
            return
        for child in children:
            _validate_check(
                pack,
                vuln_id,
                child,
                errors,
                top_level=False,
            )
    else:
        if not top_level:
            errors.append(f"{pack}: {vuln_id}: {check_type} must be top-level")
        if set(check) != {"type"}:
            errors.append(f"{pack}: {vuln_id}: {check_type} accepts only the type field")
        if TYPED_CISCO_CHECKS[check_type] != vuln_id:
            errors.append(
                f"{pack}: {vuln_id}: {check_type} is reserved for "
                f"{TYPED_CISCO_CHECKS[check_type]}"
            )


def _validate_expected(pack: str, vuln_id: str, expected: Any, errors: list[str]) -> None:
    if not isinstance(expected, dict):
        errors.append(f"{pack}: {vuln_id}: expected must be an object")
        return
    expected_type = expected.get("type")
    if expected_type not in KNOWN_EXPECTED_TYPES:
        errors.append(
            f"{pack}: {vuln_id}: unsupported v0.3 expected type {expected_type!r}"
        )
        return
    if expected_type == "match_count_at_least":
        if not isinstance(expected.get("min"), int) or expected["min"] < 1:
            errors.append(
                f"{pack}: {vuln_id}: match_count_at_least needs integer min >= 1"
            )
        if not isinstance(expected.get("pattern"), str) or not expected["pattern"]:
            errors.append(f"{pack}: {vuln_id}: match_count_at_least needs a pattern")
    if expected_type == "matches" and not isinstance(expected.get("pattern"), str):
        errors.append(f"{pack}: {vuln_id}: matches needs a pattern string")
    if expected_type == "not_contains" and not isinstance(expected.get("substring"), str):
        errors.append(f"{pack}: {vuln_id}: not_contains needs a substring string")


def _validate_pack(
    path: Path,
    expected: dict[str, Any],
    repo: Path,
    errors: list[str],
) -> set[str]:
    name = _rel(path, repo)
    document = _load_json(path, repo, errors)
    if document is None:
        return set()
    for field, expected_value in (
        ("stig_id", expected["stig_id"]),
        ("platform", expected["platform"]),
        ("version", expected["stig_release"]),
    ):
        if document.get(field) != expected_value:
            errors.append(
                f"{name}: {field} must be {expected_value!r}, got {document.get(field)!r}"
            )
    checks = document.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append(f"{name}: checks[] must be a non-empty array")
        return set()
    if len(checks) != expected["expected_automated_checks"]:
        errors.append(
            f"{name}: expected {expected['expected_automated_checks']} checks, got {len(checks)}"
        )
    seen: set[str] = set()
    for check_definition in checks:
        if not isinstance(check_definition, dict):
            errors.append(f"{name}: check definition must be an object")
            continue
        vuln_id = check_definition.get("vuln_id")
        if not isinstance(vuln_id, str) or not vuln_id:
            errors.append(f"{name}: a check is missing vuln_id")
            continue
        if vuln_id in seen:
            errors.append(f"{name}: duplicate vuln_id {vuln_id}")
        seen.add(vuln_id)
        if check_definition.get("platform") != expected["platform"]:
            errors.append(
                f"{name}: {vuln_id}: platform must be {expected['platform']!r}"
            )
        _validate_check(name, vuln_id, check_definition.get("check"), errors)
        _validate_expected(name, vuln_id, check_definition.get("expected"), errors)
    return seen


def _validate_coverage(
    path: Path,
    target_id: str,
    expected: dict[str, Any],
    pack_vuln_ids: set[str],
    repo: Path,
    errors: list[str],
) -> None:
    name = _rel(path, repo)
    document = _load_json(path, repo, errors)
    if document is None:
        return
    for field, expected_value in (
        ("stig_id", expected["stig_id"]),
        ("version", expected["stig_release"]),
    ):
        if document.get(field) != expected_value:
            errors.append(
                f"{name}: {field} must be {expected_value!r}, got {document.get(field)!r}"
            )
    rules = document.get("rules")
    if not isinstance(rules, list):
        errors.append(f"{name}: rules must be an array")
        return
    if document.get("total_rules") != len(rules):
        errors.append(f"{name}: total_rules does not match rules[] length")
    if len(rules) != expected["expected_reviewed_rules"]:
        errors.append(
            f"{name}: reviewed inventory must contain "
            f"{expected['expected_reviewed_rules']} rules, got {len(rules)}"
        )
    coverage_ids: set[str] = set()
    automated_ids: set[str] = set()
    manual_ids: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            errors.append(f"{name}: coverage rule must be an object")
            continue
        vuln_id = rule.get("vuln_id")
        if not isinstance(vuln_id, str) or not vuln_id:
            errors.append(f"{name}: coverage rule missing vuln_id")
            continue
        if vuln_id in coverage_ids:
            errors.append(f"{name}: duplicate coverage vuln_id {vuln_id}")
        coverage_ids.add(vuln_id)
        classification = rule.get("classification")
        if classification == "automated":
            automated_ids.add(vuln_id)
            if rule.get("check_pack") != target_id or rule.get("check_id") != vuln_id:
                errors.append(f"{name}: {vuln_id}: coverage does not bind to {target_id}")
        elif classification == "manual":
            manual_ids.add(vuln_id)
            if "check_pack" in rule or "check_id" in rule:
                errors.append(
                    f"{name}: {vuln_id}: manual coverage must not bind executable checks"
                )
        else:
            errors.append(
                f"{name}: {vuln_id}: classification must be automated or manual"
            )
        if not isinstance(rule.get("rule_id"), str) or not rule["rule_id"].strip():
            errors.append(f"{name}: {vuln_id}: rule_id must be non-empty")
        if not isinstance(rule.get("reason"), str) or not rule["reason"].strip():
            errors.append(f"{name}: {vuln_id}: reason must be non-empty")
        if rule.get("evidence_required") is not True:
            errors.append(f"{name}: {vuln_id}: evidence_required must be true")
        validated_by = rule.get("validated_by")
        if (
            not isinstance(validated_by, list)
            or not validated_by
            or not all(isinstance(item, str) and item.strip() for item in validated_by)
        ):
            errors.append(f"{name}: {vuln_id}: validated_by must be a non-empty path list")
        elif classification == "automated" and expected["check_pack"] not in validated_by:
            errors.append(
                f"{name}: {vuln_id}: validated_by must reference {expected['check_pack']}"
            )
    if automated_ids != pack_vuln_ids:
        errors.append(
            f"{name}: automated rule/check mismatch; "
            f"missing={sorted(pack_vuln_ids - automated_ids)} "
            f"extra={sorted(automated_ids - pack_vuln_ids)}"
        )
    if len(automated_ids) != expected["expected_automated_checks"]:
        errors.append(
            f"{name}: expected {expected['expected_automated_checks']} automated rules, "
            f"got {len(automated_ids)}"
        )
    if coverage_ids != automated_ids | manual_ids:
        errors.append(f"{name}: every reviewed rule must have exactly one classification")


def validate(repo: Path) -> list[str]:
    repo = repo.resolve()
    errors: list[str] = []
    manifest_path = repo / TARGET_MANIFEST
    manifest = _load_json(manifest_path, repo, errors)
    if manifest is None:
        return errors
    _load_json(repo / "schemas/supported-targets.schema.json", repo, errors)
    expected_top_level = {"$schema", "schema_version", "release_line", "targets"}
    if set(manifest) != expected_top_level:
        errors.append(
            f"{TARGET_MANIFEST}: fields must be exactly {sorted(expected_top_level)}"
        )
    if manifest.get("$schema") != "../schemas/supported-targets.schema.json":
        errors.append(f"{TARGET_MANIFEST}: unexpected $schema reference")
    if manifest.get("schema_version") != 1 or manifest.get("release_line") != "0.3":
        errors.append(
            f"{TARGET_MANIFEST}: schema_version/release_line must be 1/'0.3'"
        )
    targets = manifest.get("targets")
    if not isinstance(targets, dict):
        errors.append(f"{TARGET_MANIFEST}: targets must be an object")
        return errors
    if targets != EXPECTED_TARGETS:
        missing = sorted(EXPECTED_TARGETS.keys() - targets.keys())
        extra = sorted(targets.keys() - EXPECTED_TARGETS.keys())
        errors.append(
            f"{TARGET_MANIFEST}: target contract drift; missing={missing} extra={extra}"
        )
        for target_id in sorted(EXPECTED_TARGETS.keys() & targets.keys()):
            if targets[target_id] != EXPECTED_TARGETS[target_id]:
                errors.append(f"{TARGET_MANIFEST}: {target_id} metadata differs from v0.3 contract")

    expected_pack_paths = {value["check_pack"] for value in EXPECTED_TARGETS.values()}
    actual_pack_paths = {
        _rel(path, repo)
        for path in (repo / "content/check_packs").rglob("*.json")
    }
    if actual_pack_paths != expected_pack_paths:
        errors.append(
            "content/check_packs: shipped pack set differs from target contract; "
            f"missing={sorted(expected_pack_paths - actual_pack_paths)} "
            f"extra={sorted(actual_pack_paths - expected_pack_paths)}"
        )

    expected_coverage_paths = {
        value["coverage_manifest"] for value in EXPECTED_TARGETS.values()
    }
    actual_coverage_paths = {
        _rel(path, repo)
        for path in (repo / "content/coverage").rglob("*.json")
    }
    if actual_coverage_paths != expected_coverage_paths:
        errors.append(
            "content/coverage: manifest set differs from target contract; "
            f"missing={sorted(expected_coverage_paths - actual_coverage_paths)} "
            f"extra={sorted(actual_coverage_paths - expected_coverage_paths)}"
        )

    for target_id, expected in EXPECTED_TARGETS.items():
        pack_path = repo / expected["check_pack"]
        coverage_path = repo / expected["coverage_manifest"]
        pack_vuln_ids = _validate_pack(
            pack_path, expected, repo, errors
        )
        _validate_coverage(
            coverage_path, target_id, expected, pack_vuln_ids, repo, errors
        )
    return errors


def main() -> None:
    errors = validate(REPO)
    if errors:
        print(f"Supported-target validation FAILED ({len(errors)} issue(s)):", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        raise SystemExit(1)
    reviewed = sum(target["expected_reviewed_rules"] for target in EXPECTED_TARGETS.values())
    automated = sum(
        target["expected_automated_checks"] for target in EXPECTED_TARGETS.values()
    )
    print(
        "Validated exact v0.3 target set: "
        f"{len(EXPECTED_TARGETS)} targets, {len(EXPECTED_TARGETS)} packs, "
        f"{len(EXPECTED_TARGETS)} coverage manifests, {reviewed} reviewed rules, "
        f"{automated} automated checks"
    )


if __name__ == "__main__":
    main()
