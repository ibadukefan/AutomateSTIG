#!/usr/bin/env python3
"""Validate the exact v0.3 target set and its shipped check-pack content.

The supported-target manifest is the release boundary. CI rejects unlisted packs,
missing coverage, target metadata drift, and rule/check mismatches so experimental
or future content cannot become a product claim merely by landing in a directory.
Dependency-free by design.
"""
from __future__ import annotations

import json
import math
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
        "stig_release": "V2R4",
        "platform": "ontap",
        "evidence_mode": "ssh_transcript",
        "expected_benchmark_rules": 29,
        "expected_automated_checks": 15,
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
        "expected_benchmark_rules": 203,
        "expected_automated_checks": 6,
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
        "expected_benchmark_rules": 42,
        "expected_automated_checks": 33,
        "expected_reviewed_rules": 42,
        "check_pack": "content/check_packs/cisco_ios_xe_router_ndm.json",
        "coverage_manifest": "content/coverage/current-checkpacks/cisco_ios_xe_router_ndm.current.json",
        "acceptance_gate": "cisco_ios_xe",
    },
}

TYPED_CISCO_CHECKS = {
    "cisco_vty_session_limit": "V-215807",
    "cisco_login_block_for": "V-215813",
    "cisco_interface_acl_deny_log_input": "V-215818",
    "cisco_persistent_audit_modification_protection": "V-215820",
    "cisco_persistent_audit_deletion_protection": "V-215821",
    "cisco_file_system_privilege": "V-215822",
    "cisco_single_local_fallback_account": "V-215824",
    "cisco_password_minimum_length": "V-215826",
    "cisco_management_idle_timeout": "V-215833",
    "cisco_logging_buffer_capacity": "V-215836",
    "cisco_logging_trap_severity": "V-215837",
    "cisco_redundant_authoritative_ntp_sources": "V-215838",
    "cisco_ntp_authentication": "V-215843",
    "cisco_ssh_mac_algorithms": "V-215844",
    "cisco_ssh_encryption_algorithms": "V-215845",
    "cisco_syslog_server_count": "V-220139",
}
TYPED_BSD_CHECKS = {"bsd_pf_enabled": "V-203784"}
TYPED_BSD_AUDIT_CLASSES = {
    "V-203767": ["lo"],
    "V-203621": ["aa"],
    "V-203774": ["ad"],
    "V-203772": ["fr", "fw", "fa", "fm", "fc", "fd"],
}
KNOWN_CHECK_TYPES = {
    "predicate",
    "command",
    "config_line",
    "all",
    "any",
    "bsd_audit_class_selection",
    *TYPED_BSD_CHECKS,
    *TYPED_CISCO_CHECKS,
}
KNOWN_EXPECTED_TYPES = {"matches", "not_contains", "is_true", "match_count_at_least"}
IMPLEMENTATION_CLASSES = {
    "declarative_predicate",
    "legacy_declarative",
    "reviewed_imperative",
}
LEGACY_DECLARATIVE_TYPES = {"command", "config_line", "all", "any"}
MAX_SAFE_NUMBER = 9_007_199_254_740_991


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
    if check_type == "predicate":
        if set(check) != {"type", "program"}:
            errors.append(f"{pack}: {vuln_id}: predicate accepts only type and program")
        _validate_predicate_program(pack, vuln_id, check.get("program"), errors)
    elif check_type == "config_line":
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
    elif check_type == "bsd_audit_class_selection":
        if not top_level:
            errors.append(f"{pack}: {vuln_id}: {check_type} must be top-level")
        if set(check) != {"type", "classes"}:
            errors.append(
                f"{pack}: {vuln_id}: {check_type} accepts only type and classes"
            )
        expected_classes = TYPED_BSD_AUDIT_CLASSES.get(vuln_id)
        if expected_classes is None:
            errors.append(
                f"{pack}: {vuln_id}: {check_type} is not approved for this rule"
            )
        elif check.get("classes") != expected_classes:
            errors.append(
                f"{pack}: {vuln_id}: {check_type} requires {expected_classes!r}"
            )
    else:
        if not top_level:
            errors.append(f"{pack}: {vuln_id}: {check_type} must be top-level")
        if set(check) != {"type"}:
            errors.append(f"{pack}: {vuln_id}: {check_type} accepts only the type field")
        expected_vuln_id = {
            **TYPED_BSD_CHECKS,
            **TYPED_CISCO_CHECKS,
        }[check_type]
        if expected_vuln_id != vuln_id:
            errors.append(
                f"{pack}: {vuln_id}: {check_type} is reserved for "
                f"{expected_vuln_id}"
            )


def _bounded_string(value: Any, maximum: int = 1024) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value.encode("utf-8")) <= maximum
        and not any(ord(character) < 32 for character in value)
    )


def _validate_value_ref(
    pack: str, vuln_id: str, value: Any, errors: list[str], *, in_row: bool
) -> None:
    if not isinstance(value, dict) or set(value) - {"scope", "pointer"}:
        errors.append(f"{pack}: {vuln_id}: predicate value reference is invalid")
        return
    scope = value.get("scope", "root")
    if scope not in {"root", "current_row"} or (scope == "current_row" and not in_row):
        errors.append(f"{pack}: {vuln_id}: predicate value scope is invalid here")
    pointer = value.get("pointer", "")
    if not isinstance(pointer, str) or len(pointer.encode("utf-8")) > 512:
        errors.append(f"{pack}: {vuln_id}: predicate JSON pointer is invalid")
    elif pointer and (
        not pointer.startswith("/") or len(pointer[1:].split("/")) > 16
    ):
        errors.append(f"{pack}: {vuln_id}: predicate JSON pointer is not bounded")


def _validate_operand(
    pack: str, vuln_id: str, value: Any, errors: list[str], *, in_row: bool
) -> None:
    if not isinstance(value, dict) or value.get("type") not in {"value", "literal"}:
        errors.append(f"{pack}: {vuln_id}: predicate operand is invalid")
        return
    if value["type"] == "value":
        if set(value) != {"type", "value"}:
            errors.append(f"{pack}: {vuln_id}: value operand fields are invalid")
        _validate_value_ref(pack, vuln_id, value.get("value"), errors, in_row=in_row)
    else:
        if set(value) != {"type", "value"} or isinstance(
            value.get("value"), (dict, list)
        ):
            errors.append(f"{pack}: {vuln_id}: literal operand must be scalar")
        if isinstance(value.get("value"), str) and not _bounded_string(value["value"]):
            errors.append(f"{pack}: {vuln_id}: predicate literal is not bounded")


def _validate_predicate_input(
    pack: str, vuln_id: str, value: Any, errors: list[str]
) -> None:
    if not isinstance(value, dict):
        errors.append(f"{pack}: {vuln_id}: predicate input parser is invalid")
        return
    input_type = value.get("type")
    allowed_fields = {
        "text": {"type"},
        "json": {"type"},
        "key_value": {"type", "separator", "comment_prefixes"},
        "delimited_table": {"type", "delimiter", "comment_prefixes"},
        "structured_config": {"type", "comment_prefixes", "block_separators"},
    }
    if input_type not in allowed_fields or set(value) - allowed_fields[input_type]:
        errors.append(f"{pack}: {vuln_id}: predicate input parser fields are invalid")
        return
    separator_name = (
        "separator" if input_type == "key_value" else "delimiter"
        if input_type == "delimited_table"
        else None
    )
    if separator_name is not None:
        separator = value.get(separator_name)
        if (
            not isinstance(separator, str)
            or not separator
            or len(separator.encode("utf-8")) > 8
            or any(ord(character) < 32 for character in separator)
        ):
            errors.append(f"{pack}: {vuln_id}: predicate input separator is invalid")
    for field in ("comment_prefixes", "block_separators"):
        if field in value:
            tokens = value[field]
            if (
                not isinstance(tokens, list)
                or len(tokens) > 16
                or any(not _bounded_string(token) for token in tokens)
            ):
                errors.append(f"{pack}: {vuln_id}: predicate input {field} is invalid")


def _validate_predicate_ast(
    pack: str,
    vuln_id: str,
    predicate: Any,
    errors: list[str],
    *,
    depth: int,
    nodes: list[int],
    in_row: bool,
) -> None:
    if depth > 16:
        errors.append(f"{pack}: {vuln_id}: predicate AST exceeds depth 16")
        return
    nodes[0] += 1
    if nodes[0] > 256:
        errors.append(f"{pack}: {vuln_id}: predicate AST exceeds 256 nodes")
        return
    if not isinstance(predicate, dict):
        errors.append(f"{pack}: {vuln_id}: predicate AST node must be an object")
        return
    operation = predicate.get("op")
    if operation in {"all", "any"}:
        children = predicate.get("predicates")
        if set(predicate) != {"op", "predicates"} or not isinstance(children, list) or not 1 <= len(children) <= 64:
            errors.append(f"{pack}: {vuln_id}: {operation} requires 1-64 predicates")
            return
        for child in children:
            _validate_predicate_ast(
                pack, vuln_id, child, errors, depth=depth + 1, nodes=nodes, in_row=in_row
            )
    elif operation == "not":
        if set(predicate) != {"op", "predicate"}:
            errors.append(f"{pack}: {vuln_id}: not predicate fields are invalid")
            return
        _validate_predicate_ast(
            pack,
            vuln_id,
            predicate.get("predicate"),
            errors,
            depth=depth + 1,
            nodes=nodes,
            in_row=in_row,
        )
    elif operation == "present":
        if set(predicate) != {"op", "value"}:
            errors.append(f"{pack}: {vuln_id}: present predicate fields are invalid")
        _validate_value_ref(pack, vuln_id, predicate.get("value"), errors, in_row=in_row)
    elif operation == "equal":
        if set(predicate) - {"op", "left", "right", "case_sensitive"}:
            errors.append(f"{pack}: {vuln_id}: equal predicate fields are invalid")
        _validate_operand(pack, vuln_id, predicate.get("left"), errors, in_row=in_row)
        _validate_operand(pack, vuln_id, predicate.get("right"), errors, in_row=in_row)
        if "case_sensitive" in predicate and not isinstance(predicate["case_sensitive"], bool):
            errors.append(f"{pack}: {vuln_id}: case_sensitive must be boolean")
    elif operation == "in_set":
        if set(predicate) - {"op", "value", "values", "case_sensitive"}:
            errors.append(f"{pack}: {vuln_id}: in_set predicate fields are invalid")
        _validate_operand(pack, vuln_id, predicate.get("value"), errors, in_row=in_row)
        values = predicate.get("values")
        if not isinstance(values, list) or not 1 <= len(values) <= 128 or any(
            isinstance(value, (dict, list)) for value in values
        ):
            errors.append(f"{pack}: {vuln_id}: in_set requires 1-128 scalar values")
        elif any(isinstance(value, str) and not _bounded_string(value) for value in values):
            errors.append(f"{pack}: {vuln_id}: in_set contains an unbounded string")
        if "case_sensitive" in predicate and not isinstance(predicate["case_sensitive"], bool):
            errors.append(f"{pack}: {vuln_id}: case_sensitive must be boolean")
    elif operation == "numeric_range":
        if set(predicate) - {"op", "value", "min", "max", "include_min", "include_max"}:
            errors.append(f"{pack}: {vuln_id}: numeric_range fields are invalid")
        _validate_operand(pack, vuln_id, predicate.get("value"), errors, in_row=in_row)
        bounds = [predicate.get(name) for name in ("min", "max") if name in predicate]
        if not bounds or any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or abs(value) > MAX_SAFE_NUMBER
            for value in bounds
        ):
            errors.append(f"{pack}: {vuln_id}: numeric_range needs finite bounds")
        for field in ("include_min", "include_max"):
            if field in predicate and not isinstance(predicate[field], bool):
                errors.append(f"{pack}: {vuln_id}: {field} must be boolean")
    elif operation == "ordered":
        if set(predicate) != {"op", "left", "relation", "right", "value_type"}:
            errors.append(f"{pack}: {vuln_id}: ordered predicate fields are invalid")
        _validate_operand(pack, vuln_id, predicate.get("left"), errors, in_row=in_row)
        _validate_operand(pack, vuln_id, predicate.get("right"), errors, in_row=in_row)
        if predicate.get("relation") not in {
            "less_than", "less_than_or_equal", "greater_than", "greater_than_or_equal"
        } or predicate.get("value_type") not in {"number", "string"}:
            errors.append(f"{pack}: {vuln_id}: ordered relation/type is invalid")
    elif operation == "table_rows":
        if set(predicate) - {"op", "rows", "quantifier", "predicate", "require_nonempty"}:
            errors.append(f"{pack}: {vuln_id}: table_rows fields are invalid")
        _validate_value_ref(pack, vuln_id, predicate.get("rows"), errors, in_row=in_row)
        if predicate.get("quantifier") not in {"every", "any", "none"}:
            errors.append(f"{pack}: {vuln_id}: table_rows quantifier is invalid")
        if "require_nonempty" in predicate and not isinstance(
            predicate["require_nonempty"], bool
        ):
            errors.append(f"{pack}: {vuln_id}: require_nonempty must be boolean")
        _validate_predicate_ast(
            pack,
            vuln_id,
            predicate.get("predicate"),
            errors,
            depth=depth + 1,
            nodes=nodes,
            in_row=True,
        )
    else:
        errors.append(f"{pack}: {vuln_id}: unsupported predicate operation {operation!r}")


def _validate_predicate_program(
    pack: str, vuln_id: str, program: Any, errors: list[str]
) -> None:
    if not isinstance(program, dict) or set(program) != {
        "schema_version", "source", "input", "predicate"
    }:
        errors.append(f"{pack}: {vuln_id}: predicate program fields are invalid")
        return
    if program.get("schema_version") != 1:
        errors.append(f"{pack}: {vuln_id}: predicate schema_version must be 1")
    source = program.get("source")
    if not isinstance(source, dict) or source.get("type") not in {
        "network_config", "observation"
    }:
        errors.append(f"{pack}: {vuln_id}: predicate source is invalid")
    elif source["type"] == "network_config" and set(source) != {"type"}:
        errors.append(f"{pack}: {vuln_id}: network_config source accepts no fields")
    elif source["type"] == "observation" and (
        set(source) != {"type", "key"} or not _bounded_string(source.get("key"))
    ):
        errors.append(f"{pack}: {vuln_id}: observation source key is invalid")
    _validate_predicate_input(pack, vuln_id, program.get("input"), errors)
    _validate_predicate_ast(
        pack,
        vuln_id,
        program.get("predicate"),
        errors,
        depth=1,
        nodes=[0],
        in_row=False,
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
        check_value = check_definition.get("check")
        check_type = check_value.get("type") if isinstance(check_value, dict) else None
        required_class = (
            "declarative_predicate"
            if check_type == "predicate"
            else "legacy_declarative"
            if check_type in LEGACY_DECLARATIVE_TYPES
            else "reviewed_imperative"
        )
        implementation_class = check_definition.get("implementation_class")
        if implementation_class not in IMPLEMENTATION_CLASSES:
            errors.append(
                f"{name}: {vuln_id}: implementation_class must be explicitly classified"
            )
        elif implementation_class != required_class:
            errors.append(
                f"{name}: {vuln_id}: implementation_class must be {required_class!r}"
            )
        introduction_release = check_definition.get("introduction_release")
        parts = introduction_release.split(".") if isinstance(introduction_release, str) else []
        if len(parts) not in (2, 3) or any(
            not part.isdigit() or (len(part) > 1 and part.startswith("0"))
            for part in parts
        ):
            errors.append(
                f"{name}: {vuln_id}: introduction_release must be numeric MAJOR.MINOR[.PATCH]"
            )
        if check_type == "predicate" and check_definition.get("expected") != {"type": "is_true"}:
            errors.append(
                f"{name}: {vuln_id}: predicate checks must use expected.type=is_true"
            )
        _validate_check(name, vuln_id, check_value, errors)
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
