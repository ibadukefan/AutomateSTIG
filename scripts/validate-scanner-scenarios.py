#!/usr/bin/env python3
"""Validate synthetic scanner-first analyst and manager scenarios.

The validator intentionally uses only the Python standard library so the
fixtures remain usable in air-gapped development and release checks.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
ROOT = REPO / "fixtures" / "scanner_scenarios"
SCENARIOS = ROOT / "scenarios"
SUPPORTED = REPO / "content" / "supported-targets.json"

TOP_LEVEL_KEYS = {
    "schema",
    "id",
    "actors",
    "mode",
    "target",
    "input",
    "destination",
    "remote_state",
    "delivery_attempts",
    "receipt",
    "expected",
    "notes",
}
TARGET_KEYS = {
    "profile_id",
    "stig_id",
    "stig_release",
    "hostname",
    "software_version",
}
EXPECTED_KEYS = {
    "evaluation",
    "collection_complete",
    "automated_results",
    "manual_untouched",
    "out_of_scope_untouched",
    "run_state",
    "delivery_state",
    "creates",
    "updates",
    "unchanged",
    "conflicts",
    "review_write_count",
    "handoff",
}
FORBIDDEN_SECRET_KEYS = {
    "access_token",
    "client_secret",
    "password",
    "passphrase",
    "private_key",
    "refresh_token",
    "secret",
}
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SCENARIO_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")
FULL_BENCHMARK_RULES = {
    "netapp_ontap9": 29,
    "freebsd_gpos": 203,
    "cisco_ios_xe_router_ndm": 42,
}
EXPECTED_INPUTS = {
    "netapp_ontap9": {
        "pass": "../ontap/ontap_evidence_compliant.json",
        "fail": "../ontap/ontap_evidence_findings.json",
        "incomplete": "../ontap/ontap_evidence_transport_failure.json",
    },
    "freebsd_gpos": {
        "pass": "../bsd/bsd_evidence_compliant.json",
        "fail": "../bsd/bsd_evidence_findings.json",
        "incomplete": "../bsd/bsd_evidence_transport_failure.json",
    },
    "cisco_ios_xe_router_ndm": {
        "pass": "../network/ios_xe_router_compliant.txt",
        "fail": "../network/ios_xe_router_findings.txt",
        "incomplete": "inputs/cisco-truncated.cfg",
    },
}


class ValidationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{path.relative_to(REPO)}: invalid JSON: {error}")


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        fail(
            f"{label} keys differ: missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def resolve_fixture(relative: str, label: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        fail(f"{label} must be a nonempty relative path")
    path = (ROOT / relative).resolve()
    try:
        path.relative_to(REPO)
    except ValueError:
        fail(f"{label} escapes the repository: {relative}")
    if not path.is_file():
        fail(f"{label} does not exist: {relative}")
    return path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def find_forbidden_keys(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_SECRET_KEYS:
                findings.append(f"{path}.{key}")
            findings.extend(find_forbidden_keys(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(find_forbidden_keys(child, f"{path}[{index}]"))
    return findings


def validate_input(scenario: dict[str, Any], profile: dict[str, Any], label: str) -> None:
    document = require_dict(scenario["input"], f"{label}.input")
    allowed = {"kind", "path", "sha256", "organization_policy"}
    required = {"kind", "path", "sha256"}
    if not required.issubset(document) or not set(document).issubset(allowed):
        fail(f"{label}.input has missing or unsupported fields")

    expected_kind = (
        "running_configuration"
        if profile["evidence_mode"] == "running_configuration"
        else "evidence_v2"
    )
    if document["kind"] != expected_kind:
        fail(f"{label}.input.kind must be {expected_kind}")
    expected_path = EXPECTED_INPUTS[scenario["target"]["profile_id"]][
        scenario["expected"]["evaluation"]
    ]
    if document["path"] != expected_path:
        fail(f"{label} does not reference its established deterministic input oracle")
    if not isinstance(document["sha256"], str) or not SHA256_RE.fullmatch(document["sha256"]):
        fail(f"{label}.input.sha256 must be lowercase SHA-256")
    input_path = resolve_fixture(document["path"], f"{label}.input.path")
    actual_sha = sha256(input_path)
    if actual_sha != document["sha256"]:
        fail(
            f"{label}.input SHA mismatch: expected {document['sha256']}, got {actual_sha}"
        )

    target = scenario["target"]
    expected = scenario["expected"]
    if expected_kind == "evidence_v2":
        evidence = require_dict(load_json(input_path), f"{label}.evidence")
        if evidence.get("schema") != "automatestig-evidence/v2":
            fail(f"{label} must use strict evidence v2")
        if evidence.get("hostname") != target["hostname"]:
            fail(f"{label} evidence hostname does not match the selected target")
        if evidence.get("complete") is not expected["collection_complete"]:
            fail(f"{label} evidence completeness does not match the expected run")
        if "organization_policy" in document:
            fail(f"{label} evidence input cannot carry an organization policy")
        return

    text = input_path.read_text(encoding="utf-8")
    hostnames = re.findall(r"(?im)^\s*hostname\s+(\S+)\s*$", text)
    if hostnames != [target["hostname"]]:
        fail(f"{label} configuration must contain exactly the selected hostname")
    versions = re.findall(r"(?im)^\s*version\s+(\d+)\.", text)
    if versions != [target["software_version"].split(".", 1)[0]]:
        fail(f"{label} configuration version does not match target fingerprint")
    lines = text.rstrip().splitlines()
    complete_config = bool(lines and lines[-1].strip() == "end")
    if complete_config is not expected["collection_complete"]:
        fail(f"{label} configuration completeness does not match expected result")

    policy_ref = require_dict(
        document.get("organization_policy"), f"{label}.input.organization_policy"
    )
    require_exact_keys(
        policy_ref, {"path", "sha256", "signature"}, f"{label}.organization_policy"
    )
    if policy_ref["signature"] != "ephemeral_test_signature_required":
        fail(f"{label} must require an ephemeral test signature")
    policy_path = resolve_fixture(policy_ref["path"], f"{label}.organization_policy.path")
    if not isinstance(policy_ref["sha256"], str) or not SHA256_RE.fullmatch(
        policy_ref["sha256"]
    ):
        fail(f"{label} organization-policy digest is invalid")
    if sha256(policy_path) != policy_ref["sha256"]:
        fail(f"{label} organization-policy SHA mismatch")
    policy = require_dict(load_json(policy_path), f"{label}.organization_policy")
    if policy.get("schema") != "automatestig-organization-policy/v1":
        fail(f"{label} has an unsupported organization-policy schema")
    if policy.get("asset_hostname") != target["hostname"]:
        fail(f"{label} organization policy is not bound to the selected hostname")
    if policy.get("stig_id") != target["stig_id"] or policy.get("stig_release") != target["stig_release"]:
        fail(f"{label} organization policy STIG binding is wrong")


def validate_destination(scenario: dict[str, Any], label: str) -> dict[str, Any] | None:
    destination = scenario["destination"]
    if scenario["mode"] == "disconnected":
        if destination is not None or scenario["remote_state"] is not None:
            fail(f"{label} disconnected mode cannot have remote destination state")
        if scenario["delivery_attempts"]:
            fail(f"{label} disconnected mode cannot have delivery attempts")
        return None

    destination = require_dict(destination, f"{label}.destination")
    require_exact_keys(
        destination,
        {"inventory_path", "collection_id", "asset_id", "assignment_id"},
        f"{label}.destination",
    )
    inventory_path = resolve_fixture(destination["inventory_path"], f"{label}.inventory_path")
    inventory = require_dict(load_json(inventory_path), f"{label}.inventory")
    if inventory.get("schema") != "automatestig-synthetic-stig-manager-inventory/v1":
        fail(f"{label} has an unsupported synthetic inventory schema")
    if not str(inventory.get("api_url", "")).startswith("https://") or not str(
        inventory.get("api_url", "")
    ).split("/", 3)[2].endswith(".invalid"):
        fail(f"{label} inventory must use a synthetic HTTPS .invalid destination")
    if inventory.get("collection", {}).get("collection_id") != destination["collection_id"]:
        fail(f"{label} selected collection is not in the inventory fixture")

    asset = next(
        (
            item
            for item in inventory.get("assets", [])
            if item.get("asset_id") == destination["asset_id"]
        ),
        None,
    )
    if asset is None:
        fail(f"{label} selected asset does not already exist")
    if asset.get("name") != scenario["target"]["hostname"]:
        fail(f"{label} selected asset name does not match device identity")
    assignment = next(
        (
            item
            for item in asset.get("assignments", [])
            if item.get("assignment_id") == destination["assignment_id"]
        ),
        None,
    )
    if assignment is None:
        fail(f"{label} selected assignment does not already exist")
    if (
        assignment.get("stig_id") != scenario["target"]["stig_id"]
        or assignment.get("stig_release") != scenario["target"]["stig_release"]
    ):
        fail(f"{label} selected assignment is not the exact scanner revision")
    expected_rule_count = FULL_BENCHMARK_RULES[scenario["target"]["profile_id"]]
    if assignment.get("rule_count") != expected_rule_count:
        fail(f"{label} assignment benchmark rule count is wrong")

    remote_path = resolve_fixture(scenario["remote_state"], f"{label}.remote_state")
    remote = require_dict(load_json(remote_path), f"{label}.remote_state")
    if remote.get("schema") != "automatestig-synthetic-remote-review-state/v1":
        fail(f"{label} has an unsupported remote-review schema")
    return remote


def expected_preview(
    scenario: dict[str, Any], automated: int, remote: dict[str, Any] | None
) -> tuple[int, int, int, int, int]:
    expected = scenario["expected"]
    if not expected["collection_complete"] or scenario["mode"] == "disconnected":
        return (0, 0, 0, 0, 0)
    assert remote is not None
    selector = remote.get("selector")
    proposed = "not_a_finding" if expected["evaluation"] == "pass" else "open"
    if selector == "none":
        return (automated, 0, 0, 0, 0)
    if selector == "all_scanner_owned" and remote.get("ownership") == "automatestig":
        if remote.get("result") == proposed:
            return (0, 0, automated, 0, 0)
        return (0, automated, 0, 0, 0)
    if selector == "specific" and remote.get("ownership") == "human":
        conflict_ids = remote.get("conflict_vuln_ids")
        if not isinstance(conflict_ids, list) or not conflict_ids:
            fail(f"{scenario['id']} human conflict state needs vulnerability IDs")
        conflicts = len(set(conflict_ids))
        if conflicts != len(conflict_ids) or conflicts > automated:
            fail(f"{scenario['id']} conflict vulnerability IDs are invalid")
        return (automated - conflicts, 0, 0, conflicts, 0)
    fail(f"{scenario['id']} has an unsupported synthetic remote state")


def validate_attempts(scenario: dict[str, Any], label: str) -> None:
    attempts = scenario["delivery_attempts"]
    if not isinstance(attempts, list):
        fail(f"{label}.delivery_attempts must be an array")
    digests: set[str] = set()
    for index, attempt in enumerate(attempts, start=1):
        attempt = require_dict(attempt, f"{label}.delivery_attempts[{index - 1}]")
        require_exact_keys(
            attempt,
            {"attempt", "outcome", "http_status", "payload_sha256"},
            f"{label}.delivery_attempts[{index - 1}]",
        )
        if attempt["attempt"] != index:
            fail(f"{label} delivery attempts must be consecutively numbered")
        if not isinstance(attempt["payload_sha256"], str) or not SHA256_RE.fullmatch(
            attempt["payload_sha256"]
        ):
            fail(f"{label} delivery payload digest is invalid")
        digests.add(attempt["payload_sha256"])
        if attempt["outcome"] == "transient_error":
            if attempt["http_status"] != 429 and attempt["http_status"] < 500:
                fail(f"{label} transient error needs HTTP 429 or 5xx")
        elif attempt["outcome"] == "delivered":
            if not 200 <= attempt["http_status"] < 300:
                fail(f"{label} delivered attempt needs HTTP 2xx")
        else:
            fail(f"{label} has an unsupported delivery outcome")
    if len(digests) > 1:
        fail(f"{label} retry changed the immutable payload digest")
    if len(attempts) > 1 and any(
        attempt["outcome"] != "transient_error" for attempt in attempts[:-1]
    ):
        fail(f"{label} retry attempts before the receipt must be transient failures")
    if attempts and attempts[-1]["outcome"] != "delivered":
        fail(f"{label} fixture attempts must end with a delivered receipt")


def validate_receipt(scenario: dict[str, Any], label: str) -> None:
    receipt_ref = scenario["receipt"]
    expected = scenario["expected"]
    if expected["delivery_state"] != "delivered":
        if receipt_ref is not None:
            fail(f"{label} non-delivered run cannot have a remote receipt")
        return
    receipt_path = resolve_fixture(receipt_ref, f"{label}.receipt")
    receipt = require_dict(load_json(receipt_path), f"{label}.receipt")
    required = {
        "schema",
        "scenario_id",
        "delivery_id",
        "collection_id",
        "asset_id",
        "assignment_id",
        "request_sha256",
        "attempt_count",
        "created",
        "updated",
        "unchanged",
        "delivered_at",
        "remote_url",
    }
    require_exact_keys(receipt, required, f"{label}.receipt")
    if receipt["schema"] != "automatestig-synthetic-delivery-receipt/v1":
        fail(f"{label} has an unsupported receipt schema")
    if receipt["scenario_id"] != scenario["id"]:
        fail(f"{label} receipt is bound to another scenario")
    destination = scenario["destination"]
    if any(
        receipt[key] != destination[key]
        for key in ("collection_id", "asset_id", "assignment_id")
    ):
        fail(f"{label} receipt destination binding is wrong")
    attempts = scenario["delivery_attempts"]
    if (
        receipt["request_sha256"] != attempts[-1]["payload_sha256"]
        or receipt["attempt_count"] != len(attempts)
    ):
        fail(f"{label} receipt does not bind the immutable delivery attempts")
    if (
        receipt["created"] != expected["creates"]
        or receipt["updated"] != expected["updates"]
        or receipt["unchanged"] != expected["unchanged"]
    ):
        fail(f"{label} receipt review counts differ from the preview")
    remote_url = str(receipt["remote_url"])
    if not remote_url.startswith("https://") or not remote_url.split("/", 3)[2].endswith(
        ".invalid"
    ):
        fail(f"{label} receipt must use a synthetic HTTPS .invalid link")


def validate_scenario(
    path: Path, profiles: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    scenario = require_dict(load_json(path), path.name)
    label = path.stem
    require_exact_keys(scenario, TOP_LEVEL_KEYS, label)
    if scenario["schema"] != "automatestig-scanner-scenario/v1":
        fail(f"{label} has an unsupported schema")
    if scenario["id"] != label or not SCENARIO_ID_RE.fullmatch(label):
        fail(f"{label} id must match its filename")
    actors = scenario["actors"]
    if (
        not isinstance(actors, list)
        or not actors
        or len(set(actors)) != len(actors)
        or not set(actors).issubset({"cybersecurity_analyst", "cybersecurity_manager"})
    ):
        fail(f"{label} actors are invalid")
    if scenario["mode"] not in {"connected", "disconnected"}:
        fail(f"{label} mode is invalid")

    target = require_dict(scenario["target"], f"{label}.target")
    require_exact_keys(target, TARGET_KEYS, f"{label}.target")
    profile = profiles.get(target["profile_id"])
    if profile is None:
        fail(f"{label} references unsupported profile {target['profile_id']!r}")
    if target["stig_id"] != profile["stig_id"] or target["stig_release"] != profile["stig_release"]:
        fail(f"{label} does not use the exact supported STIG release")
    if not isinstance(target["software_version"], str) or not target["software_version"].strip():
        fail(f"{label} must include an observed software version")
    major_match = re.match(r"^(\d+)", target["software_version"])
    major = int(major_match.group(1)) if major_match else None
    compatible = {
        "netapp_ontap9": major == 9,
        "freebsd_gpos": major in {13, 14},
        "cisco_ios_xe_router_ndm": major == 17,
    }[target["profile_id"]]
    if not compatible:
        fail(f"{label} software version is outside the profile compatibility boundary")

    expected = require_dict(scenario["expected"], f"{label}.expected")
    require_exact_keys(expected, EXPECTED_KEYS, f"{label}.expected")
    if expected["evaluation"] not in {"pass", "fail", "incomplete"}:
        fail(f"{label} expected evaluation is invalid")
    complete = expected["evaluation"] != "incomplete"
    if expected["collection_complete"] is not complete:
        fail(f"{label} incomplete state and completeness disagree")
    automated = profile["expected_automated_checks"]
    reviewed = profile["expected_reviewed_rules"]
    if expected["automated_results"] != (automated if complete else 0):
        fail(f"{label} automated result count is wrong")
    if expected["manual_untouched"] != reviewed - automated:
        fail(f"{label} manual untouched count is wrong")
    if expected["out_of_scope_untouched"] != FULL_BENCHMARK_RULES[target["profile_id"]] - reviewed:
        fail(f"{label} out-of-scope untouched count is wrong")
    if not isinstance(scenario["notes"], list) or not scenario["notes"]:
        fail(f"{label} needs explanatory notes")

    validate_input(scenario, profile, label)
    remote = validate_destination(scenario, label)
    coverage_path = (REPO / profile["coverage_manifest"]).resolve()
    coverage = require_dict(load_json(coverage_path), f"{label}.coverage")
    automated_ids = {
        rule.get("vuln_id")
        for rule in coverage.get("rules", [])
        if rule.get("classification") == "automated"
    }
    if len(automated_ids) != automated:
        fail(f"{label} coverage manifest automated count is wrong")
    if remote is not None and not set(remote.get("conflict_vuln_ids", [])).issubset(
        automated_ids
    ):
        fail(f"{label} conflict state names a non-scanner-owned rule")
    validate_attempts(scenario, label)
    validate_receipt(scenario, label)
    preview = expected_preview(scenario, automated, remote)
    actual_preview = tuple(
        expected[key]
        for key in ("creates", "updates", "unchanged", "conflicts", "review_write_count")
    )
    if actual_preview != preview:
        fail(f"{label} sparse preview expected {preview}, found {actual_preview}")

    if not complete:
        if (
            expected["run_state"] != "incomplete"
            or expected["delivery_state"] != "none"
            or expected["handoff"]
            or scenario["delivery_attempts"]
        ):
            fail(f"{label} incomplete run must be diagnostic-only")
    elif scenario["mode"] == "disconnected":
        if (
            expected["run_state"] != "preview_ready"
            or expected["delivery_state"] != "none"
            or not expected["handoff"]
        ):
            fail(f"{label} disconnected complete run needs one selected-run handoff")
    elif expected["conflicts"]:
        if (
            expected["run_state"] != "conflicted"
            or expected["delivery_state"] != "conflicted"
            or expected["review_write_count"] != 0
            or not expected["handoff"]
            or scenario["delivery_attempts"]
        ):
            fail(
                f"{label} human conflict must block every review write and retain a handoff"
            )
    elif expected["creates"] or expected["updates"]:
        if (
            expected["run_state"] != "preview_ready"
            or expected["delivery_state"] != "preview_ready"
            or expected["review_write_count"] != 0
            or not expected["handoff"]
            or scenario["delivery_attempts"]
        ):
            fail(
                f"{label} changed reviews require a zero-write preview and selected-run handoff"
            )
    elif expected["unchanged"]:
        if (
            expected["run_state"] != "delivered"
            or expected["delivery_state"] != "delivered"
            or expected["review_write_count"] != 0
            or not expected["handoff"]
            or not scenario["delivery_attempts"]
        ):
            fail(f"{label} exact no-op delivery needs a receipt and retained handoff")
    else:
        fail(f"{label} connected complete run has no review disposition")
    return scenario


def main() -> int:
    try:
        supported = require_dict(load_json(SUPPORTED), "supported-targets")
        profiles = require_dict(supported.get("targets"), "supported-targets.targets")
        if set(profiles) != {
            "netapp_ontap9",
            "freebsd_gpos",
            "cisco_ios_xe_router_ndm",
        }:
            fail("scenario validator requires the exact three scanner profiles")
        load_json(ROOT / "scenario.schema.json")

        for json_path in sorted(ROOT.rglob("*.json")):
            document = load_json(json_path)
            forbidden = find_forbidden_keys(document)
            if forbidden:
                fail(
                    f"{json_path.relative_to(REPO)} contains forbidden secret fields: "
                    + ", ".join(forbidden)
                )

        scenario_paths = sorted(SCENARIOS.glob("*.json"))
        if not scenario_paths:
            fail("no scanner scenarios found")
        scenarios = [validate_scenario(path, profiles) for path in scenario_paths]

        matrix: dict[str, set[str]] = {profile_id: set() for profile_id in profiles}
        modes: set[str] = set()
        actors: set[str] = set()
        has_retry = False
        has_conflict = False
        for scenario in scenarios:
            matrix[scenario["target"]["profile_id"]].add(scenario["expected"]["evaluation"])
            modes.add(scenario["mode"])
            actors.update(scenario["actors"])
            has_retry |= len(scenario["delivery_attempts"]) > 1
            has_conflict |= scenario["expected"]["conflicts"] > 0
        for profile_id, outcomes in matrix.items():
            if outcomes != {"pass", "fail", "incomplete"}:
                fail(f"{profile_id} scenario outcomes are incomplete: {sorted(outcomes)}")
        if modes != {"connected", "disconnected"}:
            fail("scenario matrix must cover connected and disconnected modes")
        if actors != {"cybersecurity_analyst", "cybersecurity_manager"}:
            fail("scenario matrix must cover analyst and manager roles")
        if not has_retry or not has_conflict:
            fail("scenario matrix must cover both retry and human-review conflict")

        print(
            f"validated {len(scenarios)} scanner scenarios across "
            f"{len(profiles)} exact profiles; synthetic secret scan passed"
        )
        for profile_id in sorted(matrix):
            print(f"  {profile_id}: {', '.join(sorted(matrix[profile_id]))}")
        return 0
    except ValidationError as error:
        print(f"scanner scenario validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
