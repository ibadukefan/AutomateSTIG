#!/usr/bin/env python3
"""Generate static per-target release scorecards without making release claims."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from adapter_tooling import (
    ToolingError,
    absent_output_directory,
    canonical_text_sha256,
    canonical_json,
    load_repo_json,
    sha256,
    validate_nonempty,
    validate_stig_release,
    validate_target_key,
    write_new_bundle,
)


CLASSIFICATIONS = ("automated", "manual", "not_applicable", "unsupported")
IMPLEMENTATION_CLASSES = (
    "declarative_predicate",
    "legacy_declarative",
    "reviewed_imperative",
    "unknown",
)
DECLARATIVE_IMPLEMENTATION_CLASSES = {
    "declarative_predicate",
    "legacy_declarative",
}
GATE_KEYS = (
    "rule_classification",
    "automation_depth",
    "safety",
    "traceability",
    "collection_reliability",
    "version_handling",
    "transport_reuse",
    "declarative_checks",
    "delivery_integrity",
    "human_review_safety",
    "interchange",
    "first_use_ux",
    "content_maintenance",
)


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ToolingError(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ToolingError(f"{label} must be a string")
    return validate_nonempty(value, label, maximum=500)


def _acceptance_metadata(
    target: dict[str, Any],
    release_evidence: tuple[str, dict[str, Any], bytes] | None,
) -> dict[str, Any]:
    gate_name = _string(target.get("acceptance_gate"), "acceptance gate")
    if release_evidence is None:
        return {
            "gate": gate_name,
            "release_evidence_supplied": False,
            "reported_gate": None,
            "generator_verified_live_acceptance": False,
            "interpretation": "No release-evidence document was supplied; live acceptance is not claimed.",
        }

    source_name, document, raw = release_evidence
    if document.get("schema") != "automatestig-release-evidence/v1":
        raise ToolingError("release evidence has an unsupported schema")
    tag = _string(document.get("tag"), "release evidence tag")
    acceptance = document.get("acceptance")
    if not isinstance(acceptance, dict) or gate_name not in acceptance:
        raise ToolingError(f"release evidence does not contain acceptance gate {gate_name!r}")
    gate = acceptance[gate_name]
    if not isinstance(gate, dict):
        raise ToolingError(f"release acceptance gate {gate_name!r} must be an object")
    reported_status = _string(gate.get("status"), "reported acceptance status")
    reported = {
        "status": reported_status,
        "executed_at": _string(gate.get("executed_at"), "acceptance executed_at"),
        "environment": _string(gate.get("environment"), "acceptance environment"),
        "version": _string(gate.get("version"), "accepted target version"),
        "evidence_reference": _string(
            gate.get("evidence_reference"), "acceptance evidence reference"
        ),
        "evidence_sha256": _string(
            gate.get("evidence_sha256"), "acceptance evidence SHA-256"
        ),
    }
    if len(reported["evidence_sha256"]) != 64 or any(
        character not in "0123456789abcdef" for character in reported["evidence_sha256"]
    ):
        raise ToolingError("acceptance evidence SHA-256 must be 64 lowercase hexadecimal characters")
    return {
        "gate": gate_name,
        "release_evidence_supplied": True,
        "release_evidence": {
            "source": source_name,
            "sha256": sha256(raw),
            "tag": tag,
        },
        "reported_gate": reported,
        "generator_verified_live_acceptance": False,
        "interpretation": (
            "The generator records reported gate metadata but does not authenticate the protected "
            "workflow artifact, reviewers, device custody, or live result. It makes no live-acceptance claim."
        ),
    }


def _gate_summary(
    full_rules: int,
    reviewed_rules: int,
    automated_rules: int,
    validated_automated_rules: int,
    acceptance: dict[str, Any],
    automation: dict[str, Any],
) -> list[dict[str, Any]]:
    classified_status = "metadata_complete" if reviewed_rules == full_rules else "not_met"
    acceptance_status = (
        "human_evidence_referenced_not_verified"
        if acceptance["release_evidence_supplied"]
        else "human_evidence_not_supplied"
    )
    gates = {
        "rule_classification": {
            "status": classified_status,
            "numerator": reviewed_rules,
            "denominator": full_rules,
            "explanation": (
                "Every full-benchmark rule has static classification metadata."
                if reviewed_rules == full_rules
                else "The coverage inventory does not classify every full-benchmark rule."
            ),
        },
        "automation_depth": {
            "status": "not_measurable",
            "numerator": automated_rules,
            "denominator": None,
            "explanation": "Technically automatable rule count is not present in the source metadata.",
        },
        "safety": {
            "status": "not_measurable",
            "explanation": "Static metadata does not establish false-pass results across the required error corpus.",
        },
        "traceability": {
            "status": "metadata_present_not_release_proof",
            "numerator": validated_automated_rules,
            "denominator": automated_rules,
            "explanation": "Validation references are inventoried; live decision-to-evidence traceability is not executed here.",
        },
        "collection_reliability": {
            "status": acceptance_status,
            "explanation": "The generator never converts release-gate metadata into a live reliability claim.",
        },
        "version_handling": {
            "status": "not_measurable",
            "explanation": "A machine-readable accepted firmware matrix is not part of these static inputs.",
        },
        "transport_reuse": {
            "status": "not_measurable",
            "explanation": "Duplicate retrieval operations are not measured by the coverage manifest.",
        },
        "declarative_checks": {
            "status": automation["declarative_new_automation_ratio"]["status"],
            "numerator": automation["declarative_new_automation_ratio"]["numerator"],
            "denominator": automation["declarative_new_automation_ratio"]["denominator"],
            "ratio": automation["declarative_new_automation_ratio"]["ratio"],
            "explanation": automation["declarative_new_automation_ratio"]["interpretation"],
        },
        "delivery_integrity": {
            "status": "not_measurable",
            "explanation": "Target metadata does not execute handoff, interruption, conflict, or no-op tests.",
        },
        "human_review_safety": {
            "status": "not_measurable",
            "explanation": "Static target metadata cannot prove remote human reviews remain untouched.",
        },
        "interchange": {
            "status": "not_measurable",
            "explanation": "Receiver mapping and independent STIG Manager readback are external acceptance evidence.",
        },
        "first_use_ux": {
            "status": "human_evidence_not_supplied",
            "explanation": "Representative first-time user completion is a human study gate.",
        },
        "content_maintenance": {
            "status": "not_measurable",
            "explanation": "The inputs do not contain revision triage and validation-plan elapsed time.",
        },
    }
    return [{"gate": key, **gates[key]} for key in GATE_KEYS]


def _release_value(value: Any, label: str) -> str:
    value = _string(value, label)
    parts = value.split(".")
    if len(parts) not in (2, 3) or any(
        not part.isdigit() or (len(part) > 1 and part.startswith("0"))
        for part in parts
    ):
        raise ToolingError(f"{label} must be numeric MAJOR.MINOR[.PATCH]")
    return value


def _automation_metadata(
    checks: list[dict[str, Any]], release_line: str
) -> dict[str, Any]:
    counts = {name: 0 for name in IMPLEMENTATION_CLASSES}
    introductions: dict[str, int] = {}
    unknown_introduction_ids: list[str] = []
    unknown_implementation_ids: list[str] = []
    automations: list[dict[str, Any]] = []
    known_new: list[dict[str, Any]] = []
    for check in checks:
        vuln_id = _string(check.get("vuln_id"), "automation vuln_id")
        executable = check.get("check")
        if not isinstance(executable, dict):
            raise ToolingError(f"{vuln_id} check must be an object")
        check_type = _string(executable.get("type"), f"{vuln_id} check type")
        implementation_class = check.get("implementation_class", "unknown")
        if implementation_class not in counts:
            raise ToolingError(
                f"{vuln_id} has unsupported implementation_class {implementation_class!r}"
            )
        counts[implementation_class] += 1
        if implementation_class == "unknown":
            unknown_implementation_ids.append(vuln_id)
        else:
            expected_class = (
                "declarative_predicate"
                if check_type == "predicate"
                else "legacy_declarative"
                if check_type in {"command", "config_line", "all", "any"}
                else "reviewed_imperative"
            )
            if implementation_class != expected_class:
                raise ToolingError(
                    f"{vuln_id} implementation_class {implementation_class!r} "
                    f"does not match {check_type!r} ({expected_class!r})"
                )
        introduction = check.get("introduction_release")
        if introduction is None:
            unknown_introduction_ids.append(vuln_id)
        else:
            introduction = _release_value(
                introduction, f"{vuln_id} introduction_release"
            )
            introductions[introduction] = introductions.get(introduction, 0) + 1
        entry = {
            "vuln_id": vuln_id,
            "implementation_class": implementation_class,
            "introduction_release": introduction,
        }
        automations.append(entry)
        if introduction == release_line:
            known_new.append(entry)

    declarative_new = sum(
        entry["implementation_class"] in DECLARATIVE_IMPLEMENTATION_CLASSES
        for entry in known_new
    )
    unknown_new = sum(entry["implementation_class"] == "unknown" for entry in known_new)
    measurable = not unknown_introduction_ids and unknown_new == 0
    denominator = len(known_new) if measurable else None
    ratio = (
        declarative_new / denominator
        if denominator is not None and denominator > 0
        else None
    )
    if measurable:
        interpretation = (
            "Static per-automation metadata measures declarative automations introduced in "
            f"release line {release_line}; it does not prove semantic correctness."
        )
        status = "measured_metadata_only"
    else:
        interpretation = (
            "The declarative-new-automation ratio is unknown because one or more automations "
            "lack reviewed implementation-class or introduction-release metadata."
        )
        status = "not_measurable"
    return {
        "automations": sorted(automations, key=lambda item: item["vuln_id"]),
        "implementation_class_counts": counts,
        "introduction_release_counts": dict(sorted(introductions.items())),
        "unknown_implementation_class_vuln_ids": sorted(unknown_implementation_ids),
        "unknown_introduction_release_vuln_ids": sorted(unknown_introduction_ids),
        "declarative_new_automation_ratio": {
            "release_line": release_line,
            "status": status,
            "numerator": declarative_new,
            "denominator": denominator,
            "ratio": ratio,
            "known_new_automations": len(known_new),
            "unknown_new_implementation_classes": unknown_new,
            "interpretation": interpretation,
        },
    }


def _target_scorecard(
    repo: Path,
    target_key: str,
    target: dict[str, Any],
    supported_raw: bytes,
    release_line: str,
    release_evidence: tuple[str, dict[str, Any], bytes] | None,
) -> dict[str, Any]:
    target_key = validate_target_key(target_key)
    display_name = _string(target.get("display_name"), f"{target_key} display name")
    stig_id = _string(target.get("stig_id"), f"{target_key} STIG ID")
    stig_release = validate_stig_release(target.get("stig_release"))
    check_pack_name = _string(target.get("check_pack"), f"{target_key} check pack")
    coverage_name = _string(
        target.get("coverage_manifest"), f"{target_key} coverage manifest"
    )
    full_rules = _integer(
        target.get("expected_benchmark_rules"), f"{target_key} full benchmark rules", 1
    )
    expected_automated = _integer(
        target.get("expected_automated_checks"), f"{target_key} automated checks", 1
    )
    expected_reviewed = _integer(
        target.get("expected_reviewed_rules"), f"{target_key} reviewed rules", 1
    )
    if expected_reviewed > full_rules or expected_automated > expected_reviewed:
        raise ToolingError(f"{target_key} supported-target denominators are inconsistent")

    coverage, coverage_raw = load_repo_json(repo, coverage_name)
    check_pack, check_pack_raw = load_repo_json(repo, check_pack_name)
    profile_name = f"content/scanner_profiles/{target_key}.source.json"
    profile, profile_raw = load_repo_json(repo, profile_name)
    benchmark_name = f"content/scanner_profiles/{target_key}.benchmark.json"
    benchmark, benchmark_raw = load_repo_json(repo, benchmark_name)

    if coverage.get("stig_id") != stig_id or coverage.get("version") != stig_release:
        raise ToolingError(f"{target_key} coverage identity does not match the target contract")
    rules = coverage.get("rules")
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise ToolingError(f"{target_key} coverage rules must be an array of objects")
    if _integer(coverage.get("total_rules"), f"{target_key} coverage total") != len(rules):
        raise ToolingError(f"{target_key} coverage total_rules does not match its rule inventory")
    vuln_ids = [_string(rule.get("vuln_id"), "coverage vuln_id") for rule in rules]
    if len(set(vuln_ids)) != len(vuln_ids):
        raise ToolingError(f"{target_key} coverage contains duplicate vuln_id values")
    counts = {name: 0 for name in CLASSIFICATIONS}
    validated_rule_ids: list[str] = []
    validated_automated_ids: list[str] = []
    validation_references: set[str] = set()
    automated_ids: set[str] = set()
    for rule in rules:
        classification = rule.get("classification")
        if classification not in counts:
            raise ToolingError(f"{target_key} has unsupported classification {classification!r}")
        counts[classification] += 1
        references = rule.get("validated_by")
        if isinstance(references, list) and references and all(
            isinstance(value, str) and value.strip() for value in references
        ):
            validated_rule_ids.append(rule["vuln_id"])
            validation_references.update(references)
            if classification == "automated":
                validated_automated_ids.append(rule["vuln_id"])
        if classification == "automated":
            automated_ids.add(rule["vuln_id"])

    if len(rules) != expected_reviewed or counts["automated"] != expected_automated:
        raise ToolingError(f"{target_key} coverage counts drift from supported-target metadata")
    if check_pack.get("stig_id") != stig_id or check_pack.get("version") != stig_release:
        raise ToolingError(f"{target_key} check-pack identity does not match the target contract")
    checks = check_pack.get("checks")
    if not isinstance(checks, list) or not all(isinstance(check, dict) for check in checks):
        raise ToolingError(f"{target_key} check pack must contain a checks array")
    check_ids = {_string(check.get("vuln_id"), "check-pack vuln_id") for check in checks}
    if len(check_ids) != len(checks) or check_ids != automated_ids:
        raise ToolingError(f"{target_key} executable checks do not match automated coverage")
    automation = _automation_metadata(checks, release_line)

    if (
        profile.get("schema_version") != 1
        or profile.get("target_key") != target_key
        or profile.get("stig_id") != stig_id
        or profile.get("stig_revision") != stig_release
        or profile.get("coverage_manifest") != coverage_name
        or profile.get("coverage_manifest_sha256") != canonical_text_sha256(coverage_raw)
        or profile.get("rule_count") != len(rules)
    ):
        raise ToolingError(f"{target_key} scanner-profile source metadata is inconsistent")
    if profile.get("benchmark_model_sha256") != canonical_text_sha256(benchmark_raw):
        raise ToolingError(f"{target_key} bundled benchmark digest is inconsistent")
    benchmark_rules = benchmark.get("rules")
    if (
        benchmark.get("id") != stig_id
        or f"V{benchmark.get('version')}R{benchmark.get('release')}" != stig_release
        or not isinstance(benchmark_rules, list)
        or len(benchmark_rules) != len(rules)
    ):
        raise ToolingError(f"{target_key} bundled benchmark identity or rule count is inconsistent")

    acceptance = _acceptance_metadata(target, release_evidence)
    outside_reviewed = full_rules - len(rules)
    source_status = _string(coverage.get("status"), f"{target_key} coverage status")
    return {
        "schema": "automatestig-target-release-scorecard/v1",
        "schema_version": 1,
        "release_line": release_line,
        "target": {
            "key": target_key,
            "display_name": display_name,
            "stig_id": stig_id,
            "stig_release": stig_release,
            "platform": _string(target.get("platform"), f"{target_key} platform"),
            "evidence_mode": _string(
                target.get("evidence_mode"), f"{target_key} evidence mode"
            ),
        },
        "source_metadata": {
            "supported_targets": {
                "path": "content/supported-targets.json",
                "sha256_canonical_lf": canonical_text_sha256(supported_raw),
            },
            "coverage": {
                "path": coverage_name,
                "sha256_canonical_lf": canonical_text_sha256(coverage_raw),
                "reported_status": source_status,
            },
            "check_pack": {
                "path": check_pack_name,
                "sha256_canonical_lf": canonical_text_sha256(check_pack_raw),
            },
            "scanner_profile": {
                "path": profile_name,
                "sha256_canonical_lf": canonical_text_sha256(profile_raw),
                "source_archive_sha256": profile.get("source_archive_sha256"),
                "source_xccdf_sha256": profile.get("source_xccdf_sha256"),
                "benchmark_model": {
                    "path": benchmark_name,
                    "sha256_canonical_lf": canonical_text_sha256(benchmark_raw),
                },
            },
        },
        "denominators": {
            "total_benchmark_rules": full_rules,
            "technically_automatable_rules": None,
            "implemented_automated_rules": counts["automated"],
            "manual_rules": counts["manual"],
            "unsupported_rules": counts["unsupported"],
            "not_applicable_rules": counts["not_applicable"],
            "reviewed_profile_rules": len(rules),
            "outside_reviewed_profile_rules": outside_reviewed,
            "collection_error_rules": None,
        },
        "validation_metadata": {
            "rules_with_references": len(validated_rule_ids),
            "automated_rules_with_references": len(validated_automated_ids),
            "automated_rules_total": counts["automated"],
            "missing_rule_references": sorted(set(vuln_ids) - set(validated_rule_ids)),
            "missing_automated_references": sorted(automated_ids - set(validated_automated_ids)),
            "references": sorted(validation_references),
            "interpretation": "References are static inventory, not proof that validation or live acceptance ran for this release.",
        },
        "automation_implementation_metadata": automation,
        "acceptance_metadata": acceptance,
        "release_gates": _gate_summary(
            full_rules,
            len(rules),
            counts["automated"],
            len(validated_automated_ids),
            acceptance,
            automation,
        ),
        "claims": {
            "support_claimed_by_generator": False,
            "live_acceptance_claimed_by_generator": False,
            "better_than_evaluate_stig_claimed": False,
            "comparison_status": "not_directly_comparable",
            "permitted_wording": "Static target metadata inventory; release and live-acceptance claims require independent gates.",
        },
    }


def build_scorecard_bundle(
    repo: Path, release_evidence_name: str | None = None
) -> dict[str, bytes]:
    supported, supported_raw = load_repo_json(repo, "content/supported-targets.json")
    if supported.get("schema_version") != 1:
        raise ToolingError("supported-target contract has an unsupported schema version")
    release_line = _release_value(supported.get("release_line"), "release line")
    targets = supported.get("targets")
    if not isinstance(targets, dict) or not targets:
        raise ToolingError("supported-target contract must contain a non-empty targets object")

    release_evidence = None
    if release_evidence_name is not None:
        document, raw = load_repo_json(repo, release_evidence_name)
        release_evidence = (release_evidence_name, document, raw)

    files: dict[str, bytes] = {}
    scorecards: list[dict[str, Any]] = []
    for target_key in sorted(targets):
        target = targets[target_key]
        if not isinstance(target, dict):
            raise ToolingError(f"supported target {target_key!r} must be an object")
        scorecard = _target_scorecard(
            repo,
            target_key,
            target,
            supported_raw,
            release_line,
            release_evidence,
        )
        scorecards.append(scorecard)
        files[f"{target_key}.scorecard.json"] = canonical_json(scorecard)

    index_targets = []
    for scorecard in scorecards:
        target_key = scorecard["target"]["key"]
        filename = f"{target_key}.scorecard.json"
        index_targets.append(
            {
                "target_key": target_key,
                "display_name": scorecard["target"]["display_name"],
                "scorecard": filename,
                "scorecard_sha256": sha256(files[filename]),
                "support_claimed": False,
                "live_acceptance_claimed": False,
            }
        )
    index = {
        "schema": "automatestig-target-release-scorecard-index/v1",
        "schema_version": 1,
        "release_line": release_line,
        "targets": index_targets,
        "claims": {
            "support_claimed_by_generator": False,
            "live_acceptance_claimed_by_generator": False,
            "better_than_evaluate_stig_claimed": False,
        },
    }
    files["scorecards.index.json"] = canonical_json(index)

    rows = []
    for scorecard in scorecards:
        target = scorecard["target"]
        counts = scorecard["denominators"]
        acceptance = scorecard["acceptance_metadata"]
        acceptance_text = (
            "reported metadata only"
            if acceptance["release_evidence_supplied"]
            else "not supplied"
        )
        declarative = scorecard["automation_implementation_metadata"][
            "declarative_new_automation_ratio"
        ]
        declarative_text = (
            "unknown"
            if declarative["denominator"] is None
            else f"{declarative['numerator']}/{declarative['denominator']}"
        )
        rows.append(
            f"| {target['display_name']} | {target['stig_id']} {target['stig_release']} | "
            f"{counts['implemented_automated_rules']} | {counts['manual_rules']} | "
            f"{counts['outside_reviewed_profile_rules']} | unknown | {declarative_text} | "
            f"{acceptance_text} |"
        )
    files["README.md"] = (
        "# AutomateSTIG target release scorecards\n\n"
        "These deterministic reports inventory checked-in static metadata. They do **not** claim "
        "that any target is supported, live-accepted, or better than Evaluate-STIG. A reported "
        "release-evidence gate remains unverified by this generator.\n\n"
        "| Target | STIG | Implemented automated | Manual | Outside reviewed profile | Technically automatable | Declarative / new automation | Live acceptance |\n"
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |\n"
        + "\n".join(rows)
        + "\n\nUnknown values remain unknown; the generator never converts absent evidence into zero.\n"
    ).encode("utf-8")
    return files


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--output-dir", required=True, help="Absent directory to create")
    parser.add_argument(
        "--release-evidence",
        help="Optional safe repository-relative automatestig-release-evidence/v1 JSON",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        repo = Path(args.repo_root).resolve(strict=True)
        output = absent_output_directory(args.output_dir)
        files = build_scorecard_bundle(repo, args.release_evidence)
        write_new_bundle(output, files)
    except (OSError, ToolingError) as error:
        print(f"target scorecard generation failed: {error}", file=sys.stderr)
        return 1
    print(f"Created {len(files) - 2} non-claiming target scorecards at {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
