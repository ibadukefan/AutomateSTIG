#!/usr/bin/env python3
"""Create a deterministic, explicitly unsupported target-adapter work bundle."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from adapter_tooling import (
    ToolingError,
    absent_output_directory,
    canonical_json,
    sha256,
    validate_nonempty,
    validate_stig_release,
    validate_target_key,
    write_new_bundle,
)


ERROR_FIXTURES = (
    ("malformed-output", "malformed_output"),
    ("permission-denied", "permission_denied"),
    ("timeout", "timeout"),
    ("truncated-output", "truncated_output"),
    ("unsupported-version", "unsupported_version"),
)
RULE_FIXTURES = (
    ("finding", "finding"),
    ("not-a-finding", "not_a_finding"),
)


def _fixture(target_key: str, fixture_id: str, purpose: str) -> dict[str, Any]:
    return {
        "schema": "automatestig-adapter-fixture/v1",
        "schema_version": 1,
        "target_key": target_key,
        "fixture_id": fixture_id,
        "purpose": purpose,
        "synthetic": True,
        "redacted": True,
        "capture": {
            "status": "placeholder",
            "artifact_path": None,
            "artifact_sha256": None,
            "redaction_manifest": [],
        },
        "expected": {
            "contract_status": "not_executable_until_completed",
            "evaluation_outcome": None,
            "handoff_allowed": False,
        },
        "observed": None,
        "notes": ["TODO: replace placeholders with reviewed, non-secret fixture data."],
    }


def _contract_test_manifest(target_key: str, adapter_contract_sha256: str) -> dict[str, Any]:
    cases = []
    for name, _purpose in ERROR_FIXTURES:
        cases.append(
            {
                "case_id": name,
                "kind": "error",
                "fixture": f"fixtures/errors/{name}.json",
            }
        )
    for name, _purpose in RULE_FIXTURES:
        cases.append(
            {
                "case_id": name,
                "kind": "rule",
                "fixture": f"fixtures/rules/{name}.json",
            }
        )
    return {
        "schema": "automatestig-adapter-contract-test/v1",
        "schema_version": 1,
        "target_key": target_key,
        "adapter_contract": "adapter-contract.json",
        "adapter_contract_sha256": adapter_contract_sha256,
        "shared_validator": "scripts/validate-adapter-contract.py",
        "cases": sorted(cases, key=lambda case: case["case_id"]),
    }


def build_bundle(
    target_key: str,
    display_name: str,
    stig_id: str,
    stig_release: str,
    transport: str,
) -> dict[str, bytes]:
    target_key = validate_target_key(target_key)
    display_name = validate_nonempty(display_name, "display name")
    stig_id = validate_nonempty(stig_id, "STIG ID")
    stig_release = validate_stig_release(stig_release)

    contract = {
        "schema": "automatestig-adapter-contract/v1",
        "schema_version": 1,
        "target_key": target_key,
        "display_name": display_name,
        "stig": {"id": stig_id, "release": stig_release},
        "development_status": "candidate",
        "release_registration": False,
        "support_claim": "none",
        "adapter": {
            "version": "0.1.0-dev",
            "transport": transport,
            "read_only_collection_plan": [],
            "normalized_observations": [],
            "redaction_policy_status": "todo",
        },
        "required_contract_behaviors": {
            "fingerprint_device": "todo",
            "preview_collection_plan": "todo",
            "detect_partial_or_stale_output": "todo",
            "redact_and_manifest_secrets": "todo",
            "validate_collection_completeness": "todo",
            "replay_deterministically": "todo",
        },
        "live_acceptance": {
            "status": "not_run",
            "tested_versions": [],
            "evidence_references": [],
        },
    }
    compatibility = {
        "schema": "automatestig-adapter-compatibility/v1",
        "schema_version": 1,
        "target_key": target_key,
        "declared_version_grammar": None,
        "candidate_versions": [],
        "accepted_tested_versions": [],
        "rejected_version_fixtures": [],
        "live_acceptance_status": "not_run",
        "support_claim": "none",
    }
    coverage = {
        "schema": "automatestig-adapter-coverage-draft/v1",
        "schema_version": 1,
        "target_key": target_key,
        "stig_id": stig_id,
        "stig_release": stig_release,
        "status": "draft",
        "denominators": {
            "total_benchmark_rules": None,
            "technically_automatable_rules": None,
            "implemented_automated_rules": 0,
            "manual_rules": None,
            "unsupported_rules": None,
            "collection_error_rules": None,
        },
        "rules": [],
        "automation_metadata_contract": {
            "implementation_class_values": [
                "declarative_predicate",
                "legacy_declarative",
                "reviewed_imperative",
                "unknown",
            ],
            "introduction_release_required_for_implemented_automation": True,
            "unclassified_value": "unknown",
        },
        "support_claim": "none",
        "live_acceptance_claim": False,
    }

    contract_bytes = canonical_json(contract)
    files: dict[str, bytes] = {
        "adapter-contract.json": contract_bytes,
        "compatibility-matrix.json": canonical_json(compatibility),
        "coverage-inventory.json": canonical_json(coverage),
        "tests/contract-test.json": canonical_json(
            _contract_test_manifest(target_key, sha256(contract_bytes))
        ),
    }
    for name, purpose in ERROR_FIXTURES:
        files[f"fixtures/errors/{name}.json"] = canonical_json(
            _fixture(target_key, name, purpose)
        )
    for name, purpose in RULE_FIXTURES:
        files[f"fixtures/rules/{name}.json"] = canonical_json(
            _fixture(target_key, name, purpose)
        )

    files["README.md"] = (
        f"# {display_name} adapter candidate\n\n"
        "This deterministic scaffold is development material only. It does not register "
        "a supported target, prove a live collection, or authorize a release claim.\n\n"
        f"- Target key: `{target_key}`\n"
        f"- STIG contract: `{stig_id}` `{stig_release}`\n"
        f"- Candidate transport: `{transport}`\n"
        "- Support claim: **none**\n"
        "- Live acceptance: **not run**\n\n"
        "## Completion checklist\n\n"
        "1. Define a read-only plan and normalized observations in `adapter-contract.json`.\n"
        "2. Replace every placeholder fixture with reviewed, redacted, replayable data.\n"
        "3. Add golden parser and contract tests for positive, negative, and every error fixture.\n"
        "4. Classify the full benchmark with rationales and evidence requirements.\n"
        "5. Declare a rejection-first version grammar and test unsupported versions.\n"
        "6. Obtain independent review and authorized live-device acceptance before changing any support status.\n\n"
        "Do not add this directory to `content/supported-targets.json` until the repository's "
        "target-addition release gates are independently satisfied.\n"
    ).encode("utf-8")
    files["fixtures/README.md"] = (
        "# Adapter fixtures\n\n"
        "All generated fixtures are synthetic placeholders, marked redacted, and blocked from "
        "handoff. Populate them with non-secret, independently reviewed evidence. A positive "
        "fixture is not live acceptance.\n"
    ).encode("utf-8")
    files["tests/README.md"] = (
        "# Executable shared contract test\n\n"
        "Run from the AutomateSTIG repository root:\n\n"
        f"```console\npython3 scripts/validate-adapter-contract.py --adapter-root {target_key}\n```\n\n"
        "The generated placeholders intentionally exit 2 as **not ready**. Replace every capture "
        "with a bounded redacted artifact, its SHA-256, and an `observed` result. Complete rule "
        "fixtures must produce Finding and Not a Finding respectively. Malformed, permission-denied, "
        "timeout, truncated, and unsupported-version fixtures must remain collection errors with no "
        "evaluation outcome and no handoff. Contract violations exit 1.\n"
    ).encode("utf-8")
    files["tests/run-contract-test.py"] = (
        "#!/usr/bin/env python3\n"
        "import argparse\n"
        "import subprocess\n"
        "import sys\n"
        "from pathlib import Path\n\n"
        "parser = argparse.ArgumentParser(description='Run the shared AutomateSTIG adapter contract')\n"
        "parser.add_argument('--repo-root', default='.')\n"
        "args = parser.parse_args()\n"
        "adapter_root = Path(__file__).resolve().parents[1]\n"
        "validator = Path(args.repo_root).resolve() / 'scripts/validate-adapter-contract.py'\n"
        "raise SystemExit(subprocess.run([sys.executable, str(validator), '--adapter-root', str(adapter_root)], check=False).returncode)\n"
    ).encode("utf-8")
    return files


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-key", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--stig-id", required=True)
    parser.add_argument("--stig-release", required=True)
    parser.add_argument(
        "--transport",
        choices=("unselected", "ssh_cli", "offline_configuration", "netconf_restconf", "https_api"),
        default="unselected",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Absent directory whose final name must exactly equal --target-key",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        target_key = validate_target_key(args.target_key)
        output = absent_output_directory(args.output_dir, expected_leaf=target_key)
        files = build_bundle(
            target_key,
            args.display_name,
            args.stig_id,
            args.stig_release,
            args.transport,
        )
        write_new_bundle(
            output,
            files,
            executable_files={"tests/run-contract-test.py"},
        )
    except (OSError, ToolingError) as error:
        print(f"adapter scaffold failed: {error}", file=sys.stderr)
        return 1
    print(f"Created unsupported adapter candidate scaffold at {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
