#!/usr/bin/env python3
"""Validate human approvals and live acceptance before a release tag publishes."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

TAG = re.compile(r"^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$")
POLICY_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SIGNER_FINGERPRINT = re.compile(r"^SHA256:[0-9a-f]{64}$")
SSH_SERVER_KEY_FINGERPRINT = re.compile(
    r"^SHA256:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$"
)
GATES = ("ontap", "freebsd", "cisco_ios_xe", "stig_viewer", "stig_manager")
EXPECTED_DEVICE_BENCHMARKS = {
    "ontap": ("NetApp_ONTAP_DSC_9-x_STIG", "V2R4"),
    "freebsd": ("General_Purpose_Operating_System", "V3R3"),
    "cisco_ios_xe": ("Cisco_IOS-XE_Router_NDM_STIG", "V3R7"),
}
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_FIRST_USE_STUDY_BYTES = 128 * 1024
MAX_WORKFLOW_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_CEREMONY_PACK_BYTES = 48_000
MAX_HANDOFF_CEREMONY_BYTES = 16 * 1024 * 1024
MAX_HANDOFF_SIGNATURE_BYTES = 16 * 1024
MAX_HANDOFF_CUSTODY_BYTES = 64 * 1024
CONTENT_CEREMONY_ARTIFACT = "content-signing-ceremony"
CONTENT_CEREMONY_EVIDENCE = "content-signing-ceremony.json"
CONTENT_CEREMONY_PUBLIC_KEY = "content-signing-public-key.pub"
CONTENT_CEREMONY_TEST_PACK = "content-signing-test-pack.stigpack"
HANDOFF_CEREMONY_ARTIFACT = "handoff-receiver-ceremony"
HANDOFF_CEREMONY_EVIDENCE = "handoff-receiver-ceremony.json"
HANDOFF_CEREMONY_PUBLIC_KEY = "handoff-producer-public-key.pub"
HANDOFF_CEREMONY_ZIP = "producer-handoff.zip"
HANDOFF_CEREMONY_SIGNATURE = "producer-handoff.zip.signature.json"
HANDOFF_CEREMONY_CUSTODY = "handoff-key-custody-ceremony.json"
REQUIRED_STATUS_CONTEXTS = {
    "Governance",
    "Check",
    "Test (ubuntu-latest)",
    "Test (windows-latest)",
    "Test (macos-latest)",
    "E2E acceptance",
    "Format",
    "Clippy",
    "Scanner frontend contracts",
    "Archive fuzz smoke",
    "Coverage manifest validation",
    "Dependency audit",
    "Dependency Review",
    "CodeQL (actions)",
    "CodeQL (javascript-typescript)",
    "CodeQL (python)",
    "CodeQL (rust)",
    # Windows portability remains required through Test (windows-latest), but
    # there is deliberately no Windows release-build context.
    "Build Release (x86_64-unknown-linux-gnu)",
    "Build Release (aarch64-unknown-linux-gnu)",
    "Build Release (x86_64-apple-darwin)",
    "Build Release (aarch64-apple-darwin)",
}
GITHUB_ACTIONS_APP_ID = 15368
RELEASE_TAG_AUTHORITY = {
    "actor_id": 3534006,
    "actor_type": "User",
    "bypass_mode": "always",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        fail(f"{field} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{field} must be an RFC 3339 timestamp")
    if parsed.tzinfo is None:
        fail(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return sha256_bytes(encoded)


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def strict_json_loads(raw):
    return json.loads(raw, object_pairs_hook=unique_json_object)


def read_bound_file(
    repo: Path,
    reference: object,
    expected_sha256: object,
    tag: str,
    field: str,
    maximum_bytes: int = MAX_EVIDENCE_BYTES,
) -> tuple[Path, bytes]:
    if not isinstance(reference, str) or not reference.strip():
        fail(f"{field}.evidence_reference must be non-empty")
    if "\\" in reference:
        fail(f"{field}.evidence_reference must use repository-relative POSIX paths")
    relative = Path(reference)
    if relative.is_absolute() or ".." in relative.parts:
        fail(f"{field}.evidence_reference must not be absolute or contain '..'")
    expected_root = Path("release-evidence") / "artifacts" / tag
    try:
        relative.relative_to(expected_root)
    except ValueError:
        fail(f"{field}.evidence_reference must be under {expected_root.as_posix()}/")
    current = repo
    for component in relative.parts:
        current = current / component
        try:
            metadata = os.lstat(current)
        except OSError as error:
            fail(f"cannot inspect {field} artifact {reference}: {error}")
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"{field}.evidence_reference must not traverse a symlink")
    path = repo / relative
    try:
        metadata = path.stat()
        raw = path.read_bytes()
    except OSError as error:
        fail(f"cannot read {field} artifact {reference}: {error}")
    if not stat.S_ISREG(metadata.st_mode) or not raw or len(raw) > maximum_bytes:
        fail(
            f"{field} artifact must be a non-empty regular file no larger than "
            f"{maximum_bytes} bytes"
        )
    if not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256):
        fail(f"{field}.evidence_sha256 must be a lowercase SHA-256 digest")
    actual = sha256_bytes(raw)
    if actual != expected_sha256:
        fail(f"{field} artifact digest mismatch: expected {expected_sha256}, got {actual}")
    tracked = git(repo, "ls-files", "--error-unmatch", "--", relative.as_posix())
    if tracked.returncode:
        fail(f"{field} artifact must be committed to the tagged tree")
    return relative, raw


def read_bound_artifact(
    repo: Path,
    reference: object,
    expected_sha256: object,
    tag: str,
    field: str,
    maximum_bytes: int = MAX_EVIDENCE_BYTES,
) -> tuple[Path, dict]:
    relative, raw = read_bound_file(
        repo,
        reference,
        expected_sha256,
        tag,
        field,
        maximum_bytes,
    )
    try:
        document = strict_json_loads(raw)
    except ValueError as error:
        fail(f"{field} artifact is not valid JSON: {error}")
    if not isinstance(document, dict):
        fail(f"{field} artifact must contain a JSON object")
    return relative, document


def artifact_timestamp(document: dict, field: str) -> datetime:
    for name in ("executed_at", "tested_at", "completed_at"):
        if name in document:
            return timestamp(document[name], f"{field} artifact {name}")
    fail(f"{field} artifact has no execution timestamp")


def validate_first_use_study(
    document: object,
    field: str,
    expected_commit: str,
    expected_product_version: str,
    now: datetime,
    require_passed: bool,
) -> dict[str, str]:
    """Validate the complete, bounded first-time-user cohort and its math."""
    required_fields = {
        "schema",
        "passed",
        "executed_at",
        "source_commit",
        "product_version",
        "repository",
        "workflow_run_id",
        "protected_environment",
        "automatestig_gui_sha256",
        "scenario",
        "representative_roles",
        "study_team",
        "participants",
        "metrics",
    }
    if not isinstance(document, dict) or set(document) != required_fields:
        fail(f"{field} must contain exactly {sorted(required_fields)}")
    if document.get("schema") != "automatestig-first-use-ux-study/v1":
        fail(f"{field} has the wrong first-use study schema")
    if not isinstance(document.get("passed"), bool):
        fail(f"{field}.passed must be a boolean")
    if document.get("source_commit") != expected_commit or not SHA.fullmatch(
        expected_commit
    ):
        fail(f"{field}.source_commit must match the exact approved commit")
    if (
        document.get("product_version") != expected_product_version
        or not TAG.fullmatch(expected_product_version)
    ):
        fail(f"{field}.product_version must match the exact release version")
    repository = document.get("repository")
    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
    ):
        fail(f"{field}.repository must be an owner/repository identity")
    run_id = document.get("workflow_run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[1-9][0-9]*", run_id):
        fail(f"{field}.workflow_run_id must be a positive decimal identifier")
    if document.get("protected_environment") != "first-use-ux-study":
        fail(f"{field} was not produced through the first-use study environment")
    gui_digest = document.get("automatestig_gui_sha256")
    if not isinstance(gui_digest, str) or not SHA256.fullmatch(gui_digest):
        fail(f"{field}.automatestig_gui_sha256 must bind the tested GUI bytes")

    executed = timestamp(document.get("executed_at"), f"{field}.executed_at")
    if executed > now or now - executed > timedelta(days=90):
        fail(f"{field} is in the future or older than 90 days")

    scenario = document.get("scenario")
    scenario_fields = {
        "id",
        "version",
        "target_profile",
        "prepared_scan_fixture_sha256",
        "task_definition_sha256",
    }
    if not isinstance(scenario, dict) or set(scenario) != scenario_fields:
        fail(f"{field}.scenario must contain exactly {sorted(scenario_fields)}")
    for name in ("id", "version", "target_profile"):
        value = scenario.get(name)
        if not isinstance(value, str) or not POLICY_IDENTIFIER.fullmatch(value):
            fail(f"{field}.scenario.{name} must be a bounded identifier")
    for name in ("prepared_scan_fixture_sha256", "task_definition_sha256"):
        value = scenario.get(name)
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            fail(f"{field}.scenario.{name} must be a lowercase SHA-256 digest")

    required_roles = {"cybersecurity_analyst", "cybersecurity_manager"}
    representative_roles = document.get("representative_roles")
    if (
        not isinstance(representative_roles, list)
        or len(representative_roles) != 2
        or set(representative_roles) != required_roles
    ):
        fail(
            f"{field}.representative_roles must contain exactly analyst and manager"
        )

    study_team = document.get("study_team")
    team_roles = {"facilitator", "independent_observer", "independent_approver"}
    if not isinstance(study_team, dict) or set(study_team) != team_roles:
        fail(f"{field}.study_team must contain exactly {sorted(team_roles)}")
    team_logins: dict[str, str] = {}
    team_times: dict[str, datetime] = {}
    for role in sorted(team_roles):
        attestor = study_team.get(role)
        if not isinstance(attestor, dict) or set(attestor) != {
            "github_login",
            "attested_at",
        }:
            fail(f"{field}.study_team.{role} must contain a login and attestation")
        login = attestor.get("github_login")
        if not isinstance(login, str) or not GITHUB_LOGIN.fullmatch(login):
            fail(f"{field}.study_team.{role}.github_login is invalid")
        attested = timestamp(
            attestor.get("attested_at"),
            f"{field}.study_team.{role}.attested_at",
        )
        if attested < executed or attested > now:
            fail(f"{field}.study_team.{role} attestation is outside the study window")
        team_logins[role] = login
        team_times[role] = attested
    if len({login.casefold() for login in team_logins.values()}) != len(team_roles):
        fail(f"{field} facilitator, observer, and approver must be distinct people")
    if team_times["independent_approver"] < team_times["independent_observer"]:
        fail(f"{field} independent approval cannot predate observer attestation")

    participants = document.get("participants")
    if not isinstance(participants, list) or not 5 <= len(participants) <= 100:
        fail(f"{field}.participants must contain between 5 and 100 users")
    participant_fields = {
        "participant_id",
        "role",
        "role_experience_band",
        "first_time_user",
        "completed_prepared_scan",
        "external_documentation_used",
        "assistance_received",
        "outcome_notes",
    }
    participant_ids: set[str] = set()
    role_counts = {role: 0 for role in required_roles}
    experience_bands: set[str] = set()
    unaided_completions = 0
    for index, participant in enumerate(participants):
        item_field = f"{field}.participants[{index}]"
        if not isinstance(participant, dict) or set(participant) != participant_fields:
            fail(f"{item_field} must contain exactly {sorted(participant_fields)}")
        participant_id = participant.get("participant_id")
        if not isinstance(participant_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", participant_id
        ):
            fail(f"{item_field}.participant_id must be a bounded pseudonym")
        if participant_id.casefold() in participant_ids:
            fail(f"{field}.participants contains duplicate participant IDs")
        participant_ids.add(participant_id.casefold())
        role = participant.get("role")
        if role not in required_roles:
            fail(f"{item_field}.role is not representative")
        role_counts[role] += 1
        experience_band = participant.get("role_experience_band")
        if experience_band not in {
            "less_than_2_years",
            "2_to_5_years",
            "more_than_5_years",
        }:
            fail(f"{item_field}.role_experience_band is invalid")
        experience_bands.add(experience_band)
        if participant.get("first_time_user") is not True:
            fail(f"{item_field} is not a first-time user and cannot be excluded later")
        for name in (
            "completed_prepared_scan",
            "external_documentation_used",
            "assistance_received",
        ):
            if not isinstance(participant.get(name), bool):
                fail(f"{item_field}.{name} must be a boolean")
        notes = participant.get("outcome_notes")
        if not isinstance(notes, str) or not 1 <= len(notes.strip()) <= 500:
            fail(f"{item_field}.outcome_notes must contain 1 to 500 characters")
        if (
            participant["completed_prepared_scan"]
            and not participant["external_documentation_used"]
            and not participant["assistance_received"]
        ):
            unaided_completions += 1
    if any(count < 2 for count in role_counts.values()):
        fail(f"{field} must include at least two users from each representative role")
    if len(experience_bands) < 2:
        fail(f"{field} must include at least two role-experience bands")

    metrics = document.get("metrics")
    metric_fields = {"numerator", "denominator", "required_threshold_percent"}
    if not isinstance(metrics, dict) or set(metrics) != metric_fields:
        fail(f"{field}.metrics must contain exactly {sorted(metric_fields)}")
    numerator = metrics.get("numerator")
    denominator = metrics.get("denominator")
    if (
        not isinstance(numerator, int)
        or isinstance(numerator, bool)
        or not isinstance(denominator, int)
        or isinstance(denominator, bool)
        or denominator != len(participants)
        or numerator != unaided_completions
    ):
        fail(
            f"{field}.metrics must record the exact unaided numerator and full cohort denominator"
        )
    if metrics.get("required_threshold_percent") != 80:
        fail(f"{field}.metrics.required_threshold_percent must be 80")
    calculated_pass = numerator * 100 >= denominator * 80
    if document["passed"] is not calculated_pass:
        fail(f"{field}.passed must honestly reflect the exact 80 percent result")
    if require_passed and not calculated_pass:
        fail(f"{field} did not meet the 80 percent unaided first-use release gate")
    return team_logins


def validate_artifact_semantics(
    document: dict,
    gate: str,
    field: str,
    approved_commit: str,
    verify_github: bool,
    evidence_sha256: str,
    expected_version: str,
    expected_environment: str,
) -> None:
    run: object = None
    if document.get("passed") is not True:
        fail(f"{field} artifact is not a passing record")
    if document.get("source_commit") != approved_commit:
        fail(f"{field} artifact source_commit must match approved_commit")
    repository = document.get("repository")
    if not isinstance(repository, str) or not repository.strip():
        fail(f"{field} artifact must identify its repository")
    expected_repository = os.environ.get("GITHUB_REPOSITORY")
    if expected_repository and repository != expected_repository:
        fail(f"{field} artifact was produced for a different repository")
    run_id = document.get("workflow_run_id")
    if not isinstance(run_id, str) or not run_id.isdigit():
        fail(f"{field} artifact must identify its protected workflow run")
    if verify_github:
        expected_workflow = {
            "ontap": ".github/workflows/live-device-acceptance.yml",
            "freebsd": ".github/workflows/live-device-acceptance.yml",
            "cisco_ios_xe": ".github/workflows/live-device-acceptance.yml",
            "stig_viewer": ".github/workflows/stig-viewer-acceptance.yml",
            "stig_manager": ".github/workflows/stigman-staging.yml",
            "first_use_ux": ".github/workflows/first-use-ux-study.yml",
            "recovery_drill": ".github/workflows/transaction-recovery-drill.yml",
        }[gate]
        run = github_json(f"repos/{repository}/actions/runs/{run_id}")
        if not isinstance(run, dict) or (
            run.get("head_sha") != approved_commit
            or run.get("path") != expected_workflow
            or run.get("event") != "workflow_dispatch"
            or run.get("conclusion") != "success"
        ):
            fail(
                f"{field} artifact is not bound to a successful protected "
                f"{expected_workflow} run at approved_commit"
            )
        validate_workflow_artifact(
            repository,
            run_id,
            gate,
            evidence_sha256,
            expected_log_sha256=(
                document.get("output_sha256")
                if gate == "recovery_drill"
                else None
            ),
            expected_handoff_sha256=(
                (document.get("metrics") or {}).get("handoff_sha256")
                if gate == "stig_manager"
                else None
            ),
        )
    if gate in {"ontap", "freebsd", "cisco_ios_xe"}:
        if document.get("protected_environment") != "live-device-acceptance":
            fail(f"{field} artifact was not produced through the protected device environment")
        if document.get("schema") != "automatestig-live-device-acceptance/v1":
            fail(f"{field} artifact has the wrong device-acceptance schema")
        results = document.get("results") or []
        matches = [item for item in results if item.get("target") == gate]
        if len(matches) != 1 or matches[0].get("status") != "passed":
            fail(f"{field} artifact must contain exactly one passing {gate} result")
        result = matches[0]
        expected_stig_id, expected_stig_release = EXPECTED_DEVICE_BENCHMARKS[gate]
        if (
            result.get("stig_id") != expected_stig_id
            or result.get("stig_release") != expected_stig_release
            or expected_version != expected_stig_release
        ):
            fail(
                f"{field} artifact must bind {gate} to "
                f"{expected_stig_id} {expected_stig_release}"
            )
        for name in (
            "benchmark_sha256",
            "evaluated_benchmark_sha256",
            "oracle_evaluated_benchmark_sha256",
            "benchmark_rule_set_sha256",
            "automated_vuln_set_sha256",
            "check_pack_sha256",
            "evaluated_check_pack_sha256",
            "evaluation_plan_sha256",
            "input_sha256",
            "evaluated_input_sha256",
            "source_state_sha256",
            "scenario_bindings_sha256",
            "oracle_sha256",
            "oracle_pinned_sha256",
            "oracle_expected_status_sha256",
            "observed_status_sha256",
        ):
            if not isinstance(result.get(name), str) or not SHA256.fullmatch(result[name]):
                fail(f"{field} artifact result.{name} must be a SHA-256 digest")
        if result["evaluated_check_pack_sha256"] != result["check_pack_sha256"]:
            fail(
                f"{field} artifact evaluated check-pack provenance differs "
                "from the live/oracle binding"
            )
        if (
            result["evaluated_benchmark_sha256"]
            != result["oracle_evaluated_benchmark_sha256"]
        ):
            fail(
                f"{field} artifact evaluated benchmark provenance differs "
                "from the independently pinned oracle benchmark"
            )
        if result["evaluated_input_sha256"] != result["input_sha256"]:
            fail(
                f"{field} artifact evaluated input provenance differs from "
                "the protected scenario snapshots"
            )
        if not all(isinstance(result.get(name), int) and result[name] > 0 for name in ("findings", "automated_determinations")):
            fail(f"{field} artifact must record non-zero exact finding and automation counts")
        if (
            result.get("scenario_count") != 2
            or result.get("negative_control_count") != 1
            or not isinstance(result.get("negative_finding_count"), int)
            or result["negative_finding_count"] <= 0
        ):
            fail(
                f"{field} artifact must record one baseline and one "
                "nontrivial negative-control scenario"
            )
        adjudicator = result.get("oracle_adjudicator")
        if (
            not isinstance(adjudicator, str)
            or len(adjudicator.strip()) > 39
            or not GITHUB_LOGIN.fullmatch(adjudicator.strip())
        ):
            fail(
                f"{field} artifact must name the independent oracle adjudicator "
                "by GitHub login"
            )
        adjudicated_at = timestamp(
            result.get("oracle_adjudicated_at"),
            f"{field} artifact result.oracle_adjudicated_at",
        )
        now = datetime.now(timezone.utc)
        if adjudicated_at > now or now - adjudicated_at > timedelta(days=90):
            fail(f"{field} artifact decision oracle is in the future or older than 90 days")
        if (
            result["oracle_pinned_sha256"] != result["oracle_sha256"]
            or
            result["oracle_expected_status_sha256"]
            != result["observed_status_sha256"]
        ):
            fail(
                f"{field} artifact oracle pin or automated decisions do not match "
                "its independent oracle"
            )
        policy_fields = {
            "organization_policy_sha256",
            "organization_policy_pinned_sha256",
            "oracle_organization_policy_sha256",
            "evaluated_organization_policy_sha256",
            "organization_policy_signature_sha256",
            "oracle_organization_policy_signature_sha256",
            "organization_policy_id",
            "organization_policy_version",
            "organization_policy_signer_fingerprint",
            "oracle_organization_policy_signer_fingerprint",
            "organization_policy_signature_verified",
        }
        ssh_key_fields = {
            "server_key_fingerprint",
            "oracle_server_key_fingerprint",
        }
        if gate in {"ontap", "freebsd"}:
            server_key = result.get("server_key_fingerprint")
            if (
                not isinstance(server_key, str)
                or not SSH_SERVER_KEY_FINGERPRINT.fullmatch(server_key)
                or result.get("oracle_server_key_fingerprint") != server_key
            ):
                fail(
                    f"{field} artifact SSH server key differs from its "
                    "independently pinned oracle"
                )
        elif any(name in result for name in ssh_key_fields):
            fail(
                f"{field} artifact Cisco result must not contain SSH "
                "server-key provenance"
            )
        if gate == "cisco_ios_xe":
            for name in (
                "organization_policy_sha256",
                "organization_policy_pinned_sha256",
                "oracle_organization_policy_sha256",
                "evaluated_organization_policy_sha256",
                "organization_policy_signature_sha256",
                "oracle_organization_policy_signature_sha256",
            ):
                if (
                    not isinstance(result.get(name), str)
                    or not SHA256.fullmatch(result[name])
                ):
                    fail(
                        f"{field} artifact Cisco result.{name} must be a "
                        "SHA-256 digest"
                    )
            if len({
                result["organization_policy_sha256"],
                result["organization_policy_pinned_sha256"],
                result["oracle_organization_policy_sha256"],
                result["evaluated_organization_policy_sha256"],
            }) != 1:
                fail(
                    f"{field} artifact Cisco policy snapshot, pin, oracle, "
                    "and evaluated provenance differ"
                )
            if (
                result["organization_policy_signature_sha256"]
                != result["oracle_organization_policy_signature_sha256"]
            ):
                fail(
                    f"{field} artifact Cisco detached signature differs from "
                    "its independent oracle"
                )
            if not all(
                isinstance(result.get(name), str)
                and POLICY_IDENTIFIER.fullmatch(result[name])
                for name in (
                    "organization_policy_id",
                    "organization_policy_version",
                )
            ):
                fail(
                    f"{field} artifact Cisco organization-policy identity is invalid"
                )
            if (
                not isinstance(
                    result.get("organization_policy_signer_fingerprint"), str
                )
                or not SIGNER_FINGERPRINT.fullmatch(
                    result["organization_policy_signer_fingerprint"]
                )
                or result.get("oracle_organization_policy_signer_fingerprint")
                != result["organization_policy_signer_fingerprint"]
                or result.get("organization_policy_signature_verified") is not True
            ):
                fail(
                    f"{field} artifact Cisco organization policy lacks trusted "
                    "signature provenance"
                )
        elif any(name in result for name in policy_fields):
            fail(
                f"{field} artifact non-Cisco result must not contain "
                "organization-policy provenance"
            )
        expected_evaluation_plan_sha256 = canonical_json_sha256(
            {
                "stig_id": expected_stig_id,
                "stig_release": expected_stig_release,
                "benchmark_sha256": result["evaluated_benchmark_sha256"],
                "check_pack_sha256": result["check_pack_sha256"],
                "organization_policy_sha256": (
                    result["organization_policy_sha256"]
                    if gate == "cisco_ios_xe"
                    else None
                ),
            }
        )
        if result["evaluation_plan_sha256"] != expected_evaluation_plan_sha256:
            fail(
                f"{field} artifact evaluation-plan provenance differs from "
                "the benchmark, effective check pack, or organization policy"
            )
        if verify_github:
            validate_live_device_environment(
                repository,
                adjudicator.strip(),
                run,
                field,
            )
        if not isinstance(document.get("binary_sha256"), str) or not SHA256.fullmatch(document["binary_sha256"]):
            fail(f"{field} artifact must bind the tested AutomateSTIG binary")
    elif gate == "stig_viewer":
        if document.get("protected_environment") != "external-acceptance":
            fail(f"{field} artifact was not produced through the protected external environment")
        if document.get("schema") != "automatestig-stig-viewer-acceptance/v1":
            fail(f"{field} artifact has the wrong STIG Viewer schema")
        if (
            document.get("product_version") != expected_version
            or document.get("platform") != expected_environment
            or expected_version.strip().casefold() == "unknown"
        ):
            fail(f"{field} version/environment does not match its bound artifact")
        if not isinstance(document.get("automatestig_cli_sha256"), str) or not SHA256.fullmatch(
            document["automatestig_cli_sha256"]
        ):
            fail(f"{field} artifact must bind the tested AutomateSTIG CLI binary")
        cases = document.get("cases") or []
        formats = {item.get("format") for item in cases if item.get("status") == "passed"}
        if len(cases) != 2 or formats != {"ckl", "cklb"}:
            fail(f"{field} artifact must contain exactly passing CKL and CKLB cases")
        for case in cases:
            if not isinstance(case.get("finding_count"), int) or case["finding_count"] <= 0:
                fail(f"{field} artifact contains an empty STIG Viewer case")
            for name in (
                "source_sha256",
                "roundtrip_sha256",
                "semantic_sha256",
                "rule_set_sha256",
            ):
                if not isinstance(case.get(name), str) or not SHA256.fullmatch(case[name]):
                    fail(f"{field} artifact case.{name} must be a SHA-256 digest")
            if case["source_sha256"] == case["roundtrip_sha256"]:
                fail(f"{field} artifact does not prove a Viewer save round-trip")
    elif gate == "stig_manager":
        if document.get("protected_environment") != "external-acceptance":
            fail(f"{field} artifact was not produced through the protected external environment")
        if document.get("schema") != "automatestig-stig-manager-acceptance/v1":
            fail(f"{field} artifact has the wrong STIG Manager schema")
        if (
            document.get("product_version") != expected_version
            or document.get("environment") != expected_environment
            or expected_version.strip().casefold() == "unknown"
        ):
            fail(f"{field} version/environment does not match its bound artifact")
        for name in (
            "automatestig_cli_sha256",
            "automatestig_gui_sha256",
            "benchmark_sha256",
            "config_fixture_sha256",
        ):
            if not isinstance(document.get(name), str) or not SHA256.fullmatch(document[name]):
                fail(f"{field} artifact must bind {name}")
        checks = document.get("checks") or []
        if not checks or any(item.get("passed") is not True for item in checks):
            fail(f"{field} artifact contains a missing or failed STIG Manager check")
        passed_check_names = {
            item.get("name") for item in checks if isinstance(item, dict)
        }
        required_checks = {
            "STIG Manager rig creates the existing exact Cisco V3R7 assignment",
            "AutomateSTIG completes disconnected Cisco scanner run with signed policy",
            "scanner run retains verified organization-policy provenance",
            "automatestig scanner verify-handoff accepts selected-run bundle",
            "fallback CKLB contains scanner-owned reviewed rows only",
            "retired direct-push route returns 410",
            "AutomateSTIG makes zero direct STIG Manager review writes",
            "receiving operator revalidates the existing exact assignment",
            "receiving operator reconciles only sparse-reviews.json",
            "STIG Manager rule/status round-trip matches sparse handoff",
        }
        if not required_checks.issubset(passed_check_names):
            fail(
                f"{field} artifact does not prove the disconnected scanner "
                "handoff and explicit receiving-operator boundary"
            )
        metrics = document.get("metrics") or {}
        review_count = metrics.get("review_count")
        if (
            not isinstance(review_count, int)
            or review_count <= 0
            or review_count != metrics.get("source_finding_count")
            or review_count != metrics.get("fallback_sparse_rule_count")
            or review_count != metrics.get("receiving_operator_review_writes")
            or metrics.get("automatestig_direct_review_writes") != 0
            or metrics.get("boundary") != "disconnected-selected-run-handoff"
            or metrics.get("producer_handoff_filename") != HANDOFF_CEREMONY_ZIP
            or metrics.get("benchmark_id") != "Cisco_IOS-XE_Router_NDM_STIG"
            or metrics.get("assignment_revision") != "V3R7"
            or not isinstance(metrics.get("full_assignment_rule_count"), int)
            or metrics["full_assignment_rule_count"] <= review_count
            or metrics.get("full_ckl_rule_count")
            != metrics.get("full_assignment_rule_count")
            or not isinstance(metrics.get("rule_set_sha256"), str)
            or not SHA256.fullmatch(metrics["rule_set_sha256"])
            or not isinstance(metrics.get("handoff_sha256"), str)
            or not SHA256.fullmatch(metrics["handoff_sha256"])
            or not isinstance(metrics.get("handoff_manifest_sha256"), str)
            or not SHA256.fullmatch(metrics["handoff_manifest_sha256"])
        ):
            fail(
                f"{field} artifact does not prove an exact sparse handoff into "
                "a larger existing assignment with zero product writes"
            )
        if (
            not isinstance(metrics.get("organization_policy_sha256"), str)
            or not SHA256.fullmatch(metrics["organization_policy_sha256"])
            or not isinstance(
                metrics.get("organization_policy_signature_sha256"), str
            )
            or not SHA256.fullmatch(
                metrics["organization_policy_signature_sha256"]
            )
            or not isinstance(
                metrics.get("organization_policy_signer_fingerprint"), str
            )
            or not SIGNER_FINGERPRINT.fullmatch(
                metrics["organization_policy_signer_fingerprint"]
            )
        ):
            fail(
                f"{field} artifact does not bind the verified Cisco policy"
            )
    elif gate == "first_use_ux":
        if expected_environment != "first-use-ux-study":
            fail(f"{field}.environment must be first-use-ux-study")
        team = validate_first_use_study(
            document,
            f"{field} artifact",
            approved_commit,
            expected_version,
            datetime.now(timezone.utc),
            True,
        )
        if verify_github:
            validate_first_use_study_environment(
                repository,
                team["independent_observer"],
                team["independent_approver"],
                run,
                field,
            )
    elif gate == "recovery_drill":
        if document.get("schema") != "automatestig-transaction-recovery-drill/v1":
            fail(f"{field} artifact has the wrong recovery-drill schema")
        if expected_version != "v1":
            fail(f"{field}.version must be v1")
        if document.get("tracked_worktree_dirty") is not False:
            fail(f"{field} release drill must run from a clean tracked tree")
        if not isinstance(document.get("output_sha256"), str) or not SHA256.fullmatch(
            document["output_sha256"]
        ):
            fail(f"{field} must bind the complete recovery-drill log")
        scenarios = document.get("required_scenarios") or []
        if not scenarios or any(item.get("observed") is not True for item in scenarios):
            fail(f"{field} artifact did not observe every recovery scenario")


def validate_gate(
    value: object,
    field: str,
    gate: str,
    now: datetime,
    repo: Path,
    tag: str,
    approved_commit: str,
    verify_github: bool,
) -> Path:
    if not isinstance(value, dict):
        fail(f"{field} must be an object")
    required = {"status", "executed_at", "environment", "version", "evidence_reference", "evidence_sha256"}
    missing = required - set(value)
    if missing:
        fail(f"{field} is missing {sorted(missing)}")
    if value["status"] != "passed":
        fail(f"{field}.status must be passed; skips and waivers cannot publish a release")
    executed = timestamp(value["executed_at"], f"{field}.executed_at")
    if executed > now:
        fail(f"{field}.executed_at cannot be in the future")
    if now - executed > timedelta(days=90):
        fail(f"{field} evidence is older than 90 days")
    for name in ("environment", "version", "evidence_reference"):
        if not isinstance(value[name], str) or not value[name].strip():
            fail(f"{field}.{name} must be non-empty")
    if gate == "first_use_ux" and value["version"] != tag:
        fail(f"{field}.version must match the exact release tag {tag}")
    relative, document = read_bound_artifact(
        repo,
        value["evidence_reference"],
        value["evidence_sha256"],
        tag,
        field,
        MAX_FIRST_USE_STUDY_BYTES if gate == "first_use_ux" else MAX_EVIDENCE_BYTES,
    )
    artifact_time = artifact_timestamp(document, field)
    if artifact_time != executed:
        fail(f"{field}.executed_at must exactly match the bound artifact timestamp")
    validate_artifact_semantics(
        document,
        gate,
        field,
        approved_commit,
        verify_github,
        value["evidence_sha256"],
        value["version"],
        value["environment"],
    )
    return relative


def git(repo: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *arguments], cwd=repo, text=True, capture_output=True)


def github_json(endpoint: str) -> object:
    if not os.environ.get("GH_TOKEN") or not os.environ.get("GITHUB_REPOSITORY"):
        fail("connected release validation requires GH_TOKEN and GITHUB_REPOSITORY")
    result = subprocess.run(
        ["gh", "api", endpoint],
        text=True,
        capture_output=True,
    )
    if result.returncode:
        fail(f"GitHub verification failed for {endpoint}: {result.stderr.strip()}")
    try:
        return strict_json_loads(result.stdout)
    except ValueError as error:
        fail(f"GitHub returned invalid JSON for {endpoint}: {error}")


def github_bytes(endpoint: str) -> bytes:
    if not os.environ.get("GH_TOKEN") or not os.environ.get("GITHUB_REPOSITORY"):
        fail("connected release validation requires GH_TOKEN and GITHUB_REPOSITORY")
    result = subprocess.run(
        ["gh", "api", endpoint],
        capture_output=True,
    )
    if result.returncode:
        fail(
            f"GitHub artifact download failed for {endpoint}: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    if not result.stdout or len(result.stdout) > MAX_WORKFLOW_ARTIFACT_BYTES:
        fail("protected workflow artifact ZIP is empty or exceeds 16 MiB")
    return result.stdout


def validate_live_device_environment(
    repository: str,
    adjudicator: str,
    run: object,
    field: str,
) -> None:
    environment = github_json(
        f"repos/{repository}/environments/live-device-acceptance"
    )
    if not isinstance(environment, dict) or not isinstance(run, dict):
        fail(f"{field} live-device environment or workflow run is invalid")
    review_rules = [
        rule
        for rule in environment.get("protection_rules") or []
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    reviewers = review_rules[0].get("reviewers") if len(review_rules) == 1 else None
    branch_policy = environment.get("deployment_branch_policy") or {}
    reviewer = reviewers[0] if isinstance(reviewers, list) and len(reviewers) == 1 else {}
    reviewer_login = (
        ((reviewer.get("reviewer") or {}).get("login") or "")
        if isinstance(reviewer, dict)
        else ""
    )
    actor = ((run.get("actor") or {}).get("login") or "")
    triggering_actor = ((run.get("triggering_actor") or {}).get("login") or "")
    approvals = github_json(
        f"repos/{repository}/actions/runs/{run.get('id') or run.get('run_id')}/approvals"
    )
    approved = [
        review
        for review in approvals
        if isinstance(review, dict) and review.get("state") == "approved"
    ] if isinstance(approvals, list) else []
    approval = approved[0] if len(approved) == 1 and len(approvals) == 1 else {}
    approved_environments = approval.get("environments") or []
    approval_login = ((approval.get("user") or {}).get("login") or "")
    jobs = github_json(
        f"repos/{repository}/actions/runs/{run.get('id') or run.get('run_id')}"
        "/jobs?filter=latest&per_page=100"
    )
    job_items = jobs.get("jobs") if isinstance(jobs, dict) else None
    job = job_items[0] if isinstance(job_items, list) and len(job_items) == 1 else {}
    labels = {
        str(label).casefold()
        for label in (job.get("labels") or [])
        if isinstance(label, str)
    } if isinstance(job, dict) else set()
    if (
        environment.get("can_admins_bypass") is not False
        or len(review_rules) != 1
        or review_rules[0].get("prevent_self_review") is not True
        or not isinstance(reviewer, dict)
        or reviewer.get("type") != "User"
        or reviewer_login.casefold() != adjudicator.casefold()
        or branch_policy.get("protected_branches") is not True
        or branch_policy.get("custom_branch_policies") is not False
        or not GITHUB_LOGIN.fullmatch(actor)
        or not GITHUB_LOGIN.fullmatch(triggering_actor)
        or actor.casefold() != triggering_actor.casefold()
        or actor.casefold() == adjudicator.casefold()
        or run.get("run_attempt") != 1
        or not isinstance(approval, dict)
        or approval_login.casefold() != adjudicator.casefold()
        or len(approved_environments) != 1
        or not isinstance(approved_environments[0], dict)
        or approved_environments[0].get("name") != "live-device-acceptance"
        or not isinstance(jobs, dict)
        or jobs.get("total_count") != 1
        or not isinstance(job, dict)
        or job.get("conclusion") != "success"
        or not re.fullmatch(
            r"(?:all|ontap|freebsd|cisco-ios-xe) collection and evaluation",
            str(job.get("name", "")),
        )
        or not {
            "self-hosted",
            "linux",
            "x64",
            "automatestig-live-devices",
        }.issubset(labels)
        or not isinstance(job.get("runner_id"), int)
        or job["runner_id"] <= 0
        or not isinstance(job.get("runner_name"), str)
        or not job["runner_name"].strip()
    ):
        fail(
            f"{field} must use one identified protected Linux x64 runner, be "
            "dispatched by one actor, and be independently approved by its exact "
            "sole oracle adjudicator"
        )


def validate_first_use_study_environment(
    repository: str,
    observer: str,
    approver: str,
    run: object,
    field: str,
) -> None:
    """Bind observer dispatch and independent approval to one protected run."""
    environment = github_json(
        f"repos/{repository}/environments/first-use-ux-study"
    )
    if not isinstance(environment, dict) or not isinstance(run, dict):
        fail(f"{field} first-use environment or workflow run is invalid")
    review_rules = [
        rule
        for rule in environment.get("protection_rules") or []
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    reviewers = review_rules[0].get("reviewers") if len(review_rules) == 1 else None
    reviewer = reviewers[0] if isinstance(reviewers, list) and len(reviewers) == 1 else {}
    reviewer_login = (
        ((reviewer.get("reviewer") or {}).get("login") or "")
        if isinstance(reviewer, dict)
        else ""
    )
    branch_policy = environment.get("deployment_branch_policy") or {}
    actor = ((run.get("actor") or {}).get("login") or "")
    triggering_actor = ((run.get("triggering_actor") or {}).get("login") or "")
    run_id = run.get("id") or run.get("run_id")
    approvals = github_json(f"repos/{repository}/actions/runs/{run_id}/approvals")
    approved = [
        review
        for review in approvals
        if isinstance(review, dict) and review.get("state") == "approved"
    ] if isinstance(approvals, list) else []
    approval = approved[0] if len(approved) == 1 and len(approvals) == 1 else {}
    approved_environments = approval.get("environments") or []
    approval_login = ((approval.get("user") or {}).get("login") or "")
    jobs = github_json(
        f"repos/{repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100"
    )
    job_items = jobs.get("jobs") if isinstance(jobs, dict) else None
    job = job_items[0] if isinstance(job_items, list) and len(job_items) == 1 else {}
    labels = {
        str(label).casefold()
        for label in (job.get("labels") or [])
        if isinstance(label, str)
    } if isinstance(job, dict) else set()
    if (
        environment.get("can_admins_bypass") is not False
        or len(review_rules) != 1
        or review_rules[0].get("prevent_self_review") is not True
        or not isinstance(reviewer, dict)
        or reviewer.get("type") != "User"
        or reviewer_login.casefold() != approver.casefold()
        or branch_policy.get("protected_branches") is not True
        or branch_policy.get("custom_branch_policies") is not False
        or not GITHUB_LOGIN.fullmatch(observer)
        or not GITHUB_LOGIN.fullmatch(approver)
        or observer.casefold() == approver.casefold()
        or actor.casefold() != observer.casefold()
        or triggering_actor.casefold() != observer.casefold()
        or run.get("run_attempt") != 1
        or not isinstance(approval, dict)
        or approval_login.casefold() != approver.casefold()
        or len(approved_environments) != 1
        or not isinstance(approved_environments[0], dict)
        or approved_environments[0].get("name") != "first-use-ux-study"
        or not isinstance(jobs, dict)
        or jobs.get("total_count") != 1
        or not isinstance(job, dict)
        or job.get("name") != "Independent first-use study attestation"
        or job.get("conclusion") != "success"
        or not {
            "self-hosted",
            "linux",
            "x64",
            "automatestig-first-use-study",
        }.issubset(labels)
        or not isinstance(job.get("runner_id"), int)
        or job["runner_id"] <= 0
        or not isinstance(job.get("runner_name"), str)
        or not job["runner_name"].strip()
    ):
        fail(
            f"{field} must be dispatched by the exact observer and independently "
            "approved by the protected environment's sole exact approver"
        )


def validate_workflow_artifact(
    repository: str,
    run_id: str,
    gate: str,
    expected_sha256: str,
    expected_log_sha256: object = None,
    expected_handoff_sha256: object = None,
) -> None:
    response = github_json(
        f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"
    )
    if not isinstance(response, dict) or not isinstance(response.get("artifacts"), list):
        fail("GitHub workflow artifact response must contain an artifacts array")
    if response.get("total_count", len(response["artifacts"])) > 100:
        fail("protected workflow produced too many artifacts to bind unambiguously")
    if gate in {"ontap", "freebsd", "cisco_ios_xe"}:
        name = re.compile(
            rf"^live-device-acceptance-(?:all|ontap|freebsd|cisco-ios-xe)-{re.escape(run_id)}$"
        )
        filename = "live-device-acceptance.json"
    elif gate == "stig_viewer":
        name = re.compile(rf"^stig-viewer-acceptance-{re.escape(run_id)}$")
        filename = "stig-viewer-acceptance.json"
    elif gate == "stig_manager":
        name = re.compile(rf"^stig-manager-acceptance-{re.escape(run_id)}$")
        filename = "stig-manager-acceptance.json"
    elif gate == "first_use_ux":
        name = re.compile(rf"^first-use-ux-study-{re.escape(run_id)}$")
        filename = "first-use-ux-study.json"
    elif gate == "recovery_drill":
        name = re.compile(rf"^transaction-recovery-drill-{re.escape(run_id)}$")
        filename = "transaction-recovery-drill.json"
    else:
        fail(f"no protected workflow artifact policy exists for {gate}")
    matches = [
        artifact
        for artifact in response["artifacts"]
        if isinstance(artifact, dict)
        and isinstance(artifact.get("name"), str)
        and name.fullmatch(artifact["name"])
        and artifact.get("expired") is False
    ]
    if len(matches) != 1:
        fail(f"protected workflow run must contain exactly one unexpired {gate} artifact")
    artifact = matches[0]
    if (
        not isinstance(artifact.get("id"), int)
        or not isinstance(artifact.get("size_in_bytes"), int)
        or artifact["size_in_bytes"] <= 0
        or artifact["size_in_bytes"] > MAX_WORKFLOW_ARTIFACT_BYTES
    ):
        fail(f"protected {gate} workflow artifact metadata is invalid or oversized")
    archive = github_bytes(f"repos/{repository}/actions/artifacts/{artifact['id']}/zip")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            entries = [item for item in bundle.infolist() if not item.is_dir()]
            expected_files = {filename}
            if gate == "recovery_drill":
                expected_files.add("transaction-recovery-drill.log")
            if gate == "stig_manager":
                expected_files.add(HANDOFF_CEREMONY_ZIP)
            by_name = {item.filename: item for item in entries}
            if (
                len(entries) != len(expected_files)
                or set(by_name) != expected_files
                or by_name[filename].file_size <= 0
                or by_name[filename].file_size
                > (
                    MAX_FIRST_USE_STUDY_BYTES
                    if gate == "first_use_ux"
                    else MAX_EVIDENCE_BYTES
                )
                or any(
                    item.file_size <= 0
                    or item.file_size > MAX_WORKFLOW_ARTIFACT_BYTES
                    or stat.S_ISLNK(item.external_attr >> 16)
                    for item in entries
                )
            ):
                fail(
                    f"protected {gate} artifact must contain exactly "
                    + ", ".join(sorted(expected_files))
                )
            uploaded = bundle.read(by_name[filename])
            if gate == "stig_manager":
                staged_handoff = bundle.read(by_name[HANDOFF_CEREMONY_ZIP])
                if (
                    len(staged_handoff) > MAX_HANDOFF_CEREMONY_BYTES
                    or not isinstance(expected_handoff_sha256, str)
                    or not SHA256.fullmatch(expected_handoff_sha256)
                    or sha256_bytes(staged_handoff) != expected_handoff_sha256
                ):
                    fail(
                        "protected STIG Manager staging handoff does not match "
                        "its recorded exact SHA-256"
                    )
            if gate == "recovery_drill":
                log = bundle.read(by_name["transaction-recovery-drill.log"])
                if (
                    not isinstance(expected_log_sha256, str)
                    or not SHA256.fullmatch(expected_log_sha256)
                    or sha256_bytes(log) != expected_log_sha256
                ):
                    fail("recovery-drill log does not match its recorded SHA-256")
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        fail(f"cannot read protected {gate} workflow artifact: {error}")
    actual = sha256_bytes(uploaded)
    if actual != expected_sha256:
        fail(
            f"committed {gate} evidence does not match the protected workflow artifact: "
            f"expected {expected_sha256}, got {actual}"
        )


def validate_content_ceremony_artifact(
    repository: str,
    run_id: str,
    expected_files: dict[str, bytes],
) -> None:
    response = github_json(
        f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"
    )
    if not isinstance(response, dict) or not isinstance(response.get("artifacts"), list):
        fail("GitHub ceremony artifact response must contain an artifacts array")
    artifacts = response["artifacts"]
    if response.get("total_count") != 1 or len(artifacts) != 1:
        fail("content-signing ceremony workflow must upload exactly one artifact")
    artifact = artifacts[0]
    if (
        not isinstance(artifact, dict)
        or artifact.get("name") != CONTENT_CEREMONY_ARTIFACT
        or artifact.get("expired") is not False
        or not isinstance(artifact.get("id"), int)
        or not isinstance(artifact.get("size_in_bytes"), int)
        or artifact["size_in_bytes"] <= 0
        or artifact["size_in_bytes"] > MAX_WORKFLOW_ARTIFACT_BYTES
    ):
        fail("content-signing ceremony artifact metadata or fixed name is invalid")
    archive = github_bytes(f"repos/{repository}/actions/artifacts/{artifact['id']}/zip")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            entries = bundle.infolist()
            by_name = {item.filename: item for item in entries}
            if (
                len(entries) != len(expected_files)
                or len(by_name) != len(entries)
                or set(by_name) != set(expected_files)
                or any(
                    item.is_dir()
                    or item.file_size <= 0
                    or item.file_size != len(expected_files[item.filename])
                    or item.file_size > MAX_EVIDENCE_BYTES
                    or stat.S_ISLNK(item.external_attr >> 16)
                    for item in entries
                )
            ):
                fail(
                    "protected content-signing ceremony artifact must contain exactly "
                    + ", ".join(sorted(expected_files))
                )
            for name, expected in expected_files.items():
                if bundle.read(by_name[name]) != expected:
                    fail(
                        f"committed {name} is not byte-for-byte identical to the "
                        "protected ceremony workflow artifact"
                    )
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        fail(f"cannot read protected content-signing ceremony artifact: {error}")


def validate_content_ceremony_environment(repository: str, approver: str) -> None:
    environment = github_json(
        f"repos/{repository}/environments/content-signing-ceremony"
    )
    if not isinstance(environment, dict):
        fail("content-signing-ceremony environment response must be an object")
    reviewer_rules = [
        rule
        for rule in environment.get("protection_rules") or []
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    if len(reviewer_rules) != 1:
        fail("content-signing-ceremony must have exactly one required-reviewers rule")
    rule = reviewer_rules[0]
    reviewers = rule.get("reviewers")
    branch_policy = environment.get("deployment_branch_policy") or {}
    if (
        environment.get("can_admins_bypass") is not False
        or rule.get("prevent_self_review") is not True
        or not isinstance(reviewers, list)
        or len(reviewers) != 1
        or not isinstance(reviewers[0], dict)
        or reviewers[0].get("type") != "User"
        or ((reviewers[0].get("reviewer") or {}).get("login") or "").casefold()
        != approver.casefold()
        or branch_policy.get("protected_branches") is not True
        or branch_policy.get("custom_branch_policies") is not False
    ):
        fail(
            "content-signing-ceremony must be non-bypassable, protected-branch-only, "
            "and require exactly the recorded GitHub user content approver"
        )


def validate_content_ceremony_workflow(
    ceremony: dict,
    approved_commit: str,
    custodian: str,
    approver: str,
    expected_files: dict[str, bytes],
) -> None:
    repository = ceremony.get("repository")
    expected_repository = os.environ.get("GITHUB_REPOSITORY")
    if (
        not isinstance(repository, str)
        or not repository.strip()
        or repository != expected_repository
    ):
        fail("content-signing ceremony was produced for a different repository")
    run_id = ceremony.get("workflow_run_id")
    if not isinstance(run_id, str) or not run_id.isdigit():
        fail("content-signing ceremony must identify its protected workflow run")
    run = github_json(f"repos/{repository}/actions/runs/{run_id}")
    actor = ((run.get("actor") or {}).get("login") or "") if isinstance(run, dict) else ""
    triggering_actor = (
        ((run.get("triggering_actor") or {}).get("login") or "")
        if isinstance(run, dict)
        else ""
    )
    if not isinstance(run, dict) or (
        run.get("head_sha") != approved_commit
        or run.get("name") != "Content Signing Ceremony"
        or run.get("path") != ".github/workflows/content-signing-ceremony.yml"
        or run.get("event") != "workflow_dispatch"
        or run.get("conclusion") != "success"
        or actor.casefold() != custodian.casefold()
        or triggering_actor.casefold() != custodian.casefold()
    ):
        fail(
            "content-signing ceremony is not bound to a successful protected workflow "
            "at approved_commit dispatched by the recorded key custodian"
        )
    validate_content_ceremony_environment(repository, approver)
    validate_content_ceremony_artifact(repository, run_id, expected_files)


def validate_handoff_ceremony_artifact(
    repository: str,
    run_id: str,
    expected_files: dict[str, bytes],
) -> None:
    response = github_json(
        f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"
    )
    artifacts = response.get("artifacts") if isinstance(response, dict) else None
    if (
        not isinstance(artifacts, list)
        or response.get("total_count") != 1
        or len(artifacts) != 1
    ):
        fail("handoff receiver ceremony workflow must upload exactly one artifact")
    artifact = artifacts[0]
    if (
        not isinstance(artifact, dict)
        or artifact.get("name") != HANDOFF_CEREMONY_ARTIFACT
        or artifact.get("expired") is not False
        or not isinstance(artifact.get("id"), int)
        or not isinstance(artifact.get("size_in_bytes"), int)
        or artifact["size_in_bytes"] <= 0
        or artifact["size_in_bytes"] > MAX_WORKFLOW_ARTIFACT_BYTES
    ):
        fail("handoff receiver ceremony artifact metadata or fixed name is invalid")
    archive = github_bytes(f"repos/{repository}/actions/artifacts/{artifact['id']}/zip")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            entries = bundle.infolist()
            by_name = {item.filename: item for item in entries}
            if (
                len(entries) != len(expected_files)
                or len(by_name) != len(entries)
                or set(by_name) != set(expected_files)
                or any(
                    item.is_dir()
                    or item.file_size <= 0
                    or item.file_size != len(expected_files[item.filename])
                    or item.file_size > MAX_HANDOFF_CEREMONY_BYTES
                    or stat.S_ISLNK(item.external_attr >> 16)
                    for item in entries
                )
            ):
                fail(
                    "protected handoff receiver artifact must contain exactly "
                    + ", ".join(sorted(expected_files))
                )
            for name, expected in expected_files.items():
                if bundle.read(by_name[name]) != expected:
                    fail(
                        f"committed {name} is not byte-for-byte identical to the "
                        "protected handoff receiver workflow artifact"
                    )
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        fail(f"cannot read protected handoff receiver artifact: {error}")


def validate_handoff_ceremony_environment(
    repository: str,
    run: dict,
    approver: str,
) -> None:
    environment = github_json(
        f"repos/{repository}/environments/handoff-receiver-ceremony"
    )
    if not isinstance(environment, dict):
        fail("handoff-receiver-ceremony environment response must be an object")
    reviewer_rules = [
        rule
        for rule in environment.get("protection_rules") or []
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    rule = reviewer_rules[0] if len(reviewer_rules) == 1 else {}
    reviewers = rule.get("reviewers") if isinstance(rule, dict) else None
    reviewer = reviewers[0] if isinstance(reviewers, list) and len(reviewers) == 1 else {}
    reviewer_login = (
        ((reviewer.get("reviewer") or {}).get("login") or "")
        if isinstance(reviewer, dict)
        else ""
    )
    branch_policy = environment.get("deployment_branch_policy") or {}
    run_id = run.get("id") or run.get("run_id")
    approvals = github_json(f"repos/{repository}/actions/runs/{run_id}/approvals")
    approved = [
        item
        for item in approvals
        if isinstance(item, dict) and item.get("state") == "approved"
    ] if isinstance(approvals, list) else []
    approval = approved[0] if len(approved) == 1 and len(approvals) == 1 else {}
    approved_environments = (
        approval.get("environments") or [] if isinstance(approval, dict) else []
    )
    jobs = github_json(
        f"repos/{repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100"
    )
    job_items = jobs.get("jobs") if isinstance(jobs, dict) else None
    job = job_items[0] if isinstance(job_items, list) and len(job_items) == 1 else {}
    labels = {
        str(label).casefold()
        for label in (job.get("labels") or [])
        if isinstance(label, str)
    } if isinstance(job, dict) else set()
    if (
        environment.get("can_admins_bypass") is not False
        or len(reviewer_rules) != 1
        or rule.get("prevent_self_review") is not True
        or not isinstance(reviewer, dict)
        or reviewer.get("type") != "User"
        or reviewer_login.casefold() != approver.casefold()
        or branch_policy.get("protected_branches") is not True
        or branch_policy.get("custom_branch_policies") is not False
        or run.get("run_attempt") != 1
        or not isinstance(approval, dict)
        or ((approval.get("user") or {}).get("login") or "").casefold()
        != approver.casefold()
        or len(approved_environments) != 1
        or not isinstance(approved_environments[0], dict)
        or approved_environments[0].get("name") != "handoff-receiver-ceremony"
        or not isinstance(jobs, dict)
        or jobs.get("total_count") != 1
        or not isinstance(job, dict)
        or job.get("name") != "Trusted receiver verifies producer signature"
        or job.get("conclusion") != "success"
        or not {
            "self-hosted",
            "linux",
            "x64",
            "automatestig-handoff-receiver",
        }.issubset(labels)
        or not isinstance(job.get("runner_id"), int)
        or job["runner_id"] <= 0
        or not isinstance(job.get("runner_name"), str)
        or not job["runner_name"].strip()
    ):
        fail(
            "handoff-receiver-ceremony must use one identified protected receiver, "
            "a non-bypassable protected-branch environment, and the exact distinct "
            "receiver approver"
        )


def validate_handoff_ceremony_workflow(
    ceremony: dict,
    approved_commit: str,
    custodian: str,
    approver: str,
    expected_files: dict[str, bytes],
) -> None:
    repository = ceremony.get("repository")
    expected_repository = os.environ.get("GITHUB_REPOSITORY")
    if (
        not isinstance(repository, str)
        or repository != expected_repository
    ):
        fail("handoff receiver ceremony was produced for a different repository")
    run_id = ceremony.get("workflow_run_id")
    if not isinstance(run_id, str) or not run_id.isdigit():
        fail("handoff receiver ceremony must identify its protected workflow run")
    run = github_json(f"repos/{repository}/actions/runs/{run_id}")
    actor = ((run.get("actor") or {}).get("login") or "") if isinstance(run, dict) else ""
    triggering_actor = (
        ((run.get("triggering_actor") or {}).get("login") or "")
        if isinstance(run, dict)
        else ""
    )
    if not isinstance(run, dict) or (
        run.get("head_sha") != approved_commit
        or run.get("name") != "Handoff Receiver Ceremony"
        or run.get("path") != ".github/workflows/handoff-receiver-ceremony.yml"
        or run.get("event") != "workflow_dispatch"
        or run.get("conclusion") != "success"
        or actor.casefold() != custodian.casefold()
        or triggering_actor.casefold() != custodian.casefold()
        or actor.casefold() == approver.casefold()
    ):
        fail(
            "handoff receiver ceremony is not bound to a successful protected "
            "workflow at approved_commit dispatched by the recorded key custodian"
        )
    validate_handoff_ceremony_environment(repository, run, approver)
    validate_handoff_ceremony_artifact(repository, run_id, expected_files)


def validate_required_status_bindings(checks: object) -> None:
    if not isinstance(checks, dict):
        fail("main branch required-status-check response must be an object")
    raw_bindings = checks.get("checks")
    if not isinstance(raw_bindings, list):
        fail("main branch required checks must be bound to their expected GitHub App")
    bindings: dict[str, object] = {}
    duplicates: set[str] = set()
    for item in raw_bindings:
        if not isinstance(item, dict):
            continue
        context = item.get("context")
        if context not in REQUIRED_STATUS_CONTEXTS:
            continue
        if context in bindings:
            duplicates.add(context)
        bindings[context] = item.get("app_id")
    missing = sorted(REQUIRED_STATUS_CONTEXTS - set(bindings))
    misbound = sorted(
        context
        for context, app_id in bindings.items()
        if app_id != GITHUB_ACTIONS_APP_ID
    )
    if missing or misbound or duplicates:
        details = []
        if missing:
            details.append(f"missing={missing}")
        if misbound:
            details.append(
                f"not bound to github-actions app {GITHUB_ACTIONS_APP_ID}={misbound}"
            )
        if duplicates:
            details.append(f"duplicate={sorted(duplicates)}")
        fail("main branch required-status policy is invalid; " + "; ".join(details))


def validate_release_tag_authority(tag_ruleset: object) -> None:
    if not isinstance(tag_ruleset, dict):
        fail("an active v* release-tag ruleset is required")
    bypass_actors = tag_ruleset.get("bypass_actors")
    if (
        not isinstance(bypass_actors, list)
        or len(bypass_actors) != 1
        or not isinstance(bypass_actors[0], dict)
        or any(
            bypass_actors[0].get(field) != expected
            for field, expected in RELEASE_TAG_AUTHORITY.items()
        )
    ):
        fail(
            "the v* release-tag ruleset must name exactly the reviewed release "
            "authority with an always bypass"
        )


def is_closed_release_tag_ruleset(candidate: object) -> bool:
    """Accept only a ruleset whose ref condition protects every v* tag."""
    if not isinstance(candidate, dict):
        return False
    ref_name = ((candidate.get("conditions") or {}).get("ref_name") or {})
    rule_types = {
        rule.get("type")
        for rule in candidate.get("rules") or []
        if isinstance(rule, dict)
    }
    return (
        ref_name.get("include") == ["refs/tags/v*"]
        and ref_name.get("exclude") == []
        and {"creation", "update", "deletion"} <= rule_types
    )


def validate_repository_controls() -> None:
    repository = os.environ["GITHUB_REPOSITORY"]
    immutable = github_json(f"repos/{repository}/immutable-releases")
    if not isinstance(immutable, dict) or immutable.get("enabled") is not True:
        fail("repository-level immutable releases must be enabled")

    protection = github_json(f"repos/{repository}/branches/main/protection")
    if not isinstance(protection, dict):
        fail("main branch protection response must be an object")
    reviews = protection.get("required_pull_request_reviews") or {}
    checks = protection.get("required_status_checks") or {}
    validate_required_status_bindings(checks)
    if (
        checks.get("strict") is not True
        or reviews.get("required_approving_review_count", 0) < 2
        or reviews.get("dismiss_stale_reviews") is not True
        or reviews.get("require_code_owner_reviews") is not True
        or reviews.get("require_last_push_approval") is not True
        or (protection.get("enforce_admins") or {}).get("enabled") is not True
        or (protection.get("required_linear_history") or {}).get("enabled") is not True
        or (protection.get("required_conversation_resolution") or {}).get("enabled") is not True
        or (protection.get("allow_force_pushes") or {}).get("enabled") is not False
        or (protection.get("allow_deletions") or {}).get("enabled") is not False
    ):
        fail("main branch protection does not enforce the reviewed release policy")

    for environment_name in ("live-device-acceptance", "external-acceptance"):
        environment = github_json(f"repos/{repository}/environments/{environment_name}")
        if not isinstance(environment, dict):
            fail(f"{environment_name} response must be an object")
        rules = environment.get("protection_rules")
        reviewers = next(
            (
                rule
                for rule in (rules or [])
                if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
            ),
            {},
        )
        branch_policy = (environment or {}).get("deployment_branch_policy") or {}
        if (
            environment.get("can_admins_bypass") is not False
            or reviewers.get("prevent_self_review") is not True
            or not reviewers.get("reviewers")
            or branch_policy.get("protected_branches") is not True
            or branch_policy.get("custom_branch_policies") is not False
        ):
            fail(f"{environment_name} is not a non-bypassable, independently reviewed environment")

    rulesets = github_json(f"repos/{repository}/rulesets?includes_parents=true")
    tag_ruleset = None
    for summary in rulesets if isinstance(rulesets, list) else []:
        if (
            isinstance(summary, dict)
            and summary.get("target") == "tag"
            and summary.get("enforcement") == "active"
        ):
            candidate = github_json(f"repos/{repository}/rulesets/{summary.get('id')}")
            if not isinstance(candidate, dict):
                continue
            if is_closed_release_tag_ruleset(candidate):
                tag_ruleset = candidate
                break
    validate_release_tag_authority(tag_ruleset)


def validate_github_approvals(
    pull_request_number: int,
    approved_commit: str,
    reviewers: dict[str, tuple[str, datetime]],
) -> None:
    repository = os.environ["GITHUB_REPOSITORY"]
    pull = github_json(f"repos/{repository}/pulls/{pull_request_number}")
    if not isinstance(pull, dict):
        fail("GitHub pull-request response must be an object")
    if (
        not pull.get("merged_at")
        or pull.get("merge_commit_sha") != approved_commit
        or (pull.get("base") or {}).get("ref") != "main"
        or (pull.get("base") or {}).get("repo", {}).get("full_name") != repository
    ):
        fail("approved pull request must be merged to this repository's main branch at approved_commit")
    author = ((pull.get("user") or {}).get("login") or "").casefold()
    result = subprocess.run(
        [
            "gh",
            "api",
            "--paginate",
            f"repos/{repository}/pulls/{pull_request_number}/reviews",
            "--jq",
            ".[]",
        ],
        text=True,
        capture_output=True,
    )
    if result.returncode:
        fail(f"cannot verify GitHub reviews: {result.stderr.strip()}")
    latest: dict[str, dict] = {}
    for line in result.stdout.splitlines():
        try:
            review = strict_json_loads(line)
        except ValueError as error:
            fail(f"GitHub returned an invalid review record: {error}")
        login = ((review.get("user") or {}).get("login") or "").casefold()
        previous = latest.get(login)
        if login and (
            previous is None
            or int(review.get("id") or 0) > int(previous.get("id") or 0)
        ):
            latest[login] = review
    head_sha = (pull.get("head") or {}).get("sha")
    for role, (login, recorded_at) in reviewers.items():
        normalized = login.casefold()
        review = latest.get(normalized)
        if normalized == author:
            fail(f"{role} reviewer cannot be the pull-request author")
        if not review or review.get("state") != "APPROVED":
            fail(f"{role} reviewer @{login} does not have a current GitHub approval")
        if review.get("commit_id") != head_sha:
            fail(f"{role} reviewer @{login} did not approve the final pull-request head")
        submitted = timestamp(review.get("submitted_at"), f"GitHub review by @{login}")
        if submitted != recorded_at:
            fail(f"{role} reviewer @{login} approved_at does not match GitHub")


def validate_producer_authenticated_handoff(
    repo: Path,
    value: object,
    tag: str,
    approved_commit: str,
    now: datetime,
    stig_manager_gate: dict,
    verify_github: bool,
) -> set[Path]:
    field = "producer_authenticated_handoff"
    required = {
        "fingerprint_sha256",
        "ceremony_reference",
        "ceremony_sha256",
        "public_key_reference",
        "public_key_sha256",
        "handoff_reference",
        "handoff_sha256",
        "signature_reference",
        "signature_sha256",
        "key_custody_reference",
        "key_custody_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        fail(f"{field} must contain exactly {sorted(required)}")
    for name in (
        "fingerprint_sha256",
        "ceremony_sha256",
        "public_key_sha256",
        "handoff_sha256",
        "signature_sha256",
        "key_custody_sha256",
    ):
        if not isinstance(value.get(name), str) or not SHA256.fullmatch(value[name]):
            fail(f"{field}.{name} must be a lowercase SHA-256 digest")

    ceremony_path, ceremony_raw = read_bound_file(
        repo,
        value.get("ceremony_reference"),
        value.get("ceremony_sha256"),
        tag,
        field,
    )
    public_key_path, public_key_raw = read_bound_file(
        repo,
        value.get("public_key_reference"),
        value.get("public_key_sha256"),
        tag,
        f"{field}.public_key",
        32,
    )
    handoff_path, handoff_raw = read_bound_file(
        repo,
        value.get("handoff_reference"),
        value.get("handoff_sha256"),
        tag,
        f"{field}.handoff",
        MAX_HANDOFF_CEREMONY_BYTES,
    )
    signature_path, signature_raw = read_bound_file(
        repo,
        value.get("signature_reference"),
        value.get("signature_sha256"),
        tag,
        f"{field}.signature",
        MAX_HANDOFF_SIGNATURE_BYTES,
    )
    custody_path, custody_raw = read_bound_file(
        repo,
        value.get("key_custody_reference"),
        value.get("key_custody_sha256"),
        tag,
        f"{field}.key_custody",
        MAX_HANDOFF_CUSTODY_BYTES,
    )
    paths = {
        ceremony_path,
        public_key_path,
        handoff_path,
        signature_path,
        custody_path,
    }
    if (
        ceremony_path.name != HANDOFF_CEREMONY_EVIDENCE
        or public_key_path.name != HANDOFF_CEREMONY_PUBLIC_KEY
        or handoff_path.name != HANDOFF_CEREMONY_ZIP
        or signature_path.name != HANDOFF_CEREMONY_SIGNATURE
        or custody_path.name != HANDOFF_CEREMONY_CUSTODY
        or len(paths) != 5
    ):
        fail("producer-authenticated handoff files must use the five fixed names")
    if len(public_key_raw) != 32:
        fail("producer-authenticated handoff public key must be exactly 32 bytes")

    try:
        ceremony = strict_json_loads(ceremony_raw)
        signature = strict_json_loads(signature_raw)
        custody = strict_json_loads(custody_raw)
    except ValueError as error:
        fail(f"producer-authenticated handoff artifact is not strict JSON: {error}")
    if not all(isinstance(item, dict) for item in (ceremony, signature, custody)):
        fail("producer-authenticated handoff JSON artifacts must contain objects")

    manager_path, manager = read_bound_artifact(
        repo,
        stig_manager_gate.get("evidence_reference"),
        stig_manager_gate.get("evidence_sha256"),
        tag,
        "acceptance.stig_manager",
    )
    paths.add(manager_path)
    manager_metrics = manager.get("metrics") if isinstance(manager, dict) else None
    manager_run_id = manager.get("workflow_run_id") if isinstance(manager, dict) else None
    handoff_digest = sha256_bytes(handoff_raw)
    key_digest = sha256_bytes(public_key_raw)
    signature_digest = sha256_bytes(signature_raw)
    custody_digest = sha256_bytes(custody_raw)

    ceremony_fields = {
        "schema",
        "passed",
        "producer_signature_verified",
        "trusted_cli_verification_succeeded",
        "key_custody_ceremony_verified",
        "completed_at",
        "source_commit",
        "repository",
        "workflow_run_id",
        "staging_workflow_run_id",
        "protected_environment",
        "automatestig_cli_sha256",
        "verification_output_sha256",
        "staging_evidence_sha256",
        "handoff_filename",
        "handoff_sha256",
        "signature_filename",
        "signature_sha256",
        "public_key_filename",
        "public_key_sha256",
        "producer_key_fingerprint",
        "key_custody_filename",
        "key_custody_sha256",
        "participants",
    }
    if (
        set(ceremony) != ceremony_fields
        or ceremony.get("schema") != "automatestig-handoff-receiver-ceremony/v1"
        or ceremony.get("passed") is not True
        or ceremony.get("producer_signature_verified") is not True
        or ceremony.get("trusted_cli_verification_succeeded") is not True
        or ceremony.get("key_custody_ceremony_verified") is not True
        or ceremony.get("source_commit") != approved_commit
        or ceremony.get("protected_environment") != "handoff-receiver-ceremony"
        or not isinstance(ceremony.get("repository"), str)
        or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", ceremony["repository"]
        )
        or not isinstance(ceremony.get("workflow_run_id"), str)
        or not ceremony["workflow_run_id"].isdigit()
        or ceremony.get("staging_workflow_run_id") != manager_run_id
        or ceremony.get("staging_evidence_sha256")
        != stig_manager_gate.get("evidence_sha256")
        or ceremony.get("handoff_filename") != HANDOFF_CEREMONY_ZIP
        or ceremony.get("handoff_sha256") != handoff_digest
        or ceremony.get("signature_filename") != HANDOFF_CEREMONY_SIGNATURE
        or ceremony.get("signature_sha256") != signature_digest
        or ceremony.get("public_key_filename") != HANDOFF_CEREMONY_PUBLIC_KEY
        or ceremony.get("public_key_sha256") != key_digest
        or ceremony.get("producer_key_fingerprint") != f"SHA256:{key_digest}"
        or ceremony.get("key_custody_filename") != HANDOFF_CEREMONY_CUSTODY
        or ceremony.get("key_custody_sha256") != custody_digest
        or not isinstance(ceremony.get("automatestig_cli_sha256"), str)
        or not SHA256.fullmatch(ceremony["automatestig_cli_sha256"])
        or not isinstance(ceremony.get("verification_output_sha256"), str)
        or not SHA256.fullmatch(ceremony["verification_output_sha256"])
        or not isinstance(manager_metrics, dict)
        or manager_metrics.get("producer_handoff_filename") != HANDOFF_CEREMONY_ZIP
        or manager_metrics.get("handoff_sha256") != handoff_digest
        or value["fingerprint_sha256"] != key_digest
        or value["public_key_sha256"] != key_digest
        or value["handoff_sha256"] != handoff_digest
        or value["signature_sha256"] != signature_digest
        or value["key_custody_sha256"] != custody_digest
    ):
        fail(
            "producer-authenticated handoff ceremony is invalid or not bound to "
            "the exact approved commit, staging run, trust anchor, ZIP, sidecar, "
            "custody record, and successful trusted CLI verification"
        )
    completed = timestamp(ceremony.get("completed_at"), f"{field}.completed_at")
    manager_completed = artifact_timestamp(manager, "acceptance.stig_manager")
    if (
        completed > now
        or now - completed > timedelta(days=90)
        or completed < manager_completed
    ):
        fail("producer-authenticated handoff ceremony has an invalid execution window")

    participants = ceremony.get("participants")
    roles = {
        item.get("role"): item.get("github_login", "")
        for item in participants or []
        if isinstance(item, dict)
    }
    if (
        not isinstance(participants, list)
        or len(participants) != 2
        or set(roles) != {"key_custodian", "receiver_approver"}
        or len({login.casefold() for login in roles.values()}) != 2
        or any(
            not isinstance(item, dict)
            or set(item) != {"role", "github_login"}
            or not isinstance(item.get("github_login"), str)
            or len(item["github_login"]) > 39
            or not GITHUB_LOGIN.fullmatch(item["github_login"])
            for item in participants
        )
    ):
        fail(
            "producer-authenticated handoff requires distinct key custodian and "
            "receiver approver identities"
        )

    signature_fields = {
        "schema",
        "algorithm",
        "handoff_schema",
        "run_id",
        "handoff_sha256",
        "signing_key_fingerprint",
        "signature",
    }
    if (
        set(signature) != signature_fields
        or signature.get("schema")
        != "automatestig.selected-run-handoff-signature.v1"
        or signature.get("algorithm") != "ed25519-sha256"
        or signature.get("handoff_schema") != "automatestig.selected-run-handoff.v4"
        or not isinstance(signature.get("run_id"), str)
        or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            signature["run_id"],
        )
        or signature.get("handoff_sha256") != handoff_digest
        or signature.get("signing_key_fingerprint") != f"SHA256:{key_digest}"
        or not isinstance(signature.get("signature"), str)
        or not re.fullmatch(r"[0-9a-f]{128}", signature["signature"])
    ):
        fail(
            "producer signature sidecar is not exactly bound to the current "
            "handoff schema, ZIP, run, and trusted producer key"
        )

    custody_fields = {
        "schema",
        "source_commit",
        "signed_at",
        "producer_key_fingerprint",
        "public_key_sha256",
        "handoff_sha256",
        "signature_sidecar_sha256",
        "key_custodian",
        "receiver_approver",
        "signing_host_reference",
        "primary_key_media_reference",
        "backup_key_media_reference",
        "private_key_entered_ci",
        "private_key_entered_scanner_runtime",
        "private_key_material_recorded",
        "revocation_status_checked",
    }
    signed_at = timestamp(custody.get("signed_at"), f"{field}.key_custody.signed_at")
    references = (
        custody.get("signing_host_reference"),
        custody.get("primary_key_media_reference"),
        custody.get("backup_key_media_reference"),
    )
    reference_pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}$")
    if (
        set(custody) != custody_fields
        or custody.get("schema")
        != "automatestig-handoff-key-custody-ceremony/v1"
        or custody.get("source_commit") != approved_commit
        or custody.get("producer_key_fingerprint") != f"SHA256:{key_digest}"
        or custody.get("public_key_sha256") != key_digest
        or custody.get("handoff_sha256") != handoff_digest
        or custody.get("signature_sidecar_sha256") != signature_digest
        or str(custody.get("key_custodian", "")).casefold()
        != roles["key_custodian"].casefold()
        or str(custody.get("receiver_approver", "")).casefold()
        != roles["receiver_approver"].casefold()
        or signed_at < manager_completed
        or signed_at > completed
        or now - signed_at > timedelta(days=90)
        or len(set(references)) != 3
        or any(
            not isinstance(reference, str) or not reference_pattern.fullmatch(reference)
            for reference in references
        )
        or custody.get("private_key_entered_ci") is not False
        or custody.get("private_key_entered_scanner_runtime") is not False
        or custody.get("private_key_material_recorded") is not False
        or custody.get("revocation_status_checked") is not True
    ):
        fail(
            "handoff key-custody ceremony is invalid or does not prove the exact "
            "protected signing boundaries and artifact bindings"
        )

    if verify_github:
        validate_handoff_ceremony_workflow(
            ceremony,
            approved_commit,
            roles["key_custodian"],
            roles["receiver_approver"],
            {
                HANDOFF_CEREMONY_EVIDENCE: ceremony_raw,
                HANDOFF_CEREMONY_PUBLIC_KEY: public_key_raw,
                HANDOFF_CEREMONY_ZIP: handoff_raw,
                HANDOFF_CEREMONY_SIGNATURE: signature_raw,
                HANDOFF_CEREMONY_CUSTODY: custody_raw,
            },
        )
    return paths


def validate_document(repo: Path, path: Path, expected_tag: str, offline: bool) -> None:
    try:
        data = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"cannot read release evidence {path}: {error}")
    if data.get("schema") != "automatestig-release-evidence/v1":
        fail("release evidence has an unsupported schema")
    if data.get("tag") != expected_tag or not TAG.fullmatch(expected_tag):
        fail(f"release evidence tag must match {expected_tag}")
    approved_commit = data.get("approved_commit")
    if not isinstance(approved_commit, str) or not SHA.fullmatch(approved_commit):
        fail("approved_commit must be a full lowercase Git SHA")
    approved_at = timestamp(data.get("approved_at"), "approved_at")
    now = datetime.now(timezone.utc)
    if approved_at > now or now - approved_at > timedelta(days=90):
        fail("approved_at must not be in the future or older than 90 days")
    pull_request_number = data.get("pull_request")
    if not isinstance(pull_request_number, int) or isinstance(pull_request_number, bool) or pull_request_number < 1:
        fail("pull_request must be a positive GitHub pull-request number")

    reviewers = data.get("reviewers")
    if not isinstance(reviewers, list):
        fail("reviewers must be an array")
    roles: dict[str, tuple[str, datetime]] = {}
    for index, reviewer in enumerate(reviewers):
        if not isinstance(reviewer, dict):
            fail(f"reviewers[{index}] must be an object")
        role = reviewer.get("role")
        login = reviewer.get("github_login")
        if role not in {"software", "security"}:
            fail(f"reviewers[{index}].role must be software or security")
        if not isinstance(login, str) or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", login):
            fail(f"reviewers[{index}].github_login must be a valid GitHub login")
        if role in roles:
            fail(f"reviewers contains more than one {role} approval")
        review_time = timestamp(reviewer.get("approved_at"), f"reviewers[{index}].approved_at")
        if review_time > approved_at:
            fail(f"reviewers[{index}].approved_at cannot be after approved_at")
        roles[role] = (login, review_time)
    if set(roles) != {"software", "security"}:
        fail("release evidence requires one software and one security reviewer")
    if roles["software"][0].casefold() == roles["security"][0].casefold():
        fail("software and security approvals must come from different people")
    if not offline:
        validate_repository_controls()
        validate_github_approvals(pull_request_number, approved_commit, roles)

    acceptance = data.get("acceptance")
    if not isinstance(acceptance, dict) or set(acceptance) != set(GATES):
        fail(f"acceptance must contain exactly {list(GATES)}")
    evidence_paths = {path.relative_to(repo)}
    for gate in GATES:
        evidence_paths.add(
            validate_gate(
                acceptance[gate],
                f"acceptance.{gate}",
                gate,
                now,
                repo,
                expected_tag,
                approved_commit,
                not offline,
            )
        )
    evidence_paths.add(
        validate_gate(
            data.get("first_use_ux"),
            "first_use_ux",
            "first_use_ux",
            now,
            repo,
            expected_tag,
            approved_commit,
            not offline,
        )
    )
    evidence_paths.add(
        validate_gate(
            data.get("recovery_drill"),
            "recovery_drill",
            "recovery_drill",
            now,
            repo,
            expected_tag,
            approved_commit,
            not offline,
        )
    )

    key = data.get("content_signing_key")
    if not isinstance(key, dict):
        fail("content_signing_key must be an object")
    required_key_fields = {
        "fingerprint_sha256",
        "ceremony_reference",
        "ceremony_sha256",
        "public_key_reference",
        "public_key_sha256",
        "test_pack_reference",
        "test_pack_sha256",
    }
    if set(key) != required_key_fields:
        fail(f"content_signing_key must contain exactly {sorted(required_key_fields)}")
    if not isinstance(key.get("fingerprint_sha256"), str) or not SHA256.fullmatch(key["fingerprint_sha256"]):
        fail("content_signing_key.fingerprint_sha256 must be a lowercase SHA-256 digest")
    ceremony_path, ceremony_raw = read_bound_file(
        repo,
        key.get("ceremony_reference"),
        key.get("ceremony_sha256"),
        expected_tag,
        "content_signing_key",
    )
    public_key_path, public_key_raw = read_bound_file(
        repo,
        key.get("public_key_reference"),
        key.get("public_key_sha256"),
        expected_tag,
        "content_signing_key.public_key",
        32,
    )
    test_pack_path, test_pack_raw = read_bound_file(
        repo,
        key.get("test_pack_reference"),
        key.get("test_pack_sha256"),
        expected_tag,
        "content_signing_key.test_pack",
        MAX_CEREMONY_PACK_BYTES,
    )
    evidence_paths.update((ceremony_path, public_key_path, test_pack_path))
    if (
        ceremony_path.name != CONTENT_CEREMONY_EVIDENCE
        or public_key_path.name != CONTENT_CEREMONY_PUBLIC_KEY
        or test_pack_path.name != CONTENT_CEREMONY_TEST_PACK
        or len({ceremony_path, public_key_path, test_pack_path}) != 3
    ):
        fail("content-signing ceremony files must use the three fixed, distinct names")
    try:
        ceremony = strict_json_loads(ceremony_raw)
    except ValueError as error:
        fail(f"content-signing ceremony artifact is not valid JSON: {error}")
    ceremony_fields = {
        "schema",
        "passed",
        "signature_verified",
        "completed_at",
        "source_commit",
        "repository",
        "workflow_run_id",
        "protected_environment",
        "automatestig_cli_sha256",
        "public_key_filename",
        "public_key_sha256",
        "public_key_fingerprint",
        "test_pack_filename",
        "pack_sha256",
        "participants",
    }
    public_key_digest = sha256_bytes(public_key_raw)
    test_pack_digest = sha256_bytes(test_pack_raw)
    if (
        not isinstance(ceremony, dict)
        or set(ceremony) != ceremony_fields
        or ceremony.get("schema") != "automatestig-content-signing-ceremony/v1"
        or ceremony.get("passed") is not True
        or ceremony.get("signature_verified") is not True
        or ceremony.get("source_commit") != approved_commit
        or ceremony.get("protected_environment") != "content-signing-ceremony"
        or ceremony.get("public_key_filename") != CONTENT_CEREMONY_PUBLIC_KEY
        or ceremony.get("test_pack_filename") != CONTENT_CEREMONY_TEST_PACK
        or ceremony.get("public_key_sha256") != public_key_digest
        or ceremony.get("public_key_fingerprint") != f"SHA256:{public_key_digest}"
        or ceremony.get("pack_sha256") != test_pack_digest
        or key["fingerprint_sha256"] != public_key_digest
        or key["public_key_sha256"] != public_key_digest
        or key["test_pack_sha256"] != test_pack_digest
        or not isinstance(ceremony.get("automatestig_cli_sha256"), str)
        or not SHA256.fullmatch(ceremony["automatestig_cli_sha256"])
    ):
        fail(
            "content-signing ceremony artifact is invalid or is not bound to its exact "
            "public key, signed test pack, approved commit, and verifier"
        )
    completed = artifact_timestamp(ceremony, "content_signing_key")
    if completed > now or now - completed > timedelta(days=365):
        fail("content-signing ceremony is in the future or older than one year")
    participants = ceremony.get("participants") or []
    ceremony_roles = {
        item.get("role"): item.get("github_login", "").casefold()
        for item in participants
        if isinstance(item, dict) and item.get("role") in {"key_custodian", "content_approver"}
    }
    if (
        len(participants) != 2
        or set(ceremony_roles) != {"key_custodian", "content_approver"}
        or not all(ceremony_roles.values())
        or len(set(ceremony_roles.values())) != 2
        or any(
            not isinstance(item, dict)
            or set(item) != {"role", "github_login"}
            or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})",
                str(item.get("github_login", "")),
            )
            for item in participants
        )
    ):
        fail("content-signing ceremony requires distinct key custodian and content approver identities")
    if not offline:
        validate_content_ceremony_workflow(
            ceremony,
            approved_commit,
            ceremony_roles["key_custodian"],
            ceremony_roles["content_approver"],
            {
                CONTENT_CEREMONY_EVIDENCE: ceremony_raw,
                CONTENT_CEREMONY_PUBLIC_KEY: public_key_raw,
                CONTENT_CEREMONY_TEST_PACK: test_pack_raw,
            },
        )

    evidence_paths.update(
        validate_producer_authenticated_handoff(
            repo,
            data.get("producer_authenticated_handoff"),
            expected_tag,
            approved_commit,
            now,
            acceptance["stig_manager"],
            not offline,
        )
    )

    risk_acceptances = data.get("risk_acceptances")
    if not isinstance(risk_acceptances, list):
        fail("risk_acceptances must be an array (empty is allowed)")
    for index, risk in enumerate(risk_acceptances):
        if not isinstance(risk, dict):
            fail(f"risk_acceptances[{index}] must be an object")
        for field in ("id", "owner", "justification"):
            if not isinstance(risk.get(field), str) or not risk[field].strip():
                fail(f"risk_acceptances[{index}].{field} must be non-empty")
        if timestamp(risk.get("expires_at"), f"risk_acceptances[{index}].expires_at") <= now:
            fail(f"risk_acceptances[{index}] has expired")

    ancestry = git(repo, "merge-base", "--is-ancestor", approved_commit, "HEAD")
    if ancestry.returncode:
        fail("approved_commit is not an ancestor of the tagged commit")
    changed = git(repo, "diff", "--name-only", f"{approved_commit}..HEAD")
    if changed.returncode:
        fail(f"cannot inspect changes after approval: {changed.stderr.strip()}")
    allowed = {item.as_posix() for item in evidence_paths}
    after_approval = [line for line in changed.stdout.splitlines() if line and line not in allowed]
    if after_approval:
        fail(
            "the tagged tree contains changes after approved_commit other than its release evidence: "
            + ", ".join(after_approval)
        )
    if not offline:
        remote_main = git(repo, "rev-parse", "--verify", "origin/main")
        if remote_main.returncode:
            fail("connected release validation requires a fetched origin/main")
        on_main = git(repo, "merge-base", "--is-ancestor", "HEAD", "origin/main")
        if on_main.returncode:
            fail("the release tag must point to a commit on origin/main")
    print(
        f"Release evidence valid for {expected_tag}: independent reviewers, five "
        "acceptance gates, first-use UX study, recovery drill, content signing, "
        "producer-authenticated handoff receiver ceremony, and approved commit ancestry"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--schema-only", action="store_true")
    parser.add_argument("--first-use-study", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--product-version")
    parser.add_argument("--gui-binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-passed", action="store_true")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="skip GitHub approval/main-branch verification for local development only",
    )
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    for schema_name in (
        "release-evidence.schema.json",
        "first-use-ux-study.schema.json",
        "handoff-key-custody-ceremony.schema.json",
        "handoff-receiver-ceremony.schema.json",
    ):
        schema = repo / "schemas" / schema_name
        try:
            document = strict_json_loads(schema.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            fail(f"cannot read {schema_name}: {error}")
        if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            fail(f"{schema_name} must use JSON Schema 2020-12")
    study_mode = args.first_use_study is not None
    study_only_options = (
        args.source_commit,
        args.product_version,
        args.gui_binary,
        args.output,
        args.require_passed,
    )
    if study_mode:
        if args.tag or args.schema_only or args.offline:
            fail("--first-use-study cannot be combined with release-document options")
        if (
            not isinstance(args.source_commit, str)
            or not SHA.fullmatch(args.source_commit)
            or not isinstance(args.product_version, str)
            or not TAG.fullmatch(args.product_version)
            or args.gui_binary is None
        ):
            fail(
                "--first-use-study requires --source-commit, --product-version, "
                "and --gui-binary"
            )
        if args.output is not None and args.require_passed:
            fail("study normalization and --require-passed must be separate steps")
        try:
            raw = args.first_use_study.read_bytes()
        except OSError as error:
            fail(f"cannot read first-use study: {error}")
        if not raw or len(raw) > MAX_FIRST_USE_STUDY_BYTES:
            fail("first-use study must be non-empty and no larger than 128 KiB")
        try:
            study = strict_json_loads(raw)
        except ValueError as error:
            fail(f"first-use study is not strict JSON: {error}")
        try:
            gui_raw = args.gui_binary.read_bytes()
        except OSError as error:
            fail(f"cannot read tested GUI binary: {error}")
        if not gui_raw:
            fail("tested GUI binary must be non-empty")
        if isinstance(study, dict):
            study = dict(study)
            workflow_run_id = os.environ.get("GITHUB_RUN_ID")
            if workflow_run_id:
                study["workflow_run_id"] = workflow_run_id
            expected_repository = os.environ.get("GITHUB_REPOSITORY")
            if expected_repository and study.get("repository") != expected_repository:
                fail("first-use study repository differs from the protected workflow")
        if (
            isinstance(study, dict)
            and study.get("automatestig_gui_sha256") != sha256_bytes(gui_raw)
        ):
            fail("first-use study GUI digest does not match the exact tested binary")
        validate_first_use_study(
            study,
            "first-use study",
            args.source_commit,
            args.product_version,
            datetime.now(timezone.utc),
            args.require_passed,
        )
        if args.output is not None:
            normalized = (
                json.dumps(
                    study,
                    sort_keys=True,
                    indent=2,
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            )
            try:
                args.output.write_text(normalized, encoding="utf-8")
            except OSError as error:
                fail(f"cannot write normalized first-use study: {error}")
            print(f"First-use study record validated and written to {args.output}")
        else:
            print("First-use study record validated")
        return
    if any(option not in (None, False) for option in study_only_options):
        fail("standalone study options require --first-use-study")
    if args.schema_only:
        if args.tag or args.offline:
            fail("--schema-only cannot be combined with --tag or --offline")
        print("Release evidence schema valid")
        return
    if not args.tag or not TAG.fullmatch(args.tag):
        fail("--tag must be a semantic version tag beginning with v")
    validate_document(
        repo,
        repo / "release-evidence" / f"{args.tag}.json",
        args.tag,
        args.offline,
    )


if __name__ == "__main__":
    main()
