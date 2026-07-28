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
GATES = ("ontap", "freebsd", "cisco_ios_xe", "stig_viewer", "stig_manager")
EXPECTED_DEVICE_BENCHMARKS = {
    "ontap": ("NetApp_ONTAP_DSC_9-x_STIG", "V2R2"),
    "freebsd": ("General_Purpose_Operating_System", "V3R3"),
    "cisco_ios_xe": ("Cisco_IOS-XE_Router_NDM_STIG", "V3R7"),
}
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_WORKFLOW_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_CEREMONY_PACK_BYTES = 48_000
CONTENT_CEREMONY_ARTIFACT = "content-signing-ceremony"
CONTENT_CEREMONY_EVIDENCE = "content-signing-ceremony.json"
CONTENT_CEREMONY_PUBLIC_KEY = "content-signing-public-key.pub"
CONTENT_CEREMONY_TEST_PACK = "content-signing-test-pack.stigpack"
REQUIRED_STATUS_CONTEXTS = {
    "Governance",
    "Check",
    "Test (ubuntu-latest)",
    "Test (windows-latest)",
    "Test (macos-latest)",
    "E2E acceptance",
    "Format",
    "Clippy",
    "Frontend syntax",
    "Archive fuzz smoke",
    "Coverage manifest validation",
    "Dependency audit",
    "Dependency Review",
    "CodeQL (actions)",
    "CodeQL (javascript-typescript)",
    "CodeQL (python)",
    "CodeQL (rust)",
    "Build Release (x86_64-unknown-linux-gnu)",
    "Build Release (aarch64-unknown-linux-gnu)",
    "Build Release (x86_64-pc-windows-msvc)",
    "Build Release (x86_64-apple-darwin)",
    "Build Release (aarch64-apple-darwin)",
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
) -> tuple[Path, dict]:
    relative, raw = read_bound_file(repo, reference, expected_sha256, tag, field)
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"{field} artifact is not valid JSON: {error}")
    if not isinstance(document, dict):
        fail(f"{field} artifact must contain a JSON object")
    return relative, document


def artifact_timestamp(document: dict, field: str) -> datetime:
    for name in ("executed_at", "tested_at", "completed_at"):
        if name in document:
            return timestamp(document[name], f"{field} artifact {name}")
    fail(f"{field} artifact has no execution timestamp")


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
            document.get("output_sha256") if gate == "recovery_drill" else None,
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
            "benchmark_rule_set_sha256",
            "automated_vuln_set_sha256",
            "check_pack_sha256",
            "input_sha256",
            "source_state_sha256",
            "scenario_bindings_sha256",
            "oracle_sha256",
            "oracle_expected_status_sha256",
            "observed_status_sha256",
        ):
            if not isinstance(result.get(name), str) or not SHA256.fullmatch(result[name]):
                fail(f"{field} artifact result.{name} must be a SHA-256 digest")
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
        if not isinstance(adjudicator, str) or len(adjudicator.strip()) < 3:
            fail(f"{field} artifact must name the independent oracle adjudicator")
        adjudicated_at = timestamp(
            result.get("oracle_adjudicated_at"),
            f"{field} artifact result.oracle_adjudicated_at",
        )
        now = datetime.now(timezone.utc)
        if adjudicated_at > now or now - adjudicated_at > timedelta(days=90):
            fail(f"{field} artifact decision oracle is in the future or older than 90 days")
        if (
            result["oracle_expected_status_sha256"]
            != result["observed_status_sha256"]
        ):
            fail(
                f"{field} artifact automated decisions do not match its "
                "independent oracle"
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
            "automatestig_gui_sha256",
            "benchmark_sha256",
            "config_fixture_sha256",
        ):
            if not isinstance(document.get(name), str) or not SHA256.fullmatch(document[name]):
                fail(f"{field} artifact must bind {name}")
        checks = document.get("checks") or []
        if not checks or any(item.get("passed") is not True for item in checks):
            fail(f"{field} artifact contains a missing or failed STIG Manager check")
        metrics = document.get("metrics") or {}
        review_count = metrics.get("review_count")
        if (
            not isinstance(review_count, int)
            or review_count <= 0
            or review_count != metrics.get("source_finding_count")
            or metrics.get("benchmark_id") != "Cisco_IOS-XE_Router_NDM_STIG"
            or not isinstance(metrics.get("rule_set_sha256"), str)
            or not SHA256.fullmatch(metrics["rule_set_sha256"])
        ):
            fail(f"{field} artifact does not prove an exact non-empty review set")
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
    relative, document = read_bound_artifact(
        repo,
        value["evidence_reference"],
        value["evidence_sha256"],
        tag,
        field,
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
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
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


def validate_workflow_artifact(
    repository: str,
    run_id: str,
    gate: str,
    expected_sha256: str,
    expected_log_sha256: object = None,
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
            by_name = {item.filename: item for item in entries}
            if (
                len(entries) != len(expected_files)
                or set(by_name) != expected_files
                or by_name[filename].file_size <= 0
                or by_name[filename].file_size > MAX_EVIDENCE_BYTES
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
    contexts = set(checks.get("contexts") or [])
    missing = sorted(REQUIRED_STATUS_CONTEXTS - contexts)
    if (
        checks.get("strict") is not True
        or missing
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
        fail(
            "main branch protection does not enforce the reviewed release policy"
            + (f"; missing contexts: {missing}" if missing else "")
        )

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
            include = ((candidate.get("conditions") or {}).get("ref_name") or {}).get("include") or []
            types = {
                rule.get("type")
                for rule in candidate.get("rules") or []
                if isinstance(rule, dict)
            }
            if include == ["refs/tags/v*"] and {"creation", "update", "deletion"} <= types:
                tag_ruleset = candidate
                break
    if not tag_ruleset or not tag_ruleset.get("bypass_actors"):
        fail("an active v* release-tag ruleset with a named release authority is required")


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
            review = json.loads(line)
        except json.JSONDecodeError as error:
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


def validate_document(repo: Path, path: Path, expected_tag: str, offline: bool) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
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
        ceremony = json.loads(ceremony_raw)
    except json.JSONDecodeError as error:
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
        f"Release evidence valid for {expected_tag}: independent reviewers, five acceptance gates, "
        "recovery drill, signing ceremony, and approved commit ancestry"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--schema-only", action="store_true")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="skip GitHub approval/main-branch verification for local development only",
    )
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    schema = repo / "schemas/release-evidence.schema.json"
    try:
        document = json.loads(schema.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read release evidence schema: {error}")
    if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("release evidence schema must use JSON Schema 2020-12")
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
