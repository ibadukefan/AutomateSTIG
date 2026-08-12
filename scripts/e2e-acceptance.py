#!/usr/bin/env python3
"""Black-box acceptance for the release-bundled scanner product surface.

This gate deliberately runs the default CLI and GUI binaries. Content import,
pack construction, catalog maintenance, broad checklist conversion/export,
and every other maintainer-only or STIG Manager-duplicate command are outside
this product acceptance path.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


REPO = Path(
    os.environ.get("E2E_REPO_ROOT", Path(__file__).resolve().parents[1])
).resolve()
EXE = ".exe" if sys.platform == "win32" else ""
BIN = Path(os.environ.get("AUTOMATESTIG_BIN", REPO / "target" / "release" / f"automatestig{EXE}"))
TRANSITION_BIN = Path(
    os.environ.get(
        "AUTOMATESTIG_TRANSITION_BIN",
        REPO / "target" / "release" / f"automatestig-transition{EXE}",
    )
)
GUI_BIN = Path(
    os.environ.get(
        "AUTOMATESTIG_GUI_BIN",
        REPO / "target" / "release" / f"automatestig-gui{EXE}",
    )
)
GUI_PORT = int(os.environ.get("AUTOMATESTIG_E2E_PORT", "18321"))
TOKEN = "automatestig-e2e-loopback-token-2026"
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

PRODUCT_TOP_LEVEL_COMMANDS = frozenset(
    {"collect", "evaluate", "scanner", "status"}
)
RETIRED_OR_MAINTAINER_TOP_LEVEL_COMMANDS = (
    "import",
    "verify",
    "library",
    "generate-signing-key",
    "sign-organization-policy",
    "build-pack",
    "disa-import",
    "coverage",
    "migration",
    "convert",
    "summary",
    "gen-answer",
    "export",
)

FIXTURE_INPUTS = REPO / "fixtures" / "scanner_scenarios" / "inputs"
CISCO_CONFIG = REPO / "fixtures" / "network" / "ios_xe_router_compliant.txt"
CISCO_TRUNCATED_CONFIG = FIXTURE_INPUTS / "cisco-truncated.cfg"
CISCO_POLICY = FIXTURE_INPUTS / "cisco-compliant-policy.json"
CISCO_POLICY_PUBLIC_B64 = FIXTURE_INPUTS / "e2e-organization-policy.pub.b64"
CISCO_POLICY_SIGNATURE_B64 = FIXTURE_INPUTS / "e2e-organization-policy.sig.b64"
CISCO_POLICY_SHA256 = "8c6f16467f8aa360d5abc20595a463bdfd0fd788f3209c7b1ac4a18a0081d06b"


class AcceptanceFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceFailure(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise AcceptanceFailure(f"{label} is not valid JSON: {path}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def decode_base64_fixture(path: Path, expected_bytes: int) -> bytes:
    try:
        value = base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
    except (OSError, ValueError) as error:
        raise AcceptanceFailure(f"invalid base64 fixture: {path}") from error
    require(len(value) == expected_bytes, f"{path.name} must decode to {expected_bytes} bytes")
    return value


def prepare_work_directory() -> Path:
    configured = os.environ.get("E2E_WORK")
    if configured:
        work = Path(configured).resolve()
        if work.exists():
            require(work.is_dir(), "E2E_WORK must name a directory")
            require(not any(work.iterdir()), "E2E_WORK must be empty; acceptance never deletes it")
        else:
            work.mkdir(parents=True, mode=0o700)
    else:
        work = Path(tempfile.mkdtemp(prefix="automatestig-product-e2e-"))
    if os.name != "nt":
        work.chmod(0o700)
    return work


WORK = prepare_work_directory()
HOME = WORK / "home"
DATA_DIR = WORK / "gui-data"
LIBRARY = WORK / "legacy-library"
OUT = WORK / "out"
ARTIFACTS = WORK / "scanner-artifacts"
POLICY_TRUST = WORK / "organization-policy-keys"
POLICY_SIGNATURE = WORK / "cisco-compliant-policy.sig"
DB = DATA_DIR / "data.db"


def prepare_directories_and_policy() -> None:
    for directory in (HOME, DATA_DIR, OUT, ARTIFACTS, POLICY_TRUST):
        directory.mkdir(parents=True, exist_ok=False)
        if os.name != "nt":
            directory.chmod(0o700)
    policy_bytes = CISCO_POLICY.read_bytes()
    require(
        sha256_bytes(policy_bytes) == CISCO_POLICY_SHA256,
        "synthetic Cisco policy changed without regenerating its public test signature",
    )
    public_key = decode_base64_fixture(CISCO_POLICY_PUBLIC_B64, 32)
    signature = decode_base64_fixture(CISCO_POLICY_SIGNATURE_B64, 64)
    public_path = POLICY_TRUST / "e2e-organization-policy.pub"
    public_path.write_bytes(public_key)
    POLICY_SIGNATURE.write_bytes(signature)
    if os.name != "nt":
        public_path.chmod(0o644)
        POLICY_SIGNATURE.chmod(0o600)


def product_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "HOME": str(HOME),
            "USERPROFILE": str(HOME),
            "AUTOMATESTIG_DATA_DIR": str(DATA_DIR),
            "AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR": str(POLICY_TRUST),
        }
    )
    return environment


def run_cli(*arguments: str, expect_ok: bool = True) -> subprocess.CompletedProcess[str]:
    command = [
        str(BIN),
        "--db",
        str(DB),
        "--library",
        str(LIBRARY),
        *arguments,
    ]
    result = subprocess.run(
        command,
        cwd=REPO,
        env=product_environment(),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if expect_ok and result.returncode != 0:
        detail = (result.stdout + result.stderr)[-2000:]
        raise AcceptanceFailure(f"command failed ({' '.join(arguments)}):\n{detail}")
    return result


def run_transition_cli(
    *arguments: str, expect_ok: bool = True
) -> subprocess.CompletedProcess[str]:
    command = [
        str(TRANSITION_BIN),
        "--db",
        str(DB),
        "--library",
        str(LIBRARY),
        *arguments,
    ]
    result = subprocess.run(
        command,
        cwd=REPO,
        env=product_environment(),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if expect_ok and result.returncode != 0:
        detail = (result.stdout + result.stderr)[-2000:]
        raise AcceptanceFailure(
            f"transition command failed ({' '.join(arguments)}):\n{detail}"
        )
    return result


def verify_default_cli_boundary() -> None:
    version = subprocess.run(
        [str(BIN), "--version"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=30,
    )
    require(version.returncode == 0 and "0.3.0" in version.stdout, "release CLI version failed")
    help_result = subprocess.run(
        [str(BIN), "--help"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=30,
    )
    require(help_result.returncode == 0, "release CLI help failed")
    help_text = help_result.stdout
    for command in PRODUCT_TOP_LEVEL_COMMANDS:
        require(re.search(rf"(?m)^  {re.escape(command)}\b", help_text) is not None, f"missing {command}")
    for command in RETIRED_OR_MAINTAINER_TOP_LEVEL_COMMANDS:
        require(
            re.search(rf"(?m)^  {re.escape(command)}\b", help_text) is None,
            f"non-product command leaked into default help: {command}",
        )
        rejected = run_cli(command, expect_ok=False)
        require(rejected.returncode != 0, f"default release binary accepted non-product command {command}")

    status = run_cli("status")
    combined = status.stdout + status.stderr
    for expected in (
        "Scanner Content",
        "NetApp ONTAP",
        "FreeBSD",
        "Cisco IOS-XE",
        "System of record",
        "STIG Manager",
        "Deterministic; no AI/ML",
    ):
        require(expected in combined, f"status omitted release contract text {expected!r}")


def verify_transition_cli_boundary() -> None:
    help_result = subprocess.run(
        [str(TRANSITION_BIN), "--help"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=30,
    )
    require(help_result.returncode == 0, "protected transition CLI help failed")
    for command in ("migration", "scanner"):
        require(
            re.search(rf"(?m)^  {re.escape(command)}\b", help_result.stdout) is not None,
            f"protected transition CLI omitted {command}",
        )
    migration_help = subprocess.run(
        [str(TRANSITION_BIN), "migration", "--help"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=30,
    )
    require(migration_help.returncode == 0, "protected migration help failed")
    for action in ("inventory", "export", "bind-run"):
        require(
            re.search(rf"(?m)^  {re.escape(action)}\b", migration_help.stdout)
            is not None,
            f"protected migration CLI omitted {action}",
        )
    scanner_help = subprocess.run(
        [str(TRANSITION_BIN), "scanner", "--help"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=30,
    )
    require(scanner_help.returncode == 0, "protected signing help failed")
    for action in ("generate-signing-key", "sign-handoff"):
        require(
            re.search(rf"(?m)^  {re.escape(action)}\b", scanner_help.stdout)
            is not None,
            f"protected transition CLI omitted {action}",
        )
    for product_command in PRODUCT_TOP_LEVEL_COMMANDS - {"scanner"}:
        require(
            re.search(rf"(?m)^  {re.escape(product_command)}\b", help_result.stdout)
            is None,
            f"product command leaked into protected transition CLI: {product_command}",
        )


def generated_evidence_index() -> dict[tuple[str, str], Path]:
    manifest_path = ARTIFACTS / "native-evidence" / "manifest.json"
    manifest = json_object(manifest_path, "native evidence manifest")
    require(
        manifest.get("schema") == "automatestig.localhost-native-evidence/v1",
        "native evidence manifest schema changed",
    )
    result: dict[tuple[str, str], Path] = {}
    files = manifest.get("files")
    require(isinstance(files, list) and len(files) == 6, "native evidence matrix must contain six cases")
    for raw in files:
        require(isinstance(raw, dict), "native evidence manifest item must be an object")
        path = (manifest_path.parent / str(raw.get("path", ""))).resolve()
        require(path.parent == manifest_path.parent.resolve(), "native evidence path escaped its directory")
        require(path.is_file(), f"native evidence file is missing: {path}")
        require(sha256_file(path) == raw.get("sha256"), f"native evidence digest changed: {path.name}")
        key = (str(raw.get("profile_id")), str(raw.get("case")))
        require(key not in result, f"duplicate native evidence case {key}")
        result[key] = path
    return result


def assert_scanner_result(
    document: dict[str, Any], *, complete: bool, reviews: int, planned: int
) -> None:
    require(document.get("collection_complete") is complete, "scanner completion state changed")
    sparse_reviews = document.get("sparse_reviews")
    require(isinstance(sparse_reviews, list), "scanner result has no sparse review array")
    require(len(sparse_reviews) == reviews, "scanner-owned sparse review count changed")
    summary = document.get("summary")
    require(isinstance(summary, dict), "scanner result has no summary")
    require(summary.get("checks_planned") == planned, "planned executable check count changed")
    require(summary.get("sparse_review_count") == reviews, "summary sparse count changed")
    digests = document.get("digests")
    require(isinstance(digests, dict), "scanner result has no digest bindings")
    for name, value in digests.items():
        require(
            isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
            f"scanner digest {name} is not lowercase SHA-256",
        )


def verify_cli_evaluation() -> None:
    evidence = generated_evidence_index()

    complete_output = OUT / "cli-netapp-compliant.scanner-result.json"
    run_cli(
        "evaluate",
        "--stig",
        "netapp_ontap9",
        "--evidence",
        str(evidence[("netapp_ontap9", "compliant")]),
        "--output",
        str(complete_output),
        "--format",
        "json",
    )
    assert_scanner_result(
        json_object(complete_output, "complete native scanner result"),
        complete=True,
        reviews=15,
        planned=15,
    )

    incomplete_output = OUT / "cli-netapp-incomplete.scanner-result.json"
    incomplete = run_cli(
        "evaluate",
        "--stig",
        "netapp_ontap9",
        "--evidence",
        str(evidence[("netapp_ontap9", "incomplete")]),
        "--output",
        str(incomplete_output),
        "--format",
        "json",
        expect_ok=False,
    )
    require(incomplete.returncode != 0, "incomplete evidence returned success")
    assert_scanner_result(
        json_object(incomplete_output, "incomplete diagnostic scanner result"),
        complete=False,
        reviews=0,
        planned=15,
    )

    tampered_path = OUT / "tampered-native-evidence.json"
    tampered = json_object(evidence[("netapp_ontap9", "compliant")], "native evidence")
    tampered["evidence_sha256"] = "0" * 64
    tampered_path.write_text(json.dumps(tampered, separators=(",", ":")), encoding="utf-8")
    tampered_output = OUT / "tampered-native-result.json"
    rejected = run_cli(
        "evaluate",
        "--stig",
        "netapp_ontap9",
        "--evidence",
        str(tampered_path),
        "--output",
        str(tampered_output),
        expect_ok=False,
    )
    require(rejected.returncode != 0 and not tampered_output.exists(), "tampered evidence produced output")

    config_output = OUT / "cli-cisco-compliant.scanner-result.json"
    run_cli(
        "evaluate",
        "--stig",
        "cisco_ios_xe_router_ndm",
        "--config",
        str(CISCO_CONFIG),
        "--host",
        "rtr-compliant-01",
        "--organization-policy",
        str(CISCO_POLICY),
        "--organization-policy-signature",
        str(POLICY_SIGNATURE),
        "--output",
        str(config_output),
        "--format",
        "json",
    )
    config_result = json_object(config_output, "Cisco configuration scanner result")
    assert_scanner_result(config_result, complete=True, reviews=33, planned=33)
    provenance = config_result.get("checklist", {}).get("evaluation_provenance", {})
    policy = provenance.get("organization_policy", {})
    require(provenance.get("origin") == "config_file", "Cisco result origin is not config_file")
    require(policy.get("signature_verified") is True, "Cisco policy is not signature-verified")
    require(policy.get("policy_sha256") == CISCO_POLICY_SHA256, "Cisco policy digest changed")

    truncated_output = OUT / "cli-cisco-truncated.scanner-result.json"
    truncated = run_cli(
        "evaluate",
        "--stig",
        "cisco_ios_xe_router_ndm",
        "--config",
        str(CISCO_TRUNCATED_CONFIG),
        "--organization-policy",
        str(CISCO_POLICY),
        "--organization-policy-signature",
        str(POLICY_SIGNATURE),
        "--output",
        str(truncated_output),
        expect_ok=False,
    )
    require(
        truncated.returncode != 0 and not truncated_output.exists(),
        "truncated running configuration produced a deliverable result",
    )


def gui_request(path: str, *, method: str = "GET", authenticated: bool = True) -> tuple[int, bytes]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{GUI_PORT}{path}",
        method=method,
    )
    if authenticated:
        request.add_header("X-Auth-Token", TOKEN)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except urllib.error.URLError:
        return 0, b""


def run_gui_scenarios() -> dict[str, Any]:
    environment = product_environment()
    environment.update(
        {
            "PORT": str(GUI_PORT),
            "AUTOMATESTIG_AUTH_TOKEN": TOKEN,
        }
    )
    log_path = DATA_DIR / "acceptance-gui.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [str(GUI_BIN)],
            cwd=REPO,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            for _ in range(120):
                if gui_request("/api/v1/status")[0] == 200:
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.25)
            else:
                raise AcceptanceFailure("GUI scanner API did not become ready")
            if process.poll() is not None:
                log.flush()
                raise AcceptanceFailure(f"GUI exited during startup:\n{log_path.read_text()[-2000:]}")
            unauthenticated, _ = gui_request("/api/v1/runs", authenticated=False)
            require(unauthenticated in (401, 403), "scanner run API did not require authentication")

            harness = subprocess.run(
                [
                    sys.executable,
                    str(REPO / "scripts" / "scanner_scenarios" / "run_localhost.py"),
                    "--base-url",
                    f"http://127.0.0.1:{GUI_PORT}",
                    "--auth-token",
                    TOKEN,
                    "--artifacts-dir",
                    str(ARTIFACTS),
                ],
                cwd=REPO,
                env=environment,
                capture_output=True,
                text=True,
                timeout=300,
            )
            require(
                harness.returncode == 0,
                "scanner localhost scenarios failed:\n" + (harness.stdout + harness.stderr)[-3000:],
            )
            summary = json_object(ARTIFACTS / "summary.json", "scanner scenario summary")
            complete = summary.get("complete_handoff_runs")
            require(isinstance(complete, list) and len(complete) == 3, "three complete handoffs were not exercised")
            methods = {item.get("collection_method") for item in complete if isinstance(item, dict)}
            require(methods == {"evidence", "configuration"}, "API did not exercise both input modes")
            require(bool(summary.get("incomplete_fail_closed_run")), "fail-closed API case was omitted")

            for path in (
                "/api/assets",
                "/api/stigman/push/retired-checklist",
                "/api/evaluate/with-evidence",
                "/api/library/import-disa",
            ):
                status, body = gui_request(path, method="POST")
                require(status == 410, f"retired manager-duplicate route {path} returned {status}: {body[:300]!r}")
            return summary
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


def verify_handoffs(summary: dict[str, Any]) -> None:
    complete = summary.get("complete_handoff_runs")
    require(isinstance(complete, list), "scanner summary has no complete runs")
    handoffs: list[Path] = []
    for item in complete:
        require(isinstance(item, dict), "complete run summary must be an object")
        handoff = item.get("handoff")
        require(isinstance(handoff, dict), "complete run has no handoff summary")
        path = Path(str(handoff.get("zip", ""))).resolve()
        require(path.parent == ARTIFACTS.resolve(), "handoff path escaped the acceptance artifact directory")
        require(path.is_file() and sha256_file(path) == handoff.get("zip_sha256"), "handoff digest changed")
        run_cli("scanner", "verify-handoff", str(path))
        handoffs.append(path)
    require(len(handoffs) == 3, "expected three verified selected-run handoffs")

    original = handoffs[0].read_bytes()
    require(len(original) > 32, "handoff is unexpectedly small")
    corrupted = bytearray(original)
    corrupted[len(corrupted) // 2] ^= 0x01
    tampered = OUT / "tampered-selected-run.handoff.zip"
    tampered.write_bytes(corrupted)
    rejected = run_cli("scanner", "verify-handoff", str(tampered), expect_ok=False)
    require(rejected.returncode != 0, "offline verifier accepted a tampered selected-run handoff")


def safe_zip_members(archive: zipfile.ZipFile) -> list[str]:
    names = archive.namelist()
    require(len(names) == len(set(names)), "migration ZIP contains duplicate members")
    for name in names:
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts, f"unsafe migration member {name!r}")
        require(not archive.getinfo(name).flag_bits & 0x1, f"encrypted migration member {name!r}")
    return names


def verify_migration() -> None:
    require(DB.is_file(), "GUI scanner database was not created")
    before = sha256_file(DB)
    inventory_path = OUT / "migration-inventory.json"
    run_transition_cli("migration", "inventory", "--output", str(inventory_path))
    require(sha256_file(DB) == before, "read-only migration inventory changed the scanner database")
    inventory = json_object(inventory_path, "migration inventory")
    require(inventory.get("schema") == "automatestig.migration-inventory.v1", "inventory schema changed")
    require(inventory.get("read_only") is True, "migration inventory is not marked read-only")
    summary = inventory.get("summary")
    require(isinstance(summary, dict), "migration inventory has no summary")
    require(summary.get("immutable_scanner_runs") == 4, "migration missed scanner runs")
    require(summary.get("completed_scanner_output_records") == 3, "completed scanner classification changed")
    require(summary.get("incomplete_audit_only_records") >= 1, "incomplete run was not audit-only")

    bundle_path = OUT / "scanner-transition.zip"
    run_transition_cli("migration", "export", "--output", str(bundle_path))
    require(sha256_file(DB) == before, "read-only migration export changed the scanner database")
    original_bundle = bundle_path.read_bytes()
    refused = run_transition_cli(
        "migration", "export", "--output", str(bundle_path), expect_ok=False
    )
    require(
        refused.returncode != 0 and bundle_path.read_bytes() == original_bundle,
        "migration export replaced an existing artifact",
    )

    try:
        with zipfile.ZipFile(bundle_path) as archive:
            names = safe_zip_members(archive)
            members = {name: archive.read(name) for name in names}
    except zipfile.BadZipFile as error:
        raise AcceptanceFailure("migration export is not a valid ZIP") from error
    require({"manifest.json", "checksums.sha256", "inventory-report.json"} <= set(names), "migration bundle is incomplete")
    manifest = json.loads(members["manifest.json"])
    require(manifest.get("schema") == "automatestig.migration-bundle.v2", "migration bundle schema changed")
    require(manifest.get("read_only_export") is True, "migration bundle is not read-only")
    require(manifest.get("sensitive_data") is True, "migration bundle lost its sensitivity marker")
    require(manifest.get("retention_cleanup_performed") is False, "migration export claimed cleanup")
    declared = manifest.get("members")
    require(isinstance(declared, list), "migration bundle has no member manifest")
    declared_paths = {item.get("path") for item in declared if isinstance(item, dict)}
    require(declared_paths == set(names) - {"manifest.json", "checksums.sha256"}, "migration member manifest differs")
    for item in declared:
        require(isinstance(item, dict), "migration member declaration must be an object")
        path = str(item.get("path"))
        require(sha256_bytes(members[path]) == item.get("sha256"), f"migration member digest mismatch: {path}")
        require(len(members[path]) == item.get("size_bytes"), f"migration member size mismatch: {path}")
    checksum_rows = {}
    for line in members["checksums.sha256"].decode("ascii").splitlines():
        digest, separator, path = line.partition("  ")
        require(separator == "  " and SHA256_RE.fullmatch(digest) is not None, "invalid checksum row")
        require(path not in checksum_rows, f"duplicate checksum path {path}")
        checksum_rows[path] = digest
    require(set(checksum_rows) == set(names) - {"checksums.sha256"}, "checksum coverage differs")
    for path, digest in checksum_rows.items():
        require(sha256_bytes(members[path]) == digest, f"checksum mismatch for {path}")
    require(
        any(name.startswith("verified-scanner-evidence/") for name in names),
        "migration bundle omitted verified scanner evidence",
    )
    require(
        any(name.startswith("audit-only/scanner-runs/") for name in names),
        "migration bundle omitted the incomplete audit-only run",
    )
    required_scanner_state = {
        "scanner/jobs.json",
        "scanner/job-transitions.json",
        "scanner/target-connection-profiles.json",
        "scanner/operational-purge-tombstones.json",
        "scanner/retention-config.json",
        "stig-manager/delivery-records.json",
        "stig-manager/delivery-receipts.json",
        "stig-manager/destination-bindings.json",
        "stig-manager/retained-run-bindings.json",
    }
    require(required_scanner_state <= set(names), "migration bundle omitted scanner custody state")
    retention = json.loads(members["scanner/retention-config.json"])
    require(
        retention.get("schema") == "automatestig.scanner-retention-config.v1",
        "migration retention contract changed",
    )
    custody_names = [
        name for name in names if name.startswith("scanner/replay-evidence/") and name.endswith("/custody.json")
    ]
    require(len(custody_names) == 4, "migration bundle omitted replay-evidence custody")
    for custody_name in custody_names:
        custody = json.loads(members[custody_name])
        require(
            custody.get("schema") == "automatestig.encrypted-custody.v1"
            and custody.get("object_kind") == "scan_replay_evidence"
            and custody.get("stored_bindings_verified") is True
            and custody.get("plaintext_exported") is False,
            f"migration replay-evidence custody is invalid: {custody_name}",
        )
        for member_field, digest_field, size_field in (
            ("ciphertext_member", "ciphertext_sha256", "ciphertext_size_bytes"),
            ("wrapped_dek_member", "wrapped_dek_sha256", "wrapped_dek_size_bytes"),
        ):
            member_name = custody.get(member_field)
            require(isinstance(member_name, str) and member_name in members, f"missing {member_field}: {custody_name}")
            require(
                sha256_bytes(members[member_name]) == custody.get(digest_field)
                and len(members[member_name]) == custody.get(size_field),
                f"migration encrypted custody binding changed: {member_name}",
            )


def main() -> int:
    try:
        for binary in (BIN, GUI_BIN, TRANSITION_BIN):
            require(binary.is_file(), f"binary not found: {binary}; build the acceptance binaries")
        prepare_directories_and_policy()
        verify_default_cli_boundary()
        verify_transition_cli_boundary()
        gui_summary = run_gui_scenarios()
        verify_cli_evaluation()
        verify_handoffs(gui_summary)
        verify_migration()
        result = {
            "schema": "automatestig.product-acceptance.v2",
            "default_release_binary_only": True,
            "maintainer_commands_exercised": False,
            "protected_transition_binary_exercised": True,
            "native_adapter_evidence": "complete-and-incomplete",
            "running_configuration": "signed-policy-complete-and-truncated-rejected",
            "selected_run_handoffs_verified": 3,
            "migration_read_only": True,
            "artifacts": str(WORK),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (AcceptanceFailure, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print(f"product acceptance failed: {error}", file=sys.stderr)
        print(f"retained diagnostic workspace: {WORK}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
