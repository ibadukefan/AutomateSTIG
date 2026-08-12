#!/usr/bin/env python3
"""Execute the shared fail-closed contract for a scaffolded target adapter."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any


SCHEMA = "automatestig-adapter-contract-test/v1"
FIXTURE_SCHEMA = "automatestig-adapter-fixture/v1"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_FIXTURE_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
REQUIRED_CASES = {
    "finding": ("rule", "complete", "finding", True),
    "not-a-finding": ("rule", "complete", "not_a_finding", True),
    "malformed-output": ("error", "collection_error", None, False),
    "permission-denied": ("error", "collection_error", None, False),
    "timeout": ("error", "collection_error", None, False),
    "truncated-output": ("error", "collection_error", None, False),
    "unsupported-version": ("error", "collection_error", None, False),
}


class ContractError(RuntimeError):
    """Invalid or unsafe completed contract evidence."""


class ContractNotReady(ContractError):
    """One or more generated placeholders have not been completed."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"contract JSON contains duplicate field {key!r}")
        result[key] = value
    return result


def _string(value: Any, label: str, maximum: int = 500) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ContractError(f"{label} must be a non-empty bounded string")
    return value


def _regular_json(path: Path, root: Path, maximum: int) -> dict[str, Any]:
    _safe_regular(path, root, maximum)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"{path.relative_to(root)} is not valid UTF-8 JSON: {error}") from error
    return _object(value, str(path.relative_to(root)))


def _safe_regular(path: Path, root: Path, maximum: int) -> None:
    root = root.resolve(strict=True)
    lexical = Path(os.path.abspath(path))
    if not lexical.is_relative_to(root):
        raise ContractError(f"path escapes adapter root: {path}")
    relative = lexical.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ContractError(f"symlinks are forbidden in contract evidence: {relative}")
    if not lexical.is_file():
        raise ContractError(f"contract evidence is not a regular file: {relative}")
    size = lexical.stat().st_size
    if size > maximum:
        raise ContractError(f"contract evidence exceeds {maximum} bytes: {relative}")


def _relative_file(root: Path, value: Any, label: str, maximum: int) -> Path:
    name = _string(value, label, 1_024)
    candidate = Path(name)
    if (
        candidate.is_absolute()
        or ".." in candidate.parts
        or "\\" in name
        or candidate.as_posix() != name
    ):
        raise ContractError(f"{label} must be a normalized relative path")
    path = root / candidate
    _safe_regular(path, root, maximum)
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(64 * 1024):
            digest.update(block)
    return digest.hexdigest()


def validate_contract(adapter_root: Path) -> dict[str, Any]:
    if adapter_root.is_symlink():
        raise ContractError("adapter root must not be a symlink")
    root = adapter_root.resolve(strict=True)
    if not root.is_dir():
        raise ContractError("adapter root must be a regular, non-symlink directory")
    manifest = _regular_json(root / "tests/contract-test.json", root, MAX_MANIFEST_BYTES)
    if set(manifest) != {
        "schema",
        "schema_version",
        "target_key",
        "adapter_contract",
        "adapter_contract_sha256",
        "shared_validator",
        "cases",
    }:
        raise ContractError("contract-test manifest fields are invalid")
    if manifest.get("schema") != SCHEMA or manifest.get("schema_version") != 1:
        raise ContractError("contract-test manifest has an unsupported schema")
    if manifest.get("shared_validator") != "scripts/validate-adapter-contract.py":
        raise ContractError("contract-test manifest does not bind the shared validator")
    target_key = _string(manifest.get("target_key"), "manifest target_key", 100)
    adapter_contract_path = _relative_file(
        root,
        manifest.get("adapter_contract"),
        "manifest adapter_contract",
        MAX_MANIFEST_BYTES,
    )
    adapter_contract_digest = _string(
        manifest.get("adapter_contract_sha256"), "manifest adapter_contract_sha256", 64
    )
    if (
        len(adapter_contract_digest) != 64
        or any(character not in "0123456789abcdef" for character in adapter_contract_digest)
        or _sha256(adapter_contract_path) != adapter_contract_digest
    ):
        raise ContractError("adapter contract SHA-256 does not match the manifest")
    adapter_contract = _regular_json(
        adapter_contract_path, root, MAX_MANIFEST_BYTES
    )
    if (
        adapter_contract.get("schema") != "automatestig-adapter-contract/v1"
        or adapter_contract.get("schema_version") != 1
        or adapter_contract.get("target_key") != target_key
        or adapter_contract.get("release_registration") is not False
        or adapter_contract.get("support_claim") != "none"
    ):
        raise ContractError("adapter contract identity or non-claiming status is invalid")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ContractError("contract-test manifest cases must be a non-empty array")
    indexed: dict[str, dict[str, Any]] = {}
    for case_value in cases:
        case = _object(case_value, "contract case")
        if set(case) != {"case_id", "kind", "fixture"}:
            raise ContractError("contract case fields are invalid")
        case_id = _string(case.get("case_id"), "case_id", 100)
        if case_id in indexed:
            raise ContractError(f"duplicate contract case: {case_id}")
        indexed[case_id] = case
    missing = sorted(set(REQUIRED_CASES) - set(indexed))
    extra = sorted(set(indexed) - set(REQUIRED_CASES))
    if missing or extra:
        raise ContractError(f"contract cases drifted; missing={missing} extra={extra}")

    placeholders: list[str] = []
    passed: list[str] = []
    for case_id in sorted(indexed):
        case = indexed[case_id]
        expected_kind, expected_status, expected_outcome, expected_handoff = REQUIRED_CASES[case_id]
        if case.get("kind") != expected_kind:
            raise ContractError(f"{case_id}: manifest kind must be {expected_kind}")
        fixture_path = _relative_file(
            root, case.get("fixture"), f"{case_id} fixture", MAX_FIXTURE_BYTES
        )
        fixture = _regular_json(fixture_path, root, MAX_FIXTURE_BYTES)
        if set(fixture) != {
            "schema",
            "schema_version",
            "target_key",
            "fixture_id",
            "purpose",
            "synthetic",
            "redacted",
            "capture",
            "expected",
            "observed",
            "notes",
        }:
            raise ContractError(f"{case_id}: fixture fields are invalid")
        if (
            fixture.get("schema") != FIXTURE_SCHEMA
            or fixture.get("schema_version") != 1
            or fixture.get("target_key") != target_key
            or fixture.get("fixture_id") != case_id
            or fixture.get("synthetic") is not True
            or fixture.get("redacted") is not True
        ):
            raise ContractError(f"{case_id}: fixture identity/safety metadata is invalid")
        capture = _object(fixture.get("capture"), f"{case_id} capture")
        if set(capture) != {
            "status",
            "artifact_path",
            "artifact_sha256",
            "redaction_manifest",
        }:
            raise ContractError(f"{case_id}: capture fields are invalid")
        if capture.get("status") == "placeholder":
            placeholders.append(case_id)
            continue
        if capture.get("status") != "complete":
            raise ContractError(f"{case_id}: capture status must be placeholder or complete")
        artifact = _relative_file(
            root,
            capture.get("artifact_path"),
            f"{case_id} artifact_path",
            MAX_ARTIFACT_BYTES,
        )
        digest = _string(capture.get("artifact_sha256"), f"{case_id} artifact_sha256", 64)
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ContractError(f"{case_id}: artifact_sha256 must be 64 lowercase hex characters")
        if _sha256(artifact) != digest:
            raise ContractError(f"{case_id}: artifact SHA-256 does not match")
        if not isinstance(capture.get("redaction_manifest"), list):
            raise ContractError(f"{case_id}: redaction_manifest must be an array")

        expected = _object(fixture.get("expected"), f"{case_id} expected")
        observed = _object(fixture.get("observed"), f"{case_id} observed")
        result_fields = {"contract_status", "evaluation_outcome", "handoff_allowed"}
        if set(expected) != result_fields or set(observed) != result_fields:
            raise ContractError(f"{case_id}: expected/observed result fields are invalid")
        required_result = {
            "contract_status": expected_status,
            "evaluation_outcome": expected_outcome,
            "handoff_allowed": expected_handoff,
        }
        if expected != required_result:
            raise ContractError(f"{case_id}: fixture oracle does not match the shared contract")
        if observed != expected:
            raise ContractError(f"{case_id}: observed result does not match its fixture oracle")
        if observed.get("contract_status") != expected_status:
            raise ContractError(
                f"{case_id}: expected contract_status={expected_status}; "
                f"got {observed.get('contract_status')!r}"
            )
        if observed.get("evaluation_outcome") != expected_outcome:
            raise ContractError(
                f"{case_id}: expected evaluation_outcome={expected_outcome!r}; "
                f"got {observed.get('evaluation_outcome')!r}"
            )
        if observed.get("handoff_allowed") is not expected_handoff:
            raise ContractError(
                f"{case_id}: expected handoff_allowed={expected_handoff}; "
                f"got {observed.get('handoff_allowed')!r}"
            )
        # This invariant is intentionally redundant with case expectations: an
        # error corpus may never be weakened by editing one expected field.
        if expected_kind == "error" and (
            observed.get("contract_status") != "collection_error"
            or observed.get("evaluation_outcome") is not None
            or observed.get("handoff_allowed") is not False
        ):
            raise ContractError(f"{case_id}: collection error did not fail closed")
        passed.append(case_id)

    if placeholders:
        raise ContractNotReady(
            "adapter contract is not ready; placeholder fixtures: " + ", ".join(placeholders)
        )
    return {
        "schema": "automatestig-adapter-contract-test-result/v1",
        "schema_version": 1,
        "target_key": target_key,
        "status": "passed",
        "passed_cases": passed,
        "fail_closed_error_cases": sorted(
            case_id for case_id, values in REQUIRED_CASES.items() if values[0] == "error"
        ),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter-root", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = validate_contract(Path(args.adapter_root))
    except ContractNotReady as error:
        print(f"adapter contract not ready: {error}", file=sys.stderr)
        return 2
    except (OSError, ContractError) as error:
        print(f"adapter contract failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
