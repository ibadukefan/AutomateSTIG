#!/usr/bin/env python3
"""Verify an externally signed selected-run handoff on a protected receiver.

This program deliberately has no signing or key-generation capability.  The
producer private key stays on the custodian's protected host; this program
accepts only the public trust anchor, detached sidecar, and a non-secret
custody record after the signing operation has happened.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


CEREMONY_NAME = "handoff-receiver-ceremony.json"
PUBLIC_KEY_NAME = "handoff-producer-public-key.pub"
HANDOFF_NAME = "producer-handoff.zip"
SIGNATURE_NAME = "producer-handoff.zip.signature.json"
CUSTODY_NAME = "handoff-key-custody-ceremony.json"
PROTECTED_ENVIRONMENT = "handoff-receiver-ceremony"
HANDOFF_SCHEMA = "automatestig.selected-run-handoff.v4"
SIGNATURE_SCHEMA = "automatestig.selected-run-handoff-signature.v1"
SIGNATURE_ALGORITHM = "ed25519-sha256"
MAX_HANDOFF_BYTES = 16 * 1024 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_CUSTODY_BYTES = 64 * 1024
MAX_STAGING_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_CLI_BYTES = 256 * 1024 * 1024
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
OPAQUE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}$")


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def strict_json(raw: bytes, field: str) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=unique_json_object)
    except (UnicodeDecodeError, ValueError) as error:
        fail(f"{field} must be strict UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must contain a JSON object")
    return value


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


def read_regular_file(path: Path, field: str, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {field}: {error}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{field} must be a regular, non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        fail(f"{field} must contain between 1 and {maximum} bytes")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            value = os.read(descriptor, maximum + 1)
            current = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        fail(f"cannot read {field} without following links: {error}")
    if not stat.S_ISREG(current.st_mode) or len(value) != current.st_size:
        fail(f"{field} changed while it was being read")
    return value


def decode_input(name: str, field: str, maximum: int) -> bytes:
    encoded = os.environ.get(name)
    if not encoded:
        fail(f"{name} must contain base64-encoded public ceremony input")
    if len(encoded) > ((maximum + 2) // 3) * 4:
        fail(f"{name} exceeds the ceremony input limit")
    try:
        value = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        fail(f"{name} must be canonical base64 without whitespace")
    if not value or len(value) > maximum:
        fail(f"{field} decoded size is outside the ceremony input limit")
    return value


def ceremony_input(
    path: Path | None,
    environment_name: str,
    field: str,
    maximum: int,
) -> bytes:
    if path is not None:
        return read_regular_file(path, field, maximum)
    return decode_input(environment_name, field, maximum)


def write_output(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o644)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                output.write(value)
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(descriptor)
    except OSError as error:
        fail(f"cannot create ceremony output {path}: {error}")


def validate_login(value: str, field: str) -> None:
    if not LOGIN.fullmatch(value):
        fail(f"{field} must be a valid GitHub login")


def validate_staging_evidence(
    document: dict,
    source_commit: str,
    repository: str,
    staging_run_id: str,
    handoff_digest: str,
) -> None:
    metrics = document.get("metrics")
    if (
        document.get("schema") != "automatestig-stig-manager-acceptance/v1"
        or document.get("passed") is not True
        or document.get("source_commit") != source_commit
        or document.get("repository") != repository
        or document.get("workflow_run_id") != staging_run_id
        or document.get("protected_environment") != "external-acceptance"
        or not isinstance(metrics, dict)
        or metrics.get("boundary") != "disconnected-selected-run-handoff"
        or metrics.get("producer_handoff_filename") != HANDOFF_NAME
        or metrics.get("handoff_sha256") != handoff_digest
    ):
        fail(
            "staging evidence is not a passing approved-commit-bound selected-run "
            "handoff record for this exact ZIP"
        )


def validate_signature(document: dict, handoff_digest: str, key_digest: str) -> None:
    required = {
        "schema",
        "algorithm",
        "handoff_schema",
        "run_id",
        "handoff_sha256",
        "signing_key_fingerprint",
        "signature",
    }
    if set(document) != required:
        fail("signature sidecar has an unexpected or missing field")
    if (
        document.get("schema") != SIGNATURE_SCHEMA
        or document.get("algorithm") != SIGNATURE_ALGORITHM
        or document.get("handoff_schema") != HANDOFF_SCHEMA
        or not isinstance(document.get("run_id"), str)
        or not UUID.fullmatch(document["run_id"])
        or document.get("handoff_sha256") != handoff_digest
        or document.get("signing_key_fingerprint") != f"SHA256:{key_digest}"
        or not isinstance(document.get("signature"), str)
        or not re.fullmatch(r"[0-9a-f]{128}", document["signature"])
    ):
        fail(
            "signature sidecar is not exactly bound to the current handoff schema, "
            "ZIP digest, and supplied producer trust anchor"
        )


def validate_custody_record(
    document: dict,
    source_commit: str,
    custodian: str,
    approver: str,
    key_digest: str,
    handoff_digest: str,
    signature_digest: str,
) -> datetime:
    required = {
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
    if set(document) != required:
        fail("key-custody ceremony record has an unexpected or missing field")
    signed_at = timestamp(document.get("signed_at"), "key custody signed_at")
    now = datetime.now(timezone.utc)
    if signed_at > now or now - signed_at > timedelta(days=90):
        fail("key-custody signing ceremony is in the future or older than 90 days")
    references = (
        document.get("signing_host_reference"),
        document.get("primary_key_media_reference"),
        document.get("backup_key_media_reference"),
    )
    if (
        document.get("schema")
        != "automatestig-handoff-key-custody-ceremony/v1"
        or document.get("source_commit") != source_commit
        or document.get("producer_key_fingerprint") != f"SHA256:{key_digest}"
        or document.get("public_key_sha256") != key_digest
        or document.get("handoff_sha256") != handoff_digest
        or document.get("signature_sidecar_sha256") != signature_digest
        or str(document.get("key_custodian", "")).casefold()
        != custodian.casefold()
        or str(document.get("receiver_approver", "")).casefold()
        != approver.casefold()
        or len(set(references)) != 3
        or any(
            not isinstance(reference, str)
            or not OPAQUE_REFERENCE.fullmatch(reference)
            for reference in references
        )
        or document.get("private_key_entered_ci") is not False
        or document.get("private_key_entered_scanner_runtime") is not False
        or document.get("private_key_material_recorded") is not False
        or document.get("revocation_status_checked") is not True
    ):
        fail(
            "key-custody ceremony is not exactly bound to the participants, "
            "approved commit, trust anchor, handoff, sidecar, and protected-key rules"
        )
    return signed_at


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--handoff", required=True, type=Path)
    parser.add_argument("--staging-evidence", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--staging-workflow-run-id", required=True)
    parser.add_argument("--key-custodian", required=True)
    parser.add_argument("--receiver-approver", required=True)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--custody-record", type=Path)
    args = parser.parse_args()

    validate_login(args.key_custodian, "key_custodian")
    validate_login(args.receiver_approver, "receiver_approver")
    if args.key_custodian.casefold() == args.receiver_approver.casefold():
        fail("the key custodian and receiver approver must be different GitHub users")
    if not REPOSITORY.fullmatch(args.repository):
        fail("repository must be an owner/name GitHub repository")
    if not SHA.fullmatch(args.source_commit):
        fail("source_commit must be a full lowercase Git commit")
    if not args.workflow_run_id.isdigit() or not args.staging_workflow_run_id.isdigit():
        fail("workflow run IDs must contain only decimal digits")

    handoff = read_regular_file(args.handoff, "staged handoff ZIP", MAX_HANDOFF_BYTES)
    staging_raw = read_regular_file(
        args.staging_evidence,
        "STIG Manager staging evidence",
        MAX_STAGING_EVIDENCE_BYTES,
    )
    public_key = ceremony_input(
        args.public_key,
        "AUTOMATESTIG_HANDOFF_CEREMONY_PUBLIC_KEY_BASE64",
        "producer public key",
        32,
    )
    if len(public_key) != 32:
        fail("the Ed25519 producer public key must contain exactly 32 raw bytes")
    signature_raw = ceremony_input(
        args.signature,
        "AUTOMATESTIG_HANDOFF_CEREMONY_SIGNATURE_BASE64",
        "detached signature sidecar",
        MAX_SIGNATURE_BYTES,
    )
    custody_raw = ceremony_input(
        args.custody_record,
        "AUTOMATESTIG_HANDOFF_CEREMONY_CUSTODY_BASE64",
        "key-custody ceremony record",
        MAX_CUSTODY_BYTES,
    )
    cli = read_regular_file(args.cli, "reviewed AutomateSTIG CLI", MAX_CLI_BYTES)

    handoff_digest = sha256(handoff)
    public_key_digest = sha256(public_key)
    signature_digest = sha256(signature_raw)
    custody_digest = sha256(custody_raw)
    staging_digest = sha256(staging_raw)
    cli_digest = sha256(cli)
    staging = strict_json(staging_raw, "STIG Manager staging evidence")
    signature = strict_json(signature_raw, "signature sidecar")
    custody = strict_json(custody_raw, "key-custody ceremony record")
    validate_staging_evidence(
        staging,
        args.source_commit,
        args.repository,
        args.staging_workflow_run_id,
        handoff_digest,
    )
    validate_signature(signature, handoff_digest, public_key_digest)
    signed_at = validate_custody_record(
        custody,
        args.source_commit,
        args.key_custodian,
        args.receiver_approver,
        public_key_digest,
        handoff_digest,
        signature_digest,
    )

    try:
        args.output_dir.mkdir(mode=0o755)
    except OSError as error:
        fail(f"ceremony output directory must not already exist: {error}")

    with tempfile.TemporaryDirectory(prefix="automatestig-handoff-receiver-") as temporary:
        work = Path(temporary)
        trust = work / "trusted_handoff_keys"
        trust.mkdir(mode=0o700)
        trusted_key = trust / PUBLIC_KEY_NAME
        staged_handoff = work / HANDOFF_NAME
        signature_path = work / SIGNATURE_NAME
        trusted_key.write_bytes(public_key)
        staged_handoff.write_bytes(handoff)
        signature_path.write_bytes(signature_raw)
        environment = os.environ.copy()
        environment["HOME"] = str(work)
        environment["AUTOMATESTIG_HANDOFF_TRUSTED_KEYS_DIR"] = str(trust)
        environment.pop("AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK", None)
        try:
            verified = subprocess.run(
                [
                    str(args.cli),
                    "scanner",
                    "verify-handoff",
                    str(staged_handoff),
                    "--signature",
                    str(signature_path),
                    "--trust-dir",
                    str(trust),
                ],
                env=environment,
                capture_output=True,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            fail(f"cannot run the reviewed receiver CLI: {error}")
        if verified.returncode != 0:
            detail = (verified.stderr or verified.stdout).decode(errors="replace").strip()
            fail(
                "the reviewed receiver CLI rejected the signed handoff"
                + (f": {detail[-500:]}" if detail else "")
            )
        verification_text = (verified.stdout + verified.stderr).decode(
            errors="replace"
        )
        if (
            "Producer signature: verified with trusted handoff key"
            not in verification_text
            or f"SHA256:{public_key_digest}" not in verification_text
            or "Producer authenticity: NOT VERIFIED" in verification_text
        ):
            fail(
                "the reviewed receiver CLI did not report trusted producer-signature "
                "success for the exact supplied key fingerprint"
            )
        output_digest = sha256(
            verified.stdout + b"\x00AUTOMATESTIG-STDERR\x00" + verified.stderr
        )
        if sha256(read_regular_file(args.cli, "reviewed AutomateSTIG CLI", MAX_CLI_BYTES)) != cli_digest:
            fail("the reviewed receiver CLI changed during verification")

    completed_at = datetime.now(timezone.utc)
    if completed_at < signed_at:
        fail("receiver verification completed before the recorded signing ceremony")
    ceremony = {
        "schema": "automatestig-handoff-receiver-ceremony/v1",
        "passed": True,
        "producer_signature_verified": True,
        "trusted_cli_verification_succeeded": True,
        "key_custody_ceremony_verified": True,
        "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
        "source_commit": args.source_commit,
        "repository": args.repository,
        "workflow_run_id": args.workflow_run_id,
        "staging_workflow_run_id": args.staging_workflow_run_id,
        "protected_environment": PROTECTED_ENVIRONMENT,
        "automatestig_cli_sha256": cli_digest,
        "verification_output_sha256": output_digest,
        "staging_evidence_sha256": staging_digest,
        "handoff_filename": HANDOFF_NAME,
        "handoff_sha256": handoff_digest,
        "signature_filename": SIGNATURE_NAME,
        "signature_sha256": signature_digest,
        "public_key_filename": PUBLIC_KEY_NAME,
        "public_key_sha256": public_key_digest,
        "producer_key_fingerprint": f"SHA256:{public_key_digest}",
        "key_custody_filename": CUSTODY_NAME,
        "key_custody_sha256": custody_digest,
        "participants": [
            {"role": "key_custodian", "github_login": args.key_custodian},
            {"role": "receiver_approver", "github_login": args.receiver_approver},
        ],
    }
    ceremony_raw = (json.dumps(ceremony, indent=2, sort_keys=True) + "\n").encode()
    write_output(args.output_dir / CEREMONY_NAME, ceremony_raw)
    write_output(args.output_dir / PUBLIC_KEY_NAME, public_key)
    write_output(args.output_dir / HANDOFF_NAME, handoff)
    write_output(args.output_dir / SIGNATURE_NAME, signature_raw)
    write_output(args.output_dir / CUSTODY_NAME, custody_raw)
    print(
        "PASS: the reviewed receiver CLI authenticated the exact staged handoff "
        "against the independently supplied producer trust anchor"
    )


if __name__ == "__main__":
    main()
