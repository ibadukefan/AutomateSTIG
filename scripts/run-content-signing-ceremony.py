#!/usr/bin/env python3
"""Verify a content key ceremony without exposing the offline private key."""

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
from datetime import datetime, timezone
from pathlib import Path


PUBLIC_KEY_NAME = "content-signing-public-key.pub"
TEST_PACK_NAME = "content-signing-test-pack.stigpack"
EVIDENCE_NAME = "content-signing-ceremony.json"
PROTECTED_ENVIRONMENT = "content-signing-ceremony"
MAX_TEST_PACK_BYTES = 48_000
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def decode_input(name: str, maximum: int) -> bytes:
    encoded = os.environ.get(name)
    if not encoded:
        fail(f"{name} must contain base64-encoded public ceremony input")
    # Reject oversized input before allocating decoded attacker-controlled bytes.
    if len(encoded) > ((maximum + 2) // 3) * 4:
        fail(f"{name} exceeds the ceremony input limit")
    try:
        value = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        fail(f"{name} must be canonical base64 without whitespace")
    if not value or len(value) > maximum:
        fail(f"{name} decoded size is outside the ceremony input limit")
    return value


def input_bytes(path: Path | None, environment_name: str, field: str, maximum: int) -> bytes:
    if path is not None:
        return read_regular_file(path, field, maximum)
    return decode_input(environment_name, maximum)


def validate_identity(value: str, field: str) -> None:
    if not LOGIN.fullmatch(value):
        fail(f"{field} must be a valid GitHub login")


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--key-custodian", required=True)
    parser.add_argument("--content-approver", required=True)
    parser.add_argument(
        "--public-key",
        type=Path,
        help="local-test alternative to AUTOMATESTIG_CEREMONY_PUBLIC_KEY_BASE64",
    )
    parser.add_argument(
        "--test-pack",
        type=Path,
        help="local-test alternative to AUTOMATESTIG_CEREMONY_TEST_PACK_BASE64",
    )
    args = parser.parse_args()

    validate_identity(args.key_custodian, "key_custodian")
    validate_identity(args.content_approver, "content_approver")
    if args.key_custodian.casefold() == args.content_approver.casefold():
        fail("the key custodian and content approver must be different GitHub users")
    if not REPOSITORY.fullmatch(args.repository):
        fail("repository must be an owner/name GitHub repository")
    if not SHA.fullmatch(args.source_commit):
        fail("source_commit must be a full lowercase Git commit")
    if not args.workflow_run_id.isdigit():
        fail("workflow_run_id must contain only decimal digits")
    if (args.public_key is None) != (args.test_pack is None):
        fail("--public-key and --test-pack must be supplied together")

    public_key = input_bytes(
        args.public_key,
        "AUTOMATESTIG_CEREMONY_PUBLIC_KEY_BASE64",
        "public key",
        32,
    )
    if len(public_key) != 32:
        fail("the Ed25519 public key must contain exactly 32 raw bytes")
    test_pack = input_bytes(
        args.test_pack,
        "AUTOMATESTIG_CEREMONY_TEST_PACK_BASE64",
        "signed test pack",
        MAX_TEST_PACK_BYTES,
    )
    cli = read_regular_file(args.cli, "just-built AutomateSTIG CLI", 256 * 1024 * 1024)
    cli_digest = sha256(cli)

    try:
        args.output_dir.mkdir(mode=0o755)
    except OSError as error:
        fail(f"ceremony output directory must not already exist: {error}")

    with tempfile.TemporaryDirectory(prefix="automatestig-ceremony-") as temporary:
        work = Path(temporary)
        trust = work / "trusted_keys"
        trust.mkdir(mode=0o700)
        trusted_key = trust / PUBLIC_KEY_NAME
        pack_path = work / TEST_PACK_NAME
        trusted_key.write_bytes(public_key)
        pack_path.write_bytes(test_pack)
        environment = os.environ.copy()
        environment["AUTOMATESTIG_TRUSTED_KEYS_DIR"] = str(trust)
        environment["HOME"] = str(work)
        environment.pop("AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK", None)
        try:
            verified = subprocess.run(
                [str(args.cli), "verify", "--pack", str(pack_path)],
                env=environment,
                text=True,
                capture_output=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            fail(f"cannot run the just-built CLI verifier: {error}")
        if verified.returncode != 0:
            detail = (verified.stderr or verified.stdout).strip()
            fail("the signed test pack did not verify against the supplied public key" + (
                f": {detail[-500:]}" if detail else ""
            ))
        verified_cli = read_regular_file(
            args.cli,
            "just-built AutomateSTIG CLI",
            256 * 1024 * 1024,
        )
        if sha256(verified_cli) != cli_digest:
            fail("the just-built CLI changed while the ceremony verification was running")

    key_digest = sha256(public_key)
    pack_digest = sha256(test_pack)
    evidence = {
        "schema": "automatestig-content-signing-ceremony/v1",
        "passed": True,
        "signature_verified": True,
        "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_commit": args.source_commit,
        "repository": args.repository,
        "workflow_run_id": args.workflow_run_id,
        "protected_environment": PROTECTED_ENVIRONMENT,
        "automatestig_cli_sha256": cli_digest,
        "public_key_filename": PUBLIC_KEY_NAME,
        "public_key_sha256": key_digest,
        "public_key_fingerprint": f"SHA256:{key_digest}",
        "test_pack_filename": TEST_PACK_NAME,
        "pack_sha256": pack_digest,
        "participants": [
            {"role": "key_custodian", "github_login": args.key_custodian},
            {"role": "content_approver", "github_login": args.content_approver},
        ],
    }
    encoded_evidence = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode()
    write_output(args.output_dir / PUBLIC_KEY_NAME, public_key)
    write_output(args.output_dir / TEST_PACK_NAME, test_pack)
    write_output(args.output_dir / EVIDENCE_NAME, encoded_evidence)
    print(
        "PASS: the just-built CLI verified the bounded ceremony pack; "
        f"wrote {EVIDENCE_NAME}, {PUBLIC_KEY_NAME}, and {TEST_PACK_NAME}"
    )


if __name__ == "__main__":
    main()
