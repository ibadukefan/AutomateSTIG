#!/usr/bin/env python3
"""Bind every supported release archive to its exact tested CLI and GUI bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request


SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
SUPPORTED_TARGETS = {
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
}
ARCHIVE_MEMBERS = {
    "automatestig",
    "automatestig-gui",
    "automatestig-backup-restore",
    "README.md",
    "LICENSE",
    "quickstart.md",
    "installation.md",
}
# Protected transition/signing tooling is intentionally source-built on a
# controlled host and must never be smuggled into the analyst product archive.
PROHIBITED_ARCHIVE_MEMBERS = {"automatestig-transition"}
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_CONTENT_BYTES = 768 * 1024 * 1024


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json(path: pathlib.Path):
    return json.loads(
        path.read_bytes(),
        object_pairs_hook=unique_json_object,
    )


def write_json_once(path: pathlib.Path, document: dict) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"refusing to replace existing manifest: {path}")
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular_file(path: pathlib.Path, description: str) -> pathlib.Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{description} must be a regular nonsymlink file")
    path = path.resolve()
    size = path.stat().st_size
    if size <= 0 or size > MAX_BINARY_BYTES:
        raise ValueError(f"{description} has an invalid size")
    return path


def workspace_version(repo: pathlib.Path) -> str:
    import tomllib

    document = tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
    version = document.get("workspace", {}).get("package", {}).get("version")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError("workspace package version is not a valid semantic version")
    return version


def snapshot_binaries(
    *,
    repo: pathlib.Path,
    target: str,
    source_commit: str,
    cli: pathlib.Path,
    gui: pathlib.Path,
    backup_restore: pathlib.Path,
    output: pathlib.Path,
) -> dict:
    if target not in SUPPORTED_TARGETS:
        raise ValueError(f"unsupported release target: {target}")
    if not GIT_SHA.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git SHA")
    cli = regular_file(cli, "CLI binary")
    gui = regular_file(gui, "GUI binary")
    backup_restore = regular_file(backup_restore, "backup/restore utility")
    document = {
        "schema": "automatestig-release-binary-snapshot/v1",
        "target": target,
        "version": workspace_version(repo),
        "source_commit": source_commit,
        "binaries": {
            "cli": {
                "name": "automatestig",
                "pre_package_sha256": sha256_file(cli),
                "size": cli.stat().st_size,
            },
            "gui": {
                "name": "automatestig-gui",
                "pre_package_sha256": sha256_file(gui),
                "size": gui.stat().st_size,
            },
        },
        "operational_tools": {
            "backup_restore": {
                "name": "automatestig-backup-restore",
                "pre_package_sha256": sha256_file(backup_restore),
                "size": backup_restore.stat().st_size,
            }
        },
    }
    write_json_once(output, document)
    return document


def validate_snapshot(document: object) -> dict:
    if not isinstance(document, dict):
        raise ValueError("binary snapshot must contain a JSON object")
    if set(document) != {
        "schema",
        "target",
        "version",
        "source_commit",
        "binaries",
        "operational_tools",
    }:
        raise ValueError("binary snapshot has an unexpected field set")
    if document.get("schema") != "automatestig-release-binary-snapshot/v1":
        raise ValueError("binary snapshot schema is not supported")
    target = document.get("target")
    if target not in SUPPORTED_TARGETS:
        raise ValueError("binary snapshot has an unsupported target")
    if not isinstance(document.get("version"), str) or not VERSION.fullmatch(
        document["version"]
    ):
        raise ValueError("binary snapshot has an invalid version")
    if not isinstance(document.get("source_commit"), str) or not GIT_SHA.fullmatch(
        document["source_commit"]
    ):
        raise ValueError("binary snapshot has an invalid source commit")
    binaries = document.get("binaries")
    if not isinstance(binaries, dict) or set(binaries) != {"cli", "gui"}:
        raise ValueError("binary snapshot must bind exactly the CLI and GUI")
    expected_names = {"cli": "automatestig", "gui": "automatestig-gui"}
    for role, expected_name in expected_names.items():
        record = binaries.get(role)
        if not isinstance(record, dict) or set(record) != {
            "name",
            "pre_package_sha256",
            "size",
        }:
            raise ValueError(f"binary snapshot {role} record is invalid")
        if record.get("name") != expected_name:
            raise ValueError(f"binary snapshot {role} name is invalid")
        if not isinstance(record.get("pre_package_sha256"), str) or not SHA256.fullmatch(
            record["pre_package_sha256"]
        ):
            raise ValueError(f"binary snapshot {role} digest is invalid")
        if not isinstance(record.get("size"), int) or not (
            0 < record["size"] <= MAX_BINARY_BYTES
        ):
            raise ValueError(f"binary snapshot {role} size is invalid")
    tools = document.get("operational_tools")
    if not isinstance(tools, dict) or set(tools) != {"backup_restore"}:
        raise ValueError("binary snapshot must bind the backup/restore utility")
    backup = tools["backup_restore"]
    if (
        not isinstance(backup, dict)
        or set(backup) != {"name", "pre_package_sha256", "size"}
        or backup.get("name") != "automatestig-backup-restore"
        or not isinstance(backup.get("pre_package_sha256"), str)
        or not SHA256.fullmatch(backup["pre_package_sha256"])
        or not isinstance(backup.get("size"), int)
        or not (0 < backup["size"] <= MAX_BINARY_BYTES)
    ):
        raise ValueError("binary snapshot backup/restore record is invalid")
    return document


def archive_binary_bytes(archive: pathlib.Path) -> dict[str, bytes]:
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("release archive must be a regular nonsymlink file")
    archive = archive.resolve()
    if not archive.name.endswith(".tar.gz"):
        raise ValueError("supported release archives must use .tar.gz")
    normalized = {}
    total_size = 0
    try:
        package = tarfile.open(archive, mode="r:gz")
    except (OSError, tarfile.TarError) as error:
        raise ValueError(f"release archive cannot be read: {error}") from error
    with package:
        for member in package.getmembers():
            path = pathlib.PurePosixPath(member.name)
            parts = tuple(part for part in path.parts if part not in ("", "."))
            if path.is_absolute() or ".." in parts or len(parts) != 1:
                raise ValueError("release archive contains an unsafe member path")
            name = parts[0]
            if name in normalized:
                raise ValueError("release archive contains duplicate member paths")
            if not member.isreg():
                raise ValueError("release archive members must all be regular files")
            if member.size < 0:
                raise ValueError("release archive member has a negative size")
            total_size += member.size
            if total_size > MAX_ARCHIVE_CONTENT_BYTES:
                raise ValueError("release archive expands beyond its size limit")
            normalized[name] = member
        if PROHIBITED_ARCHIVE_MEMBERS & set(normalized):
            raise ValueError("release archive contains protected transition tooling")
        if set(normalized) != ARCHIVE_MEMBERS:
            raise ValueError(
                "release archive member set is not closed: "
                f"missing={sorted(ARCHIVE_MEMBERS - set(normalized))} "
                f"unexpected={sorted(set(normalized) - ARCHIVE_MEMBERS)}"
            )
        result = {}
        for name in (
            "automatestig",
            "automatestig-gui",
            "automatestig-backup-restore",
        ):
            member = normalized[name]
            if member.size <= 0 or member.size > MAX_BINARY_BYTES:
                raise ValueError(f"release archive {name} has an invalid size")
            if member.mode & 0o111 == 0:
                raise ValueError(f"release archive {name} is not executable")
            stream = package.extractfile(member)
            if stream is None:
                raise ValueError(f"release archive {name} cannot be read")
            raw = stream.read(MAX_BINARY_BYTES + 1)
            if len(raw) != member.size or len(raw) > MAX_BINARY_BYTES:
                raise ValueError(f"release archive {name} length differs from its header")
            result[name] = raw
    return result


def finalize_equivalence(
    *, snapshot: pathlib.Path, archive: pathlib.Path, output: pathlib.Path
) -> dict:
    if snapshot.is_symlink() or not snapshot.is_file():
        raise ValueError("binary snapshot must be a regular nonsymlink file")
    source = validate_snapshot(load_json(snapshot))
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("release archive must be a regular nonsymlink file")
    archive = archive.resolve()
    extracted = archive_binary_bytes(archive)
    binaries = {}
    for role, record in source["binaries"].items():
        raw = extracted[record["name"]]
        observed = hashlib.sha256(raw).hexdigest()
        if observed != record["pre_package_sha256"] or len(raw) != record["size"]:
            raise ValueError(
                f"packaged {role} bytes differ from the pre-package binary snapshot"
            )
        binaries[role] = {
            **record,
            "archive_member_sha256": observed,
        }
    tools = {}
    for role, record in source["operational_tools"].items():
        raw = extracted[record["name"]]
        observed = hashlib.sha256(raw).hexdigest()
        if observed != record["pre_package_sha256"] or len(raw) != record["size"]:
            raise ValueError(
                f"packaged {role} bytes differ from the pre-package utility snapshot"
            )
        tools[role] = {**record, "archive_member_sha256": observed}
    document = {
        "schema": "automatestig-release-artifact-equivalence/v1",
        "target": source["target"],
        "version": source["version"],
        "source_commit": source["source_commit"],
        "archive": {
            "name": archive.name,
            "sha256": sha256_file(archive),
            "size": archive.stat().st_size,
            "format": "tar.gz",
        },
        "binaries": binaries,
        "operational_tools": tools,
    }
    write_json_once(output, document)
    return document


def validate_equivalence(document: object) -> dict:
    if not isinstance(document, dict):
        raise ValueError("equivalence manifest must contain a JSON object")
    if set(document) != {
        "schema",
        "target",
        "version",
        "source_commit",
        "archive",
        "binaries",
        "operational_tools",
    }:
        raise ValueError("equivalence manifest has an unexpected field set")
    if document.get("schema") != "automatestig-release-artifact-equivalence/v1":
        raise ValueError("equivalence manifest schema is not supported")
    if document.get("target") not in SUPPORTED_TARGETS:
        raise ValueError("equivalence manifest has an unsupported target")
    if not isinstance(document.get("version"), str) or not VERSION.fullmatch(
        document["version"]
    ):
        raise ValueError("equivalence manifest has an invalid version")
    if not isinstance(document.get("source_commit"), str) or not GIT_SHA.fullmatch(
        document["source_commit"]
    ):
        raise ValueError("equivalence manifest has an invalid source commit")
    archive = document.get("archive")
    if not isinstance(archive, dict) or set(archive) != {
        "name",
        "sha256",
        "size",
        "format",
    }:
        raise ValueError("equivalence manifest archive record is invalid")
    if (
        not isinstance(archive.get("name"), str)
        or pathlib.PurePath(archive["name"]).name != archive["name"]
        or not archive["name"].endswith(".tar.gz")
        or archive.get("format") != "tar.gz"
        or not isinstance(archive.get("sha256"), str)
        or not SHA256.fullmatch(archive["sha256"])
        or not isinstance(archive.get("size"), int)
        or archive["size"] <= 0
    ):
        raise ValueError("equivalence manifest archive identity is invalid")
    binaries = document.get("binaries")
    if not isinstance(binaries, dict) or set(binaries) != {"cli", "gui"}:
        raise ValueError("equivalence manifest must bind exactly the CLI and GUI")
    expected_names = {"cli": "automatestig", "gui": "automatestig-gui"}
    for role, expected_name in expected_names.items():
        record = binaries.get(role)
        if not isinstance(record, dict) or set(record) != {
            "name",
            "pre_package_sha256",
            "archive_member_sha256",
            "size",
        }:
            raise ValueError(f"equivalence manifest {role} record is invalid")
        if record.get("name") != expected_name:
            raise ValueError(f"equivalence manifest {role} name is invalid")
        before = record.get("pre_package_sha256")
        after = record.get("archive_member_sha256")
        if (
            not isinstance(before, str)
            or not SHA256.fullmatch(before)
            or not isinstance(after, str)
            or not SHA256.fullmatch(after)
            or before != after
        ):
            raise ValueError(f"equivalence manifest {role} digest binding is invalid")
        if not isinstance(record.get("size"), int) or not (
            0 < record["size"] <= MAX_BINARY_BYTES
        ):
            raise ValueError(f"equivalence manifest {role} size is invalid")
    tools = document.get("operational_tools")
    backup = tools.get("backup_restore") if isinstance(tools, dict) else None
    if (
        not isinstance(tools, dict)
        or set(tools) != {"backup_restore"}
        or not isinstance(backup, dict)
        or set(backup) != {
            "name",
            "pre_package_sha256",
            "archive_member_sha256",
            "size",
        }
        or backup.get("name") != "automatestig-backup-restore"
        or backup.get("pre_package_sha256")
        != backup.get("archive_member_sha256")
        or not isinstance(backup.get("archive_member_sha256"), str)
        or not SHA256.fullmatch(backup["archive_member_sha256"])
        or not isinstance(backup.get("size"), int)
        or not (0 < backup["size"] <= MAX_BINARY_BYTES)
    ):
        raise ValueError("equivalence manifest backup/restore binding is invalid")
    return document


def verify_checksum(archive: pathlib.Path, checksum: pathlib.Path) -> None:
    if checksum.is_symlink() or not checksum.is_file():
        raise ValueError("release archive checksum is missing")
    fields = checksum.read_text(encoding="utf-8").strip().split()
    observed = sha256_file(archive)
    if (
        len(fields) != 2
        or fields[1].lstrip("*") != archive.name
        or not SHA256.fullmatch(fields[0])
        or fields[0] != observed
    ):
        raise ValueError("release archive checksum is invalid")


def tag_version(tag: str) -> str:
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", tag):
        raise ValueError("tag is not a semantic version tag")
    return tag[1:].split("+", 1)[0].split("-", 1)[0]


def safe_repo_reference(repo, reference, tag):
    if not isinstance(reference, str):
        raise ValueError("live evidence reference must be a string")
    relative = pathlib.PurePosixPath(reference)
    expected_parent = pathlib.PurePosixPath("release-evidence", "artifacts", tag)
    if relative.is_absolute() or ".." in relative.parts or relative.parent != expected_parent:
        raise ValueError("live evidence reference escapes its tagged artifact directory")
    path = repo.joinpath(*relative.parts)
    if path.is_symlink() or not path.is_file():
        raise ValueError("live evidence reference must be a regular nonsymlink file")
    return path


def live_binary_digest(repo, tag):
    release_path = repo / "release-evidence" / f"{tag}.json"
    release = load_json(release_path)
    if release.get("schema") != "automatestig-release-evidence/v1" or release.get("tag") != tag:
        raise ValueError("release evidence identity does not match the tag")
    acceptance = release.get("acceptance")
    if not isinstance(acceptance, dict):
        raise ValueError("release evidence acceptance map is missing")
    digests = set()
    references = set()
    for gate in ("ontap", "freebsd", "cisco_ios_xe"):
        entry = acceptance.get(gate)
        if not isinstance(entry, dict):
            raise ValueError(f"release evidence is missing {gate}")
        reference = entry.get("evidence_reference")
        artifact = safe_repo_reference(repo, reference, tag)
        expected_artifact_sha = entry.get("evidence_sha256")
        if (
            not isinstance(expected_artifact_sha, str)
            or not SHA256.fullmatch(expected_artifact_sha)
            or sha256_file(artifact) != expected_artifact_sha
        ):
            raise ValueError(f"{gate} live evidence artifact digest mismatch")
        evidence = load_json(artifact)
        binary_sha256 = evidence.get("binary_sha256")
        if (
            evidence.get("schema") != "automatestig-live-device-acceptance/v1"
            or evidence.get("source_commit") != release.get("approved_commit")
            or not isinstance(binary_sha256, str)
            or not SHA256.fullmatch(binary_sha256)
        ):
            raise ValueError(f"{gate} live evidence lacks exact tested-binary provenance")
        references.add(reference)
        digests.add(binary_sha256)
    if len(references) != 1 or len(digests) != 1:
        raise ValueError("device gates do not share one exact live-tested binary artifact")
    return digests.pop()


def cli_version(binary: pathlib.Path, expected_version: str) -> None:
    result = subprocess.run(
        [binary, "--version"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0 or output != f"automatestig {expected_version}":
        raise ValueError(
            f"CLI version check failed: exit={result.returncode} output={output!r}"
        )


def available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def gui_version(binary: pathlib.Path, expected_version: str, data_dir: pathlib.Path) -> None:
    port = available_loopback_port()
    env = dict(os.environ)
    env.update(
        {
            "PORT": str(port),
            "AUTOMATESTIG_BIND": "127.0.0.1",
            "AUTOMATESTIG_DATA_DIR": str(data_dir),
        }
    )
    process = subprocess.Popen(
        [binary],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    response = None
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/api/status", timeout=1
                ) as stream:
                    response = json.loads(stream.read())
                break
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                time.sleep(0.2)
        observed = ((response or {}).get("data") or {}).get("version")
        if observed != expected_version:
            raise ValueError(
                f"GUI runtime version check failed: expected {expected_version}, got {observed!r}"
            )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        output = process.stdout.read() if process.stdout is not None else ""
        if response is None and output:
            print(output[-2000:], file=sys.stderr)


def recovery_smoke(binary: pathlib.Path, root: pathlib.Path) -> None:
    """Execute the packaged recovery entrypoint through a real round trip."""
    root = root.resolve()
    source = root / "recovery-source"
    source.mkdir(mode=0o700)
    database = sqlite3.connect(source / "data.db")
    try:
        database.executescript(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE app_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE recovery_smoke (id TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO app_config VALUES ('stigman_config', 'must-be-removed');
            INSERT INTO recovery_smoke VALUES ('round-trip', 'preserved');
            """
        )
        database.commit()
    finally:
        database.close()
    secret = source / "secret.key"
    secret.write_text("release-recovery-smoke\n", encoding="utf-8")
    secret.chmod(0o600)
    archive = root / "recovery-smoke.zip"
    restored = root / "recovery-restored"

    for action, arguments in (
        (
            "backup",
            ["backup", "--data-dir", str(source), "--output", str(archive)],
        ),
        (
            "restore",
            ["restore", "--input", str(archive), "--data-dir", str(restored)],
        ),
    ):
        result = subprocess.run(
            [binary, *arguments],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            output = (result.stdout + result.stderr).strip()
            raise ValueError(
                f"packaged recovery {action} smoke failed: "
                f"exit={result.returncode} output={output!r}"
            )

    restored_db = sqlite3.connect(restored / "data.db")
    try:
        preserved = restored_db.execute(
            "SELECT value FROM recovery_smoke WHERE id = 'round-trip'"
        ).fetchone()
        credential = restored_db.execute(
            "SELECT value FROM app_config WHERE key = 'stigman_config'"
        ).fetchone()
    except sqlite3.Error as error:
        raise ValueError(f"packaged recovery smoke database is invalid: {error}") from error
    finally:
        restored_db.close()
    if preserved != ("preserved",) or credential is not None:
        raise ValueError(
            "packaged recovery smoke did not preserve state and require credential re-entry"
        )
    if secret.read_bytes() != (restored / "secret.key").read_bytes():
        raise ValueError("packaged recovery smoke did not preserve the recovery key material")


def execute_versions(extracted: dict[str, bytes], version: str) -> None:
    with tempfile.TemporaryDirectory(prefix="automatestig-release-execute-") as temporary:
        # macOS exposes its temporary directory through `/var`, which is a
        # system symlink. The recovery utility deliberately rejects every
        # symlink/reparse ancestor, so pass the canonical real directory.
        root = pathlib.Path(temporary).resolve()
        paths = {}
        for name, raw in extracted.items():
            path = root / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
            path.chmod(0o700)
            paths[name] = path
        cli_version(paths["automatestig"], version)
        gui_version(paths["automatestig-gui"], version, root / "gui-data")
        recovery_smoke(paths["automatestig-backup-restore"], root)


def verify_equivalence(
    *,
    manifest: pathlib.Path,
    archive: pathlib.Path,
    checksum: pathlib.Path,
    target: str | None = None,
    source_commit: str | None = None,
    tag: str | None = None,
    execute: bool = False,
    repo: pathlib.Path | None = None,
    require_live_cli: bool = False,
) -> dict:
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("equivalence manifest must be a regular nonsymlink file")
    document = validate_equivalence(load_json(manifest))
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("release archive must be a regular nonsymlink file")
    archive = archive.resolve()
    if target is not None and document["target"] != target:
        raise ValueError("equivalence manifest target does not match the requested target")
    if source_commit is not None and document["source_commit"] != source_commit:
        raise ValueError("equivalence manifest source commit does not match the workflow commit")
    if tag is not None and document["version"] != tag_version(tag):
        raise ValueError("equivalence manifest version does not match the release tag")
    archive_record = document["archive"]
    if (
        archive.name != archive_record["name"]
        or archive.stat().st_size != archive_record["size"]
        or sha256_file(archive) != archive_record["sha256"]
    ):
        raise ValueError("release archive differs from its equivalence manifest")
    verify_checksum(archive, checksum)
    extracted = archive_binary_bytes(archive)
    for role, record in document["binaries"].items():
        raw = extracted[record["name"]]
        if (
            len(raw) != record["size"]
            or hashlib.sha256(raw).hexdigest() != record["archive_member_sha256"]
        ):
            raise ValueError(f"release archive {role} differs from its equivalence manifest")
    for role, record in document["operational_tools"].items():
        raw = extracted[record["name"]]
        if (
            len(raw) != record["size"]
            or hashlib.sha256(raw).hexdigest() != record["archive_member_sha256"]
        ):
            raise ValueError(
                f"release archive {role} differs from its equivalence manifest"
            )
    if require_live_cli:
        if document["target"] != "x86_64-unknown-linux-gnu" or repo is None or tag is None:
            raise ValueError("protected live CLI comparison is valid only for tagged Linux x86_64")
        expected = live_binary_digest(repo.resolve(), tag)
        if document["binaries"]["cli"]["archive_member_sha256"] != expected:
            raise ValueError(
                "release Linux x86_64 CLI differs from protected live-device acceptance"
            )
    if execute:
        execute_versions(extracted, document["version"])
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("--repo-root", default=".", type=pathlib.Path)
    snapshot.add_argument("--target", required=True)
    snapshot.add_argument("--source-commit", required=True)
    snapshot.add_argument("--cli", required=True, type=pathlib.Path)
    snapshot.add_argument("--gui", required=True, type=pathlib.Path)
    snapshot.add_argument("--backup-restore", required=True, type=pathlib.Path)
    snapshot.add_argument("--output", required=True, type=pathlib.Path)

    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--snapshot", required=True, type=pathlib.Path)
    finalize.add_argument("--archive", required=True, type=pathlib.Path)
    finalize.add_argument("--output", required=True, type=pathlib.Path)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", required=True, type=pathlib.Path)
    verify.add_argument("--archive", required=True, type=pathlib.Path)
    verify.add_argument("--checksum", required=True, type=pathlib.Path)
    verify.add_argument("--target")
    verify.add_argument("--source-commit")
    verify.add_argument("--tag")
    verify.add_argument("--execute", action="store_true")
    verify.add_argument("--repo-root", type=pathlib.Path)
    verify.add_argument("--require-live-cli", action="store_true")

    args = parser.parse_args()
    try:
        if args.command == "snapshot":
            document = snapshot_binaries(
                repo=args.repo_root.resolve(),
                target=args.target,
                source_commit=args.source_commit,
                cli=args.cli,
                gui=args.gui,
                backup_restore=args.backup_restore,
                output=args.output,
            )
            print(
                f"Snapshotted CLI, GUI, and recovery utility for "
                f"{document['target']} before packaging"
            )
        elif args.command == "finalize":
            document = finalize_equivalence(
                snapshot=args.snapshot,
                archive=args.archive,
                output=args.output,
            )
            print(
                f"Bound {document['archive']['name']} to exact pre-package "
                "CLI, GUI, and recovery utility bytes"
            )
        else:
            document = verify_equivalence(
                manifest=args.manifest,
                archive=args.archive,
                checksum=args.checksum,
                target=args.target,
                source_commit=args.source_commit,
                tag=args.tag,
                execute=args.execute,
                repo=args.repo_root,
                require_live_cli=args.require_live_cli,
            )
            suffix = (
                " and executed both binaries plus the recovery round trip"
                if args.execute
                else ""
            )
            print(
                f"Verified {document['target']} archive against exact CLI/GUI bytes{suffix}"
            )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
