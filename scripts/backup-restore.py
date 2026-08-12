#!/usr/bin/env python3
"""Create and restore bounded, integrity-checked AutomateSTIG state backups."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import sys
import tempfile
from typing import Optional
import urllib.parse
import zipfile


SCHEMA = "automatestig.backup.v1"
MANIFEST_NAME = "automatestig-backup/manifest.json"
FILES_PREFIX = "automatestig-backup/files/"
MAX_FILES = 100_000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
STATE_PATHS = (
    "secret.key",
    "library",
    "known_hosts",
    "trusted_keys",
    "organization_policy_keys",
    "handoff_trusted_keys",
)
MINIMUM_PYTHON = (3, 10)
MINIMUM_PYTHON_TEXT = ".".join(str(part) for part in MINIMUM_PYTHON)


class BackupError(RuntimeError):
    pass


def require_supported_python(version_info=None) -> None:
    """Fail with an actionable message before attempting recovery work."""
    observed = sys.version_info if version_info is None else version_info
    if tuple(observed[:2]) < MINIMUM_PYTHON:
        version = ".".join(str(part) for part in observed[:3])
        raise BackupError(
            f"Python {MINIMUM_PYTHON_TEXT} or newer is required; found {version}"
        )


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    """Recognize POSIX links and Windows junction/reparse-point objects."""
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        reparse_flag and attributes & reparse_flag
    )


def reject_link_or_reparse_ancestors(path: Path, label: str) -> Path:
    """Reject a link/reparse point in an existing path or any of its ancestors.

    ``Path.resolve`` is deliberately not used: resolving first would hide the
    very custody-boundary indirection this check is intended to reject.
    """
    path = path.expanduser().absolute()
    anchor = Path(path.anchor)
    components = [anchor]
    current = anchor
    for part in path.parts[1:]:
        current = current / part
        components.append(current)
    for component in components:
        try:
            metadata = component.lstat()
        except FileNotFoundError as error:
            raise BackupError(
                f"{label} path component does not exist: {component}"
            ) from error
        except OSError as error:
            raise BackupError(
                f"could not inspect {label} path component {component}: {error}"
            ) from error
        if is_link_or_reparse(metadata):
            raise BackupError(
                f"{label} contains a symlink or reparse-point component: {component}"
            )
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_real_directory(path: Path, label: str) -> Path:
    path = reject_link_or_reparse_ancestors(path, label)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise BackupError(f"{label} does not exist: {path}") from error
    if is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise BackupError(f"{label} must be a real directory: {path}")
    if os.name != "nt":
        if metadata.st_uid != os.geteuid():
            raise BackupError(f"{label} is not owned by the current user: {path}")
        if metadata.st_mode & 0o077:
            raise BackupError(f"{label} must not be accessible by group or other users: {path}")
    return path


def require_regular_file(path: Path, label: str) -> Path:
    path = reject_link_or_reparse_ancestors(path, label)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise BackupError(f"{label} does not exist: {path}") from error
    if is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise BackupError(f"{label} must be a regular, non-symlink file: {path}")
    return path


def ensure_private_directory_chain(root: Path, parent: Path, label: str) -> None:
    """Create each restore directory privately and validate every component."""
    root = require_real_directory(root, "restore workspace")
    parent = parent.absolute()
    try:
        relative = parent.relative_to(root)
    except ValueError as error:
        raise BackupError(f"{label} escapes the restore workspace") from error
    current = root
    for part in relative.parts:
        current = current / part
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        require_real_directory(current, label)


def validate_relative_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value:
        raise BackupError(f"unsafe backup member path: {value!r}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise BackupError(f"unsafe backup member path: {value!r}")
    return path


def file_record(path: Path, relative: PurePosixPath, source_mode: int | None = None) -> dict:
    size = path.stat().st_size
    if size > MAX_MEMBER_BYTES:
        raise BackupError(f"backup member exceeds the {MAX_MEMBER_BYTES}-byte limit: {relative}")
    mode = (source_mode if source_mode is not None else path.stat().st_mode) & 0o700
    return {
        "path": relative.as_posix(),
        "size": size,
        "sha256": sha256_file(path),
        "mode": f"{mode or 0o600:04o}",
    }


def copy_regular_tree(source: Path, destination: Path, relative: PurePosixPath) -> list[dict]:
    entries: list[dict] = []
    reject_link_or_reparse_ancestors(source, f"backup source {relative}")
    metadata = source.lstat()
    if is_link_or_reparse(metadata):
        raise BackupError(f"backup source contains a symlink: {relative}")
    if stat.S_ISREG(metadata.st_mode):
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        source_descriptor = os.open(source, flags)
        try:
            opened = os.fstat(source_descriptor)
            if not stat.S_ISREG(opened.st_mode) or (
                metadata.st_ino
                and opened.st_ino
                and (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise BackupError(f"backup source changed while it was opened: {relative}")
            destination_descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(source_descriptor, "rb") as input_stream, os.fdopen(
                destination_descriptor, "wb"
            ) as output_stream:
                source_descriptor = -1
                shutil.copyfileobj(input_stream, output_stream, 1024 * 1024)
                output_stream.flush()
                os.fsync(output_stream.fileno())
        finally:
            if source_descriptor >= 0:
                os.close(source_descriptor)
        os.chmod(destination, metadata.st_mode & 0o700 or 0o600)
        entries.append(file_record(destination, relative, metadata.st_mode))
        return entries
    if not stat.S_ISDIR(metadata.st_mode):
        raise BackupError(f"backup source contains a non-file object: {relative}")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    with os.scandir(source) as children:
        for child in sorted(children, key=lambda item: item.name):
            child_relative = relative / child.name
            validate_relative_path(child_relative.as_posix())
            entries.extend(copy_regular_tree(Path(child.path), destination / child.name, child_relative))
            if len(entries) > MAX_FILES:
                raise BackupError(f"backup contains more than {MAX_FILES} files")
    return entries


def sqlite_snapshot(source: Path, destination: Path) -> None:
    uri = "file:" + urllib.parse.quote(str(source), safe="/") + "?mode=ro"
    source_db = sqlite3.connect(uri, uri=True, timeout=30)
    destination_db = sqlite3.connect(destination)
    try:
        check = source_db.execute("PRAGMA quick_check").fetchone()
        if not check or check[0] != "ok":
            raise BackupError(f"source database quick_check failed: {check!r}")
        source_db.backup(destination_db)
        destination_db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        destination_db.commit()
    except sqlite3.Error as error:
        raise BackupError(f"could not snapshot SQLite database: {error}") from error
    finally:
        destination_db.close()
        source_db.close()


def sync_file_and_parent(path: Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())
    if os.name != "nt":
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def create_backup(data_dir: Path, output: Path) -> None:
    data_dir = require_real_directory(data_dir, "data directory")
    database = require_regular_file(data_dir / "data.db", "AutomateSTIG database")
    output = output.expanduser().absolute()
    output_parent = require_real_directory(output.parent, "backup output parent")
    if os.path.lexists(output):
        raise BackupError(f"backup output already exists: {output}")
    if output == database or data_dir in output.parents:
        raise BackupError("backup output must be outside the AutomateSTIG data directory")

    workspace = Path(tempfile.mkdtemp(prefix=".automatestig-backup-", dir=output_parent))
    archive_temp = workspace / "backup.zip"
    files_root = workspace / "files"
    files_root.mkdir(mode=0o700)
    records: list[dict] = []
    try:
        snapshot = files_root / "data.db"
        sqlite_snapshot(database, snapshot)
        os.chmod(snapshot, 0o600)
        records.append(file_record(snapshot, PurePosixPath("data.db"), 0o600))
        for name in STATE_PATHS:
            source = data_dir / name
            if os.path.lexists(source):
                records.extend(copy_regular_tree(source, files_root / name, PurePosixPath(name)))
        if len(records) > MAX_FILES:
            raise BackupError(f"backup contains more than {MAX_FILES} files")
        total = sum(record["size"] for record in records)
        if total > MAX_TOTAL_BYTES:
            raise BackupError(f"backup expands beyond the {MAX_TOTAL_BYTES}-byte limit")
        records.sort(key=lambda record: record["path"])
        manifest = {
            "schema": SCHEMA,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "credential_reentry_required": True,
            "database_snapshot": "sqlite-online-backup",
            "excluded": ["logs", "data.db-wal", "data.db-shm", "data.db-journal"],
            "files": records,
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise BackupError("backup manifest exceeds its safe size limit")
        descriptor = os.open(archive_temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w+b") as raw_archive:
            with zipfile.ZipFile(raw_archive, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                archive.writestr(MANIFEST_NAME, manifest_bytes)
                for record in records:
                    archive.write(files_root / record["path"], FILES_PREFIX + record["path"])
            raw_archive.flush()
            os.fsync(raw_archive.fileno())
        output_parent = require_real_directory(output_parent, "backup output parent")
        try:
            os.link(archive_temp, output)
        except FileExistsError as error:
            raise BackupError(f"backup output was created concurrently: {output}") from error
        os.chmod(output, 0o600)
        sync_file_and_parent(output)
        print(f"Backup created: {output}")
        print(f"Archive SHA-256: {sha256_file(output)}")
        print(f"Files: {len(records)}; uncompressed bytes: {total}")
        print("Protect this archive like assessment data plus credential key material.")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def safe_zip_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    members: dict[str, zipfile.ZipInfo] = {}
    total = 0
    for info in archive.infolist():
        if info.filename in members:
            raise BackupError(f"duplicate ZIP member: {info.filename}")
        validate_relative_path(info.filename)
        mode = (info.external_attr >> 16) & 0o170000
        if mode not in (0, stat.S_IFREG):
            raise BackupError(f"ZIP member is not a regular file: {info.filename}")
        if info.is_dir() or info.file_size > MAX_MEMBER_BYTES:
            raise BackupError(f"invalid or oversized ZIP member: {info.filename}")
        total += info.file_size
        if total > MAX_TOTAL_BYTES + MAX_MANIFEST_BYTES:
            raise BackupError("backup expands beyond its total size limit")
        members[info.filename] = info
    return members


def parse_manifest(archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo]) -> dict:
    info = members.get(MANIFEST_NAME)
    if info is None or info.file_size > MAX_MANIFEST_BYTES:
        raise BackupError("backup has no bounded manifest")
    try:
        manifest = json.loads(archive.read(info))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise BackupError(f"backup manifest is invalid: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise BackupError("backup manifest schema is unsupported")
    if manifest.get("credential_reentry_required") is not True:
        raise BackupError("backup does not require credential re-entry")
    records = manifest.get("files")
    if not isinstance(records, list) or not records or len(records) > MAX_FILES:
        raise BackupError("backup manifest has an invalid file inventory")
    declared: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "size", "sha256", "mode"}:
            raise BackupError("backup manifest contains an invalid file record")
        path = validate_relative_path(record["path"]).as_posix()
        if path in declared:
            raise BackupError(f"backup manifest repeats a file: {path}")
        declared.add(path)
        if not isinstance(record["size"], int) or not 0 <= record["size"] <= MAX_MEMBER_BYTES:
            raise BackupError(f"backup manifest has an invalid size for {path}")
        digest = record["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise BackupError(f"backup manifest has an invalid digest for {path}")
        try:
            mode = int(record["mode"], 8)
        except (TypeError, ValueError) as error:
            raise BackupError(f"backup manifest has an invalid mode for {path}") from error
        if mode & ~0o700:
            raise BackupError(f"backup manifest mode is not private for {path}")
    expected = {MANIFEST_NAME} | {FILES_PREFIX + path for path in declared}
    if set(members) != expected:
        raise BackupError("backup ZIP members do not exactly match the manifest")
    if "data.db" not in declared:
        raise BackupError("backup does not contain data.db")
    return manifest


def extract_verified(archive: zipfile.ZipFile, manifest: dict, destination: Path) -> None:
    for record in manifest["files"]:
        relative = validate_relative_path(record["path"])
        target = destination.joinpath(*relative.parts)
        ensure_private_directory_chain(
            destination,
            target.parent,
            f"restore destination for {relative}",
        )
        digest = hashlib.sha256()
        written = 0
        descriptor = os.open(
            target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            with archive.open(FILES_PREFIX + record["path"], "r") as source, os.fdopen(descriptor, "wb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > record["size"]:
                        raise BackupError(
                            f"backup member failed integrity verification (larger than declared): {relative}"
                        )
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        except Exception:
            target.unlink(missing_ok=True)
            raise
        if written != record["size"] or digest.hexdigest() != record["sha256"]:
            target.unlink(missing_ok=True)
            raise BackupError(f"backup member failed integrity verification: {relative}")
        os.chmod(target, int(record["mode"], 8) or 0o600)


def require_credential_reentry(database: Path) -> None:
    database = require_regular_file(database, "restored AutomateSTIG database")
    connection = sqlite3.connect(database, timeout=30)
    try:
        connection.execute("PRAGMA secure_delete = ON")
        check = connection.execute("PRAGMA quick_check").fetchone()
        if not check or check[0] != "ok":
            raise BackupError(f"restored database quick_check failed: {check!r}")
        has_config = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='app_config'"
        ).fetchone()
        if has_config:
            connection.execute("DELETE FROM app_config WHERE key = 'stigman_config'")
            connection.commit()
            connection.execute("VACUUM")
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.commit()
    except sqlite3.Error as error:
        raise BackupError(f"could not prepare restored database: {error}") from error
    finally:
        connection.close()
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(database) + suffix)
        if sidecar.exists():
            sidecar.unlink()


def restore_backup(archive_path: Path, data_dir: Path) -> None:
    archive_path = require_regular_file(archive_path, "backup archive")
    data_dir = data_dir.expanduser().absolute()
    parent = require_real_directory(data_dir.parent, "restore parent")
    if os.path.lexists(data_dir):
        raise BackupError(f"restore target must not already exist: {data_dir}")
    workspace: Optional[Path] = Path(
        tempfile.mkdtemp(prefix=".automatestig-restore-", dir=parent)
    )
    os.chmod(workspace, 0o700)
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            members = safe_zip_members(archive)
            manifest = parse_manifest(archive, members)
            extract_verified(archive, manifest, workspace)
        require_credential_reentry(workspace / "data.db")
        if os.path.lexists(data_dir):
            raise BackupError(f"restore target was created concurrently: {data_dir}")
        parent = require_real_directory(parent, "restore parent")
        os.rename(workspace, data_dir)
        workspace = None
        if os.name != "nt":
            descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        print(f"Backup restored: {data_dir}")
        print("STIG Manager connection credentials were removed; re-enter and test them before scanning.")
    except zipfile.BadZipFile as error:
        raise BackupError(f"backup archive is not a valid ZIP: {error}") from error
    finally:
        if workspace is not None:
            shutil.rmtree(workspace, ignore_errors=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=__doc__,
        epilog=f"Requires Python {MINIMUM_PYTHON_TEXT} or newer.",
    )
    result.add_argument(
        "--version",
        action="version",
        version=f"automatestig-backup-restore (Python >= {MINIMUM_PYTHON_TEXT})",
    )
    actions = result.add_subparsers(dest="action", required=True)
    backup = actions.add_parser("backup", help="create a new protected backup ZIP")
    backup.add_argument("--data-dir", type=Path, default=Path.home() / ".automatestig")
    backup.add_argument("--output", type=Path, required=True)
    restore = actions.add_parser("restore", help="restore into a new data directory")
    restore.add_argument("--input", type=Path, required=True)
    restore.add_argument("--data-dir", type=Path, default=Path.home() / ".automatestig")
    return result


def main() -> int:
    try:
        require_supported_python()
    except BackupError as error:
        print(f"backup/restore error: {error}", file=sys.stderr)
        return 2
    arguments = parser().parse_args()
    try:
        if arguments.action == "backup":
            create_backup(arguments.data_dir, arguments.output)
        else:
            restore_backup(arguments.input, arguments.data_dir)
    except BackupError as error:
        print(f"backup/restore error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
