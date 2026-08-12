#!/usr/bin/env python3
"""Shared, dependency-free safety helpers for adapter development tooling."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import AbstractSet, Any, Mapping


SAFE_KEY = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
SAFE_OUTPUT_LEAF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
STIG_RELEASE = re.compile(r"^V[0-9]+R[0-9]+$")
MAX_JSON_BYTES = 16 * 1024 * 1024


class ToolingError(ValueError):
    """Raised when an input cannot be consumed without weakening safety."""


def validate_target_key(value: str) -> str:
    if not isinstance(value, str) or not SAFE_KEY.fullmatch(value):
        raise ToolingError(
            "target key must match ^[a-z][a-z0-9_]{2,63}$"
        )
    return value


def validate_nonempty(value: str, label: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ToolingError(f"{label} must be a non-empty, trimmed string")
    if len(value) > maximum or any(ord(character) < 0x20 for character in value):
        raise ToolingError(f"{label} is invalid or too long")
    return value


def validate_stig_release(value: str) -> str:
    if not isinstance(value, str) or not STIG_RELEASE.fullmatch(value):
        raise ToolingError("STIG release must use the exact V<number>R<number> form")
    return value


def _reject_symlink_components(path: Path) -> None:
    """Require every existing component to be a real directory, never a link."""
    absolute = path if path.is_absolute() else Path.cwd() / path
    parts = absolute.parts
    current = Path(parts[0])
    for component in parts[1:]:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            raise ToolingError(f"output parent does not exist: {current}") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise ToolingError(f"symlink path components are not allowed: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ToolingError(f"output parent is not a directory: {current}")


def absent_output_directory(raw_path: str | Path, *, expected_leaf: str | None = None) -> Path:
    """Validate an absent output directory and bind creation to its real parent."""
    path = Path(raw_path)
    if not str(path) or "\x00" in str(path) or ".." in path.parts:
        raise ToolingError("output directory must be a safe path without '..'")
    if not SAFE_OUTPUT_LEAF.fullmatch(path.name):
        raise ToolingError("output directory name contains unsafe characters")
    if expected_leaf is not None and path.name != expected_leaf:
        raise ToolingError(
            f"adapter output directory must be named exactly {expected_leaf!r}"
        )
    lexical = path if path.is_absolute() else Path.cwd() / path
    try:
        real_parent = lexical.parent.resolve(strict=True)
    except (FileNotFoundError, OSError) as error:
        raise ToolingError(f"output parent does not exist or cannot be resolved: {lexical.parent}") from error
    _reject_symlink_components(real_parent)
    absolute = real_parent / path.name
    if os.path.lexists(absolute):
        raise ToolingError(f"output directory already exists: {absolute}")
    return absolute


def canonical_json(document: Any) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_new_bundle(
    output: Path,
    files: Mapping[str, bytes],
    *,
    executable_files: AbstractSet[str] = frozenset(),
) -> None:
    """Create an output tree once; never merge with or overwrite an old tree."""
    unknown_executables = set(executable_files) - set(files)
    if unknown_executables:
        raise ToolingError(
            f"executable generated members do not exist: {sorted(unknown_executables)}"
        )
    os.mkdir(output, 0o700)
    created_directories = {PurePosixPath(".")}
    for relative_name in sorted(files):
        relative = PurePosixPath(relative_name)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ToolingError(f"unsafe generated member path: {relative_name!r}")
        parent = relative.parent
        current = output
        for part in parent.parts:
            current = current / part
            logical = PurePosixPath(*current.relative_to(output).parts)
            if logical not in created_directories:
                os.mkdir(current, 0o700)
                created_directories.add(logical)
        destination = output.joinpath(*relative.parts)
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o700 if relative_name in executable_files else 0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(files[relative_name])
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
    if os.name != "nt":
        directory_descriptor = os.open(output, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ToolingError(f"JSON contains duplicate object key {key!r}")
        result[key] = value
    return result


def safe_repo_member(repo_root: Path, relative_name: str) -> tuple[Path, bytes]:
    """Read one bounded, stable, non-linked repository file."""
    if not isinstance(relative_name, str) or "\\" in relative_name or "\x00" in relative_name:
        raise ToolingError("repository member must be a safe POSIX path")
    relative = PurePosixPath(relative_name)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ToolingError(f"unsafe repository member path: {relative_name!r}")

    root = repo_root.resolve(strict=True)
    candidate = root.joinpath(*relative.parts)
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            raise ToolingError(f"required repository member is missing: {relative_name}") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise ToolingError(f"repository member traverses a symlink: {relative_name}")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise ToolingError(f"repository member parent is not a directory: {relative_name}")
    metadata = candidate.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ToolingError(f"repository member is not a regular file: {relative_name}")
    if metadata.st_size <= 0 or metadata.st_size > MAX_JSON_BYTES:
        raise ToolingError(f"repository member is empty or oversized: {relative_name}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(candidate, flags)
    try:
        before = os.fstat(descriptor)
        raw = b""
        while len(raw) <= MAX_JSON_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_JSON_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if len(raw) != before.st_size or identity(before) != identity(after):
        raise ToolingError(f"repository member changed while being read: {relative_name}")
    return candidate, raw


def load_repo_json(repo_root: Path, relative_name: str) -> tuple[dict[str, Any], bytes]:
    _, raw = safe_repo_member(repo_root, relative_name)
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ToolingError(f"invalid JSON in {relative_name}: {error}") from error
    if not isinstance(document, dict):
        raise ToolingError(f"{relative_name} must contain a JSON object")
    return document, raw


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_text_sha256(raw: bytes) -> str:
    """Hash checked-in text consistently across LF and CRLF worktrees."""
    return sha256(raw.replace(b"\r\n", b"\n"))
