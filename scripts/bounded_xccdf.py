#!/usr/bin/env python3
"""Fail-closed, resource-bounded access to XCCDF members in ZIP archives.

ZIP metadata is attacker-controlled.  This module therefore preflights the
whole archive and decompresses selected members itself so a forged
``ZipInfo.file_size`` cannot make ``zipfile.ZipExtFile`` silently truncate the
security boundary.  The limits intentionally match ``parsers::disa``.
"""
from __future__ import annotations

import binascii
import os
import stat
import struct
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

MAX_COMPRESSED_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 256
MAX_SELECTED_MEMBER_BYTES = 16 * 1024 * 1024
MAX_SELECTED_TOTAL_BYTES = 64 * 1024 * 1024
MAX_DECLARED_TOTAL_BYTES = 256 * 1024 * 1024
MAX_NAME_BYTES = 1024
MAX_PATH_COMPONENTS = 16
MAX_COMPRESSION_RATIO = 100
COMPRESSION_RATIO_GRACE_BYTES = 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024

ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


class BoundedXccdfError(ValueError):
    """The archive is malformed, ambiguous, or exceeds its resource policy."""


@dataclass(frozen=True)
class _Member:
    info: zipfile.ZipInfo
    data_start: int


def is_zipfile(path: str | os.PathLike[str]) -> bool:
    """Return whether *path* has a ZIP end record, without extracting it."""
    return zipfile.is_zipfile(path)


def read_bounded_file(
    path: str | os.PathLike[str], limit: int = MAX_SELECTED_MEMBER_BYTES
) -> bytes:
    """Read a direct XML/XCCDF file with an N+1 byte limit probe."""
    source = Path(path)
    size = source.stat().st_size
    if size > limit:
        raise BoundedXccdfError(
            f"XCCDF input is {size} bytes, exceeding {limit}-byte limit"
        )
    data = bytearray()
    with source.open("rb") as handle:
        while len(data) <= limit:
            chunk = handle.read(min(READ_CHUNK_BYTES, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    if len(data) > limit:
        raise BoundedXccdfError(f"XCCDF input exceeds {limit}-byte limit")
    return bytes(data)


class BoundedXccdfArchive:
    """A preflighted ZIP with bounded reads for selected XCCDF members."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        compressed_size = self.path.stat().st_size
        if compressed_size > MAX_COMPRESSED_BYTES:
            raise BoundedXccdfError(
                f"archive is {compressed_size} bytes, exceeding compressed-size "
                f"limit of {MAX_COMPRESSED_BYTES} bytes"
            )

        declared_count = _central_directory_entry_count(self.path, compressed_size)
        if declared_count is not None and declared_count > MAX_ENTRIES:
            raise BoundedXccdfError(
                f"archive declares {declared_count} entries, exceeding limit of "
                f"{MAX_ENTRIES}"
            )

        try:
            self._zip = zipfile.ZipFile(self.path)
        except (OSError, zipfile.BadZipFile, LargeZipFile) as error:
            raise BoundedXccdfError(f"invalid ZIP archive: {error}") from error

        self._members: dict[str, _Member] = {}
        self._names: tuple[str, ...] = ()
        self._selected_actual = 0
        try:
            self._preflight(declared_count, compressed_size)
        except Exception:
            self._zip.close()
            raise

    def __enter__(self) -> "BoundedXccdfArchive":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def close(self) -> None:
        self._zip.close()

    @property
    def names(self) -> tuple[str, ...]:
        """Canonical member names in central-directory order."""
        return self._names

    @property
    def selected_actual_bytes(self) -> int:
        return self._selected_actual

    def is_directory(self, name: str) -> bool:
        member = self._members.get(name)
        if member is None:
            raise BoundedXccdfError(f"archive member not found: {name}")
        return member.info.is_dir()

    def read_member(self, name: str) -> bytes:
        """Read one selected member under member and aggregate N+1 limits."""
        member = self._members.get(name)
        if member is None:
            raise BoundedXccdfError(f"archive member not found: {name}")
        info = member.info
        if info.is_dir():
            raise BoundedXccdfError(f"cannot read directory archive member: {name}")
        if info.file_size > MAX_SELECTED_MEMBER_BYTES:
            raise BoundedXccdfError(
                f"declared size of selected member {name!r} is {info.file_size} "
                f"bytes, exceeding {MAX_SELECTED_MEMBER_BYTES}-byte limit"
            )

        aggregate_remaining = MAX_SELECTED_TOTAL_BYTES - self._selected_actual
        effective_limit = min(MAX_SELECTED_MEMBER_BYTES, aggregate_remaining)
        probe_limit = effective_limit + 1
        data = self._decompress(member, probe_limit)
        if len(data) > effective_limit:
            if aggregate_remaining <= MAX_SELECTED_MEMBER_BYTES:
                raise BoundedXccdfError(
                    f"selected XCCDF data exceeds aggregate limit of "
                    f"{MAX_SELECTED_TOTAL_BYTES} bytes while reading {name!r}"
                )
            raise BoundedXccdfError(
                f"actual decompressed size of selected member {name!r} exceeds "
                f"{MAX_SELECTED_MEMBER_BYTES}-byte limit"
            )

        actual_crc = binascii.crc32(data) & 0xFFFFFFFF
        if actual_crc != info.CRC:
            raise BoundedXccdfError(
                f"CRC mismatch for archive member {name!r}: expected "
                f"{info.CRC:08x}, got {actual_crc:08x}"
            )
        self._selected_actual += len(data)
        return data

    def _preflight(self, declared_count: int | None, compressed_size: int) -> None:
        infos = self._zip.infolist()
        if declared_count is not None and declared_count != len(infos):
            raise BoundedXccdfError(
                f"central directory declares {declared_count} entries but exposes "
                f"{len(infos)}"
            )
        if len(infos) > MAX_ENTRIES:
            raise BoundedXccdfError(
                f"archive contains {len(infos)} entries, exceeding limit of "
                f"{MAX_ENTRIES}"
            )

        exact_names: set[str] = set()
        normalized_names: dict[str, str] = {}
        declared_total = 0
        regions: list[tuple[int, int, str]] = []
        members: dict[str, _Member] = {}

        with self.path.open("rb") as raw_archive:
            for index, info in enumerate(infos):
                name = _validate_central_name(info, index)
                canonical, normalized = _canonical_name(name)
                if canonical in exact_names:
                    raise BoundedXccdfError(
                        f"duplicate archive member name: {canonical!r}"
                    )
                exact_names.add(canonical)
                if normalized in normalized_names:
                    raise BoundedXccdfError(
                        "archive member names collide after normalization: "
                        f"{normalized_names[normalized]!r} and {canonical!r}"
                    )
                normalized_names[normalized] = canonical

                if info.flag_bits & 0x1:
                    raise BoundedXccdfError(
                        f"encrypted archive member is not allowed: {canonical!r}"
                    )
                _validate_member_type(info, canonical)
                if info.compress_type not in ALLOWED_COMPRESSION:
                    raise BoundedXccdfError(
                        f"unsupported compression method {info.compress_type} for "
                        f"archive member {canonical!r}"
                    )
                if info.file_size < 0 or info.compress_size < 0:
                    raise BoundedXccdfError(
                        f"negative ZIP size for archive member {canonical!r}"
                    )

                declared_total += info.file_size
                if declared_total > MAX_DECLARED_TOTAL_BYTES:
                    raise BoundedXccdfError(
                        "declared archive size exceeds aggregate limit of "
                        f"{MAX_DECLARED_TOTAL_BYTES} bytes"
                    )
                if info.file_size > COMPRESSION_RATIO_GRACE_BYTES:
                    allowed = info.compress_size * MAX_COMPRESSION_RATIO
                    if info.file_size > allowed:
                        raise BoundedXccdfError(
                            f"declared compression ratio for {canonical!r} exceeds "
                            f"{MAX_COMPRESSION_RATIO}:1"
                        )

                data_start = _validate_local_header(raw_archive, info, canonical)
                region_end = data_start + info.compress_size
                if region_end < data_start or region_end > compressed_size:
                    raise BoundedXccdfError(
                        f"archive member data range is invalid: {canonical!r}"
                    )
                start_dir = getattr(self._zip, "start_dir", compressed_size)
                if region_end > start_dir:
                    raise BoundedXccdfError(
                        f"archive member overlaps the central directory: {canonical!r}"
                    )
                regions.append((info.header_offset, region_end, canonical))
                members[canonical] = _Member(info=info, data_start=data_start)

        regions.sort(key=lambda item: item[0])
        for left, right in zip(regions, regions[1:]):
            if left[0] < left[1] and right[0] < left[1]:
                raise BoundedXccdfError(
                    f"archive members overlap: {left[2]!r} and {right[2]!r}"
                )

        self._members = members
        self._names = tuple(info.filename for info in infos)

    def _decompress(self, member: _Member, probe_limit: int) -> bytes:
        info = member.info
        data = bytearray()
        with self.path.open("rb") as raw_archive:
            raw_archive.seek(member.data_start)
            compressed_remaining = info.compress_size
            if info.compress_type == zipfile.ZIP_STORED:
                while compressed_remaining and len(data) < probe_limit:
                    requested = min(
                        READ_CHUNK_BYTES,
                        compressed_remaining,
                        probe_limit - len(data),
                    )
                    chunk = raw_archive.read(requested)
                    if len(chunk) != requested:
                        raise BoundedXccdfError(
                            f"truncated stored archive member: {info.filename!r}"
                        )
                    data.extend(chunk)
                    compressed_remaining -= len(chunk)
                if compressed_remaining:
                    return bytes(data)
                return bytes(data)

            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            while compressed_remaining:
                requested = min(READ_CHUNK_BYTES, compressed_remaining)
                chunk = raw_archive.read(requested)
                if len(chunk) != requested:
                    raise BoundedXccdfError(
                        f"truncated deflate stream for {info.filename!r}"
                    )
                compressed_remaining -= len(chunk)
                pending = chunk
                while pending:
                    remaining_output = probe_limit - len(data)
                    if remaining_output <= 0:
                        return bytes(data)
                    before = len(pending)
                    try:
                        output = decompressor.decompress(pending, remaining_output)
                    except zlib.error as error:
                        raise BoundedXccdfError(
                            f"invalid deflate stream for {info.filename!r}: {error}"
                        ) from error
                    data.extend(output)
                    pending = decompressor.unconsumed_tail
                    if len(data) >= probe_limit:
                        return bytes(data)
                    if decompressor.unused_data:
                        raise BoundedXccdfError(
                            f"deflate stream for {info.filename!r} ends before its "
                            "declared compressed size"
                        )
                    if pending and not output and len(pending) == before:
                        raise BoundedXccdfError(
                            f"deflate stream made no progress for {info.filename!r}"
                        )

            if not decompressor.eof:
                raise BoundedXccdfError(
                    f"truncated deflate stream for {info.filename!r}"
                )
            remaining_output = probe_limit - len(data)
            if remaining_output > 0:
                try:
                    data.extend(decompressor.flush(remaining_output))
                except zlib.error as error:
                    raise BoundedXccdfError(
                        f"invalid deflate stream for {info.filename!r}: {error}"
                    ) from error
            return bytes(data)


def _validate_central_name(info: zipfile.ZipInfo, index: int) -> str:
    name = info.filename
    if not (info.flag_bits & 0x800) and not name.isascii():
        raise BoundedXccdfError(
            f"archive member {index} has a non-UTF-8 legacy name"
        )
    try:
        name_bytes = name.encode("utf-8", "strict")
    except UnicodeError as error:
        raise BoundedXccdfError(
            f"archive member {index} has an invalid UTF-8 name"
        ) from error
    if len(name_bytes) > MAX_NAME_BYTES:
        raise BoundedXccdfError(
            f"archive member name exceeds {MAX_NAME_BYTES} bytes: {name!r}"
        )
    return name


def _canonical_name(name: str) -> tuple[str, str]:
    if not name or "\x00" in name or "\\" in name:
        raise BoundedXccdfError(f"unsafe archive member path: {name!r}")
    if name.startswith("/") or (
        len(name) >= 2 and name[0].isalpha() and name[1] == ":"
    ):
        raise BoundedXccdfError(f"absolute archive member path: {name!r}")
    is_directory = name.endswith("/")
    core = name[:-1] if is_directory else name
    parts = core.split("/")
    if (
        not core
        or any(part in {"", ".", ".."} for part in parts)
        or len(parts) > MAX_PATH_COMPONENTS
    ):
        raise BoundedXccdfError(f"non-canonical archive member path: {name!r}")
    canonical = "/".join(parts) + ("/" if is_directory else "")
    if canonical != name:
        raise BoundedXccdfError(f"non-canonical archive member path: {name!r}")
    normalized = unicodedata.normalize("NFC", "/".join(parts)).casefold()
    return canonical, normalized


def _validate_member_type(info: zipfile.ZipInfo, name: str) -> None:
    mode = info.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    if stat.S_ISLNK(mode):
        raise BoundedXccdfError(
            f"symbolic-link archive member is not allowed: {name!r}"
        )
    if info.is_dir():
        if file_type not in {0, stat.S_IFDIR}:
            raise BoundedXccdfError(
                f"special-file archive member is not allowed: {name!r}"
            )
    elif file_type not in {0, stat.S_IFREG}:
        raise BoundedXccdfError(
            f"special-file archive member is not allowed: {name!r}"
        )


def _validate_local_header(raw_archive, info: zipfile.ZipInfo, name: str) -> int:
    raw_archive.seek(info.header_offset)
    fixed = raw_archive.read(30)
    if len(fixed) != 30:
        raise BoundedXccdfError(f"truncated local header for {name!r}")
    fields = struct.unpack("<4s5H3L2H", fixed)
    if fields[0] != b"PK\x03\x04":
        raise BoundedXccdfError(f"invalid local header for {name!r}")
    local_flags = fields[2]
    local_method = fields[3]
    local_crc = fields[6]
    local_compressed = fields[7]
    local_uncompressed = fields[8]
    name_length = fields[9]
    extra_length = fields[10]
    raw_name = raw_archive.read(name_length)
    if len(raw_name) != name_length:
        raise BoundedXccdfError(f"truncated local filename for {name!r}")
    try:
        if local_flags & 0x800:
            local_name = raw_name.decode("utf-8", "strict")
        else:
            local_name = raw_name.decode("ascii", "strict")
    except UnicodeError as error:
        raise BoundedXccdfError(
            f"local filename is not strict UTF-8/ASCII for {name!r}"
        ) from error
    if local_name != name:
        raise BoundedXccdfError(
            f"local/central filename mismatch: {local_name!r} and {name!r}"
        )
    if local_flags != info.flag_bits or local_method != info.compress_type:
        raise BoundedXccdfError(f"local/central header mismatch for {name!r}")
    if not (local_flags & 0x8):
        if local_crc != info.CRC:
            raise BoundedXccdfError(f"local/central CRC mismatch for {name!r}")
        if local_compressed != 0xFFFFFFFF and info.compress_size <= 0xFFFFFFFF:
            if local_compressed != info.compress_size:
                raise BoundedXccdfError(
                    f"local/central compressed-size mismatch for {name!r}"
                )
        if local_uncompressed != 0xFFFFFFFF and info.file_size <= 0xFFFFFFFF:
            if local_uncompressed != info.file_size:
                raise BoundedXccdfError(
                    f"local/central uncompressed-size mismatch for {name!r}"
                )
    return info.header_offset + 30 + name_length + extra_length


def _central_directory_entry_count(path: Path, archive_size: int) -> int | None:
    if archive_size < 22:
        return None
    tail_size = min(archive_size, 22 + 0xFFFF)
    with path.open("rb") as handle:
        handle.seek(archive_size - tail_size)
        tail = handle.read(tail_size)
        relative = None
        for offset in range(len(tail) - 22, -1, -1):
            if tail[offset : offset + 4] != b"PK\x05\x06":
                continue
            comment_length = struct.unpack_from("<H", tail, offset + 20)[0]
            if offset + 22 + comment_length == len(tail):
                relative = offset
                break
        if relative is None:
            return None
        count = struct.unpack_from("<H", tail, relative + 10)[0]
        if count != 0xFFFF:
            return count

        eocd_offset = archive_size - tail_size + relative
        if eocd_offset < 20:
            return None
        handle.seek(eocd_offset - 20)
        locator = handle.read(20)
        if len(locator) != 20 or locator[:4] != b"PK\x06\x07":
            return None
        zip64_eocd_offset = struct.unpack_from("<Q", locator, 8)[0]
        handle.seek(zip64_eocd_offset)
        record = handle.read(56)
        if len(record) != 56 or record[:4] != b"PK\x06\x06":
            return None
        return struct.unpack_from("<Q", record, 32)[0]


# Python exposes this as zipfile.LargeZipFile; keep the except tuple readable.
LargeZipFile = zipfile.LargeZipFile
