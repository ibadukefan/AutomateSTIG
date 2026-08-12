import contextlib
import importlib.util
import io
import stat
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import bounded_xccdf as bounded


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


extract_inventory = load_script(
    "bounded_extract_xccdf_inventory",
    SCRIPTS_ROOT / "disa_corpus/extract_xccdf_inventory.py",
)
external_workflows = load_script(
    "bounded_validate_external_workflows",
    SCRIPTS_ROOT / "validate-external-workflows.py",
)

XCCDF = b'''<Benchmark id="Example_STIG"><title>Example</title><Group id="V-1"><Rule id="SV-1" severity="medium"><version>EX-1</version><title>Rule</title></Rule></Group></Benchmark>'''


def write_zip(path, files, compression=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, contents in files:
            archive.writestr(name, contents)


def _find_named_header(data, signature, name, name_length_offset, name_offset):
    start = 0
    while True:
        offset = data.find(signature, start)
        if offset < 0:
            raise AssertionError(f"missing ZIP header for {name}")
        name_length = struct.unpack_from("<H", data, offset + name_length_offset)[0]
        raw_name = data[offset + name_offset : offset + name_offset + name_length]
        if raw_name == name.encode("ascii"):
            return offset
        start = offset + 4


def forge_uncompressed_size(path, name, size):
    data = bytearray(path.read_bytes())
    local = _find_named_header(data, b"PK\x03\x04", name, 26, 30)
    central = _find_named_header(data, b"PK\x01\x02", name, 28, 46)
    struct.pack_into("<L", data, local + 22, size)
    struct.pack_into("<L", data, central + 24, size)
    path.write_bytes(data)


def forge_encrypted_flag(path, name):
    data = bytearray(path.read_bytes())
    local = _find_named_header(data, b"PK\x03\x04", name, 26, 30)
    central = _find_named_header(data, b"PK\x01\x02", name, 28, 46)
    local_flags = struct.unpack_from("<H", data, local + 6)[0] | 1
    central_flags = struct.unpack_from("<H", data, central + 8)[0] | 1
    struct.pack_into("<H", data, local + 6, local_flags)
    struct.pack_into("<H", data, central + 8, central_flags)
    path.write_bytes(data)


class BoundedXccdfTests(unittest.TestCase):
    def test_policy_matches_rust_disa_limits(self):
        self.assertEqual(bounded.MAX_COMPRESSED_BYTES, 32 * 1024 * 1024)
        self.assertEqual(bounded.MAX_ENTRIES, 256)
        self.assertEqual(bounded.MAX_SELECTED_MEMBER_BYTES, 16 * 1024 * 1024)
        self.assertEqual(bounded.MAX_SELECTED_TOTAL_BYTES, 64 * 1024 * 1024)
        self.assertEqual(bounded.MAX_DECLARED_TOTAL_BYTES, 256 * 1024 * 1024)
        self.assertEqual(bounded.MAX_NAME_BYTES, 1024)
        self.assertEqual(bounded.MAX_PATH_COMPONENTS, 16)
        self.assertEqual(bounded.MAX_COMPRESSION_RATIO, 100)
        self.assertEqual(bounded.COMPRESSION_RATIO_GRACE_BYTES, 1024 * 1024)

    def test_reads_stored_and_deflated_members_and_preserves_selection_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                path = root / f"{compression}.zip"
                write_zip(
                    path,
                    [("notes.xml", XCCDF), ("main-XCCDF.xml", XCCDF)],
                    compression,
                )
                with bounded.BoundedXccdfArchive(path) as archive:
                    self.assertEqual(
                        archive.names, ("notes.xml", "main-XCCDF.xml")
                    )
                    self.assertEqual(archive.read_member("main-XCCDF.xml"), XCCDF)
            raw, selected = extract_inventory.read_xml(root / "8.zip")
            self.assertEqual(selected, "main-XCCDF.xml")
            self.assertEqual(raw, XCCDF)

    def test_compressed_size_and_entry_count_are_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "large.zip"
            write_zip(path, [("one.xml", XCCDF)])
            with mock.patch.object(
                bounded, "MAX_COMPRESSED_BYTES", path.stat().st_size - 1
            ):
                with self.assertRaises(bounded.BoundedXccdfError):
                    bounded.BoundedXccdfArchive(path)

            entries = root / "entries.zip"
            write_zip(entries, [(f"{index}.txt", b"") for index in range(257)])
            with self.assertRaisesRegex(bounded.BoundedXccdfError, "256"):
                bounded.BoundedXccdfArchive(entries)

    def test_direct_xml_uses_an_n_plus_one_limit_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "benchmark.xml"
            path.write_bytes(XCCDF)
            self.assertEqual(bounded.read_bounded_file(path), XCCDF)

            path.write_bytes(b"A" * 1025)
            with self.assertRaisesRegex(bounded.BoundedXccdfError, "1024-byte limit"):
                bounded.read_bounded_file(path, limit=1024)

    def test_unsafe_noncanonical_and_colliding_names_are_rejected(self):
        unsafe_names = [
            "../escape.xml",
            "/absolute.xml",
            "C:/drive.xml",
            "back\\slash.xml",
            "double//slash.xml",
            "dot/./name.xml",
            "/".join(["part"] * 17) + ".xml",
            "a" * 1025,
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, name in enumerate(unsafe_names):
                with self.subTest(name=name):
                    path = root / f"unsafe-{index}.zip"
                    write_zip(path, [(name, XCCDF)], zipfile.ZIP_STORED)
                    with self.assertRaises(bounded.BoundedXccdfError):
                        bounded.BoundedXccdfArchive(path)

            collision = root / "collision.zip"
            write_zip(
                collision,
                [("A/one.xml", XCCDF), ("a/ONE.xml", XCCDF)],
                zipfile.ZIP_STORED,
            )
            with self.assertRaisesRegex(bounded.BoundedXccdfError, "collide"):
                bounded.BoundedXccdfArchive(collision)

            duplicate = root / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                write_zip(
                    duplicate,
                    [("same.xml", XCCDF), ("same.xml", XCCDF)],
                    zipfile.ZIP_STORED,
                )
            with self.assertRaisesRegex(bounded.BoundedXccdfError, "duplicate"):
                bounded.BoundedXccdfArchive(duplicate)

    def test_encryption_links_special_files_and_methods_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            encrypted = root / "encrypted.zip"
            write_zip(encrypted, [("encrypted.xml", XCCDF)], zipfile.ZIP_STORED)
            forge_encrypted_flag(encrypted, "encrypted.xml")
            with self.assertRaisesRegex(bounded.BoundedXccdfError, "encrypted"):
                bounded.BoundedXccdfArchive(encrypted)

            for label, file_type in (
                ("symlink", stat.S_IFLNK),
                ("fifo", stat.S_IFIFO),
            ):
                path = root / f"{label}.zip"
                info = zipfile.ZipInfo(f"{label}.xml")
                info.create_system = 3
                info.external_attr = (file_type | 0o777) << 16
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(info, b"target")
                with self.assertRaises(bounded.BoundedXccdfError):
                    bounded.BoundedXccdfArchive(path)

            unsupported = root / "bzip2.zip"
            try:
                write_zip(
                    unsupported,
                    [("unsupported.xml", XCCDF)],
                    zipfile.ZIP_BZIP2,
                )
            except RuntimeError as error:
                self.skipTest(f"BZIP2 unavailable: {error}")
            with self.assertRaisesRegex(bounded.BoundedXccdfError, "compression"):
                bounded.BoundedXccdfArchive(unsupported)

    def test_declared_total_and_ratio_preflight_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            total = root / "total.zip"
            write_zip(
                total,
                [("one.xml", b"1" * 700), ("two.xml", b"2" * 700)],
                zipfile.ZIP_STORED,
            )
            with mock.patch.object(bounded, "MAX_DECLARED_TOTAL_BYTES", 1024):
                with self.assertRaisesRegex(bounded.BoundedXccdfError, "aggregate"):
                    bounded.BoundedXccdfArchive(total)

            ratio = root / "ratio.zip"
            write_zip(ratio, [("ratio.xml", b"A" * 4096)])
            with mock.patch.multiple(
                bounded,
                COMPRESSION_RATIO_GRACE_BYTES=0,
                MAX_COMPRESSION_RATIO=2,
            ):
                with self.assertRaisesRegex(bounded.BoundedXccdfError, "ratio"):
                    bounded.BoundedXccdfArchive(ratio)

    def test_forged_size_cannot_bypass_member_or_aggregate_runtime_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            forged = root / "forged.zip"
            write_zip(forged, [("forged.xml", b"A" * 1025)])
            forge_uncompressed_size(forged, "forged.xml", 1)
            with mock.patch.object(bounded, "MAX_SELECTED_MEMBER_BYTES", 1024):
                with bounded.BoundedXccdfArchive(forged) as archive:
                    with self.assertRaisesRegex(
                        bounded.BoundedXccdfError, "actual decompressed"
                    ):
                        archive.read_member("forged.xml")

            aggregate = root / "aggregate.zip"
            write_zip(
                aggregate,
                [("one.xml", b"1" * 700), ("two.xml", b"2" * 700)],
                zipfile.ZIP_STORED,
            )
            with mock.patch.object(bounded, "MAX_SELECTED_TOTAL_BYTES", 1024):
                with bounded.BoundedXccdfArchive(aggregate) as archive:
                    archive.read_member("one.xml")
                    with self.assertRaisesRegex(
                        bounded.BoundedXccdfError, "aggregate limit"
                    ):
                        archive.read_member("two.xml")

    def test_hostile_archive_is_rejected_by_both_consumers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bomb.zip"
            write_zip(path, [("bomb-xccdf.xml", b"A" * 1025)])
            forge_uncompressed_size(path, "bomb-xccdf.xml", 1)
            with mock.patch.object(bounded, "MAX_SELECTED_MEMBER_BYTES", 1024):
                with self.assertRaises(bounded.BoundedXccdfError):
                    extract_inventory.read_xml(path)
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        external_workflows.validate_disa_zip(path)


if __name__ == "__main__":
    unittest.main()
