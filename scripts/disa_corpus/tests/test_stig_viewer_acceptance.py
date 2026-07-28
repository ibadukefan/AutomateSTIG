import importlib.util
import json
import os
import pathlib
import shutil
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts/run-stig-viewer-acceptance.py"
SPEC = importlib.util.spec_from_file_location("stig_viewer_acceptance", SCRIPT)
assert SPEC and SPEC.loader
VIEWER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VIEWER)


class StigViewerAcceptanceTests(unittest.TestCase):
    def test_attestation_metadata_rejects_obvious_placeholders(self):
        rejected = {
            "product_version": ["fabricated", "unknown", "<exact version>"],
            "platform": ["test", "Example Linux 9", "Linux"],
            "operator": ["tester", "Jane Placeholder", "${{ inputs.operator }}"],
        }
        for name, values in rejected.items():
            for value in values:
                with self.subTest(name=name, value=value), self.assertRaises(SystemExit):
                    VIEWER.validate_attestation_metadata(name, value)

        self.assertEqual(
            VIEWER.validate_attestation_metadata("product_version", "  STIG Viewer 3.5  "),
            "STIG Viewer 3.5",
        )
        self.assertEqual(
            VIEWER.validate_attestation_metadata("platform", "Windows 11 x86-64"),
            "Windows 11 x86-64",
        )
        self.assertEqual(
            VIEWER.validate_attestation_metadata("operator", "Jane Doe"),
            "Jane Doe",
        )

    def test_sanitized_sources_exercise_first_parse_fields(self):
        ckl = VIEWER.ckl_raw_projection(
            REPO_ROOT / "fixtures/ckl/windows_server_2022_sanitized.ckl"
        )
        cklb = VIEWER.cklb_raw_projection(
            REPO_ROOT / "fixtures/cklb/windows_server_2022_sanitized.cklb"
        )

        VIEWER.require_non_default_exercise("ckl", ckl)
        VIEWER.require_non_default_exercise("cklb", cklb)
        for document in (ckl, cklb):
            finding = document["findings"][0]
            self.assertEqual(finding["cci_refs"], ["CCI-000068", "CCI-001084"])
            self.assertEqual(
                finding["legacy_ids"],
                ["WN22-00-000001", "WN22-TLS-000001"],
            )

    def test_raw_readers_reject_more_than_one_stig(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            ckl_source = (
                REPO_ROOT / "fixtures/ckl/windows_server_2022_sanitized.ckl"
            ).read_text(encoding="utf-8")
            ckl_path = root / "multi.ckl"
            ckl_path.write_text(
                ckl_source.replace("</STIGS>", "<iSTIG></iSTIG></STIGS>"),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                VIEWER.ckl_raw_projection(ckl_path)

            cklb_source = json.loads(
                (
                    REPO_ROOT / "fixtures/cklb/windows_server_2022_sanitized.cklb"
                ).read_text(encoding="utf-8")
            )
            cklb_source["stigs"].append(cklb_source["stigs"][0])
            cklb_path = root / "multi.cklb"
            cklb_path.write_text(json.dumps(cklb_source), encoding="utf-8")
            with self.assertRaises(SystemExit):
                VIEWER.cklb_raw_projection(cklb_path)

    def test_run_case_detects_loss_during_automatestig_first_parse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = REPO_ROOT / "fixtures/ckl/windows_server_2022_sanitized.ckl"
            roundtrip = root / "roundtrip.ckl"
            roundtrip.write_bytes(source.read_bytes() + b"\n")
            normalized = VIEWER.ckl_raw_projection(source)
            normalized["asset"]["technology_area"] = None

            fake_binary = root / "fake-automatestig"
            fake_binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])\n"
                "output.write_text(os.environ['AUTOMATESTIG_FAKE_JSON'])\n",
                encoding="utf-8",
            )
            fake_binary.chmod(0o700)
            old = os.environ.get("AUTOMATESTIG_FAKE_JSON")
            os.environ["AUTOMATESTIG_FAKE_JSON"] = json.dumps(normalized)
            try:
                with self.assertRaises(SystemExit):
                    VIEWER.run_case(fake_binary, "ckl", source, roundtrip, root)
            finally:
                if old is None:
                    os.environ.pop("AUTOMATESTIG_FAKE_JSON", None)
                else:
                    os.environ["AUTOMATESTIG_FAKE_JSON"] = old

    def test_run_case_rejects_byte_identical_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = REPO_ROOT / "fixtures/ckl/windows_server_2022_sanitized.ckl"
            roundtrip = root / "copied.ckl"
            shutil.copyfile(source, roundtrip)

            with self.assertRaises(SystemExit):
                VIEWER.run_case(root / "unused-binary", "ckl", source, roundtrip, root)


if __name__ == "__main__":
    unittest.main()
