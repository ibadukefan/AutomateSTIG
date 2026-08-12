import hashlib
import importlib.util
import pathlib
import unittest


REPO = pathlib.Path(__file__).resolve().parents[3]


class GenerateScannerBenchmarksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = REPO / "scripts/generate-scanner-benchmarks.py"
        spec = importlib.util.spec_from_file_location(
            "generate_scanner_benchmarks", script
        )
        cls.generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.generator)

    def test_repository_text_hashes_are_stable_across_line_endings(self):
        lf = b'{\n  "target": "netapp_ontap9"\n}\n'
        crlf = lf.replace(b"\n", b"\r\n")

        self.assertNotEqual(
            hashlib.sha256(lf).hexdigest(), hashlib.sha256(crlf).hexdigest()
        )
        self.assertEqual(
            self.generator.canonical_text_sha256(lf),
            self.generator.canonical_text_sha256(crlf),
        )

    def test_repository_text_hashes_still_bind_content(self):
        original = b'{"target":"netapp_ontap9"}\n'
        changed = b'{"target":"freebsd_gpos"}\r\n'

        self.assertNotEqual(
            self.generator.canonical_text_sha256(original),
            self.generator.canonical_text_sha256(changed),
        )


if __name__ == "__main__":
    unittest.main()
