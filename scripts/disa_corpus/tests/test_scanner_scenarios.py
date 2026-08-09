import subprocess
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]


class ScannerScenarioTests(unittest.TestCase):
    def test_synthetic_scanner_matrix_is_self_consistent(self):
        result = subprocess.run(
            [sys.executable, "scripts/validate-scanner-scenarios.py"],
            cwd=REPO,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("validated 9 scanner scenarios", result.stdout)
        self.assertIn("synthetic secret scan passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
