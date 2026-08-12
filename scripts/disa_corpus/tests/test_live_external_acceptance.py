import importlib.util
import json
import os
import pathlib
import subprocess
import unittest
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts/run-live-external-acceptance.py"
SPEC = importlib.util.spec_from_file_location("live_external_acceptance", SCRIPT)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


class LiveExternalAcceptanceTests(unittest.TestCase):
    def test_legacy_passed_boolean_evidence_is_never_trusted(self):
        with mock.patch.dict(
            os.environ,
            {"STIG_VIEWER_ACCEPTANCE_EVIDENCE": "/tmp/self-authored.json"},
            clear=True,
        ):
            with self.assertRaises(SystemExit):
                LIVE.check_stig_viewer(REPO_ROOT, require=False)

    def test_no_configuration_skips_only_when_live_is_optional(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(LIVE.check_stig_viewer(REPO_ROOT, require=False))
            with self.assertRaises(SystemExit):
                LIVE.check_stig_viewer(REPO_ROOT, require=True)

    def test_combined_gate_executes_hardened_verifier(self):
        environment = {
            variable: f"configured-{argument}"
            for argument, variable in LIVE.VIEWER_CONFIGURATION.items()
        }

        def completed(command, **_kwargs):
            output = pathlib.Path(command[command.index("--output") + 1])
            output.write_text(
                json.dumps(
                    {
                        "passed": True,
                        "cases": [
                            {"format": "ckl", "status": "passed"},
                            {"format": "cklb", "status": "passed"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, "PASS", "")

        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            LIVE.subprocess, "run", side_effect=completed
        ) as run:
            self.assertTrue(LIVE.check_stig_viewer(REPO_ROOT, require=True))
        command = run.call_args.args[0]
        self.assertEqual(
            pathlib.Path(command[1]),
            REPO_ROOT / "scripts/run-stig-viewer-acceptance.py",
        )
        self.assertIn("--ckl-source", command)
        self.assertIn("--cklb-roundtrip", command)


if __name__ == "__main__":
    unittest.main()
