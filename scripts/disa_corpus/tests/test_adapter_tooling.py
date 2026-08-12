import importlib.util
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
SCRIPTS = REPO / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import adapter_tooling as TOOLING


def load_module(name: str, filename: str):
    specification = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


SCAFFOLDER = load_module("scaffold_target_adapter", "scaffold-target-adapter.py")
SCORECARDS = load_module("generate_target_scorecards", "generate-target-scorecards.py")
CONTRACTS = load_module("validate_adapter_contract", "validate-adapter-contract.py")


class AdapterScaffolderTests(unittest.TestCase):
    def _run(self, output: Path, *, target_key: str = "example_appliance"):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "scaffold-target-adapter.py"),
                "--target-key",
                target_key,
                "--display-name",
                "Example Appliance",
                "--stig-id",
                "Example_Appliance_STIG",
                "--stig-release",
                "V1R1",
                "--transport",
                "ssh_cli",
                "--output-dir",
                str(output),
            ],
            cwd=REPO,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_scaffold_is_schema_versioned_and_explicitly_unsupported(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "example_appliance"
            result = self._run(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = {
                "README.md",
                "adapter-contract.json",
                "compatibility-matrix.json",
                "coverage-inventory.json",
                "fixtures/README.md",
                "fixtures/errors/malformed-output.json",
                "fixtures/errors/permission-denied.json",
                "fixtures/errors/timeout.json",
                "fixtures/errors/truncated-output.json",
                "fixtures/errors/unsupported-version.json",
                "fixtures/rules/finding.json",
                "fixtures/rules/not-a-finding.json",
                "tests/README.md",
                "tests/contract-test.json",
                "tests/run-contract-test.py",
            }
            observed = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            }
            self.assertEqual(observed, expected)
            if os.name != "nt":
                self.assertEqual(
                    (output / "tests/run-contract-test.py").stat().st_mode & 0o777,
                    0o700,
                )

            for path in output.rglob("*.json"):
                document = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(document["schema_version"], 1, path)
                self.assertTrue(document["schema"].endswith("/v1"), path)
            contract = json.loads((output / "adapter-contract.json").read_text())
            self.assertEqual(contract["development_status"], "candidate")
            self.assertFalse(contract["release_registration"])
            self.assertEqual(contract["support_claim"], "none")
            self.assertEqual(contract["live_acceptance"]["status"], "not_run")
            coverage = json.loads((output / "coverage-inventory.json").read_text())
            self.assertFalse(coverage["live_acceptance_claim"])
            self.assertIsNone(coverage["denominators"]["technically_automatable_rules"])
            self.assertIn("does not register a supported target", (output / "README.md").read_text())

            with self.assertRaises(CONTRACTS.ContractNotReady):
                CONTRACTS.validate_contract(output)
            runner = output / "tests/run-contract-test.py"
            runner_command = [str(runner)] if os.name != "nt" else [sys.executable, str(runner)]
            contract_result = subprocess.run(
                runner_command + ["--repo-root", str(REPO)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(contract_result.returncode, 2)
            self.assertIn("not ready", contract_result.stderr)

    def test_completed_contract_fixtures_execute_and_errors_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "example_appliance"
            self.assertEqual(self._run(output).returncode, 0)
            artifacts = output / "fixtures/artifacts"
            artifacts.mkdir()
            expected = {
                "finding": ("complete", "finding", True),
                "not-a-finding": ("complete", "not_a_finding", True),
                "malformed-output": ("collection_error", None, False),
                "permission-denied": ("collection_error", None, False),
                "timeout": ("collection_error", None, False),
                "truncated-output": ("collection_error", None, False),
                "unsupported-version": ("collection_error", None, False),
            }
            manifest = json.loads((output / "tests/contract-test.json").read_text())
            fixture_by_case = {
                case["case_id"]: output / case["fixture"] for case in manifest["cases"]
            }
            for case_id, (status, outcome, handoff) in expected.items():
                artifact = artifacts / f"{case_id}.txt"
                artifact.write_text(f"redacted synthetic {case_id}\n", encoding="utf-8")
                fixture_path = fixture_by_case[case_id]
                fixture = json.loads(fixture_path.read_text())
                fixture["capture"] = {
                    "status": "complete",
                    "artifact_path": artifact.relative_to(output).as_posix(),
                    "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "redaction_manifest": [],
                }
                fixture["observed"] = {
                    "contract_status": status,
                    "evaluation_outcome": outcome,
                    "handoff_allowed": handoff,
                }
                fixture["expected"] = dict(fixture["observed"])
                fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

            result = CONTRACTS.validate_contract(output)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(len(result["passed_cases"]), 7)
            self.assertEqual(len(result["fail_closed_error_cases"]), 5)

            adapter_contract = output / "adapter-contract.json"
            original_contract = adapter_contract.read_bytes()
            adapter_contract.write_bytes(original_contract + b"\n")
            with self.assertRaises(CONTRACTS.ContractError):
                CONTRACTS.validate_contract(output)
            adapter_contract.write_bytes(original_contract)

            finding_artifact = artifacts / "finding.txt"
            original_artifact = finding_artifact.read_bytes()
            finding_artifact.write_bytes(original_artifact + b"tampered")
            with self.assertRaises(CONTRACTS.ContractError):
                CONTRACTS.validate_contract(output)
            finding_artifact.write_bytes(original_artifact)

            timeout_path = fixture_by_case["timeout"]
            timeout = json.loads(timeout_path.read_text())
            timeout["observed"] = {
                "contract_status": "complete",
                "evaluation_outcome": "not_a_finding",
                "handoff_allowed": True,
            }
            timeout_path.write_text(json.dumps(timeout), encoding="utf-8")
            with self.assertRaises(CONTRACTS.ContractError):
                CONTRACTS.validate_contract(output)

    def test_scaffold_is_byte_deterministic(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_output = Path(first) / "example_appliance"
            second_output = Path(second) / "example_appliance"
            self.assertEqual(self._run(first_output).returncode, 0)
            self.assertEqual(self._run(second_output).returncode, 0)
            first_files = {
                path.relative_to(first_output).as_posix(): path.read_bytes()
                for path in first_output.rglob("*")
                if path.is_file()
            }
            second_files = {
                path.relative_to(second_output).as_posix(): path.read_bytes()
                for path in second_output.rglob("*")
                if path.is_file()
            }
            self.assertEqual(first_files, second_files)

    def test_scaffold_refuses_existing_mismatched_and_unsafe_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "example_appliance"
            self.assertEqual(self._run(output).returncode, 0)
            original = (output / "README.md").read_bytes()
            repeated = self._run(output)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual((output / "README.md").read_bytes(), original)

            mismatched = self._run(root / "different_name")
            self.assertNotEqual(mismatched.returncode, 0)
            self.assertFalse((root / "different_name").exists())

            unsafe = self._run(root / "bad", target_key="../bad")
            self.assertNotEqual(unsafe.returncode, 0)
            self.assertFalse((root / "bad").exists())

            safe_parent = root / "safe"
            safe_parent.mkdir()
            traversal = self._run(
                Path(str(safe_parent / ".." / "example_appliance"))
            )
            self.assertNotEqual(traversal.returncode, 0)


class TargetScorecardTests(unittest.TestCase):
    def _run(self, output: Path):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "generate-target-scorecards.py"),
                "--repo-root",
                str(REPO),
                "--output-dir",
                str(output),
            ],
            cwd=REPO,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def _copy_scorecard_inputs(self, destination: Path) -> None:
        for relative in (
            "content/supported-targets.json",
            "content/check_packs",
            "content/coverage/current-checkpacks",
            "content/scanner_profiles",
        ):
            source = REPO / relative
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)

    def test_repository_scorecards_preserve_known_and_unknown_denominators(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scorecards"
            result = self._run(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            index = json.loads((output / "scorecards.index.json").read_text())
            self.assertEqual(
                [target["target_key"] for target in index["targets"]],
                ["cisco_ios_xe_router_ndm", "freebsd_gpos", "netapp_ontap9"],
            )
            for target in index["targets"]:
                self.assertFalse(target["support_claimed"])
                self.assertFalse(target["live_acceptance_claimed"])

            expected = {
                "netapp_ontap9": (29, 22, 15, 7, 7, 15, 0),
                "freebsd_gpos": (203, 30, 6, 24, 173, 1, 5),
                "cisco_ios_xe_router_ndm": (42, 42, 33, 9, 0, 17, 16),
            }
            for key, counts in expected.items():
                document = json.loads((output / f"{key}.scorecard.json").read_text())
                denominators = document["denominators"]
                observed = (
                    denominators["total_benchmark_rules"],
                    denominators["reviewed_profile_rules"],
                    denominators["implemented_automated_rules"],
                    denominators["manual_rules"],
                    denominators["outside_reviewed_profile_rules"],
                )
                self.assertEqual(observed, counts[:5])
                self.assertIsNone(denominators["technically_automatable_rules"])
                self.assertIsNone(denominators["collection_error_rules"])
                self.assertFalse(document["claims"]["support_claimed_by_generator"])
                self.assertFalse(document["claims"]["live_acceptance_claimed_by_generator"])
                self.assertFalse(document["claims"]["better_than_evaluate_stig_claimed"])
                self.assertEqual(document["claims"]["comparison_status"], "not_directly_comparable")
                self.assertFalse(document["acceptance_metadata"]["release_evidence_supplied"])
                automation = document["automation_implementation_metadata"]
                self.assertEqual(
                    automation["implementation_class_counts"]["legacy_declarative"],
                    counts[5],
                )
                self.assertEqual(
                    automation["implementation_class_counts"]["reviewed_imperative"],
                    counts[6],
                )
                ratio = automation["declarative_new_automation_ratio"]
                self.assertEqual(ratio["status"], "measured_metadata_only")
                self.assertEqual(ratio["numerator"], counts[5])
                self.assertEqual(ratio["denominator"], counts[2])
                self.assertAlmostEqual(ratio["ratio"], counts[5] / counts[2])
                declarative_gate = next(
                    gate
                    for gate in document["release_gates"]
                    if gate["gate"] == "declarative_checks"
                )
                self.assertEqual(declarative_gate["status"], "measured_metadata_only")
                self.assertEqual(declarative_gate["numerator"], counts[5])
                self.assertEqual(declarative_gate["denominator"], counts[2])

    def test_scorecard_preserves_unknown_automation_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repository"
            repo.mkdir()
            self._copy_scorecard_inputs(repo)
            pack_path = repo / "content/check_packs/netapp_ontap9.json"
            pack = json.loads(pack_path.read_text())
            pack["checks"][0].pop("implementation_class")
            pack["checks"][0].pop("introduction_release")
            pack_path.write_text(json.dumps(pack), encoding="utf-8")
            files = SCORECARDS.build_scorecard_bundle(repo)
            document = json.loads(files["netapp_ontap9.scorecard.json"])
            automation = document["automation_implementation_metadata"]
            self.assertEqual(automation["implementation_class_counts"]["unknown"], 1)
            self.assertEqual(
                automation["unknown_introduction_release_vuln_ids"], ["V-246922"]
            )
            ratio = automation["declarative_new_automation_ratio"]
            self.assertEqual(ratio["status"], "not_measurable")
            self.assertIsNone(ratio["denominator"])
            self.assertIsNone(ratio["ratio"])

    def test_scorecard_rejects_dishonest_implementation_class(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repository"
            repo.mkdir()
            self._copy_scorecard_inputs(repo)
            pack_path = repo / "content/check_packs/freebsd_gpos.json"
            pack = json.loads(pack_path.read_text())
            pack["checks"][0]["implementation_class"] = "declarative_predicate"
            pack_path.write_text(json.dumps(pack), encoding="utf-8")
            with self.assertRaises(TOOLING.ToolingError):
                SCORECARDS.build_scorecard_bundle(repo)

    def test_scorecards_are_byte_deterministic_and_create_new(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_output = Path(first) / "scorecards"
            second_output = Path(second) / "scorecards"
            self.assertEqual(self._run(first_output).returncode, 0)
            self.assertEqual(self._run(second_output).returncode, 0)
            first_files = {
                path.name: path.read_bytes() for path in first_output.iterdir() if path.is_file()
            }
            second_files = {
                path.name: path.read_bytes() for path in second_output.iterdir() if path.is_file()
            }
            self.assertEqual(first_files, second_files)
            repeated = self._run(first_output)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(
                {path.name: path.read_bytes() for path in first_output.iterdir() if path.is_file()},
                first_files,
            )

    def test_reported_release_gate_never_becomes_a_live_acceptance_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repository"
            repo.mkdir()
            self._copy_scorecard_inputs(repo)
            evidence_path = repo / "release-evidence/release-evidence.json"
            evidence_path.parent.mkdir()
            gate = {
                "status": "passed",
                "executed_at": "2026-08-11T00:00:00Z",
                "environment": "protected-lab",
                "version": "candidate-version",
                "evidence_reference": "release-evidence/artifacts/example/live-device-acceptance.json",
                "evidence_sha256": "a" * 64,
            }
            evidence_path.write_text(
                json.dumps(
                    {
                        "schema": "automatestig-release-evidence/v1",
                        "tag": "v0.3.0",
                        "acceptance": {
                            "ontap": gate,
                            "freebsd": gate,
                            "cisco_ios_xe": gate,
                        },
                    }
                ),
                encoding="utf-8",
            )
            files = SCORECARDS.build_scorecard_bundle(
                repo, "release-evidence/release-evidence.json"
            )
            document = json.loads(files["netapp_ontap9.scorecard.json"])
            acceptance = document["acceptance_metadata"]
            self.assertTrue(acceptance["release_evidence_supplied"])
            self.assertEqual(acceptance["reported_gate"]["status"], "passed")
            self.assertFalse(acceptance["generator_verified_live_acceptance"])
            self.assertFalse(document["claims"]["live_acceptance_claimed_by_generator"])
            collection_gate = next(
                gate
                for gate in document["release_gates"]
                if gate["gate"] == "collection_reliability"
            )
            self.assertEqual(
                collection_gate["status"], "human_evidence_referenced_not_verified"
            )

    def test_scorecards_are_stable_across_lf_and_crlf_checkouts(self):
        expected = SCORECARDS.build_scorecard_bundle(REPO)
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repository"
            repo.mkdir()
            self._copy_scorecard_inputs(repo)
            for path in repo.rglob("*.json"):
                raw = path.read_bytes()
                path.write_bytes(raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
            self.assertEqual(SCORECARDS.build_scorecard_bundle(repo), expected)

    def test_scorecard_rejects_bundled_benchmark_digest_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repository"
            repo.mkdir()
            self._copy_scorecard_inputs(repo)
            benchmark = repo / "content/scanner_profiles/netapp_ontap9.benchmark.json"
            benchmark.write_bytes(benchmark.read_bytes() + b"\n")
            with self.assertRaises(TOOLING.ToolingError):
                SCORECARDS.build_scorecard_bundle(repo)

    def test_scorecard_rejects_repository_path_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repository"
            repo.mkdir()
            self._copy_scorecard_inputs(repo)
            contract_path = repo / "content/supported-targets.json"
            contract = json.loads(contract_path.read_text())
            contract["targets"]["netapp_ontap9"]["coverage_manifest"] = "../outside.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaises(TOOLING.ToolingError):
                SCORECARDS.build_scorecard_bundle(repo)


if __name__ == "__main__":
    unittest.main()
