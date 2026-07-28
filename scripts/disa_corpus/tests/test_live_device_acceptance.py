import datetime
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


REPO = pathlib.Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "live_device_acceptance",
    REPO / "scripts/run-live-device-acceptance.py",
)
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


class LiveDecisionOracleTests(unittest.TestCase):
    def setUp(self):
        self.target = {
            "name": "CISCO_IOS_XE",
            "slug": "cisco_ios_xe",
            "stig": "Cisco_IOS-XE_Router_NDM_STIG",
            "stig_release": "V3R7",
        }
        self.curated = {"V-1", "V-2"}
        self.baseline_expected = {"V-1": "NotAFinding", "V-2": "NotAFinding"}
        self.negative_expected = {"V-1": "NotAFinding", "V-2": "Finding"}
        self.benchmark_sha = "1" * 64
        self.pack_sha = "2" * 64
        self.baseline_state_sha = "3" * 64
        self.negative_state_sha = "4" * 64
        self.hostname = "router-01"

    def write_oracle(self, root, scenario_updates=None, **updates):
        document = {
            "$schema": LIVE.ORACLE_SCHEMA_URI,
            "schema": LIVE.ORACLE_SCHEMA,
            "target": self.target["slug"],
            "stig_id": self.target["stig"],
            "stig_release": self.target["stig_release"],
            "benchmark_sha256": self.benchmark_sha,
            "check_pack_sha256": self.pack_sha,
            "adjudicated_at": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            "adjudicator": "independent-reviewer",
            "adjudication_basis": (
                "Manual DISA procedure review against an independently captured "
                "authorized device configuration."
            ),
            "independent_of_automatestig_output": True,
            "scenarios": [
                {
                    "id": "representative",
                    "kind": "baseline",
                    "asset_hostname": self.hostname,
                    "source_state_sha256": self.baseline_state_sha,
                    "expected_status_by_vuln": self.baseline_expected,
                },
                {
                    "id": "negative",
                    "kind": "negative_control",
                    "asset_hostname": self.hostname,
                    "source_state_sha256": self.negative_state_sha,
                    "expected_status_by_vuln": self.negative_expected,
                },
            ],
        }
        for index, values in (scenario_updates or {}).items():
            document["scenarios"][index].update(values)
        document.update(updates)
        path = root / "oracle.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path, document

    def load(self, path, kind="baseline", state_sha=None):
        return LIVE.load_decision_oracle(
            self.target,
            path,
            self.curated,
            self.benchmark_sha,
            self.pack_sha,
            kind,
            self.hostname,
            state_sha
            or (
                self.baseline_state_sha
                if kind == "baseline"
                else self.negative_state_sha
            ),
        )

    def test_oracle_binds_baseline_negative_decisions_and_exact_states(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, document = self.write_oracle(pathlib.Path(temporary))
            baseline, metadata = self.load(path)
            negative, negative_metadata = self.load(path, "negative_control")
        self.assertEqual(
            baseline,
            {"V-1": "notafinding", "V-2": "notafinding"},
        )
        self.assertEqual(negative["V-2"], "finding")
        self.assertEqual(metadata["oracle_scenario_id"], "representative")
        self.assertEqual(negative_metadata["oracle_scenario_id"], "negative")
        self.assertEqual(
            metadata["oracle_sha256"],
            hashlib.sha256(json.dumps(document).encode()).hexdigest(),
        )
        self.assertEqual(
            metadata["oracle_expected_status_sha256"],
            LIVE.canonical_status_sha256(
                {"representative": baseline, "negative": negative}
            ),
        )

    def test_oracle_rejects_missing_rule_wrong_state_and_automatestig_derived_claim(self):
        cases = (
            ({"scenario_updates": {0: {"expected_status_by_vuln": {"V-1": "NotAFinding"}}}}, None),
            ({"independent_of_automatestig_output": False}, None),
            ({}, "9" * 64),
        )
        for update, state_sha in cases:
            with self.subTest(update=update), tempfile.TemporaryDirectory() as temporary:
                path, _ = self.write_oracle(pathlib.Path(temporary), **update)
                with self.assertRaises(RuntimeError):
                    self.load(path, state_sha=state_sha)

    def test_oracle_rejects_schema_invalid_and_trivial_negative_scenarios(self):
        cases = (
            {"scenario_updates": {1: {"expected_status_by_vuln": {
                "V-1": "NotAFinding", "V-2": "Open"
            }}}},
            {"scenario_updates": {1: {"expected_status_by_vuln": self.baseline_expected}}},
            {"scenario_updates": {1: {"kind": "baseline"}}},
            {"scenario_updates": {1: {"id": "representative"}}},
            {"adjudicator": "x" * 201},
            {"adjudication_basis": "x" * 2001},
            {"scenario_updates": {0: {"asset_hostname": "x" * 256}}},
        )
        for update in cases:
            with self.subTest(update=update), tempfile.TemporaryDirectory() as temporary:
                path, _ = self.write_oracle(pathlib.Path(temporary), **update)
                with self.assertRaises(RuntimeError):
                    self.load(path)

    def test_checklist_must_match_oracle_statuses_exactly(self):
        checklist = {
            "findings": [
                {"rule_id": "R-1", "vuln_id": "V-1", "status": "NotAFinding"},
                {"rule_id": "R-2", "vuln_id": "V-2", "status": "Finding"},
                {"rule_id": "R-3", "vuln_id": "V-3", "status": "NotReviewed"},
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "checklist.json"
            path.write_text(json.dumps(checklist), encoding="utf-8")
            findings, automated, observed = LIVE.validate_checklist(
                path,
                {"R-1", "R-2", "R-3"},
                self.curated,
                {"V-1": "notafinding", "V-2": "finding"},
            )
            self.assertEqual((findings, automated), (3, 2))
            self.assertEqual(observed["V-2"], "finding")
            with self.assertRaisesRegex(RuntimeError, "independent oracle"):
                LIVE.validate_checklist(
                    path,
                    {"R-1", "R-2", "R-3"},
                    self.curated,
                    {"V-1": "notafinding", "V-2": "notafinding"},
                )

    def test_source_snapshot_is_bounded_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source.txt"
            snapshot = root / "snapshot.txt"
            source.write_bytes(b"fixed state")
            digest = LIVE.snapshot_regular_file(source, snapshot)
            self.assertEqual(snapshot.read_bytes(), b"fixed state")
            self.assertEqual(digest, hashlib.sha256(b"fixed state").hexdigest())
            if hasattr(source, "symlink_to"):
                link = root / "source-link.txt"
                try:
                    link.symlink_to(source)
                except OSError:
                    return
                with self.assertRaises(RuntimeError):
                    LIVE.snapshot_regular_file(link, root / "link-snapshot.txt")


if __name__ == "__main__":
    unittest.main()
