import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


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
            "mode": "config",
        }
        self.curated = {"V-1", "V-2"}
        self.baseline_expected = {"V-1": "NotAFinding", "V-2": "NotAFinding"}
        self.negative_expected = {"V-1": "NotAFinding", "V-2": "Finding"}
        self.benchmark_sha = "1" * 64
        self.evaluated_benchmark_sha = "7" * 64
        self.pack_sha = "2" * 64
        self.baseline_state_sha = "3" * 64
        self.negative_state_sha = "4" * 64
        self.policy_sha = "5" * 64
        self.policy_signature_sha = "6" * 64
        self.policy_signer = f"SHA256:{'a' * 64}"
        self.hostname = "router-01"

    def write_oracle(self, root, scenario_updates=None, **updates):
        document = {
            "$schema": LIVE.ORACLE_SCHEMA_URI,
            "schema": LIVE.ORACLE_SCHEMA,
            "target": self.target["slug"],
            "stig_id": self.target["stig"],
            "stig_release": self.target["stig_release"],
            "benchmark_sha256": self.benchmark_sha,
            "evaluated_benchmark_sha256": self.evaluated_benchmark_sha,
            "check_pack_sha256": self.pack_sha,
            "organization_policy_sha256": self.policy_sha,
            "organization_policy_signature_sha256": self.policy_signature_sha,
            "organization_policy_signer_fingerprint": self.policy_signer,
            "ssh_server_key_fingerprint": None,
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

    def load(self, path, kind="baseline", state_sha=None, oracle_sha=None):
        return LIVE.load_decision_oracle(
            self.target,
            path,
            oracle_sha or hashlib.sha256(path.read_bytes()).hexdigest(),
            self.curated,
            self.benchmark_sha,
            self.evaluated_benchmark_sha,
            self.pack_sha,
            self.policy_sha,
            self.policy_signature_sha,
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
            metadata["oracle_pinned_sha256"],
            metadata["oracle_sha256"],
        )
        self.assertEqual(
            metadata["oracle_organization_policy_sha256"],
            self.policy_sha,
        )
        self.assertEqual(
            metadata["oracle_organization_policy_signature_sha256"],
            self.policy_signature_sha,
        )
        self.assertEqual(
            metadata["oracle_organization_policy_signer_fingerprint"],
            self.policy_signer,
        )
        self.assertEqual(
            metadata["oracle_expected_status_sha256"],
            LIVE.canonical_status_sha256(
                {"representative": baseline, "negative": negative}
            ),
        )

    def test_ssh_oracle_pins_the_exact_server_key(self):
        ssh_target = {
            "name": "ONTAP",
            "slug": "ontap",
            "stig": "NetApp_ONTAP_DSC_9-x_STIG",
            "stig_release": "V2R2",
            "mode": "ssh",
        }
        fingerprint = "SHA256:" + ("A" * 43)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, document = self.write_oracle(root)
            document.update(
                {
                    "target": ssh_target["slug"],
                    "stig_id": ssh_target["stig"],
                    "stig_release": ssh_target["stig_release"],
                    "organization_policy_sha256": None,
                    "organization_policy_signature_sha256": None,
                    "organization_policy_signer_fingerprint": None,
                    "ssh_server_key_fingerprint": fingerprint,
                }
            )
            path.write_text(json.dumps(document), encoding="utf-8")
            _, metadata = LIVE.load_decision_oracle(
                ssh_target,
                path,
                hashlib.sha256(path.read_bytes()).hexdigest(),
                self.curated,
                self.benchmark_sha,
                self.evaluated_benchmark_sha,
                self.pack_sha,
                None,
                None,
                "baseline",
                self.hostname,
                self.baseline_state_sha,
            )
            self.assertEqual(
                metadata["oracle_server_key_fingerprint"], fingerprint
            )
            document["ssh_server_key_fingerprint"] = (
                "SHA256:" + ("A" * 42) + "B"
            )
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "server-key fingerprint"):
                LIVE.load_decision_oracle(
                    ssh_target,
                    path,
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    self.curated,
                    self.benchmark_sha,
                    self.evaluated_benchmark_sha,
                    self.pack_sha,
                    None,
                    None,
                    "baseline",
                    self.hostname,
                    self.baseline_state_sha,
                )
            document["ssh_server_key_fingerprint"] = None
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "server-key fingerprint"):
                LIVE.load_decision_oracle(
                    ssh_target,
                    path,
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    self.curated,
                    self.benchmark_sha,
                    self.evaluated_benchmark_sha,
                    self.pack_sha,
                    None,
                    None,
                    "baseline",
                    self.hostname,
                    self.baseline_state_sha,
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

    def test_oracle_rejects_a_digest_that_was_not_precommitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.write_oracle(pathlib.Path(temporary))
            with self.assertRaisesRegex(RuntimeError, "protected precommitted"):
                self.load(path, oracle_sha="9" * 64)

    def test_oracle_rejects_duplicate_json_members_at_every_depth(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, _ = self.write_oracle(root)
            raw = path.read_text(encoding="utf-8")
            for duplicate in (
                raw.replace(
                    '"target": "cisco_ios_xe",',
                    '"target": "cisco_ios_xe", "target": "ontap",',
                    1,
                ),
                raw.replace(
                    '"V-1": "NotAFinding",',
                    '"V-1": "NotAFinding", "V-1": "Finding",',
                    1,
                ),
            ):
                path.write_text(duplicate, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "duplicate JSON member"):
                    self.load(path)

    def test_oracle_rejects_missing_or_substituted_organization_policy(self):
        cases = (
            {"organization_policy_sha256": "9" * 64},
            {"organization_policy_sha256": None},
            {"organization_policy_signature_sha256": "9" * 64},
            {"organization_policy_signer_fingerprint": "SHA256:bad"},
        )
        for update in cases:
            with self.subTest(update=update), tempfile.TemporaryDirectory() as temporary:
                path, _ = self.write_oracle(pathlib.Path(temporary), **update)
                with self.assertRaises(RuntimeError):
                    self.load(path)
        with tempfile.TemporaryDirectory() as temporary:
            path, document = self.write_oracle(pathlib.Path(temporary))
            document.pop("organization_policy_sha256")
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "closed schema"):
                self.load(path)

    def test_effective_check_pack_digest_matches_runtime_serde_defaults(self):
        source_pack = {
            "stig_id": "Example_STIG",
            "platform": "ontap",
            "version": "V1R1",
            "checks": [
                {
                    "vuln_id": "V-1",
                    "platform": "ontap",
                    "check": {"type": "command", "command": "version"},
                    "expected": {"type": "is_true"},
                }
            ],
        }
        effective_pack = json.loads(json.dumps(source_pack))
        effective_pack["priority"] = 0
        effective_pack["checks"][0]["description"] = None
        effective_pack["checks"][0]["check"].update(
            {"pattern": None, "is_regex": False}
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "pack.json").write_text(
                json.dumps(source_pack, indent=4), encoding="utf-8"
            )
            vulns, digest = LIVE.load_curated_vulns(
                root,
                {
                    "stig": "Example_STIG",
                    "check_pack": "pack.json",
                },
            )
        self.assertEqual(vulns, {"V-1"})
        self.assertEqual(digest, LIVE.canonical_json_sha256([effective_pack]))
        self.assertNotEqual(
            digest,
            hashlib.sha256(json.dumps(source_pack, indent=4).encode()).hexdigest(),
        )

    def test_checklist_must_match_oracle_statuses_exactly(self):
        input_sha = "6" * 64
        benchmark_sha = "5" * 64
        check_pack_sha = "7" * 64
        evaluation_plan_sha = "8" * 64
        checklist = {
            "findings": [
                {"rule_id": "R-1", "vuln_id": "V-1", "status": "NotAFinding"},
                {"rule_id": "R-2", "vuln_id": "V-2", "status": "Finding"},
                {"rule_id": "R-3", "vuln_id": "V-3", "status": "NotReviewed"},
            ],
            "evaluation_provenance": {
                "origin": "evidence_file",
                "collection_complete": True,
                "evidence_sha256": input_sha,
                "benchmark_sha256": benchmark_sha,
                "check_pack_sha256": check_pack_sha,
                "evaluation_plan_sha256": evaluation_plan_sha,
                "unsafe_legacy_evidence": False,
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "checklist.json"
            path.write_text(json.dumps(checklist), encoding="utf-8")
            findings, automated, observed, provenance = LIVE.validate_checklist(
                path,
                {"R-1", "R-2", "R-3"},
                self.curated,
                {"V-1": "notafinding", "V-2": "finding"},
                expected_origin="evidence_file",
                expected_input_sha256=input_sha,
                expected_benchmark_sha256=benchmark_sha,
                expected_check_pack_sha256=check_pack_sha,
                expected_evaluation_plan_sha256=evaluation_plan_sha,
            )
            self.assertEqual((findings, automated), (3, 2))
            self.assertEqual(observed["V-2"], "finding")
            self.assertEqual(provenance["evaluated_input_sha256"], input_sha)
            self.assertEqual(
                provenance["evaluated_check_pack_sha256"], check_pack_sha
            )
            with self.assertRaisesRegex(RuntimeError, "independent oracle"):
                LIVE.validate_checklist(
                    path,
                    {"R-1", "R-2", "R-3"},
                    self.curated,
                    {"V-1": "notafinding", "V-2": "notafinding"},
                    expected_origin="evidence_file",
                    expected_input_sha256=input_sha,
                    expected_benchmark_sha256=benchmark_sha,
                    expected_check_pack_sha256=check_pack_sha,
                    expected_evaluation_plan_sha256=evaluation_plan_sha,
                )
            for field, value, message in (
                ("evidence_sha256", "9" * 64, "exact selected input"),
                ("benchmark_sha256", "9" * 64, "evaluated benchmark"),
                ("check_pack_sha256", "9" * 64, "check-pack set"),
                ("evaluation_plan_sha256", "9" * 64, "evaluated plan"),
                ("collection_complete", False, "collection-complete"),
            ):
                invalid = json.loads(json.dumps(checklist))
                invalid["evaluation_provenance"][field] = value
                path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.subTest(field=field), self.assertRaisesRegex(
                    RuntimeError, message
                ):
                    LIVE.validate_checklist(
                        path,
                        {"R-1", "R-2", "R-3"},
                        self.curated,
                        {"V-1": "notafinding", "V-2": "finding"},
                        expected_origin="evidence_file",
                        expected_input_sha256=input_sha,
                        expected_benchmark_sha256=benchmark_sha,
                        expected_check_pack_sha256=check_pack_sha,
                        expected_evaluation_plan_sha256=evaluation_plan_sha,
                    )

    def test_checklist_binds_exact_verified_policy_provenance(self):
        input_sha = "6" * 64
        plan_sha = LIVE.expected_evaluation_plan_sha256(
            self.target,
            self.evaluated_benchmark_sha,
            self.pack_sha,
            self.policy_sha,
        )
        checklist = {
            "findings": [
                {"rule_id": "R-1", "vuln_id": "V-1", "status": "NotAFinding"},
                {"rule_id": "R-2", "vuln_id": "V-2", "status": "Finding"},
            ],
            "evaluation_provenance": {
                "origin": "config_file",
                "collection_complete": True,
                "evidence_sha256": input_sha,
                "benchmark_sha256": self.evaluated_benchmark_sha,
                "check_pack_sha256": self.pack_sha,
                "evaluation_plan_sha256": plan_sha,
                "unsafe_legacy_evidence": False,
                "organization_policy": {
                    "policy_id": "site-policy",
                    "policy_version": "1",
                    "policy_sha256": self.policy_sha,
                    "signer_fingerprint": self.policy_signer,
                    "signature_verified": True,
                },
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "checklist.json"
            path.write_text(json.dumps(checklist), encoding="utf-8")
            _, _, _, provenance = LIVE.validate_checklist(
                path,
                {"R-1", "R-2"},
                self.curated,
                {"V-1": "notafinding", "V-2": "finding"},
                expected_origin="config_file",
                expected_input_sha256=input_sha,
                expected_benchmark_sha256=self.evaluated_benchmark_sha,
                expected_check_pack_sha256=self.pack_sha,
                expected_evaluation_plan_sha256=plan_sha,
                expected_policy_sha256=self.policy_sha,
            )
            self.assertEqual(
                provenance["evaluated_organization_policy_sha256"],
                self.policy_sha,
            )
            for field, value in (
                ("policy_sha256", "9" * 64),
                ("signature_verified", False),
                ("signer_fingerprint", "untrusted"),
            ):
                invalid = json.loads(json.dumps(checklist))
                invalid["evaluation_provenance"]["organization_policy"][field] = value
                path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    LIVE.validate_checklist(
                        path,
                        {"R-1", "R-2"},
                        self.curated,
                        {"V-1": "notafinding", "V-2": "finding"},
                        expected_origin="config_file",
                        expected_input_sha256=input_sha,
                        expected_benchmark_sha256=self.evaluated_benchmark_sha,
                        expected_check_pack_sha256=self.pack_sha,
                        expected_evaluation_plan_sha256=plan_sha,
                        expected_policy_sha256=self.policy_sha,
                    )

    def test_config_evaluation_passes_only_snapshotted_policy_inputs(self):
        input_sha = "6" * 64
        plan_sha = LIVE.expected_evaluation_plan_sha256(
            self.target,
            self.evaluated_benchmark_sha,
            self.pack_sha,
            self.policy_sha,
        )
        policy = {
            "path": pathlib.Path("/private/snapshot-policy.json"),
            "signature_path": pathlib.Path("/private/snapshot-policy.sig"),
            "sha256": self.policy_sha,
        }
        checklist_document = {
            "findings": [
                {"rule_id": "R-1", "vuln_id": "V-1", "status": "NotAFinding"},
                {"rule_id": "R-2", "vuln_id": "V-2", "status": "Finding"},
            ],
            "evaluation_provenance": {
                "origin": "config_file",
                "collection_complete": True,
                "evidence_sha256": input_sha,
                "benchmark_sha256": self.evaluated_benchmark_sha,
                "check_pack_sha256": self.pack_sha,
                "evaluation_plan_sha256": plan_sha,
                "unsafe_legacy_evidence": False,
                "organization_policy": {
                    "policy_id": "site-policy",
                    "policy_version": "1",
                    "policy_sha256": self.policy_sha,
                    "signer_fingerprint": self.policy_signer,
                    "signature_verified": True,
                },
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            input_path = root / "running-config.txt"
            checklist = root / "checklist.json"
            input_path.write_bytes(b"config")
            input_sha = hashlib.sha256(b"config").hexdigest()
            checklist_document["evaluation_provenance"]["evidence_sha256"] = input_sha
            captured = []

            def fake_run(command, _environment):
                captured.extend(command)
                checklist.write_text(
                    json.dumps(checklist_document), encoding="utf-8"
                )
                return SimpleNamespace(returncode=0, stderr="")

            with mock.patch.object(LIVE, "run", side_effect=fake_run):
                LIVE.evaluate_scenario(
                    ["automatestig"],
                    {},
                    self.target,
                    "--config",
                    input_path,
                    self.hostname,
                    checklist,
                    {"R-1", "R-2"},
                    self.curated,
                    {"V-1": "notafinding", "V-2": "finding"},
                    self.evaluated_benchmark_sha,
                    self.pack_sha,
                    policy,
                )
            self.assertEqual(
                captured[captured.index("--organization-policy") + 1],
                str(policy["path"]),
            )
            self.assertEqual(
                captured[captured.index("--organization-policy-signature") + 1],
                str(policy["signature_path"]),
            )

    def test_ssh_hostname_cannot_alias_the_connection_endpoint(self):
        target = {"name": "ONTAP", "mode": "ssh"}
        environment = {
            LIVE.env_name(target, "HOST"): "device.example",
            LIVE.env_name(target, "HOSTNAME"): "alias.example",
            LIVE.env_name(target, "USERNAME"): "auditor",
        }
        with mock.patch.dict(os.environ, environment, clear=False), self.assertRaisesRegex(
            RuntimeError, "same endpoint"
        ):
            LIVE.exercise_ssh(
                target,
                pathlib.Path("/unused"),
                pathlib.Path("/unused/automatestig"),
                pathlib.Path("/unused/work"),
            )
        self.assertEqual(
            LIVE.normalized_asset_hostname("Device.Example."),
            LIVE.normalized_asset_hostname("device.example"),
        )

    def test_sut_environment_exposes_only_the_selected_command_inputs(self):
        target = {"name": "ONTAP", "mode": "ssh"}
        environment = {
            "HOME": "/runner/home",
            "PATH": "/usr/bin",
            "AUTOMATESTIG_SSH_TARGET_ALLOWLIST": "device.example",
            LIVE.env_name(target, "PASSWORD"): "selected-password",
            LIVE.env_name(target, "ORACLE"): "/protected/oracle.json",
            "AUTOMATESTIG_LIVE_FREEBSD_PASSWORD": "other-target-password",
            "AUTOMATESTIG_GOVERNANCE_TOKEN": "governance-secret",
            "AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR": "/protected/policy-keys",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            base = LIVE.sut_environment()
            ssh = LIVE.sut_environment(target, include_ssh_auth=True)
            policy = LIVE.sut_environment(include_organization_policy=True)
        self.assertEqual(base, {"HOME": "/runner/home", "PATH": "/usr/bin"})
        self.assertEqual(
            ssh,
            {
                "HOME": "/runner/home",
                "PATH": "/usr/bin",
                "AUTOMATESTIG_SSH_TARGET_ALLOWLIST": "device.example",
                LIVE.env_name(target, "PASSWORD"): "selected-password",
            },
        )
        self.assertEqual(
            policy,
            {
                "HOME": "/runner/home",
                "PATH": "/usr/bin",
                "AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR": "/protected/policy-keys",
            },
        )

    @unittest.skipUnless(os.name == "posix", "requires POSIX custody checks")
    def test_policy_snapshot_binds_pin_signature_size_and_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            policy = root / "policy.json"
            signature = root / "policy.sig"
            policy.write_bytes(b'{"schema":"test"}')
            signature.write_bytes(b"s" * LIVE.ED25519_SIGNATURE_BYTES)
            policy.chmod(0o600)
            signature.chmod(0o644)
            expected = hashlib.sha256(policy.read_bytes()).hexdigest()
            environment = {
                LIVE.env_name(self.target, "ORGANIZATION_POLICY"): str(policy),
                LIVE.env_name(self.target, "ORGANIZATION_POLICY_SIGNATURE"): str(
                    signature
                ),
                LIVE.env_name(self.target, "ORGANIZATION_POLICY_SHA256"): expected,
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                snapshot = LIVE.snapshot_organization_policy(
                    self.target, root / "snapshot"
                )
            self.assertEqual(snapshot["sha256"], expected)
            self.assertEqual(
                snapshot["signature_sha256"],
                hashlib.sha256(signature.read_bytes()).hexdigest(),
            )
            with mock.patch.dict(
                os.environ,
                {
                    **environment,
                    LIVE.env_name(
                        self.target, "ORGANIZATION_POLICY_SHA256"
                    ): "9" * 64,
                },
                clear=False,
            ), self.assertRaisesRegex(RuntimeError, "precommitted"):
                LIVE.snapshot_organization_policy(self.target, root / "wrong-pin")
            policy.chmod(0o644)
            with mock.patch.dict(os.environ, environment, clear=False), self.assertRaisesRegex(
                RuntimeError, "group/other access"
            ):
                LIVE.snapshot_organization_policy(
                    self.target, root / "unsafe-policy"
                )
            policy.chmod(0o600)
            signature.write_bytes(b"short")
            with mock.patch.dict(os.environ, environment, clear=False), self.assertRaisesRegex(
                RuntimeError, "1..64|exactly 64"
            ):
                LIVE.snapshot_organization_policy(self.target, root / "short-signature")

    def test_source_snapshot_is_bounded_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source.txt"
            snapshot = root / "snapshot.txt"
            source.write_bytes(b"fixed state")
            source.chmod(0o600)
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

    @unittest.skipUnless(hasattr(pathlib.Path, "chmod"), "requires POSIX modes")
    def test_source_snapshot_rejects_group_or_other_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source.txt"
            source.write_bytes(b"private state")
            source.chmod(0o640)
            with self.assertRaisesRegex(RuntimeError, "group/other access"):
                LIVE.snapshot_regular_file(source, root / "snapshot.txt")


if __name__ == "__main__":
    unittest.main()
