import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO / "scripts" / "validate-check-packs.py"
SPEC = importlib.util.spec_from_file_location("validate_check_packs", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

GENERATOR_PATH = REPO / "scripts" / "generate-checkpack-coverage.py"
GENERATOR_SPEC = importlib.util.spec_from_file_location(
    "generate_checkpack_coverage", GENERATOR_PATH
)
assert GENERATOR_SPEC and GENERATOR_SPEC.loader
GENERATOR = importlib.util.module_from_spec(GENERATOR_SPEC)
GENERATOR_SPEC.loader.exec_module(GENERATOR)


class SupportedTargetValidationTests(unittest.TestCase):
    def _copy_contract(self, destination: Path) -> None:
        for relative in (
            "content/supported-targets.json",
            "schemas/supported-targets.schema.json",
            "content/check_packs",
            "content/coverage/current-checkpacks",
        ):
            source = REPO / relative
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)

    def test_repository_has_exact_v03_contract(self):
        self.assertEqual(MODULE.validate(REPO), [])

    def test_reviewed_and_executable_totals_match_the_product_claim(self):
        expected = {
            "netapp_ontap9": (22, 15, 7),
            "freebsd_gpos": (30, 6, 24),
            "cisco_ios_xe_router_ndm": (42, 33, 9),
        }
        observed = {}
        for target_id, target in MODULE.EXPECTED_TARGETS.items():
            manifest = json.loads(
                (REPO / target["coverage_manifest"]).read_text(encoding="utf-8")
            )
            automated = sum(
                rule["classification"] == "automated" for rule in manifest["rules"]
            )
            manual = sum(
                rule["classification"] == "manual" for rule in manifest["rules"]
            )
            observed[target_id] = (len(manifest["rules"]), automated, manual)

        self.assertEqual(observed, expected)
        self.assertEqual(sum(counts[0] for counts in observed.values()), 94)
        self.assertEqual(sum(counts[1] for counts in observed.values()), 54)
        self.assertEqual(sum(counts[2] for counts in observed.values()), 40)

    def test_every_shipped_automation_has_reviewed_implementation_metadata(self):
        counts = {
            "declarative_predicate": 0,
            "legacy_declarative": 0,
            "reviewed_imperative": 0,
        }
        for target in MODULE.EXPECTED_TARGETS.values():
            pack = json.loads((REPO / target["check_pack"]).read_text(encoding="utf-8"))
            for check in pack["checks"]:
                counts[check["implementation_class"]] += 1
                self.assertEqual(check["introduction_release"], "0.3")
        self.assertEqual(counts, {
            "declarative_predicate": 0,
            "legacy_declarative": 33,
            "reviewed_imperative": 21,
        })

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_contract(root)
            path = root / "content/check_packs/freebsd_gpos.json"
            pack = json.loads(path.read_text(encoding="utf-8"))
            pack["checks"][0].pop("implementation_class")
            pack["checks"][0].pop("introduction_release")
            path.write_text(json.dumps(pack), encoding="utf-8")
            errors = MODULE.validate(root)
            self.assertTrue(any("implementation_class" in error for error in errors))
            self.assertTrue(any("introduction_release" in error for error in errors))

    def test_predicate_schema_is_versioned_bounded_and_has_no_execution_field(self):
        check = {
            "type": "predicate",
            "program": {
                "schema_version": 1,
                "source": {"type": "observation", "key": "normalized-setting"},
                "input": {"type": "json"},
                "predicate": {
                    "op": "equal",
                    "left": {"type": "value", "value": {"pointer": "/enabled"}},
                    "right": {"type": "literal", "value": True},
                },
            },
        }
        errors = []
        MODULE._validate_check("candidate", "V-PREDICATE", check, errors)
        self.assertEqual(errors, [])

        check["program"]["shell"] = "id"
        errors = []
        MODULE._validate_check("candidate", "V-PREDICATE", check, errors)
        self.assertTrue(any("program fields" in error for error in errors))

        check["program"].pop("shell")
        check["program"]["predicate"] = {
            "op": "any",
            "predicates": [
                {"op": "present", "value": {"pointer": f"/{index}"}}
                for index in range(65)
            ],
        }
        errors = []
        MODULE._validate_check("candidate", "V-PREDICATE", check, errors)
        self.assertTrue(any("requires 1-64" in error for error in errors))

    def test_scanner_frontend_uses_the_authoritative_three_profile_api(self):
        contract = json.loads(
            (REPO / "content/supported-targets.json").read_text(encoding="utf-8")
        )
        identifiers = {target["stig_id"] for target in contract["targets"].values()}
        self.assertEqual(
            identifiers,
            {
                "NetApp_ONTAP_DSC_9-x_STIG",
                "General_Purpose_Operating_System",
                "Cisco_IOS-XE_Router_NDM_STIG",
            },
        )
        modes = [target["evidence_mode"] for target in contract["targets"].values()]
        self.assertEqual(modes.count("ssh_transcript"), 2)
        self.assertEqual(modes.count("running_configuration"), 1)

        frontend = REPO / "crates/gui/frontend/scanner"
        content = (frontend / "content.js").read_text(encoding="utf-8")
        api = (frontend / "api.js").read_text(encoding="utf-8")
        scanner_api = (REPO / "crates/gui/src/scanner_api.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("request(endpoints.profiles", content)
        self.assertIn("profiles: '/scanner/profiles'", api)
        self.assertIn("bundled_scanner_profiles()", scanner_api)
        self.assertNotIn("SUPPORTED_SCANNER_TARGETS", content)

    def test_frontend_labels_automation_scope_as_not_a_compliance_score(self):
        frontend = REPO / "crates/gui/frontend/scanner"
        deliveries = (frontend / "deliveries.js").read_text(encoding="utf-8")
        content = (frontend / "content.js").read_text(encoding="utf-8")
        combined = deliveries + content
        self.assertIn("metric('Automation coverage'", deliveries)
        self.assertIn("Not a compliance score", deliveries)
        self.assertIn("full_benchmark_rules", deliveries)
        self.assertIn("countBlock('Full benchmark'", content)
        self.assertNotIn("% compliance", combined)
        self.assertNotIn("statCard('Compliance'", combined)

    def test_frontend_never_delivers_incomplete_or_training_results(self):
        frontend = REPO / "crates/gui/frontend/scanner"
        scan = (frontend / "scan.js").read_text(encoding="utf-8")
        deliveries = (frontend / "deliveries.js").read_text(encoding="utf-8")
        self.assertIn(
            "Training data only — do not use this page as assessment evidence.",
            scan,
        )
        self.assertIn("collectionComplete === false", deliveries)
        self.assertIn(
            "Incomplete or ambiguous evidence is never delivered as a compliance result.",
            deliveries,
        )
        self.assertNotIn("Deliver to STIG Manager", deliveries)

    def test_unlisted_shipped_pack_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_contract(root)
            shutil.copy2(
                root / "content/check_packs/netapp_ontap9.json",
                root / "content/check_packs/unreviewed.json",
            )
            errors = MODULE.validate(root)
            self.assertTrue(any("extra=" in error and "unreviewed.json" in error for error in errors))

    def test_coverage_cannot_omit_a_shipped_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_contract(root)
            path = root / "content/coverage/current-checkpacks/freebsd_gpos.current.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["rules"].pop()
            document["total_rules"] = len(document["rules"])
            path.write_text(json.dumps(document), encoding="utf-8")
            errors = MODULE.validate(root)
            self.assertTrue(any("reviewed inventory" in error for error in errors))

    def test_manual_rule_cannot_bind_an_executable_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_contract(root)
            path = root / "content/coverage/current-checkpacks/freebsd_gpos.current.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            manual = next(rule for rule in document["rules"] if rule["classification"] == "manual")
            manual["check_pack"] = "freebsd_gpos"
            manual["check_id"] = manual["vuln_id"]
            path.write_text(json.dumps(document), encoding="utf-8")
            errors = MODULE.validate(root)
            self.assertTrue(any("manual coverage must not bind" in error for error in errors))

    def test_automated_inventory_must_exactly_match_the_pack(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_contract(root)
            path = root / "content/coverage/current-checkpacks/freebsd_gpos.current.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            automated = next(rule for rule in document["rules"] if rule["classification"] == "automated")
            automated["classification"] = "manual"
            automated.pop("check_pack")
            automated.pop("check_id")
            path.write_text(json.dumps(document), encoding="utf-8")
            errors = MODULE.validate(root)
            self.assertTrue(any("automated rule/check mismatch" in error for error in errors))

    def test_coverage_refresh_preserves_explicit_manual_boundary(self):
        expected_counts = {
            "netapp_ontap9": (15, 7),
            "freebsd_gpos": (6, 24),
            "cisco_ios_xe_router_ndm": (33, 9),
        }
        for target_id, (automated_count, manual_count) in expected_counts.items():
            with self.subTest(target=target_id):
                pack = REPO / f"content/check_packs/{target_id}.json"
                existing = json.loads(
                    (
                        REPO
                        / f"content/coverage/current-checkpacks/{target_id}.current.json"
                    ).read_text(encoding="utf-8")
                )
                refreshed = GENERATOR.manifest_for_pack(pack, REPO, existing)
                classifications = {
                    rule["vuln_id"]: rule["classification"]
                    for rule in refreshed["rules"]
                }
                existing_manual = {
                    rule["vuln_id"]: rule
                    for rule in existing["rules"]
                    if rule["classification"] == "manual"
                }
                refreshed_manual = {
                    rule["vuln_id"]: rule
                    for rule in refreshed["rules"]
                    if rule["classification"] == "manual"
                }
                self.assertEqual(
                    sum(value == "automated" for value in classifications.values()),
                    automated_count,
                )
                self.assertEqual(
                    sum(value == "manual" for value in classifications.values()),
                    manual_count,
                )
                self.assertEqual(refreshed_manual, existing_manual)

    def test_coverage_refresh_rejects_manual_executable_overlap(self):
        pack = REPO / "content/check_packs/freebsd_gpos.json"
        existing = json.loads(
            (REPO / "content/coverage/current-checkpacks/freebsd_gpos.current.json")
            .read_text(encoding="utf-8")
        )
        executable_id = json.loads(pack.read_text(encoding="utf-8"))["checks"][0]["vuln_id"]
        existing["rules"].append(
            {
                "vuln_id": executable_id,
                "classification": "manual",
            }
        )
        with self.assertRaises(SystemExit):
            GENERATOR.manifest_for_pack(pack, REPO, existing)

    def test_out_of_scope_coverage_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_contract(root)
            destination = root / "content/coverage/research/general-linux.json"
            destination.parent.mkdir(parents=True)
            shutil.copy2(
                root / "content/coverage/current-checkpacks/freebsd_gpos.current.json",
                destination,
            )
            errors = MODULE.validate(root)
            self.assertTrue(
                any("content/coverage:" in error and "general-linux.json" in error for error in errors)
            )


if __name__ == "__main__":
    unittest.main()
