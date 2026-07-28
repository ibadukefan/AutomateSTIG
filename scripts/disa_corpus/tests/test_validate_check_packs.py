import importlib.util
import json
import re
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
            "netapp_ontap9": (22, 16, 6),
            "freebsd_gpos": (30, 3, 27),
            "cisco_ios_xe_router_ndm": (34, 18, 16),
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
        self.assertEqual(sum(counts[0] for counts in observed.values()), 86)
        self.assertEqual(sum(counts[1] for counts in observed.values()), 37)
        self.assertEqual(sum(counts[2] for counts in observed.values()), 49)

    def test_frontend_scanner_contract_has_only_three_benchmarks(self):
        source = (REPO / "crates/gui/frontend/app.js").read_text(encoding="utf-8")
        block = source.split("const SUPPORTED_SCANNER_TARGETS", 1)[1].split("});", 1)[0]
        identifiers = {
            quoted or bare
            for quoted, bare in re.findall(
                r"^  (?:'([^']+)'|([A-Za-z_][A-Za-z0-9_]*)):", block, re.MULTILINE
            )
        }
        self.assertEqual(
            identifiers,
            {
                "NetApp_ONTAP_DSC_9-x_STIG",
                "General_Purpose_Operating_System",
                "Cisco_IOS-XE_Router_NDM_STIG",
            },
        )
        self.assertEqual(block.count("remote: true"), 2)
        self.assertEqual(block.count("remote: false"), 1)

    def test_frontend_distinguishes_assessed_pass_rate_from_benchmark_coverage(self):
        source = (REPO / "crates/gui/frontend/app.js").read_text(encoding="utf-8")
        self.assertIn("statCard('Assessed Pass Rate'", source)
        self.assertIn("statCard('Benchmark Coverage'", source)
        self.assertNotIn("statCard('Compliance'", source)
        self.assertIn("'assessed_pass_pct'", source)
        self.assertIn("'benchmark_coverage_pct'", source)
        self.assertIn(
            "hasExplicitPassRate ? checklist.assessed_pass_pct : checklist?.compliance_pct",
            source,
        )
        self.assertIn("if (score.benchmarkCoverage < 100) return 'yellow';", source)
        self.assertNotIn("% compliance", source)

    def test_frontend_never_grades_imported_or_unverified_checklists(self):
        source = (REPO / "crates/gui/frontend/app.js").read_text(encoding="utf-8")
        self.assertIn("origin === 'imported_checklist'", source)
        self.assertIn("collectionComplete === false", source)
        self.assertIn("provenance?.unsafe_legacy_evidence === true", source)
        self.assertIn("if (!score.defensible || score.assessedPassRate == null)", source)
        self.assertIn("verified ? 'status-naf' : 'status-na'", source)
        self.assertIn("? { label: 'Unverified', color: 'accent' }", source)
        self.assertIn("Unverified assessment results", source)
        self.assertNotIn(
            "assessment.open || assessment.score.benchmarkCoverage < 100 ? 'Needs review' : 'Fully assessed'",
            source,
        )

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
            "netapp_ontap9": (16, 6),
            "freebsd_gpos": (3, 27),
            "cisco_ios_xe_router_ndm": (18, 16),
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
