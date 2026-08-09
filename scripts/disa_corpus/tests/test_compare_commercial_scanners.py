import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "compare_commercial_scanners",
    REPO / "scripts" / "compare-commercial-scanners.py",
)
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)


def digest(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


XCCDF_BENCHMARK_ID = "xccdf_mil.disa.stig_benchmark_Cisco_IOS-XE_Router_NDM_STIG"
BENCHMARK_RELEASE = "V3R7"


def xccdf(
    status_by_vuln,
    *,
    benchmark_id=XCCDF_BENCHMARK_ID,
    test_result_id="xccdf_test_result_default",
    release=BENCHMARK_RELEASE,
    namespace=COMPARE.XCCDF_1_2_NAMESPACE,
):
    result_names = {
        "Finding": "fail",
        "NotAFinding": "pass",
        "NotApplicable": "notapplicable",
    }
    groups = []
    rows = []
    for offset, (vuln, status) in enumerate(sorted(status_by_vuln.items()), 1):
        rule = f"SV-{1000 + offset}r1_rule"
        groups.append(
            f'<Group id="xccdf_mil.disa.stig_group_{vuln}">'
            f'<Rule id="xccdf_mil.disa.stig_rule_{rule}"><version>{vuln}</version></Rule>'
            "</Group>"
        )
        rows.append(
            f'<rule-result idref="xccdf_mil.disa.stig_rule_{rule}">'
            f"<result>{result_names[status]}</result></rule-result>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Benchmark xmlns="{namespace}" id="{benchmark_id}">'
        f"<version>{release}</version>"
        + "".join(groups)
        + f'<TestResult id="{test_result_id}" version="{release}">'
        + "".join(rows)
        + "</TestResult></Benchmark>"
    ).encode("utf-8")


def bound_file(root, relative, raw):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return str(path.relative_to(root)), hashlib.sha256(raw).hexdigest()


class CommercialComparisonTests(unittest.TestCase):
    maxDiff = None

    def build_manifest(self, root):
        now = datetime.datetime.now(datetime.timezone.utc)
        cases = []
        for kind in sorted(COMPARE.REQUIRED_CASE_KINDS):
            complete = kind in {"compliant", "noncompliant"}
            if kind == "compliant":
                statuses = {"V-1": "NotAFinding", "V-2": "NotApplicable"}
            elif kind == "noncompliant":
                statuses = {"V-1": "Finding", "V-2": "NotAFinding"}
            else:
                statuses = {}
            state_path, state_sha256 = bound_file(
                root,
                pathlib.Path("bindings") / "source-states" / f"{kind}.txt",
                f"state-{kind}".encode(),
            )
            cases.append(
                {
                    "id": kind,
                    "kind": kind,
                    "software_version": (
                        "18.99-unsupported"
                        if kind == "unsupported_version"
                        else "17.15.4c"
                    ),
                    "source_state_path": state_path,
                    "source_state_sha256": state_sha256,
                    "collection_expected": "complete" if complete else "incomplete",
                    "expected_status_by_vuln": statuses,
                }
            )
        automatestig_artifact_path, automatestig_artifact_sha = bound_file(
            root, "bindings/tools/automatestig.bin", b"automatestig-binary"
        )
        automatestig_content_path, automatestig_content_sha = bound_file(
            root, "bindings/tools/automatestig-content.bin", b"automatestig-content"
        )
        tenable_artifact_path, tenable_artifact_sha = bound_file(
            root, "bindings/tools/tenable.bin", b"tenable-package"
        )
        tenable_content_path, tenable_content_sha = bound_file(
            root, "bindings/tools/tenable-content.bin", b"tenable-audit"
        )
        tools = [
            {
                "id": "automatestig",
                "product": "AutomateSTIG",
                "vendor": "AutomateSTIG",
                "version": "0.3.0-test",
                "artifact_path": automatestig_artifact_path,
                "artifact_sha256": automatestig_artifact_sha,
                "content_path": automatestig_content_path,
                "content_sha256": automatestig_content_sha,
                "classification": "sut",
                "setup_trials": [
                    {"duration_ms": value, "analyst_actions": 2}
                    for value in (800, 900, 1000)
                ],
            },
            {
                "id": "tenable",
                "product": "Tenable Nessus",
                "vendor": "Tenable",
                "version": "test-version",
                "artifact_path": tenable_artifact_path,
                "artifact_sha256": tenable_artifact_sha,
                "content_path": tenable_content_path,
                "content_sha256": tenable_content_sha,
                "classification": "commercial",
                "setup_trials": [
                    {"duration_ms": value, "analyst_actions": 4}
                    for value in (1800, 2000, 2200)
                ],
            },
        ]
        repetitions = 3
        seed = digest("schedule-seed")
        by_case = {case["id"]: case for case in cases}
        schedule = COMPARE.expected_schedule(
            [tool["id"] for tool in tools],
            [case["id"] for case in cases],
            repetitions,
            seed,
        )
        result_root = root / "results"
        result_root.mkdir()
        runs = []
        for sequence, (tool_id, case_id, repetition) in enumerate(schedule, 1):
            case = by_case[case_id]
            result = None
            failure = None
            complete = case["collection_expected"] == "complete"
            if complete:
                test_result_id = f"xccdf_test_result_{sequence:03}"
                result_raw = xccdf(
                    case["expected_status_by_vuln"],
                    test_result_id=test_result_id,
                )
                result_path = result_root / f"{sequence:03}-{tool_id}-{case_id}-{repetition}.xml"
                result_path.write_bytes(result_raw)
                result = {
                    "format": "xccdf",
                    "path": str(result_path.relative_to(root)),
                    "sha256": hashlib.sha256(result_raw).hexdigest(),
                    "test_result_id": test_result_id,
                }
            else:
                failure_raw = (
                    f"{tool_id} observed expected {case_id} failure on repetition {repetition}\n"
                ).encode()
                failure_path, failure_sha = bound_file(
                    root,
                    pathlib.Path("results")
                    / f"{sequence:03}-{tool_id}-{case_id}-{repetition}.failure.txt",
                    failure_raw,
                )
                failure = {
                    "stage": "preflight" if case_id == "unsupported_version" else "collection",
                    "code": case_id,
                    "detail": f"The scheduled {case_id} case failed closed as expected.",
                    "evidence_path": failure_path,
                    "evidence_sha256": failure_sha,
                }
            runs.append(
                {
                    "id": f"run-{sequence:03}",
                    "tool_id": tool_id,
                    "case_id": case_id,
                    "repetition": repetition,
                    "sequence": sequence,
                    "source_state_sha256": case["source_state_sha256"],
                    "collection_complete": complete,
                    "result": result,
                    "failure": failure,
                    "duration_ms": 1000 if tool_id == "automatestig" else 1500,
                    "analyst_actions": 1 if tool_id == "automatestig" else 2,
                    "external_script_lines": 0 if tool_id == "automatestig" else 10,
                }
            )
        target_bindings = {}
        for member in (
            "hardware_identity",
            "privilege_profile",
            "network_path",
            "site_policy",
        ):
            target_bindings[member] = bound_file(
                root,
                pathlib.Path("bindings") / "target" / f"{member}.json",
                f"verified-{member}".encode(),
            )
        benchmark_source_path, benchmark_source_sha = bound_file(
            root, "bindings/benchmark/disa-source.zip", b"disa-source"
        )
        effective_model_path, effective_model_sha = bound_file(
            root, "bindings/benchmark/effective-model.json", b"effective-benchmark"
        )
        manifest = {
            "$schema": COMPARE.MANIFEST_SCHEMA_URI,
            "schema": COMPARE.MANIFEST_SCHEMA,
            "comparison_id": "cisco-iosxe-v3r7-controlled",
            "created_at": now.isoformat().replace("+00:00", "Z"),
            "target": {
                "family": "Cisco IOS-XE",
                "model": "C8000V",
                "software_version": "17.15.4c",
                "context": "default routing context",
                "hardware_identity_path": target_bindings["hardware_identity"][0],
                "hardware_identity_sha256": target_bindings["hardware_identity"][1],
                "privilege_profile_path": target_bindings["privilege_profile"][0],
                "privilege_profile_sha256": target_bindings["privilege_profile"][1],
                "network_path_artifact_path": target_bindings["network_path"][0],
                "network_path_sha256": target_bindings["network_path"][1],
                "site_policy_path": target_bindings["site_policy"][0],
                "site_policy_sha256": target_bindings["site_policy"][1],
                "representative_authorized_device": True,
                "synthetic": False,
            },
            "benchmark": {
                "id": "Cisco_IOS-XE_Router_NDM_STIG",
                "release": BENCHMARK_RELEASE,
                "xccdf_benchmark_id": XCCDF_BENCHMARK_ID,
                "source_path": benchmark_source_path,
                "source_sha256": benchmark_source_sha,
                "effective_model_path": effective_model_path,
                "effective_model_sha256": effective_model_sha,
            },
            "oracle": {
                "adjudicated_at": (now - datetime.timedelta(days=1)).isoformat().replace("+00:00", "Z"),
                "adjudication_basis": (
                    "Two-person manual adjudication of the exact DISA check text "
                    "against independently captured representative device state."
                ),
                "independent_of_tool_outputs": True,
                "adjudicators": [
                    {
                        "id": "cyber-sme",
                        "roles": ["cybersecurity_sme", "test_owner"],
                    },
                    {"id": "test-owner", "roles": ["cybersecurity_sme"]},
                ],
                "cases": cases,
            },
            "randomization": {
                "algorithm": "sha256-order-v1",
                "seed_sha256": seed,
                "repetitions": repetitions,
            },
            "tools": tools,
            "runs": runs,
            "deviations": [],
        }
        path = root / "comparison.json"
        path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return path, manifest

    def rewrite(self, path, manifest):
        path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    def record_failure(self, root, run, *, code="tool_error", stage="collection"):
        raw = f"Diagnostic evidence for {run['id']}: {code}\n".encode()
        relative, sha256 = bound_file(
            root, pathlib.Path("results") / f"{run['id']}-{code}.failure.txt", raw
        )
        run["collection_complete"] = False
        run["result"] = None
        run["failure"] = {
            "stage": stage,
            "code": code,
            "detail": f"The scanner did not produce a usable result because of {code}.",
            "evidence_path": relative,
            "evidence_sha256": sha256,
        }

    def test_accepts_randomized_repeated_native_xccdf_and_reports_denominators(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.build_manifest(pathlib.Path(temporary))
            report = COMPARE.build_report(COMPARE.load_manifest(path))
        automated = report["tools"]["automatestig"]["metrics"]
        self.assertTrue(report["gates"]["protocol_gate_passed"])
        self.assertTrue(report["gates"]["automatestig_safety_gate_passed"])
        self.assertTrue(report["gates"]["comparison_results_gate_passed"])
        self.assertTrue(report["gates"]["technical_report_complete"])
        self.assertTrue(
            report["observed_advantage_automatestig_over_comparator"]["tenable"][
                "comparable"
            ]
        )
        self.assertFalse(report["gates"]["superiority_claim_automatically_authorized"])
        self.assertEqual(automated["false_passes"], 0)
        self.assertEqual(
            automated["false_pass_measure"],
            {
                "numerator": 0,
                "denominator": 3,
                "rate": 0.0,
                "ground_truth_noncompliant_rows": 3,
                "unobservable_determined_rows": 0,
            },
        )
        self.assertEqual(automated["collection_success"], {"numerator": 6, "denominator": 6, "rate": 1.0})
        self.assertEqual(automated["automation_depth"], {"numerator": 12, "denominator": 12, "rate": 1.0})
        self.assertEqual(automated["native_xccdf_runs"], 6)
        self.assertEqual(automated["median_setup_duration_ms"], 900)
        self.assertEqual(
            report["tools"]["automatestig"]["cases"]["truncated_output"][
                "metrics"
            ]["attempts"],
            3,
        )
        self.assertEqual(len(report["report_sha256"]), 64)

    def test_prepares_a_fillable_randomized_run_sheet_from_an_empty_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            manifest["schema"] = COMPARE.DRAFT_MANIFEST_SCHEMA
            manifest["runs"] = []
            self.rewrite(path, manifest)
            prepared = COMPARE.prepare_schedule(path)
            output = root / "prepared.json"
            exit_code = COMPARE.main(
                [str(path), "--prepare-schedule-out", str(output)]
            )
            written = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(prepared["runs"]), 42)
        self.assertEqual(written["runs"], prepared["runs"])
        self.assertEqual(
            [run["sequence"] for run in prepared["runs"]], list(range(1, 43))
        )
        self.assertTrue(all(run["collection_complete"] is None for run in prepared["runs"]))
        self.assertTrue(all(run["failure"] is None for run in prepared["runs"]))
        self.assertEqual(prepared["schema"], COMPARE.DRAFT_MANIFEST_SCHEMA)

    def test_rejects_a_tampered_result_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            result = next(run["result"] for run in manifest["runs"] if run["result"])
            (root / result["path"]).write_bytes(b"tampered")
            with self.assertRaisesRegex(COMPARE.ComparisonError, "digest mismatch"):
                COMPARE.load_manifest(path)

    def test_rejects_missing_error_and_unsupported_version_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            manifest["oracle"]["cases"] = [
                case for case in manifest["oracle"]["cases"] if case["kind"] != "truncated_output"
            ]
            self.rewrite(path, manifest)
            with self.assertRaisesRegex(COMPARE.ComparisonError, "missing required case kinds"):
                COMPARE.load_manifest(path)

    def test_rejects_an_unsupported_case_that_reuses_the_supported_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            case = next(
                case
                for case in manifest["oracle"]["cases"]
                if case["kind"] == "unsupported_version"
            )
            case["software_version"] = manifest["target"]["software_version"]
            self.rewrite(path, manifest)
            with self.assertRaisesRegex(COMPARE.ComparisonError, "outside the supported baseline"):
                COMPARE.load_manifest(path)

    def test_rejects_run_order_that_does_not_match_committed_randomization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            manifest["runs"][0]["sequence"], manifest["runs"][1]["sequence"] = (
                manifest["runs"][1]["sequence"],
                manifest["runs"][0]["sequence"],
            )
            self.rewrite(path, manifest)
            with self.assertRaisesRegex(COMPARE.ComparisonError, "randomized schedule"):
                COMPARE.load_manifest(path)

    def test_approved_invalidating_deviation_remains_visible_and_blocks_protocol_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            manifest["deviations"] = [
                {
                    "id": "comparator-content-mismatch",
                    "description": (
                        "The comparator content did not implement the exact benchmark release."
                    ),
                    "impact": "invalidates_claim",
                    "approved_by": ["cyber-sme", "test-owner"],
                }
            ]
            self.rewrite(path, manifest)
            report = COMPARE.build_report(COMPARE.load_manifest(path))
            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = COMPARE.main(
                    [
                        str(path),
                        "--json-out",
                        str(root / "deviation-report.json"),
                        "--require-comparison-gate",
                    ]
                )
        self.assertFalse(report["gates"]["protocol_gate_passed"])
        self.assertEqual(exit_code, 2)
        self.assertEqual(
            report["protocol"]["blocking_deviation_ids"],
            ["comparator-content-mismatch"],
        )
        self.assertEqual(
            report["gates"]["superiority_claim_status"],
            "protocol_deviation_blocks_claim",
        )

    def test_incomplete_automatestig_pass_fails_the_technical_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            run = next(
                run
                for run in manifest["runs"]
                if run["tool_id"] == "automatestig" and run["case_id"] == "truncated_output"
            )
            test_result_id = "xccdf_test_result_unsafe_incomplete"
            raw = xccdf(
                {"V-1": "NotAFinding"}, test_result_id=test_result_id
            )
            artifact = root / "results" / "unsafe-incomplete.xml"
            artifact.write_bytes(raw)
            run["result"] = {
                "format": "xccdf",
                "path": str(artifact.relative_to(root)),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "test_result_id": test_result_id,
            }
            self.rewrite(path, manifest)
            report = COMPARE.build_report(COMPARE.load_manifest(path))
            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = COMPARE.main(
                    [
                        str(path),
                        "--json-out",
                        str(root / "rejected-report.json"),
                        "--require-technical-gate",
                    ]
                )
        automated = report["tools"]["automatestig"]["metrics"]
        self.assertEqual(automated["false_passes"], 1)
        self.assertEqual(automated["incomplete_determined_rows"], 1)
        self.assertFalse(report["gates"]["automatestig_safety_gate_passed"])
        self.assertEqual(exit_code, 2)

    def test_accepts_double_reviewed_normalization_bound_to_proprietary_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            run = next(
                run
                for run in manifest["runs"]
                if run["tool_id"] == "tenable" and run["case_id"] == "compliant"
            )
            source_raw = b"representative proprietary compliance export"
            source = root / "results" / "tenable-source.bin"
            source.write_bytes(source_raw)
            source_sha = hashlib.sha256(source_raw).hexdigest()
            decision = {
                "$schema": COMPARE.DECISION_SCHEMA_URI,
                "schema": COMPARE.DECISION_SCHEMA,
                "source_export_sha256": source_sha,
                "normalization": {
                    "method": "double_reviewed_transcription",
                    "procedure_sha256": digest("normalization-procedure-v1"),
                    "independent_of_oracle": True,
                    "reviewers": ["normalizer-one", "normalizer-two"],
                },
                "status_by_vuln": {"V-1": "NotAFinding", "V-2": "NotApplicable"},
            }
            decision_raw = json.dumps(decision).encode("utf-8")
            decision_path = root / "results" / "tenable-normalized.json"
            decision_path.write_bytes(decision_raw)
            run["result"] = {
                "format": "normalized-json",
                "path": str(decision_path.relative_to(root)),
                "sha256": hashlib.sha256(decision_raw).hexdigest(),
                "source_export_path": str(source.relative_to(root)),
                "source_export_sha256": source_sha,
            }
            self.rewrite(path, manifest)
            report = COMPARE.build_report(COMPARE.load_manifest(path))
        self.assertEqual(
            report["tools"]["tenable"]["metrics"]["double_reviewed_normalized_runs"],
            1,
        )

    def test_comparison_gate_requires_usable_results_from_every_comparator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            for run in manifest["runs"]:
                if run["tool_id"] == "tenable" and run["collection_complete"]:
                    self.record_failure(root, run, code="no_usable_export", stage="export")
            self.rewrite(path, manifest)
            report = COMPARE.build_report(COMPARE.load_manifest(path))
            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = COMPARE.main(
                    [
                        str(path),
                        "--json-out",
                        str(root / "incomplete-comparison.json"),
                        "--require-comparison-gate",
                    ]
                )
        self.assertFalse(report["gates"]["comparator_results_gate_passed"])
        self.assertFalse(report["gates"]["comparison_results_gate_passed"])
        self.assertFalse(report["gates"]["technical_report_complete"])
        self.assertEqual(report["gates"]["unusable_comparator_ids"], ["tenable"])
        self.assertEqual(
            report["observed_advantage_automatestig_over_comparator"]["tenable"],
            {
                "comparable": False,
                "deltas": None,
                "reason": (
                    "usable oracle-covered results are missing for one or more "
                    "expected-complete runs"
                ),
            },
        )
        self.assertEqual(
            report["gates"]["superiority_claim_status"],
            "usable_tool_results_required",
        )
        self.assertEqual(exit_code, 2)
        complete_case_failures = [
            failure
            for failure in report["tools"]["tenable"]["failures"]
            if failure["case_id"] in {"compliant", "noncompliant"}
        ]
        self.assertEqual(len(complete_case_failures), 6)
        self.assertTrue(
            all(failure["code"] == "no_usable_export" for failure in complete_case_failures)
        )

    def test_incomplete_run_requires_bound_structured_failure_reason(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            run = next(run for run in manifest["runs"] if not run["collection_complete"])
            run["failure"] = None
            self.rewrite(path, manifest)
            with self.assertRaisesRegex(COMPARE.ComparisonError, "structured failure reason"):
                COMPARE.load_manifest(path)

    def test_rejects_non_xccdf_namespace_and_wrong_benchmark_or_test_result(self):
        kwargs = {
            "expected_benchmark_id": XCCDF_BENCHMARK_ID,
            "expected_release": BENCHMARK_RELEASE,
            "expected_test_result_id": "xccdf_test_result_expected",
        }
        with self.assertRaisesRegex(COMPARE.ComparisonError, "XCCDF 1.2 Benchmark"):
            COMPARE.parse_xccdf(
                xccdf(
                    {"V-1": "NotAFinding"},
                    namespace="urn:not-xccdf",
                    test_result_id="xccdf_test_result_expected",
                ),
                **kwargs,
            )
        mixed_namespace = xccdf(
            {"V-1": "NotAFinding"},
            test_result_id="xccdf_test_result_expected",
        ).replace(
            b'<Group id="',
            b'<bad:Group xmlns:bad="urn:not-xccdf" id="',
            1,
        ).replace(b"</Group>", b"</bad:Group>", 1)
        with self.assertRaisesRegex(COMPARE.ComparisonError, "unexpected namespace"):
            COMPARE.parse_xccdf(mixed_namespace, **kwargs)
        with self.assertRaisesRegex(COMPARE.ComparisonError, "Benchmark id"):
            COMPARE.parse_xccdf(
                xccdf(
                    {"V-1": "NotAFinding"},
                    benchmark_id="xccdf_wrong_benchmark",
                    test_result_id="xccdf_test_result_expected",
                ),
                **kwargs,
            )
        with self.assertRaisesRegex(COMPARE.ComparisonError, "TestResult id"):
            COMPARE.parse_xccdf(
                xccdf(
                    {"V-1": "NotAFinding"},
                    test_result_id="xccdf_test_result_wrong",
                ),
                **kwargs,
            )
        extension_version = xccdf(
            {"V-1": "NotAFinding"},
            test_result_id="xccdf_test_result_expected",
        ).replace(
            b"</rule-result>",
            b'<sm:version xmlns:sm="urn:scanner-extension">1.0</sm:version></rule-result>',
            1,
        )
        self.assertEqual(
            COMPARE.parse_xccdf(extension_version, **kwargs),
            {"V-1": "NotAFinding"},
        )

    def test_rejects_tampered_and_symlinked_bound_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            tool = next(tool for tool in manifest["tools"] if tool["id"] == "tenable")
            (root / tool["artifact_path"]).write_bytes(b"tampered tool")
            with self.assertRaisesRegex(COMPARE.ComparisonError, "tool tenable artifact digest mismatch"):
                COMPARE.load_manifest(path)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            case = manifest["oracle"]["cases"][0]
            original = root / case["source_state_path"]
            linked = original.with_name("linked-state.txt")
            linked.symlink_to(original.name)
            case["source_state_path"] = str(linked.relative_to(root))
            self.rewrite(path, manifest)
            with self.assertRaisesRegex(COMPARE.ComparisonError, "symlink component"):
                COMPARE.load_manifest(path)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            run = next(run for run in manifest["runs"] if not run["collection_complete"])
            (root / run["failure"]["evidence_path"]).write_bytes(b"tampered diagnostic")
            with self.assertRaisesRegex(COMPARE.ComparisonError, "failure evidence digest mismatch"):
                COMPARE.load_manifest(path)

    def test_status_mismatch_fails_automatestig_safety_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            for run in manifest["runs"]:
                if run["tool_id"] == "automatestig" and run["case_id"] == "compliant":
                    raw = xccdf(
                        {"V-1": "NotAFinding", "V-2": "NotAFinding"},
                        test_result_id=run["result"]["test_result_id"],
                    )
                    (root / run["result"]["path"]).write_bytes(raw)
                    run["result"]["sha256"] = hashlib.sha256(raw).hexdigest()
            self.rewrite(path, manifest)
            report = COMPARE.build_report(COMPARE.load_manifest(path))
            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = COMPARE.main(
                    [
                        str(path),
                        "--json-out",
                        str(root / "mismatch-report.json"),
                        "--require-technical-gate",
                    ]
                )
        self.assertEqual(report["tools"]["automatestig"]["metrics"]["status_mismatches"], 3)
        self.assertFalse(report["gates"]["automatestig_safety_gate_passed"])
        self.assertEqual(exit_code, 2)

    def test_draft_and_completed_documents_use_distinct_contract_states(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            manifest["schema"] = COMPARE.DRAFT_MANIFEST_SCHEMA
            manifest["runs"] = []
            self.rewrite(path, manifest)
            prepared = COMPARE.prepare_schedule(path)
            self.rewrite(path, prepared)
            with self.assertRaisesRegex(COMPARE.ComparisonError, "completed schema"):
                COMPARE.load_manifest(path)
        schema = json.loads(
            (REPO / "schemas" / "scanner-comparison-manifest.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            set(schema["properties"]["schema"]["enum"]),
            {COMPARE.DRAFT_MANIFEST_SCHEMA, COMPARE.MANIFEST_SCHEMA},
        )
        self.assertIn("draftRun", schema["$defs"])
        self.assertIn("completedRun", schema["$defs"])

    def test_legacy_unbound_manifest_is_rejected_with_migration_guidance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path, manifest = self.build_manifest(root)
            manifest["schema"] = COMPARE.LEGACY_MANIFEST_SCHEMA
            self.rewrite(path, manifest)
            with self.assertRaisesRegex(COMPARE.ComparisonError, "migrate"):
                COMPARE.load_manifest(path)

    def test_rejects_xml_entity_declarations_and_invalid_schema_files(self):
        with self.assertRaisesRegex(COMPARE.ComparisonError, "entity declarations"):
            COMPARE.parse_xccdf(
                b'<!DOCTYPE x [<!ENTITY e "unsafe">]><Benchmark>&e;</Benchmark>',
                XCCDF_BENCHMARK_ID,
                BENCHMARK_RELEASE,
                "xccdf_test_result_default",
            )
        for relative in (
            "schemas/scanner-comparison-manifest.schema.json",
            "schemas/normalized-scanner-decisions.schema.json",
        ):
            with (REPO / relative).open(encoding="utf-8") as stream:
                self.assertIsInstance(json.load(stream), dict)


if __name__ == "__main__":
    unittest.main()
