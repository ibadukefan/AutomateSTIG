import datetime
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "staging/stigman/run-staging-acceptance.py"
SPEC = importlib.util.spec_from_file_location("stigman_staging_acceptance", SCRIPT)
assert SPEC and SPEC.loader
STAGING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGING)


class StigmanStagingAcceptanceTests(unittest.TestCase):
    def test_policy_is_current_asset_bound_and_contains_both_local_thresholds(self):
        now = datetime.datetime(
            2026, 7, 28, 12, 0, 0, tzinfo=datetime.timezone.utc
        )
        policy = STAGING.organization_policy_document(now)

        self.assertEqual(
            policy["schema"], "automatestig-organization-policy/v1"
        )
        self.assertEqual(
            policy["stig_id"], "Cisco_IOS-XE_Router_NDM_STIG"
        )
        self.assertEqual(policy["stig_release"], "V3R7")
        self.assertEqual(policy["asset_hostname"], STAGING.CISCO_HOSTNAME)
        effective = datetime.datetime.fromisoformat(
            policy["effective_from"].replace("Z", "+00:00")
        )
        expires = datetime.datetime.fromisoformat(
            policy["expires_at"].replace("Z", "+00:00")
        )
        self.assertLessEqual(effective, now)
        self.assertGreater(expires, now)
        self.assertEqual(
            set(policy["rules"]),
            {"V-215807", "V-215836", "V-215838"},
        )

    def test_disconnected_gui_environment_strips_stig_manager_escape_hatches(self):
        with mock.patch.dict(
            os.environ,
            {
                "AUTOMATESTIG_DEMO": "1",
                "AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST": "127.0.0.1",
                "AUTOMATESTIG_ALLOW_INVALID_STIGMAN_CERTS": "1",
                "AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_DESTINATIONS": "1",
                "AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS": "1",
                "UNRELATED_PARENT_VALUE": "retained",
            },
            clear=False,
        ):
            parent_environment = dict(os.environ)
            environment = STAGING.staging_process_environment(
                "/tmp/staging-home", "/tmp/staging-policy-trust"
            )
            self.assertEqual(dict(os.environ), parent_environment)

        for name in (
            "AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST",
            "AUTOMATESTIG_ALLOW_INVALID_STIGMAN_CERTS",
            "AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_DESTINATIONS",
            "AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS",
            "AUTOMATESTIG_DEMO",
        ):
            self.assertNotIn(name, environment)
        self.assertEqual(
            environment["AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR"],
            "/tmp/staging-policy-trust",
        )
        self.assertEqual(environment["UNRELATED_PARENT_VALUE"], "retained")

    def test_policy_provisioning_deletes_private_seed_and_installs_public_anchor(self):
        def fake_policy_command(arguments, _operation):
            if arguments[0] == "generate-signing-key":
                private_key = pathlib.Path(arguments[2])
                private_key.write_bytes(b"k" * 32)
                private_key.with_suffix(".pub").write_bytes(b"p" * 32)
            elif arguments[0] == "sign-organization-policy":
                output = pathlib.Path(arguments[arguments.index("--output") + 1])
                output.write_bytes(b"s" * 64)
            else:
                raise AssertionError(arguments)

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            STAGING, "run_policy_command", side_effect=fake_policy_command
        ):
            policy = STAGING.provision_organization_policy(temporary)
            signing_root = pathlib.Path(temporary) / "ephemeral-policy-signing"
            trust_key = (
                pathlib.Path(policy["trust_dir"])
                / "stigman-staging-policy.pub"
            )

            self.assertFalse(
                (signing_root / "organization-policy.key").exists()
            )
            self.assertEqual(trust_key.read_bytes(), b"p" * 32)
            self.assertEqual(
                pathlib.Path(policy["signature_path"]).read_bytes(), b"s" * 64
            )
            self.assertEqual(
                policy["signature_sha256"],
                STAGING.file_sha256(policy["signature_path"]),
            )
            self.assertEqual(
                set(STAGING.cisco_evaluation_files(policy)),
                {
                    "evidence",
                    "organization_policy",
                    "organization_policy_signature",
                },
            )
            document = json.loads(pathlib.Path(policy["path"]).read_text())
            self.assertEqual(document["asset_hostname"], STAGING.CISCO_HOSTNAME)

    def test_receiver_translates_only_sparse_review_fields(self):
        sparse = [
            {
                "rule_id": "SV-1r1_rule",
                "result": "fail",
                "detail": "  evidence detail  ",
                "comment": "  analyst note  ",
                "evidence_source": "supplied_evidence",
                "evaluated_at": "2026-08-08T12:00:00Z",
                "ignored": "must not cross the boundary",
            }
        ]

        writes = STAGING.receiver_review_writes(sparse)

        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["ruleId"], "SV-1r1_rule")
        self.assertEqual(writes[0]["result"], "fail")
        self.assertEqual(writes[0]["detail"], "evidence detail")
        self.assertEqual(writes[0]["comment"], "analyst note")
        self.assertFalse(writes[0]["autoResult"])
        self.assertEqual(writes[0]["status"], "saved")
        self.assertNotIn("ignored", writes[0])

    def test_xccdf_is_verified_as_supplemental_not_receiver_transport(self):
        run_id = "11111111-2222-4333-8444-555555555555"
        manifest = {
            "run_id": run_id,
            "stig_id": STAGING.CISCO_STIG,
            "stig_revision": STAGING.CISCO_REVISION,
        }
        sparse = [
            {
                "rule_id": "SV-1r1_rule",
                "result": "fail",
                "detail": "evidence detail",
                "comment": "analyst note",
                "evidence_source": "supplied_evidence",
                "evaluated_at": "2026-08-08T12:00:00Z",
            }
        ]
        xccdf = f"""<?xml version="1.0" encoding="UTF-8"?>
<cdf:Benchmark xmlns:cdf="{STAGING.XCCDF_NAMESPACE}"
 xmlns:sm="{STAGING.STIG_MANAGER_NAMESPACE}"
 xmlns:ast="{STAGING.AUTOMATESTIG_XCCDF_NAMESPACE}"
 id="{STAGING.XCCDF_BENCHMARK_PREFIX}{STAGING.CISCO_STIG}">
  <cdf:TestResult id="{STAGING.XCCDF_TEST_RESULT_PREFIX}{run_id}"
   version="{STAGING.CISCO_REVISION}">
    <cdf:rule-result idref="{STAGING.XCCDF_RULE_PREFIX}SV-1r1_rule">
      <cdf:result>fail</cdf:result>
      <cdf:metadata>
        <ast:rule-identity rule-id="SV-1r1_rule" />
      </cdf:metadata>
      <cdf:check><cdf:check-content>
        <sm:detail>evidence detail</sm:detail>
        <sm:comment>analyst note</sm:comment>
      </cdf:check-content></cdf:check>
    </cdf:rule-result>
    <cdf:metadata>
      <ast:provenance stig-id="{STAGING.CISCO_STIG}">
        <ast:field name="run-id" value="{run_id}" />
      </ast:provenance>
    </cdf:metadata>
  </cdf:TestResult>
</cdf:Benchmark>
""".encode()

        projection = STAGING.supplemental_xccdf_reviews(
            xccdf, manifest, sparse
        )
        writes = STAGING.receiver_review_writes(sparse)

        self.assertEqual(set(projection), {"SV-1r1_rule"})
        self.assertEqual(writes[0]["ruleId"], "SV-1r1_rule")
        self.assertNotIn("xccdf", writes[0])

        wrong_namespace = xccdf.replace(
            STAGING.XCCDF_NAMESPACE.encode(), b"urn:wrong:xccdf", 1
        )
        with self.assertRaisesRegex(ValueError, "XCCDF 1.2 Benchmark"):
            STAGING.supplemental_xccdf_reviews(
                wrong_namespace, manifest, sparse
            )

    def test_workflow_builds_and_passes_both_release_binaries(self):
        workflow = (
            REPO_ROOT / ".github/workflows/stigman-staging.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("--bin automatestig\n", workflow)
        self.assertIn("--bin automatestig-gui", workflow)
        self.assertIn("--cli-binary target/release/automatestig", workflow)
        self.assertIn("Scanner Handoff", workflow)
        self.assertNotIn("AUTOMATESTIG_ALLOW_INVALID_STIGMAN_CERTS", workflow)


if __name__ == "__main__":
    unittest.main()
