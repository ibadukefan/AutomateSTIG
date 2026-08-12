import datetime
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr
from unittest import mock


REPO = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts/run-handoff-receiver-ceremony.py"
COMMIT = "a" * 40
REPOSITORY = "example/AutomateSTIG"
STAGING_RUN_ID = "4100"


def digest(value):
    return hashlib.sha256(value).hexdigest()


class HandoffReceiverCeremonyTests(unittest.TestCase):
    def make_inputs(self, root):
        handoff = root / "producer-handoff.zip"
        handoff.write_bytes(b"bounded selected-run handoff fixture")
        public_key = root / "producer.pub"
        public_key.write_bytes(bytes(range(32)))
        handoff_sha = digest(handoff.read_bytes())
        key_sha = digest(public_key.read_bytes())
        signature = root / "handoff.signature.json"
        signature.write_text(
            json.dumps(
                {
                    "schema": "automatestig.selected-run-handoff-signature.v1",
                    "algorithm": "ed25519-sha256",
                    "handoff_schema": "automatestig.selected-run-handoff.v4",
                    "run_id": "123e4567-e89b-42d3-a456-426614174000",
                    "handoff_sha256": handoff_sha,
                    "signing_key_fingerprint": f"SHA256:{key_sha}",
                    "signature": "1" * 128,
                },
                sort_keys=True,
            )
            + "\n"
        )
        signed_at = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        custody = root / "custody.json"
        custody.write_text(
            json.dumps(
                {
                    "schema": "automatestig-handoff-key-custody-ceremony/v1",
                    "source_commit": COMMIT,
                    "signed_at": signed_at,
                    "producer_key_fingerprint": f"SHA256:{key_sha}",
                    "public_key_sha256": key_sha,
                    "handoff_sha256": handoff_sha,
                    "signature_sidecar_sha256": digest(signature.read_bytes()),
                    "key_custodian": "key-custodian",
                    "receiver_approver": "receiver-approver",
                    "signing_host_reference": "signing-host:asset-17",
                    "primary_key_media_reference": "media:primary-17",
                    "backup_key_media_reference": "media:backup-17",
                    "private_key_entered_ci": False,
                    "private_key_entered_scanner_runtime": False,
                    "private_key_material_recorded": False,
                    "revocation_status_checked": True,
                },
                sort_keys=True,
            )
            + "\n"
        )
        staging = root / "stig-manager-acceptance.json"
        staging.write_text(
            json.dumps(
                {
                    "schema": "automatestig-stig-manager-acceptance/v1",
                    "passed": True,
                    "source_commit": COMMIT,
                    "repository": REPOSITORY,
                    "workflow_run_id": STAGING_RUN_ID,
                    "protected_environment": "external-acceptance",
                    "metrics": {
                        "boundary": "disconnected-selected-run-handoff",
                        "producer_handoff_filename": "producer-handoff.zip",
                        "handoff_sha256": handoff_sha,
                    },
                },
                sort_keys=True,
            )
            + "\n"
        )
        cli = root / "automatestig"
        cli.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            "assert sys.argv[1:3] == ['scanner', 'verify-handoff']\n"
            "assert '--signature' in sys.argv and '--trust-dir' in sys.argv\n"
            "trust = pathlib.Path(sys.argv[sys.argv.index('--trust-dir') + 1])\n"
            "keys = list(trust.iterdir())\n"
            "assert len(keys) == 1 and len(keys[0].read_bytes()) == 32\n"
            "import hashlib\n"
            "fingerprint = hashlib.sha256(keys[0].read_bytes()).hexdigest()\n"
            "print('Producer signature: verified with trusted handoff key '"
            "      'fixture (SHA256:' + fingerprint + ')')\n"
        )
        cli.chmod(0o755)
        return {
            "handoff": handoff,
            "public_key": public_key,
            "signature": signature,
            "custody": custody,
            "staging": staging,
            "cli": cli,
        }

    def invoke(self, root, inputs, *extra):
        return subprocess.run(
            [
                sys.executable,
                SCRIPT,
                "--cli",
                inputs["cli"],
                "--handoff",
                inputs["handoff"],
                "--staging-evidence",
                inputs["staging"],
                "--output-dir",
                root / "output",
                "--repository",
                REPOSITORY,
                "--source-commit",
                COMMIT,
                "--workflow-run-id",
                "4200",
                "--staging-workflow-run-id",
                STAGING_RUN_ID,
                "--key-custodian",
                "key-custodian",
                "--receiver-approver",
                "receiver-approver",
                "--public-key",
                inputs["public_key"],
                "--signature",
                inputs["signature"],
                "--custody-record",
                inputs["custody"],
                *extra,
            ],
            cwd=REPO,
            text=True,
            capture_output=True,
        )

    def test_protected_receiver_binds_all_public_ceremony_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            inputs = self.make_inputs(root)
            result = self.invoke(root, inputs)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = root / "output"
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "handoff-receiver-ceremony.json",
                    "handoff-producer-public-key.pub",
                    "producer-handoff.zip",
                    "producer-handoff.zip.signature.json",
                    "handoff-key-custody-ceremony.json",
                },
            )
            ceremony = json.loads(
                (output / "handoff-receiver-ceremony.json").read_text()
            )
            self.assertTrue(ceremony["producer_signature_verified"])
            self.assertTrue(ceremony["trusted_cli_verification_succeeded"])
            self.assertTrue(ceremony["key_custody_ceremony_verified"])
            self.assertEqual(
                ceremony["handoff_sha256"], digest(inputs["handoff"].read_bytes())
            )
            self.assertEqual(
                ceremony["signature_sha256"],
                digest(inputs["signature"].read_bytes()),
            )
            self.assertEqual(
                ceremony["producer_key_fingerprint"],
                f"SHA256:{digest(inputs['public_key'].read_bytes())}",
            )
            self.assertEqual(
                (output / "producer-handoff.zip").read_bytes(),
                inputs["handoff"].read_bytes(),
            )

    def test_same_custodian_and_approver_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            inputs = self.make_inputs(root)
            command = [
                sys.executable,
                SCRIPT,
                "--cli",
                inputs["cli"],
                "--handoff",
                inputs["handoff"],
                "--staging-evidence",
                inputs["staging"],
                "--output-dir",
                root / "output",
                "--repository",
                REPOSITORY,
                "--source-commit",
                COMMIT,
                "--workflow-run-id",
                "4200",
                "--staging-workflow-run-id",
                STAGING_RUN_ID,
                "--key-custodian",
                "same-user",
                "--receiver-approver",
                "same-user",
                "--public-key",
                inputs["public_key"],
                "--signature",
                inputs["signature"],
                "--custody-record",
                inputs["custody"],
            ]
            result = subprocess.run(command, cwd=REPO, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be different", result.stderr)

    def test_sidecar_substitution_is_rejected_before_cli_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            inputs = self.make_inputs(root)
            signature = json.loads(inputs["signature"].read_text())
            signature["handoff_sha256"] = "f" * 64
            inputs["signature"].write_text(json.dumps(signature) + "\n")
            result = self.invoke(root, inputs)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("signature sidecar", result.stderr)

    def test_custody_record_cannot_claim_private_key_entered_ci(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            inputs = self.make_inputs(root)
            custody = json.loads(inputs["custody"].read_text())
            custody["private_key_entered_ci"] = True
            inputs["custody"].write_text(json.dumps(custody) + "\n")
            result = self.invoke(root, inputs)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("protected-key rules", result.stderr)

    def test_release_contract_requires_handoff_ceremony_and_prohibits_signing_in_receiver(self):
        release_schema = json.loads(
            (REPO / "schemas/release-evidence.schema.json").read_text()
        )
        self.assertIn(
            "producer_authenticated_handoff", release_schema["required"]
        )
        handoff = release_schema["properties"]["producer_authenticated_handoff"]
        self.assertTrue(handoff["additionalProperties"] is False)
        self.assertEqual(len(handoff["required"]), len(set(handoff["required"])))
        self.assertEqual(
            set(handoff["required"]),
            {
                "fingerprint_sha256",
                "ceremony_reference",
                "ceremony_sha256",
                "public_key_reference",
                "public_key_sha256",
                "handoff_reference",
                "handoff_sha256",
                "signature_reference",
                "signature_sha256",
                "key_custody_reference",
                "key_custody_sha256",
            },
        )
        workflow = (
            REPO / ".github/workflows/handoff-receiver-ceremony.yml"
        ).read_text()
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, automatestig-handoff-receiver]",
            workflow,
        )
        self.assertIn("environment: handoff-receiver-ceremony", workflow)
        self.assertIn("--no-default-features", workflow)
        self.assertIn("--handoff staging-handoff-input/producer-handoff.zip", workflow)
        self.assertIn("--staging-evidence staging-handoff-input/stig-manager-acceptance.json", workflow)
        self.assertNotIn("generate-signing-key", workflow)
        self.assertNotIn("sign-handoff", workflow)
        staging = (REPO / ".github/workflows/stigman-staging.yml").read_text()
        self.assertIn("--handoff-output producer-handoff.zip", staging)
        self.assertIn("producer-handoff.zip", staging)

    def test_connected_validator_requires_exact_five_file_workflow_artifact(self):
        spec = importlib.util.spec_from_file_location(
            "validate_release_evidence_handoff",
            REPO / "scripts/validate-release-evidence.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        expected = {
            module.HANDOFF_CEREMONY_EVIDENCE: b'{"passed":true}\n',
            module.HANDOFF_CEREMONY_PUBLIC_KEY: b"K" * 32,
            module.HANDOFF_CEREMONY_ZIP: b"handoff",
            module.HANDOFF_CEREMONY_SIGNATURE: b'{"signature":"fixture"}\n',
            module.HANDOFF_CEREMONY_CUSTODY: b'{"custody":"fixture"}\n',
        }

        def archive(files):
            value = io.BytesIO()
            with zipfile.ZipFile(value, "w", zipfile.ZIP_STORED) as bundle:
                for name, body in files.items():
                    bundle.writestr(name, body)
            return value.getvalue()

        archive_bytes = archive(expected)
        metadata = {
            "total_count": 1,
            "artifacts": [
                {
                    "id": 77,
                    "name": module.HANDOFF_CEREMONY_ARTIFACT,
                    "expired": False,
                    "size_in_bytes": len(archive_bytes),
                }
            ],
        }
        with (
            mock.patch.object(module, "github_json", return_value=metadata),
            mock.patch.object(module, "github_bytes", return_value=archive_bytes),
        ):
            module.validate_handoff_ceremony_artifact(
                REPOSITORY, "4200", expected
            )

        tampered = dict(expected)
        tampered[module.HANDOFF_CEREMONY_SIGNATURE] = b"substituted"
        tampered_archive = archive(tampered)
        tampered_metadata = {
            "total_count": 1,
            "artifacts": [
                {
                    "id": 78,
                    "name": module.HANDOFF_CEREMONY_ARTIFACT,
                    "expired": False,
                    "size_in_bytes": len(tampered_archive),
                }
            ],
        }
        with (
            mock.patch.object(
                module, "github_json", return_value=tampered_metadata
            ),
            mock.patch.object(
                module, "github_bytes", return_value=tampered_archive
            ),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            module.validate_handoff_ceremony_artifact(
                REPOSITORY, "4200", expected
            )

    def test_connected_workflow_binds_custodian_distinct_approver_and_receiver(self):
        spec = importlib.util.spec_from_file_location(
            "validate_release_evidence_handoff_workflow",
            REPO / "scripts/validate-release-evidence.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        run = {
            "id": 4200,
            "head_sha": COMMIT,
            "name": "Handoff Receiver Ceremony",
            "path": ".github/workflows/handoff-receiver-ceremony.yml",
            "event": "workflow_dispatch",
            "conclusion": "success",
            "run_attempt": 1,
            "actor": {"login": "key-custodian"},
            "triggering_actor": {"login": "key-custodian"},
        }
        environment = {
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {
                            "type": "User",
                            "reviewer": {"login": "receiver-approver"},
                        }
                    ],
                }
            ],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
        approvals = [
            {
                "state": "approved",
                "user": {"login": "receiver-approver"},
                "environments": [{"name": "handoff-receiver-ceremony"}],
            }
        ]
        jobs = {
            "total_count": 1,
            "jobs": [
                {
                    "name": "Trusted receiver verifies producer signature",
                    "conclusion": "success",
                    "labels": [
                        "self-hosted",
                        "linux",
                        "x64",
                        "automatestig-handoff-receiver",
                    ],
                    "runner_id": 17,
                    "runner_name": "protected-receiver-17",
                }
            ],
        }

        def response(endpoint):
            if endpoint.endswith("/environments/handoff-receiver-ceremony"):
                return environment
            if endpoint.endswith("/actions/runs/4200/approvals"):
                return approvals
            if endpoint.endswith("/actions/runs/4200/jobs?filter=latest&per_page=100"):
                return jobs
            if endpoint.endswith("/actions/runs/4200"):
                return run
            raise AssertionError(endpoint)

        ceremony = {
            "repository": REPOSITORY,
            "workflow_run_id": "4200",
        }
        with (
            mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": REPOSITORY}),
            mock.patch.object(module, "github_json", side_effect=response),
            mock.patch.object(module, "validate_handoff_ceremony_artifact") as artifact,
        ):
            module.validate_handoff_ceremony_workflow(
                ceremony,
                COMMIT,
                "key-custodian",
                "receiver-approver",
                {},
            )
            artifact.assert_called_once_with(REPOSITORY, "4200", {})
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                module.validate_handoff_ceremony_workflow(
                    ceremony,
                    COMMIT,
                    "different-custodian",
                    "receiver-approver",
                    {},
                )

if __name__ == "__main__":
    unittest.main()
