import base64
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import unittest


REPO = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts/run-content-signing-ceremony.py"


class ContentSigningCeremonyTests(unittest.TestCase):
    def invoke(
        self,
        root,
        custodian="key-custodian",
        approver="content-approver",
        verify_exit="0",
    ):
        root = pathlib.Path(root)
        cli = root / "automatestig"
        cli.write_text("#!/bin/sh\nexit \"${FAKE_VERIFY_EXIT:-0}\"\n")
        cli.chmod(0o755)
        public_key = root / "content.pub"
        public_key.write_bytes(bytes(range(32)))
        pack = root / "ceremony.stigpack"
        pack.write_bytes(b"bounded signed pack fixture")
        output = root / "output"
        result = subprocess.run(
            [
                "python3",
                SCRIPT,
                "--cli",
                cli,
                "--output-dir",
                output,
                "--repository",
                "ibadukefan/AutomateSTIG",
                "--source-commit",
                "a" * 40,
                "--workflow-run-id",
                "1234",
                "--key-custodian",
                custodian,
                "--content-approver",
                approver,
                "--public-key",
                public_key,
                "--test-pack",
                pack,
            ],
            cwd=root,
            env={**os.environ, "FAKE_VERIFY_EXIT": verify_exit},
            text=True,
            capture_output=True,
        )
        return result, output, public_key, pack, cli

    def test_emits_only_fixed_public_artifacts_after_cli_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, output, public_key, pack, cli = self.invoke(temporary)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                {item.name for item in output.iterdir()},
                {
                    "content-signing-ceremony.json",
                    "content-signing-public-key.pub",
                    "content-signing-test-pack.stigpack",
                },
            )
            self.assertEqual(
                (output / "content-signing-public-key.pub").read_bytes(),
                public_key.read_bytes(),
            )
            self.assertEqual(
                (output / "content-signing-test-pack.stigpack").read_bytes(),
                pack.read_bytes(),
            )
            evidence = json.loads((output / "content-signing-ceremony.json").read_text())
            key_sha = hashlib.sha256(public_key.read_bytes()).hexdigest()
            self.assertTrue(evidence["signature_verified"])
            self.assertEqual(evidence["public_key_sha256"], key_sha)
            self.assertEqual(evidence["public_key_fingerprint"], f"SHA256:{key_sha}")
            self.assertEqual(
                evidence["automatestig_cli_sha256"],
                hashlib.sha256(cli.read_bytes()).hexdigest(),
            )

    def test_rejects_same_person_for_both_roles_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, output, *_ = self.invoke(
                temporary,
                custodian="Same-Person",
                approver="same-person",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be different", result.stderr)
            self.assertFalse(output.exists())

    def test_failed_cli_signature_verification_emits_no_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, output, *_ = self.invoke(temporary, verify_exit="1")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("did not verify", result.stderr)
            self.assertTrue(output.is_dir())
            self.assertEqual(list(output.iterdir()), [])

    def test_accepts_bounded_public_material_from_workflow_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            cli = root / "automatestig"
            cli.write_text("#!/bin/sh\nexit 0\n")
            cli.chmod(0o755)
            output = root / "output"
            environment = os.environ.copy()
            environment.update({
                "AUTOMATESTIG_CEREMONY_PUBLIC_KEY_BASE64": base64.b64encode(
                    bytes(range(32))
                ).decode(),
                "AUTOMATESTIG_CEREMONY_TEST_PACK_BASE64": base64.b64encode(
                    b"signed workflow pack"
                ).decode(),
            })
            result = subprocess.run(
                [
                    "python3",
                    SCRIPT,
                    "--cli",
                    cli,
                    "--output-dir",
                    output,
                    "--repository",
                    "ibadukefan/AutomateSTIG",
                    "--source-commit",
                    "a" * 40,
                    "--workflow-run-id",
                    "1234",
                    "--key-custodian",
                    "key-custodian",
                    "--content-approver",
                    "content-approver",
                ],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (output / "content-signing-public-key.pub").read_bytes(),
                bytes(range(32)),
            )

    def test_rejects_non_32_byte_public_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            result, output, public_key, *_ = self.invoke(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            for item in output.iterdir():
                item.unlink()
            output.rmdir()
            public_key.write_bytes(b"short")
            command = [
                "python3",
                SCRIPT,
                "--cli",
                root / "automatestig",
                "--output-dir",
                output,
                "--repository",
                "ibadukefan/AutomateSTIG",
                "--source-commit",
                "a" * 40,
                "--workflow-run-id",
                "1234",
                "--key-custodian",
                "key-custodian",
                "--content-approver",
                "content-approver",
                "--public-key",
                public_key,
                "--test-pack",
                root / "ceremony.stigpack",
            ]
            denied = subprocess.run(
                [str(item) for item in command],
                cwd=root,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("exactly 32", denied.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
