import datetime
import http.server
import importlib.util
import json
import os
import pathlib
import shutil
import ssl
import tempfile
import threading
import unittest
import urllib.request
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
            {"V-215807", "V-215836"},
        )

    def test_gui_lab_permissions_are_child_scoped_and_exact(self):
        with mock.patch.dict(
            os.environ,
            {
                "AUTOMATESTIG_DEMO": "1",
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

        self.assertEqual(
            environment["AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST"], "127.0.0.1"
        )
        self.assertNotIn(
            "AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_DESTINATIONS", environment
        )
        self.assertNotIn(
            "AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS", environment
        )
        self.assertEqual(
            environment["AUTOMATESTIG_ALLOW_INVALID_STIGMAN_CERTS"], "1"
        )
        self.assertEqual(
            environment["AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR"],
            "/tmp/staging-policy-trust",
        )
        self.assertNotIn("AUTOMATESTIG_DEMO", environment)
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

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_ephemeral_https_proxy_forwards_to_loopback_http(self):
        class EchoHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                body = self.rfile.read(length)
                response = json.dumps(
                    {
                        "body": body.decode(),
                        "host": self.headers["Host"],
                        "path": self.path,
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, _format, *_arguments):
                pass

        backend = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), EchoHandler
        )
        backend_thread = threading.Thread(
            target=backend.serve_forever, daemon=True
        )
        backend_thread.start()
        proxy = None
        try:
            with tempfile.TemporaryDirectory() as temporary:
                certificate, private_key = STAGING.generate_lab_certificate(
                    temporary
                )
                proxy = STAGING.HttpsReverseProxy(
                    backend.server_port, certificate, private_key
                ).start()
                request = urllib.request.Request(
                    f"https://127.0.0.1:{proxy.port}/api/test?value=1",
                    data=b"payload",
                    method="POST",
                )
                context = ssl._create_unverified_context()
                with urllib.request.urlopen(
                    request, context=context, timeout=10
                ) as response:
                    observed = json.loads(response.read())
                self.assertEqual(observed["body"], "payload")
                self.assertEqual(observed["path"], "/api/test?value=1")
                self.assertEqual(
                    observed["host"], f"localhost:{backend.server_port}"
                )
        finally:
            if proxy is not None:
                proxy.close()
            backend.shutdown()
            backend.server_close()
            backend_thread.join(timeout=5)

    def test_workflow_builds_and_passes_both_release_binaries(self):
        workflow = (
            REPO_ROOT / ".github/workflows/stigman-staging.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("--bin automatestig\n", workflow)
        self.assertIn("--bin automatestig-gui", workflow)
        self.assertIn("--cli-binary target/release/automatestig", workflow)


if __name__ == "__main__":
    unittest.main()
