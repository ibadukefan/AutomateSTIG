import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import unittest


REPO = pathlib.Path(__file__).resolve().parents[3]


def run(command, cwd, env=None):
    return subprocess.run(
        [str(item) for item in command],
        cwd=cwd,
        env={**os.environ, **(env or {})},
        text=True,
        capture_output=True,
    )


def git(repo, *arguments):
    result = run(["git", "-c", "commit.gpgsign=false", *arguments], repo)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def init_repo(root):
    git(root, "init", "-q")
    git(root, "config", "user.name", "Release Test")
    git(root, "config", "user.email", "release-test@example.test")


def write_json_artifact(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseGovernanceTests(unittest.TestCase):
    def test_collector_wrappers_require_an_explicit_output_path(self):
        for name in ("ontap-collect.sh", "bsd-collect.sh"):
            with self.subTest(name=name):
                path = REPO / "scripts/collectors" / name
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("--output -", text)
                result = subprocess.run(
                    ["sh", path, "scanner@example.test"],
                    text=True,
                    capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("output.json", result.stderr)

    def test_installers_bind_archive_name_and_tagged_workflow_identity(self):
        for name in ("install-linux.sh", "install-macos.sh"):
            with self.subTest(installer=name):
                path = REPO / name
                syntax = run(["sh", "-n", path], REPO)
                self.assertEqual(syntax.returncode, 0, syntax.stderr)
                text = path.read_text()
                self.assertIn('CHECKSUM_NAME="$ARCHIVE_NAME.sha256"', text)
                self.assertIn('BUNDLE_NAME="$ARCHIVE_NAME.sigstore.bundle"', text)
                self.assertIn('--certificate-identity "$IDENTITY"', text)
                self.assertIn("https://token.actions.githubusercontent.com", text)
                self.assertIn("refs/tags/$TAG", text)

        macos = (REPO / "install-macos.sh").read_text()
        self.assertNotIn("xattr -d", macos)

        windows = (REPO / "install-windows.ps1").read_text()
        self.assertIn('$ChecksumName = "$ArchiveName.sha256"', windows)
        self.assertIn('$BundleName = "$ArchiveName.sigstore.bundle"', windows)
        self.assertIn("--certificate-identity $Identity", windows)
        self.assertIn("refs/tags/$Tag", windows)

    def test_posix_installers_verify_before_installing(self):
        cases = (
            ("install-linux.sh", "Linux", "x86_64-unknown-linux-gnu"),
            ("install-macos.sh", "Darwin", "x86_64-apple-darwin"),
        )
        for installer, system, target in cases:
            with self.subTest(installer=installer), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                fixture = root / "fixture"
                payload = root / "payload"
                fake_bin = root / "bin"
                install_dir = root / "install"
                for directory in (fixture, payload, fake_bin):
                    directory.mkdir()
                for binary in ("automatestig", "automatestig-gui"):
                    path = payload / binary
                    path.write_text("#!/bin/sh\nexit 0\n")
                    path.chmod(0o755)

                archive_name = f"automatestig-v0.3.0-{target}.tar.gz"
                archive = fixture / archive_name
                packed = run(["tar", "-czf", archive, "-C", payload, "."], root)
                self.assertEqual(packed.returncode, 0, packed.stderr)
                archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
                (fixture / f"{archive_name}.sha256").write_text(
                    f"{archive_hash}  {archive_name}\n"
                )
                (fixture / f"{archive_name}.sigstore.bundle").write_text("{}\n")

                wrappers = {
                    "uname": """#!/bin/sh
case "$1" in
  -s) printf '%s\\n' "$FAKE_UNAME_SYSTEM" ;;
  -m) printf '%s\\n' x86_64 ;;
  *) exit 1 ;;
esac
""",
                    "curl": """#!/bin/sh
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2 ;;
    http://*|https://*) url=$1; shift ;;
    --retry|--connect-timeout|--proto|--proto-redir) shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$output" ] && [ -n "$url" ] || exit 2
cp "$FIXTURE_DIR/${url##*/}" "$output"
""",
                    "cosign": """#!/bin/sh
printf '%s\\n' "$*" >> "$COSIGN_LOG"
[ "${FAKE_COSIGN_FAILURE:-0}" -ne 1 ]
""",
                }
                for name, source in wrappers.items():
                    path = fake_bin / name
                    path.write_text(source)
                    path.chmod(0o755)

                log = root / "cosign.log"
                env = {
                    "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                    "AUTOMATESTIG_VERSION": "v0.3.0",
                    "AUTOMATESTIG_INSTALL_DIR": str(install_dir),
                    "FAKE_UNAME_SYSTEM": system,
                    "FIXTURE_DIR": str(fixture),
                    "COSIGN_LOG": str(log),
                }
                installed = run(["sh", REPO / installer], root, env)
                self.assertEqual(installed.returncode, 0, installed.stderr)
                self.assertTrue((install_dir / "automatestig").is_file())
                self.assertTrue((install_dir / "automatestig-gui").is_file())
                invocation = log.read_text()
                self.assertIn(f"--bundle ", invocation)
                self.assertIn(f"{archive_name}.sigstore.bundle", invocation)
                self.assertIn(
                    "https://github.com/ibadukefan/AutomateSTIG/"
                    ".github/workflows/ci.yml@refs/tags/v0.3.0",
                    invocation,
                )

                rejected_dir = root / "rejected"
                rejected = run(
                    ["sh", REPO / installer],
                    root,
                    {
                        **env,
                        "AUTOMATESTIG_INSTALL_DIR": str(rejected_dir),
                        "FAKE_COSIGN_FAILURE": "1",
                    },
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(rejected_dir.exists())

    def test_workflow_evidence_must_match_the_uploaded_artifact(self):
        import importlib.util
        import io
        import zipfile
        from contextlib import redirect_stderr
        from unittest import mock

        spec = importlib.util.spec_from_file_location(
            "validate_release_evidence",
            REPO / "scripts/validate-release-evidence.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        evidence = b'{"passed":true}\n'
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("stig-viewer-acceptance.json", evidence)
        archive_bytes = archive.getvalue()
        metadata = {
            "total_count": 1,
            "artifacts": [{
                "id": 99,
                "name": "stig-viewer-acceptance-1234",
                "expired": False,
                "size_in_bytes": len(archive_bytes),
            }],
        }
        with (
            mock.patch.object(module, "github_json", return_value=metadata),
            mock.patch.object(module, "github_bytes", return_value=archive_bytes),
        ):
            module.validate_workflow_artifact(
                "ibadukefan/AutomateSTIG",
                "1234",
                "stig_viewer",
                hashlib.sha256(evidence).hexdigest(),
            )
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                module.validate_workflow_artifact(
                    "ibadukefan/AutomateSTIG",
                    "1234",
                    "stig_viewer",
                    "0" * 64,
                )

    def test_content_ceremony_binds_exactly_three_fixed_workflow_files(self):
        import importlib.util
        import io
        import zipfile
        from contextlib import redirect_stderr
        from unittest import mock

        spec = importlib.util.spec_from_file_location(
            "validate_release_evidence_ceremony",
            REPO / "scripts/validate-release-evidence.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        expected = {
            "content-signing-ceremony.json": b'{"signature_verified":true}\n',
            "content-signing-public-key.pub": bytes(range(32)),
            "content-signing-test-pack.stigpack": b"signed pack",
        }

        def archive(files):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
                for name, value in files.items():
                    bundle.writestr(name, value)
            return output.getvalue()

        archive_bytes = archive(expected)
        metadata = {
            "total_count": 1,
            "artifacts": [{
                "id": 99,
                "name": "content-signing-ceremony",
                "expired": False,
                "size_in_bytes": len(archive_bytes),
            }],
        }
        with (
            mock.patch.object(module, "github_json", return_value=metadata),
            mock.patch.object(module, "github_bytes", return_value=archive_bytes),
        ):
            module.validate_content_ceremony_artifact(
                "ibadukefan/AutomateSTIG", "1234", expected
            )
            tampered = dict(expected)
            tampered["content-signing-public-key.pub"] = b"X" * 32
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                module.validate_content_ceremony_artifact(
                    "ibadukefan/AutomateSTIG", "1234", tampered
                )
        extra_archive = archive({**expected, "unexpected.txt": b"not allowed"})
        with (
            mock.patch.object(module, "github_json", return_value=metadata),
            mock.patch.object(module, "github_bytes", return_value=extra_archive),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            module.validate_content_ceremony_artifact(
                "ibadukefan/AutomateSTIG", "1234", expected
            )

    def test_content_ceremony_environment_requires_exact_recorded_user(self):
        import importlib.util
        import io
        from contextlib import redirect_stderr
        from unittest import mock

        spec = importlib.util.spec_from_file_location(
            "validate_release_evidence_environment",
            REPO / "scripts/validate-release-evidence.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        environment = {
            "can_admins_bypass": False,
            "protection_rules": [{
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [{
                    "type": "User",
                    "reviewer": {"login": "content-approver"},
                }],
            }],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
        with mock.patch.object(module, "github_json", return_value=environment):
            module.validate_content_ceremony_environment(
                "ibadukefan/AutomateSTIG", "Content-Approver"
            )
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                module.validate_content_ceremony_environment(
                    "ibadukefan/AutomateSTIG", "different-user"
                )

    def test_content_ceremony_run_requires_approved_commit_and_custodian_actor(self):
        import importlib.util
        import io
        from contextlib import redirect_stderr
        from unittest import mock

        spec = importlib.util.spec_from_file_location(
            "validate_release_evidence_run",
            REPO / "scripts/validate-release-evidence.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        approved = "a" * 40
        ceremony = {
            "repository": "ibadukefan/AutomateSTIG",
            "workflow_run_id": "1234",
        }
        valid_run = {
            "head_sha": approved,
            "name": "Content Signing Ceremony",
            "path": ".github/workflows/content-signing-ceremony.yml",
            "event": "workflow_dispatch",
            "conclusion": "success",
            "actor": {"login": "key-custodian"},
            "triggering_actor": {"login": "key-custodian"},
        }
        with mock.patch.dict(
            os.environ,
            {"GITHUB_REPOSITORY": "ibadukefan/AutomateSTIG"},
            clear=False,
        ), mock.patch.object(
            module, "validate_content_ceremony_environment"
        ) as environment, mock.patch.object(
            module, "validate_content_ceremony_artifact"
        ) as artifact:
            with mock.patch.object(module, "github_json", return_value=valid_run):
                module.validate_content_ceremony_workflow(
                    ceremony,
                    approved,
                    "Key-Custodian",
                    "content-approver",
                    {},
                )
            environment.assert_called_once()
            artifact.assert_called_once()
            for field, wrong_value in (
                ("head_sha", "b" * 40),
                ("name", "Lookalike Workflow"),
                ("path", ".github/workflows/lookalike.yml"),
                ("actor", {"login": "different-custodian"}),
                ("triggering_actor", {"login": "different-custodian"}),
            ):
                with self.subTest(field=field):
                    wrong = {**valid_run, field: wrong_value}
                    with mock.patch.object(module, "github_json", return_value=wrong), \
                         redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        module.validate_content_ceremony_workflow(
                            ceremony,
                            approved,
                            "key-custodian",
                            "content-approver",
                            {},
                        )

    def test_sbom_uses_workspace_version_and_target_bound_serial(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            metadata = root / "metadata.json"
            output = root / "sbom.json"
            metadata.write_text(json.dumps({
                "workspace_members": ["automatestig 0.3.0 (path+file:///test)"],
                "packages": [{
                    "id": "automatestig 0.3.0 (path+file:///test)",
                    "name": "automatestig",
                    "version": "0.3.0",
                }],
            }))
            result = run([
                "python3", REPO / "scripts/generate-cyclonedx-sbom.py",
                "--metadata", metadata,
                "--output", output,
                "--target", "x86_64-unknown-linux-gnu",
            ], root)
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(output.read_text())
            self.assertEqual(document["metadata"]["component"]["version"], "0.3.0")
            self.assertEqual(
                document["metadata"]["component"]["properties"],
                [{"name": "target", "value": "x86_64-unknown-linux-gnu"}],
            )
            self.assertNotEqual(
                document["serialNumber"],
                "urn:uuid:00000000-0000-0000-0000-000000000000",
            )

    def test_freeze_requires_label_for_product_path(self):
        for operation in ("modify", "delete"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                init_repo(root)
                (root / ".github").mkdir()
                (root / ".github/release-freeze.json").write_text(json.dumps({
                    "schema_version": 1,
                    "active": True,
                    "target_release": "v1.2.3",
                    "approval_label": "release-freeze-approved",
                    "non_product_paths": ["docs/**"],
                }))
                product = root / "product.rs"
                product.write_text("old")
                git(root, "add", ".")
                git(root, "commit", "-qm", "base")
                base = git(root, "rev-parse", "HEAD")
                product.write_text("new") if operation == "modify" else product.unlink()
                git(root, "add", ".")
                git(root, "commit", "-qm", "change")
                head = git(root, "rev-parse", "HEAD")
                event = root / "event.json"

                def invoke(labels):
                    event.write_text(json.dumps({"pull_request": {
                        "base": {"sha": base}, "head": {"sha": head},
                        "labels": [{"name": label} for label in labels],
                    }}))
                    return run(
                        ["python3", REPO / "scripts/validate-release-freeze.py", "--repo-root", root],
                        root,
                        {"GITHUB_EVENT_PATH": str(event)},
                    )

                denied = invoke([])
                self.assertNotEqual(denied.returncode, 0)
                self.assertIn("feature freeze blocks", denied.stderr)
                allowed = invoke(["release-freeze-approved"])
                self.assertEqual(allowed.returncode, 0, allowed.stderr)

    def test_freeze_policy_bootstrap_requires_declared_label(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            init_repo(root)
            (root / "README.md").write_text("base")
            git(root, "add", ".")
            git(root, "commit", "-qm", "base without freeze")
            base = git(root, "rev-parse", "HEAD")

            path = root / ".github/release-freeze.json"
            path.parent.mkdir()
            path.write_text(json.dumps({
                "schema_version": 1,
                "active": True,
                "target_release": "v1.2.3",
                "approval_label": "release-freeze-approved",
                "non_product_paths": [".github/**", "docs/**", "*.md"],
            }))
            git(root, "add", ".")
            git(root, "commit", "-qm", "bootstrap freeze")
            head = git(root, "rev-parse", "HEAD")
            command = [
                "python3",
                REPO / "scripts/validate-release-freeze.py",
                "--repo-root",
                root,
                "--base",
                base,
                "--head",
                head,
            ]

            denied = run(command, root)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("release-freeze-approved", denied.stderr)
            allowed = run(command + ["--label", "release-freeze-approved"], root)
            self.assertEqual(allowed.returncode, 0, allowed.stderr)

    def test_freeze_policy_cannot_disable_or_relabel_itself(self):
        for mutation in ("disable", "relabel", "widen"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                init_repo(root)
                path = root / ".github/release-freeze.json"
                path.parent.mkdir()
                config = {
                    "schema_version": 1,
                    "active": True,
                    "target_release": "v1.2.3",
                    "approval_label": "release-freeze-approved",
                    "non_product_paths": ["docs/**", ".github/**"],
                }
                path.write_text(json.dumps(config))
                git(root, "add", ".")
                git(root, "commit", "-qm", "base")
                base = git(root, "rev-parse", "HEAD")
                if mutation == "disable":
                    config["active"] = False
                elif mutation == "relabel":
                    config["approval_label"] = "easy-label"
                else:
                    config["non_product_paths"].append("**")
                path.write_text(json.dumps(config))
                git(root, "add", ".")
                git(root, "commit", "-qm", "weaken freeze")
                head = git(root, "rev-parse", "HEAD")
                event = root / "event.json"
                event.write_text(json.dumps({"pull_request": {
                    "base": {"sha": base}, "head": {"sha": head},
                    "labels": [{"name": "easy-label"}],
                }}))
                denied = run(
                    ["python3", REPO / "scripts/validate-release-freeze.py", "--repo-root", root],
                    root,
                    {"GITHUB_EVENT_PATH": str(event)},
                )
                self.assertNotEqual(denied.returncode, 0)
                self.assertIn("release-freeze-approved", denied.stderr)

    def test_workflow_pin_validator_rejects_mutable_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / ".github/workflows").mkdir(parents=True)
            workflow = root / ".github/workflows/ci.yml"
            workflow.write_text("steps:\n  - uses: actions/checkout@v4\n")
            command = ["python3", REPO / "scripts/validate-workflow-pins.py", "--repo-root", root]
            denied = run(command, root)
            self.assertNotEqual(denied.returncode, 0)
            workflow.write_text(
                "steps:\n  - uses: actions/checkout@" + "a" * 40 + "\n"
            )
            allowed = run(command, root)
            self.assertEqual(allowed.returncode, 0, allowed.stderr)

    def test_governance_linter_and_fuzz_bootstraps_are_pinned(self):
        workflow = (REPO / ".github/workflows/ci.yml").read_text()
        self.assertIn('branches: ["main"]', workflow)
        self.assertNotIn('branches: ["**"]', workflow)
        governance = workflow.split("  governance:", 1)[1].split(
            "  check:", 1
        )[0]
        self.assertIn('ACTIONLINT_VERSION: "1.7.12"', governance)
        self.assertIn(
            'ACTIONLINT_SHA256: "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"',
            governance,
        )
        self.assertIn("sha256sum --check -", governance)
        self.assertIn("--proto-redir '=https'", governance)
        self.assertIn(
            "github.com/rhysd/actionlint/releases/download/"
            "v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz",
            governance,
        )
        self.assertIn('"$install_dir/actionlint" -version', governance)
        self.assertIn(
            'test "$installed_version" = "$ACTIONLINT_VERSION"',
            governance,
        )
        self.assertNotIn("tool: actionlint", governance)
        self.assertIn("run: actionlint", governance)
        freeze = governance.index("- name: Enforce release feature freeze")
        self.assertLess(
            governance.index("- name: Enforce immutable workflow dependencies"),
            freeze,
        )
        self.assertLess(
            governance.index("- name: Validate release approval evidence"),
            freeze,
        )
        job = workflow.split("  archive-fuzz-smoke:", 1)[1].split(
            "  coverage-validation:", 1
        )[0]
        self.assertRegex(
            job,
            r"cargo install cargo-fuzz --locked --version \d+\.\d+\.\d+",
        )
        self.assertNotIn("tool: cargo-fuzz", job)

    def test_content_ceremony_uses_step_scoped_runner_temp(self):
        workflow = (
            REPO / ".github/workflows/content-signing-ceremony.yml"
        ).read_text()
        self.assertNotIn("CARGO_TARGET_DIR: ${{ runner.temp }}", workflow)
        self.assertIn(
            "CARGO_TARGET_DIR=${RUNNER_TEMP:?}/automatestig-content-ceremony-"
            "${GITHUB_RUN_ID:?}",
            workflow,
        )

    def test_release_evidence_allows_only_evidence_after_approval(self):
        cases = (
            (False, False, False, False),
            (True, False, False, False),
            (False, True, False, False),
            (False, False, True, False),
            (False, False, False, True),
        )
        for (
            add_unapproved_code,
            wrong_benchmark_binding,
            wrong_key_binding,
            wrong_oracle_result,
        ) in cases:
            with self.subTest(
                add_unapproved_code=add_unapproved_code,
                wrong_benchmark_binding=wrong_benchmark_binding,
                wrong_key_binding=wrong_key_binding,
                wrong_oracle_result=wrong_oracle_result,
            ), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                init_repo(root)
                (root / "schemas").mkdir()
                (root / "schemas/release-evidence.schema.json").write_bytes(
                    (REPO / "schemas/release-evidence.schema.json").read_bytes()
                )
                (root / "product.rs").write_text("reviewed")
                git(root, "add", ".")
                git(root, "commit", "-qm", "reviewed code")
                approved = git(root, "rev-parse", "HEAD")
                if add_unapproved_code:
                    (root / "product.rs").write_text("unreviewed")
                    git(root, "add", ".")
                    git(root, "commit", "-qm", "unreviewed code")

                now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                artifact_root = root / "release-evidence/artifacts/v1.2.3"
                exact_statuses = {"V-1": "notafinding"}
                status_digest = hashlib.sha256(
                    json.dumps(
                        exact_statuses, sort_keys=True, separators=(",", ":")
                    ).encode()
                ).hexdigest()
                result_template = {
                    "status": "passed",
                    "findings": 2,
                    "automated_determinations": 1,
                    "scenario_count": 2,
                    "negative_control_count": 1,
                    "negative_finding_count": 1,
                    "benchmark_sha256": "1" * 64,
                    "benchmark_rule_set_sha256": "2" * 64,
                    "automated_vuln_set_sha256": "3" * 64,
                    "check_pack_sha256": "4" * 64,
                    "input_sha256": "a" * 64,
                    "source_state_sha256": "b" * 64,
                    "scenario_bindings_sha256": "d" * 64,
                    "oracle_sha256": "c" * 64,
                    "oracle_adjudicated_at": now,
                    "oracle_adjudicator": "independent-reviewer",
                    "oracle_expected_status_sha256": status_digest,
                    "observed_status_sha256": status_digest,
                }
                if wrong_oracle_result:
                    result_template["observed_status_sha256"] = "f" * 64
                benchmark_identity = {
                    "ontap": ("NetApp_ONTAP_DSC_9-x_STIG", "V2R2"),
                    "freebsd": ("General_Purpose_Operating_System", "V3R3"),
                    "cisco_ios_xe": ("Cisco_IOS-XE_Router_NDM_STIG", "V3R7"),
                }
                if wrong_benchmark_binding:
                    benchmark_identity["ontap"] = (
                        "NetApp_ONTAP_DSC_9-x_STIG",
                        "V1R1",
                    )
                device_path = artifact_root / "devices.json"
                device_sha = write_json_artifact(device_path, {
                    "schema": "automatestig-live-device-acceptance/v1",
                    "passed": True,
                    "executed_at": now,
                    "source_commit": approved,
                    "repository": "ibadukefan/AutomateSTIG",
                    "workflow_run_id": "1001",
                    "protected_environment": "live-device-acceptance",
                    "binary_sha256": "0" * 64,
                    "results": [
                        {
                            **result_template,
                            "target": target,
                            "stig_id": benchmark_identity[target][0],
                            "stig_release": benchmark_identity[target][1],
                        }
                        for target in ("ontap", "freebsd", "cisco_ios_xe")
                    ],
                })
                viewer_path = artifact_root / "stig-viewer.json"
                viewer_sha = write_json_artifact(viewer_path, {
                    "schema": "automatestig-stig-viewer-acceptance/v1",
                    "passed": True,
                    "tested_at": now,
                    "source_commit": approved,
                    "repository": "ibadukefan/AutomateSTIG",
                    "workflow_run_id": "1002",
                    "protected_environment": "external-acceptance",
                    "product_version": "3.5",
                    "platform": "test",
                    "operator": "viewer-operator",
                    "automatestig_cli_sha256": "d" * 64,
                    "cases": [
                        {
                            "format": kind,
                            "status": "passed",
                            "finding_count": 2,
                            "source_sha256": "5" * 64,
                            "roundtrip_sha256": "6" * 64,
                            "semantic_sha256": "7" * 64,
                            "rule_set_sha256": "e" * 64,
                        }
                        for kind in ("ckl", "cklb")
                    ],
                })
                manager_path = artifact_root / "stig-manager.json"
                manager_sha = write_json_artifact(manager_path, {
                    "schema": "automatestig-stig-manager-acceptance/v1",
                    "passed": True,
                    "tested_at": now,
                    "source_commit": approved,
                    "repository": "ibadukefan/AutomateSTIG",
                    "workflow_run_id": "1003",
                    "protected_environment": "external-acceptance",
                    "product_version": "1.6.13+1",
                    "environment": "test",
                    "automatestig_gui_sha256": "f" * 64,
                    "benchmark_sha256": "1" * 64,
                    "config_fixture_sha256": "2" * 64,
                    "checks": [{"name": "exact reviews", "passed": True}],
                    "metrics": {
                        "review_count": 2,
                        "source_finding_count": 2,
                        "rule_set_sha256": "8" * 64,
                        "benchmark_id": "Cisco_IOS-XE_Router_NDM_STIG",
                    },
                })
                recovery_path = artifact_root / "recovery.json"
                recovery_sha = write_json_artifact(recovery_path, {
                    "schema": "automatestig-transaction-recovery-drill/v1",
                    "passed": True,
                    "executed_at": now,
                    "source_commit": approved,
                    "repository": "ibadukefan/AutomateSTIG",
                    "workflow_run_id": "1004",
                    "tracked_worktree_dirty": False,
                    "output_sha256": "c" * 64,
                    "required_scenarios": [{"name": "rollback", "observed": True}],
                })
                public_key_path = artifact_root / "content-signing-public-key.pub"
                public_key_path.write_bytes(b"B" * 32)
                public_key_sha = hashlib.sha256(public_key_path.read_bytes()).hexdigest()
                test_pack_path = artifact_root / "content-signing-test-pack.stigpack"
                test_pack_path.write_bytes(b"small-signed-test-pack")
                test_pack_sha = hashlib.sha256(test_pack_path.read_bytes()).hexdigest()
                ceremony_path = artifact_root / "content-signing-ceremony.json"
                ceremony_sha = write_json_artifact(ceremony_path, {
                    "schema": "automatestig-content-signing-ceremony/v1",
                    "passed": True,
                    "signature_verified": True,
                    "completed_at": now,
                    "source_commit": approved,
                    "repository": "ibadukefan/AutomateSTIG",
                    "workflow_run_id": "1005",
                    "protected_environment": "content-signing-ceremony",
                    "automatestig_cli_sha256": "d" * 64,
                    "public_key_filename": "content-signing-public-key.pub",
                    "public_key_sha256": "0" * 64 if wrong_key_binding else public_key_sha,
                    "public_key_fingerprint": f"SHA256:{public_key_sha}",
                    "test_pack_filename": "content-signing-test-pack.stigpack",
                    "pack_sha256": test_pack_sha,
                    "participants": [
                        {"role": "key_custodian", "github_login": "key-custodian"},
                        {"role": "content_approver", "github_login": "content-approver"},
                    ],
                })

                def gate(path, digest, version):
                    return {
                    "status": "passed",
                    "executed_at": now,
                    "environment": "test",
                    "version": version,
                    "evidence_reference": path.relative_to(root).as_posix(),
                    "evidence_sha256": digest,
                    }

                document = {
                    "schema": "automatestig-release-evidence/v1",
                    "tag": "v1.2.3",
                    "approved_commit": approved,
                    "approved_at": now,
                    "pull_request": 42,
                    "reviewers": [
                        {"role": "software", "github_login": "software-reviewer", "approved_at": now},
                        {"role": "security", "github_login": "security-reviewer", "approved_at": now},
                    ],
                    "acceptance": {
                        "ontap": gate(device_path, device_sha, "V2R2"),
                        "freebsd": gate(device_path, device_sha, "V3R3"),
                        "cisco_ios_xe": gate(device_path, device_sha, "V3R7"),
                        "stig_viewer": gate(viewer_path, viewer_sha, "3.5"),
                        "stig_manager": gate(manager_path, manager_sha, "1.6.13+1"),
                    },
                    "recovery_drill": gate(recovery_path, recovery_sha, "v1"),
                    "content_signing_key": {
                        "fingerprint_sha256": public_key_sha,
                        "ceremony_reference": ceremony_path.relative_to(root).as_posix(),
                        "ceremony_sha256": ceremony_sha,
                        "public_key_reference": public_key_path.relative_to(root).as_posix(),
                        "public_key_sha256": public_key_sha,
                        "test_pack_reference": test_pack_path.relative_to(root).as_posix(),
                        "test_pack_sha256": test_pack_sha,
                    },
                    "risk_acceptances": [],
                }
                evidence = root / "release-evidence/v1.2.3.json"
                evidence.parent.mkdir(exist_ok=True)
                evidence.write_text(json.dumps(document))
                git(root, "add", ".")
                git(root, "commit", "-qm", "release evidence")
                result = run(
                    [
                        "python3", REPO / "scripts/validate-release-evidence.py",
                        "--repo-root", root,
                        "--tag", "v1.2.3",
                        "--offline",
                    ],
                    root,
                )
                if add_unapproved_code:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("changes after approved_commit", result.stderr)
                elif wrong_benchmark_binding:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("must bind ontap", result.stderr)
                elif wrong_key_binding:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("exact public key", result.stderr)
                elif wrong_oracle_result:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("independent oracle", result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_release_manifest_validates_bound_companions(self):
        targets = {
            "x86_64-unknown-linux-gnu": "tar.gz",
            "aarch64-unknown-linux-gnu": "tar.gz",
            "x86_64-pc-windows-msvc": "zip",
            "x86_64-apple-darwin": "tar.gz",
            "aarch64-apple-darwin": "tar.gz",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            commit = "c" * 40
            run_id = "1234"
            package_id = "automatestig 0.3.0 (path+file:///test)"
            inventory = {
                "workspace_members": [package_id],
                "packages": [{"id": package_id, "name": "automatestig", "version": "0.3.0"}],
            }
            for target, extension in targets.items():
                package = root / f"automatestig-v0.3.0-{target}.{extension}"
                package.write_bytes(f"archive:{target}".encode())
                archive_hash = hashlib.sha256(package.read_bytes()).hexdigest()
                pathlib.Path(f"{package}.sha256").write_text(f"{archive_hash}  {package.name}\n")
                pathlib.Path(f"{package}.sigstore.bundle").write_text("{}\n")
                (root / f"cargo-metadata-{target}.json").write_text(json.dumps(inventory))
                (root / f"automatestig-{target}.cdx.json").write_text(json.dumps({
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {"component": {
                        "name": "automatestig",
                        "version": "0.3.0",
                        "properties": [{"name": "target", "value": target}],
                    }},
                    "components": [{"name": "serde", "version": "1"}],
                }))
                (root / f"provenance-{target}.json").write_text(json.dumps({
                    "artifact": package.name,
                    "target": target,
                    "repository": "ibadukefan/AutomateSTIG",
                    "ref": "refs/tags/v0.3.0",
                    "sha": commit,
                    "workflow": "CI",
                    "run_id": run_id,
                    "sbom": f"automatestig-{target}.cdx.json",
                }))

            command = [
                "python3", REPO / "scripts/generate-release-manifest.py",
                "--artifact-dir", root,
                "--tag", "v0.3.0",
                "--repository", "ibadukefan/AutomateSTIG",
                "--commit", commit,
                "--run-id", run_id,
                "--output", root / "release-manifest.json",
            ]
            accepted = run(command, root)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(
                len(json.loads((root / "release-manifest.json").read_text())["artifacts"]),
                5,
            )

            (root / "release-manifest.json").unlink()
            unexpected = root / "undeclared-release-asset.txt"
            unexpected.write_text("must not be published")
            denied = run(command, root)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("artifact set is not closed", denied.stderr)
            unexpected.unlink()

            provenance = root / "provenance-x86_64-unknown-linux-gnu.json"
            corrupted = json.loads(provenance.read_text())
            corrupted["sha"] = "d" * 40
            provenance.write_text(json.dumps(corrupted))
            denied = run(command, root)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("mismatched release fields", denied.stderr)


if __name__ == "__main__":
    unittest.main()
