import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
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
    @staticmethod
    def first_use_study(*, completed=4, assisted=frozenset(), documented=frozenset()):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        participants = []
        for index in range(5):
            participants.append(
                {
                    "participant_id": f"P{index + 1:02d}",
                    "role": (
                        "cybersecurity_analyst"
                        if index < 3
                        else "cybersecurity_manager"
                    ),
                    "role_experience_band": (
                        "less_than_2_years"
                        if index < 2
                        else "more_than_5_years"
                    ),
                    "first_time_user": True,
                    "completed_prepared_scan": index < completed,
                    "external_documentation_used": index in documented,
                    "assistance_received": index in assisted,
                    "outcome_notes": "Observed task outcome.",
                }
            )
        numerator = sum(
            item["completed_prepared_scan"]
            and not item["external_documentation_used"]
            and not item["assistance_received"]
            for item in participants
        )
        return {
            "schema": "automatestig-first-use-ux-study/v1",
            "passed": numerator * 100 >= len(participants) * 80,
            "executed_at": now,
            "source_commit": "a" * 40,
            "product_version": "v1.2.3",
            "repository": "ibadukefan/AutomateSTIG",
            "workflow_run_id": "1234",
            "protected_environment": "first-use-ux-study",
            "automatestig_gui_sha256": "b" * 64,
            "scenario": {
                "id": "prepared-cisco-scan",
                "version": "1",
                "target_profile": "cisco-ios-xe-router-ndm",
                "prepared_scan_fixture_sha256": "c" * 64,
                "task_definition_sha256": "d" * 64,
            },
            "representative_roles": [
                "cybersecurity_analyst",
                "cybersecurity_manager",
            ],
            "study_team": {
                role: {"github_login": login, "attested_at": now}
                for role, login in (
                    ("facilitator", "study-facilitator"),
                    ("independent_observer", "study-observer"),
                    ("independent_approver", "study-approver"),
                )
            },
            "participants": participants,
            "metrics": {
                "numerator": numerator,
                "denominator": len(participants),
                "required_threshold_percent": 80,
            },
        }

    def test_first_use_study_recomputes_full_cohort_and_fails_honestly(self):
        script = REPO / "scripts/validate-release-evidence.py"
        spec = importlib.util.spec_from_file_location(
            "validate_release_first_use", script
        )
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        passing = self.first_use_study()
        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            seconds=1
        )
        team = validator.validate_first_use_study(
            passing,
            "study",
            "a" * 40,
            "v1.2.3",
            now,
            True,
        )
        self.assertEqual(team["independent_observer"], "study-observer")

        failed = self.first_use_study(completed=3)
        validator.validate_first_use_study(
            failed,
            "study",
            "a" * 40,
            "v1.2.3",
            now,
            False,
        )
        with self.assertRaises(SystemExit):
            validator.validate_first_use_study(
                failed,
                "study",
                "a" * 40,
                "v1.2.3",
                now,
                True,
            )

        dishonest = self.first_use_study(completed=5, assisted=frozenset({0}))
        dishonest["metrics"]["numerator"] = 5
        dishonest["passed"] = True
        with self.assertRaises(SystemExit):
            validator.validate_first_use_study(
                dishonest,
                "study",
                "a" * 40,
                "v1.2.3",
                now,
                False,
            )

    def test_first_use_study_rejects_unrepresentative_or_mutable_identity(self):
        script = REPO / "scripts/validate-release-evidence.py"
        spec = importlib.util.spec_from_file_location(
            "validate_release_first_use_identity", script
        )
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            seconds=1
        )
        mutations = (
            lambda value: value["participants"].__setitem__(
                4, {**value["participants"][4], "role": "cybersecurity_analyst"}
            ),
            lambda value: value["participants"][0].__setitem__(
                "first_time_user", False
            ),
            lambda value: value["participants"][1].__setitem__(
                "participant_id", "P01"
            ),
            lambda value: value["study_team"]["independent_approver"].__setitem__(
                "github_login", "study-observer"
            ),
            lambda value: value.__setitem__("product_version", "v1.2.4"),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                study = self.first_use_study()
                mutate(study)
                with self.assertRaises(SystemExit):
                    validator.validate_first_use_study(
                        study,
                        "study",
                        "a" * 40,
                        "v1.2.3",
                        now,
                        False,
                    )

    def test_first_use_workflow_preserves_external_human_gate(self):
        workflow = (
            REPO / ".github/workflows/first-use-ux-study.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("environment: first-use-ux-study", workflow)
        self.assertIn("automatestig-first-use-study", workflow)
        self.assertIn("--gui-binary target/release/automatestig-gui", workflow)
        self.assertIn("--require-passed", workflow)
        self.assertLess(
            workflow.index("Upload the honest pass or failure record"),
            workflow.index("Require at least 80 percent"),
        )
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("schedule:", workflow)
        release_schema = json.loads(
            (REPO / "schemas/release-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn("first_use_ux", release_schema["required"])

    def test_first_use_environment_binds_observer_and_distinct_approver(self):
        import io
        from contextlib import redirect_stderr
        from unittest import mock

        spec = importlib.util.spec_from_file_location(
            "validate_release_first_use_environment",
            REPO / "scripts/validate-release-evidence.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        environment = {
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {
                            "type": "User",
                            "reviewer": {"login": "study-approver"},
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
                "user": {"login": "study-approver"},
                "environments": [{"name": "first-use-ux-study"}],
            }
        ]
        jobs = {
            "total_count": 1,
            "jobs": [
                {
                    "name": "Independent first-use study attestation",
                    "conclusion": "success",
                    "labels": [
                        "self-hosted",
                        "Linux",
                        "X64",
                        "automatestig-first-use-study",
                    ],
                    "runner_id": 7,
                    "runner_name": "ux-lab-runner",
                }
            ],
        }
        run_record = {
            "id": 1234,
            "actor": {"login": "study-observer"},
            "triggering_actor": {"login": "study-observer"},
            "run_attempt": 1,
        }

        def response(endpoint):
            if endpoint.endswith("/environments/first-use-ux-study"):
                return environment
            if endpoint.endswith("/approvals"):
                return approvals
            if "/jobs?" in endpoint:
                return jobs
            raise AssertionError(endpoint)

        with mock.patch.object(module, "github_json", side_effect=response):
            module.validate_first_use_study_environment(
                "ibadukefan/AutomateSTIG",
                "study-observer",
                "study-approver",
                run_record,
                "first_use_ux",
            )
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                module.validate_first_use_study_environment(
                    "ibadukefan/AutomateSTIG",
                    "study-observer",
                    "study-observer",
                    run_record,
                    "first_use_ux",
                )

    def test_first_use_cli_binds_exact_gui_and_protected_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "schemas").mkdir()
            for name in (
                "release-evidence.schema.json",
                "first-use-ux-study.schema.json",
                "handoff-key-custody-ceremony.schema.json",
                "handoff-receiver-ceremony.schema.json",
            ):
                shutil.copyfile(REPO / "schemas" / name, root / "schemas" / name)
            gui = root / "automatestig-gui"
            gui.write_bytes(b"exact-tested-gui")
            study = self.first_use_study()
            study["automatestig_gui_sha256"] = hashlib.sha256(
                gui.read_bytes()
            ).hexdigest()
            source = root / "study.json"
            source.write_text(json.dumps(study), encoding="utf-8")
            output = root / "normalized.json"
            result = run(
                [
                    "python3",
                    REPO / "scripts/validate-release-evidence.py",
                    "--repo-root",
                    root,
                    "--first-use-study",
                    source,
                    "--source-commit",
                    "a" * 40,
                    "--product-version",
                    "v1.2.3",
                    "--gui-binary",
                    gui,
                    "--output",
                    output,
                ],
                root,
                {
                    "GITHUB_REPOSITORY": "ibadukefan/AutomateSTIG",
                    "GITHUB_RUN_ID": "9876",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            normalized = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(normalized["workflow_run_id"], "9876")
            self.assertEqual(
                normalized["automatestig_gui_sha256"],
                hashlib.sha256(gui.read_bytes()).hexdigest(),
            )

            gui.write_bytes(b"different-gui")
            mismatch = run(
                [
                    "python3",
                    REPO / "scripts/validate-release-evidence.py",
                    "--repo-root",
                    root,
                    "--first-use-study",
                    output,
                    "--source-commit",
                    "a" * 40,
                    "--product-version",
                    "v1.2.3",
                    "--gui-binary",
                    gui,
                    "--require-passed",
                ],
                root,
                {
                    "GITHUB_REPOSITORY": "ibadukefan/AutomateSTIG",
                    "GITHUB_RUN_ID": "9876",
                },
            )
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertIn("exact tested binary", mismatch.stderr)

    def test_release_ssh_fingerprint_regex_requires_canonical_base64(self):
        script = REPO / "scripts/validate-release-evidence.py"
        spec = importlib.util.spec_from_file_location(
            "validate_release_evidence", script
        )
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)

        self.assertIsNotNone(
            validator.SSH_SERVER_KEY_FINGERPRINT.fullmatch(
                "SHA256:" + ("A" * 43)
            )
        )
        self.assertIsNone(
            validator.SSH_SERVER_KEY_FINGERPRINT.fullmatch(
                "SHA256:" + ("A" * 42) + "B"
            )
        )

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

    def test_supported_installers_bind_archive_name_and_tagged_workflow_identity(self):
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
        self.assertIn(
            "does not currently publish or support Windows release binaries",
            windows,
        )
        self.assertIn("source-portability testing only", windows)
        self.assertNotIn("Invoke-WebRequest", windows)

        for documentation in (REPO / "README.md", REPO / "docs/installation.md"):
            with self.subTest(documentation=documentation.name):
                text = documentation.read_text(encoding="utf-8")
                self.assertNotIn(
                    "raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-",
                    text,
                )
                self.assertIn("gh release verify", text)
                self.assertIn("AutomateSTIG/$version/install-", text)

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
                for binary in (
                    "automatestig",
                    "automatestig-gui",
                    "automatestig-backup-restore",
                ):
                    path = payload / binary
                    path.write_text("#!/bin/sh\nexit 0\n")
                    path.chmod(0o755)
                for document in (
                    "README.md",
                    "LICENSE",
                    "quickstart.md",
                    "installation.md",
                ):
                    (payload / document).write_text(f"test {document}\n")

                archive_name = f"automatestig-v0.3.0-{target}.tar.gz"
                archive = fixture / archive_name
                members = [
                    "automatestig",
                    "automatestig-gui",
                    "automatestig-backup-restore",
                    "README.md",
                    "LICENSE",
                    "quickstart.md",
                    "installation.md",
                ]
                packed = run(
                    ["tar", "-czf", archive, "-C", payload, *members], root
                )
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
                self.assertTrue(
                    (install_dir / "automatestig-backup-restore").is_file()
                )
                invocation = log.read_text()
                self.assertIn(f"--bundle ", invocation)
                self.assertIn(f"{archive_name}.sigstore.bundle", invocation)
                self.assertIn(
                    "https://github.com/ibadukefan/AutomateSTIG/"
                    ".github/workflows/ci.yml@refs/tags/v0.3.0",
                    invocation,
                )

                # A failure while publishing the final tool must restore the
                # complete prior toolset instead of leaving old/new entry points.
                old_cli = b"old-cli-version\n"
                old_gui = b"old-gui-version\n"
                old_backup_tool = b"old-backup-tool-version\n"
                (install_dir / "automatestig").write_bytes(old_cli)
                (install_dir / "automatestig-gui").write_bytes(old_gui)
                (install_dir / "automatestig-backup-restore").write_bytes(
                    old_backup_tool
                )
                real_mv = shutil.which("mv", path=os.environ["PATH"])
                self.assertIsNotNone(real_mv)
                mv_wrapper = fake_bin / "mv"
                mv_wrapper.write_text("""#!/bin/sh
if [ "${FAKE_MV_FAIL_DEST:-}" = "${2:-}" ] && [ ! -e "$FAKE_MV_FAILURE_MARKER" ]; then
  : > "$FAKE_MV_FAILURE_MARKER"
  if [ "${FAKE_MV_SIGNAL_PARENT:-0}" -eq 1 ]; then
    kill -TERM "$PPID"
  fi
  exit 73
fi
exec "$REAL_MV" "$@"
""")
                mv_wrapper.chmod(0o755)
                marker = root / "mv-failed-once"
                interrupted = run(
                    ["sh", REPO / installer],
                    root,
                    {
                        **env,
                        "FAKE_MV_FAIL_DEST": str(
                            install_dir / "automatestig-backup-restore"
                        ),
                        "FAKE_MV_FAILURE_MARKER": str(marker),
                        "REAL_MV": real_mv,
                    },
                )
                self.assertNotEqual(interrupted.returncode, 0)
                self.assertEqual((install_dir / "automatestig").read_bytes(), old_cli)
                self.assertEqual((install_dir / "automatestig-gui").read_bytes(), old_gui)
                self.assertEqual(
                    (install_dir / "automatestig-backup-restore").read_bytes(),
                    old_backup_tool,
                )
                self.assertEqual(
                    list(install_dir.glob(".automatestig-install.*")),
                    [],
                    interrupted.stderr,
                )

                signal_marker = root / "mv-signaled-once"
                signaled = run(
                    ["sh", REPO / installer],
                    root,
                    {
                        **env,
                        "FAKE_MV_FAIL_DEST": str(install_dir / "automatestig-gui"),
                        "FAKE_MV_FAILURE_MARKER": str(signal_marker),
                        "FAKE_MV_SIGNAL_PARENT": "1",
                        "REAL_MV": real_mv,
                    },
                )
                self.assertNotEqual(signaled.returncode, 0)
                self.assertEqual((install_dir / "automatestig").read_bytes(), old_cli)
                self.assertEqual((install_dir / "automatestig-gui").read_bytes(), old_gui)
                self.assertEqual(
                    (install_dir / "automatestig-backup-restore").read_bytes(),
                    old_backup_tool,
                )
                self.assertEqual(
                    list(install_dir.glob(".automatestig-install.*")),
                    [],
                    signaled.stderr,
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

                # Even a correctly hashed and signed archive is rejected before
                # extraction if its closed member set changes.
                (payload / "unexpected-helper").write_text("not shipped\n")
                malicious = run(
                    [
                        "tar",
                        "-czf",
                        archive,
                        "-C",
                        payload,
                        *members,
                        "unexpected-helper",
                    ],
                    root,
                )
                self.assertEqual(malicious.returncode, 0, malicious.stderr)
                archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
                (fixture / f"{archive_name}.sha256").write_text(
                    f"{archive_hash}  {archive_name}\n"
                )
                unsafe_dir = root / "unsafe-archive-install"
                unsafe = run(
                    ["sh", REPO / installer],
                    root,
                    {**env, "AUTOMATESTIG_INSTALL_DIR": str(unsafe_dir)},
                )
                self.assertNotEqual(unsafe.returncode, 0)
                self.assertIn("unsafe or unexpected members", unsafe.stderr)
                self.assertFalse(unsafe_dir.exists())

                python_wrapper = fake_bin / "python3"
                python_wrapper.write_text("#!/bin/sh\nexit 1\n")
                python_wrapper.chmod(0o755)
                unsupported_dir = root / "unsupported-python"
                unsupported = run(
                    ["sh", REPO / installer],
                    root,
                    {
                        **env,
                        "AUTOMATESTIG_INSTALL_DIR": str(unsupported_dir),
                    },
                )
                self.assertNotEqual(unsupported.returncode, 0)
                self.assertIn(
                    "Python 3.10 or newer is required",
                    unsupported.stderr,
                )
                self.assertFalse(unsupported_dir.exists())

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

    def test_first_use_workflow_artifact_is_exact_and_bounded(self):
        import io
        import zipfile
        from contextlib import redirect_stderr
        from unittest import mock

        spec = importlib.util.spec_from_file_location(
            "validate_release_first_use_artifact",
            REPO / "scripts/validate-release-evidence.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        evidence = json.dumps(self.first_use_study()).encode() + b"\n"

        def archive(files):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
                for name, value in files.items():
                    bundle.writestr(name, value)
            return output.getvalue()

        archive_bytes = archive({"first-use-ux-study.json": evidence})
        metadata = {
            "total_count": 1,
            "artifacts": [
                {
                    "id": 99,
                    "name": "first-use-ux-study-1234",
                    "expired": False,
                    "size_in_bytes": len(archive_bytes),
                }
            ],
        }
        with (
            mock.patch.object(module, "github_json", return_value=metadata),
            mock.patch.object(module, "github_bytes", return_value=archive_bytes),
        ):
            module.validate_workflow_artifact(
                "ibadukefan/AutomateSTIG",
                "1234",
                "first_use_ux",
                hashlib.sha256(evidence).hexdigest(),
            )
        extra = archive(
            {
                "first-use-ux-study.json": evidence,
                "participant-identities.csv": b"must not be uploaded",
            }
        )
        with (
            mock.patch.object(module, "github_json", return_value=metadata),
            mock.patch.object(module, "github_bytes", return_value=extra),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            module.validate_workflow_artifact(
                "ibadukefan/AutomateSTIG",
                "1234",
                "first_use_ux",
                hashlib.sha256(evidence).hexdigest(),
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

    def test_live_device_environment_binds_adjudicator_and_distinct_dispatcher(self):
        import importlib.util
        import io
        from contextlib import redirect_stderr
        from unittest import mock

        spec = importlib.util.spec_from_file_location(
            "validate_live_device_environment",
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
                    "reviewer": {"login": "independent-reviewer"},
                }],
            }],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
        run = {
            "id": 1234,
            "run_attempt": 1,
            "actor": {"login": "lab-operator"},
            "triggering_actor": {"login": "lab-operator"},
        }
        approval = [{
            "state": "approved",
            "environments": [{"name": "live-device-acceptance"}],
            "user": {"login": "independent-reviewer"},
        }]
        jobs = {
            "total_count": 1,
            "jobs": [{
                "name": "all collection and evaluation",
                "conclusion": "success",
                "labels": [
                    "self-hosted",
                    "Linux",
                    "X64",
                    "automatestig-live-devices",
                ],
                "runner_id": 42,
                "runner_name": "lab-runner-01",
            }],
        }

        def github_response(endpoint):
            if endpoint.endswith("/approvals"):
                return approval
            if "/jobs?" in endpoint:
                return jobs
            return environment

        with mock.patch.object(module, "github_json", side_effect=github_response):
            module.validate_live_device_environment(
                "ibadukefan/AutomateSTIG",
                "Independent-Reviewer",
                run,
                "acceptance.ontap",
            )
            for bad_run in (
                {**run, "actor": {"login": "independent-reviewer"}},
                {**run, "triggering_actor": {"login": "other-operator"}},
            ):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    module.validate_live_device_environment(
                        "ibadukefan/AutomateSTIG",
                        "independent-reviewer",
                        bad_run,
                        "acceptance.ontap",
                    )
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                module.validate_live_device_environment(
                    "ibadukefan/AutomateSTIG",
                    "other-reviewer",
                    run,
                    "acceptance.ontap",
                )
            wrong_architecture = {
                **jobs,
                "jobs": [{
                    **jobs["jobs"][0],
                    "labels": [
                        "self-hosted",
                        "Linux",
                        "automatestig-live-devices",
                    ],
                }],
            }
            with mock.patch.object(
                module,
                "github_json",
                side_effect=lambda endpoint: (
                    approval
                    if endpoint.endswith("/approvals")
                    else wrong_architecture
                    if "/jobs?" in endpoint
                    else environment
                ),
            ), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                module.validate_live_device_environment(
                    "ibadukefan/AutomateSTIG",
                    "independent-reviewer",
                    run,
                    "acceptance.ontap",
                )
            bad_approval = [{**approval[0], "user": {"login": "other-reviewer"}}]
            with mock.patch.object(
                module,
                "github_json",
                side_effect=lambda endpoint: (
                    bad_approval
                    if endpoint.endswith("/approvals")
                    else jobs if "/jobs?" in endpoint else environment
                ),
            ), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                module.validate_live_device_environment(
                    "ibadukefan/AutomateSTIG",
                    "independent-reviewer",
                    run,
                    "acceptance.ontap",
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

    def test_required_status_checks_are_bound_to_github_actions(self):
        import importlib.util
        import io
        from contextlib import redirect_stderr

        spec = importlib.util.spec_from_file_location(
            "validate_release_evidence_status_bindings",
            REPO / "scripts/validate-release-evidence.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        valid = {
            "checks": [
                {
                    "context": context,
                    "app_id": module.GITHUB_ACTIONS_APP_ID,
                }
                for context in sorted(module.REQUIRED_STATUS_CONTEXTS)
            ],
        }
        module.validate_required_status_bindings(valid)

        cases = {
            "unbound": {
                "checks": [
                    {**item, "app_id": None}
                    if index == 0
                    else item
                    for index, item in enumerate(valid["checks"])
                ],
            },
            "missing": {"checks": valid["checks"][1:]},
            "duplicate": {"checks": [*valid["checks"], valid["checks"][0]]},
        }
        for name, value in cases.items():
            with (
                self.subTest(name=name),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                module.validate_required_status_bindings(value)

    def test_required_frontend_status_context_matches_ci_and_documentation(self):
        spec = importlib.util.spec_from_file_location(
            "validate_release_evidence_frontend_context",
            REPO / "scripts/validate-release-evidence.py",
        )
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)

        expected = "Scanner frontend contracts"
        self.assertIn(expected, validator.REQUIRED_STATUS_CONTEXTS)
        self.assertNotIn("Frontend syntax", validator.REQUIRED_STATUS_CONTEXTS)

        workflow = (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        frontend_job = workflow.split("  frontend-syntax:", 1)[1].split(
            "  archive-fuzz-smoke:", 1
        )[0]
        self.assertIn(f"name: {expected}", frontend_job)

        release_process = (REPO / "docs/release-process.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"exactly `{expected}`", release_process)

    def test_release_tag_ruleset_requires_exact_singleton_authority(self):
        import importlib.util
        import io
        from contextlib import redirect_stderr

        spec = importlib.util.spec_from_file_location(
            "validate_release_evidence_tag_authority",
            REPO / "scripts/validate-release-evidence.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        authority = dict(module.RELEASE_TAG_AUTHORITY)
        module.validate_release_tag_authority({"bypass_actors": [authority]})

        cases = {
            "wrong actor": {**authority, "actor_id": authority["actor_id"] + 1},
            "broad role": {**authority, "actor_type": "RepositoryRole"},
            "wrong mode": {**authority, "bypass_mode": "pull_request"},
        }
        for name, actor in cases.items():
            with (
                self.subTest(name=name),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                module.validate_release_tag_authority({"bypass_actors": [actor]})
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            module.validate_release_tag_authority(
                {"bypass_actors": [authority, authority]}
            )

        closed = {
            "conditions": {
                "ref_name": {
                    "include": ["refs/tags/v*"],
                    "exclude": [],
                }
            },
            "rules": [
                {"type": "creation"},
                {"type": "update"},
                {"type": "deletion"},
            ],
        }
        self.assertTrue(module.is_closed_release_tag_ruleset(closed))
        excluded = {
            **closed,
            "conditions": {
                "ref_name": {
                    "include": ["refs/tags/v*"],
                    "exclude": ["refs/tags/v*"],
                }
            },
        }
        self.assertFalse(module.is_closed_release_tag_ruleset(excluded))

    def test_release_security_json_rejects_duplicate_members_recursively(self):
        for filename in (
            "validate-release-evidence.py",
            "generate-cyclonedx-sbom.py",
            "generate-release-manifest.py",
            "generate-release-provenance.py",
        ):
            with self.subTest(script=filename):
                spec = importlib.util.spec_from_file_location(
                    f"unique_json_{filename.replace('-', '_').replace('.', '_')}",
                    REPO / "scripts" / filename,
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                for raw in (
                    '{"schema":"one","schema":"two"}',
                    '{"outer":{"value":1,"value":2}}',
                ):
                    with self.assertRaisesRegex(
                        ValueError, "duplicate JSON member"
                    ):
                        module.strict_json_loads(raw)

    def test_sbom_uses_workspace_version_and_target_bound_serial(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            metadata = root / "metadata.json"
            output = root / "sbom.json"
            application_id = "automatestig 0.3.0 (path+file:///test)"
            dependency_id = "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0"
            metadata.write_text(json.dumps({
                "workspace_root": str(root),
                "workspace_members": [application_id],
                "packages": [
                    {
                        "id": application_id,
                        "name": "automatestig",
                        "version": "0.3.0",
                        "repository": "https://github.com/ibadukefan/AutomateSTIG",
                    },
                    {
                        "id": dependency_id,
                        "name": "serde",
                        "version": "1.0.0",
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                    },
                ],
                "resolve": {
                    "nodes": [
                        {
                            "id": application_id,
                            "dependencies": [dependency_id],
                            "deps": [{"name": "serde", "pkg": dependency_id}],
                        },
                        {"id": dependency_id, "dependencies": [], "deps": []},
                    ]
                },
            }))
            (root / "Cargo.lock").write_text("""version = 4

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abababababababababababababababababababababababababababababababab"
""")
            archive = root / "automatestig-v0.3.0-x86_64-unknown-linux-gnu.tar.gz"
            archive.write_bytes(b"release archive")
            archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            cli_sha = hashlib.sha256(b"cli").hexdigest()
            gui_sha = hashlib.sha256(b"gui").hexdigest()
            backup_sha = hashlib.sha256(b"backup").hexdigest()
            equivalence = root / "release-equivalence-x86_64-unknown-linux-gnu.json"
            equivalence.write_text(json.dumps({
                "schema": "automatestig-release-artifact-equivalence/v1",
                "target": "x86_64-unknown-linux-gnu",
                "version": "0.3.0",
                "source_commit": "a" * 40,
                "archive": {
                    "name": archive.name,
                    "sha256": archive_sha,
                    "size": archive.stat().st_size,
                    "format": "tar.gz",
                },
                "binaries": {
                    "cli": {
                        "name": "automatestig",
                        "pre_package_sha256": cli_sha,
                        "archive_member_sha256": cli_sha,
                        "size": 3,
                    },
                    "gui": {
                        "name": "automatestig-gui",
                        "pre_package_sha256": gui_sha,
                        "archive_member_sha256": gui_sha,
                        "size": 3,
                    },
                },
                "operational_tools": {
                    "backup_restore": {
                        "name": "automatestig-backup-restore",
                        "pre_package_sha256": backup_sha,
                        "archive_member_sha256": backup_sha,
                        "size": 6,
                    }
                },
            }))
            result = run([
                "python3", REPO / "scripts/generate-cyclonedx-sbom.py",
                "--metadata", metadata,
                "--output", output,
                "--target", "x86_64-unknown-linux-gnu",
                "--equivalence-manifest", equivalence,
                "--archive", archive,
            ], root)
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(output.read_text())
            self.assertEqual(document["metadata"]["component"]["version"], "0.3.0")
            self.assertIn(
                {"name": "target", "value": "x86_64-unknown-linux-gnu"},
                document["metadata"]["component"]["properties"],
            )
            self.assertIn(
                {
                    "name": "automatestig:transition-cli-included",
                    "value": "false",
                },
                document["metadata"]["component"]["properties"],
            )
            self.assertIn(
                {
                    "name": "automatestig:release-archive-sha256",
                    "value": archive_sha,
                },
                document["metadata"]["component"]["properties"],
            )
            self.assertNotEqual(
                document["serialNumber"],
                "urn:uuid:00000000-0000-0000-0000-000000000000",
            )
            components = {item["name"]: item for item in document["components"]}
            self.assertEqual(
                components["serde"]["hashes"],
                [{"alg": "SHA-256", "content": "ab" * 32}],
            )
            self.assertIn(
                {
                    "type": "distribution",
                    "url": "https://github.com/rust-lang/crates.io-index",
                },
                components["serde"]["externalReferences"],
            )
            self.assertIn(
                {
                    "name": "cargo:source",
                    "value": "registry+https://github.com/rust-lang/crates.io-index",
                },
                components["serde"]["properties"],
            )
            application_ref = document["metadata"]["component"]["bom-ref"]
            self.assertNotIn(application_ref, {
                component["bom-ref"] for component in document["components"]
            })
            dependency_graph = {
                item["ref"]: item["dependsOn"] for item in document["dependencies"]
            }
            self.assertEqual(
                set(dependency_graph[application_ref]),
                {
                    components["serde"]["bom-ref"],
                    "urn:automatestig:release-binary:x86_64-unknown-linux-gnu:cli",
                    "urn:automatestig:release-binary:x86_64-unknown-linux-gnu:gui",
                    "urn:automatestig:release-tool:x86_64-unknown-linux-gnu:backup_restore",
                },
            )
            self.assertEqual(dependency_graph[components["serde"]["bom-ref"]], [])
            self.assertEqual(
                components["automatestig-gui"]["hashes"],
                [{"alg": "SHA-256", "content": gui_sha}],
            )
            self.assertEqual(
                components["automatestig-backup-restore"]["hashes"],
                [{"alg": "SHA-256", "content": backup_sha}],
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
        nightly = "nightly-2026-07-12"
        self.assertIn(
            f"toolchain: {nightly}",
            job,
        )
        self.assertRegex(
            job,
            rf"cargo \+{nightly} install cargo-fuzz --locked "
            r"--version \d+\.\d+\.\d+",
        )
        self.assertIn(f"cargo +{nightly} fuzz run", job)
        self.assertNotIn("tool: cargo-fuzz", job)

    def test_workflows_install_the_repository_pinned_stable_toolchain(self):
        import tomllib

        pinned = tomllib.loads((REPO / "rust-toolchain.toml").read_text())[
            "toolchain"
        ]["channel"]
        self.assertEqual(pinned, "1.94.0")
        stable_action = (
            "dtolnay/rust-toolchain@"
            "4be7066ada62dd38de10e7b70166bc74ed198c30"
        )
        for path in sorted((REPO / ".github/workflows").glob("*.yml")):
            lines = path.read_text().splitlines()
            for index, line in enumerate(lines):
                if stable_action not in line:
                    continue
                with self.subTest(workflow=path.name, line=index + 1):
                    self.assertIn(
                        f"toolchain: {pinned}",
                        "\n".join(lines[index + 1:index + 6]),
                    )

    def test_windows_is_portability_tested_but_not_published(self):
        workflow = (REPO / ".github/workflows/ci.yml").read_text()
        test_job = workflow.split("  test:", 1)[1].split("  e2e:", 1)[0]
        release_job = workflow.split("  build-release:", 1)[1].split(
            "  publish-release:", 1
        )[0]
        self.assertIn("windows-latest", test_job)
        self.assertNotIn("x86_64-pc-windows-msvc", release_job)

        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "generate_release_manifest",
            REPO / "scripts/generate-release-manifest.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertNotIn("x86_64-pc-windows-msvc", module.TARGETS)

        validator_spec = importlib.util.spec_from_file_location(
            "validate_release_evidence_platforms",
            REPO / "scripts/validate-release-evidence.py",
        )
        validator = importlib.util.module_from_spec(validator_spec)
        validator_spec.loader.exec_module(validator)
        self.assertIn("Test (windows-latest)", validator.REQUIRED_STATUS_CONTEXTS)
        self.assertNotIn(
            "Build Release (x86_64-pc-windows-msvc)",
            validator.REQUIRED_STATUS_CONTEXTS,
        )

    def test_tag_publication_requires_exact_cli_gui_archives_for_every_target(self):
        workflow = (REPO / ".github/workflows/ci.yml").read_text()
        release = workflow.split("  build-release:", 1)[1].split(
            "  release-artifact-equivalence:", 1
        )[0]
        equivalence = workflow.split(
            "  release-artifact-equivalence:", 1
        )[1].split("  publish-release:", 1)[0]
        publication = workflow.split("  publish-release:", 1)[1]
        self.assertIn("toolchain: 1.94.0", release)
        self.assertIn("targets: ${{ matrix.target }}", release)
        self.assertNotIn('-czf "dist/$package.tar.gz" .', release)
        for member in (
            '"${{ matrix.cli }}"',
            '"${{ matrix.gui }}"',
            "automatestig-backup-restore",
            "README.md",
            "LICENSE",
            "quickstart.md",
            "installation.md",
        ):
            with self.subTest(member=member):
                self.assertIn(member, release)
        self.assertIn("needs: build-release", equivalence)
        for target in (
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        ):
            with self.subTest(target=target):
                self.assertIn(f"target: {target}", equivalence)
        self.assertIn("--execute", equivalence)
        self.assertIn("--require-live-cli", equivalence)
        self.assertIn("release-equivalence-${target}.json", equivalence)
        self.assertIn("ubuntu-24.04-arm", equivalence)
        self.assertIn("macos-15-intel", equivalence)
        self.assertIn(
            "needs: [build-release, release-artifact-equivalence]",
            publication,
        )

    def test_ci_isolates_maintainer_cli_from_product_and_release_binaries(self):
        workflow = (REPO / ".github/workflows/ci.yml").read_text()
        maintainer = workflow.split("  maintainer-tooling:", 1)[1].split(
            "  test:", 1
        )[0]
        e2e = workflow.split("  e2e:", 1)[1].split("  fmt:", 1)[0]
        release = workflow.split("  build-release:", 1)[1].split(
            "  release-artifact-equivalence:", 1
        )[0]
        self.assertIn(
            "cargo test -p automatestig --all-targets --no-default-features\n"
            "          --features maintainer",
            maintainer,
        )
        self.assertIn(
            "cargo test -p automatestig --all-targets --no-default-features\n"
            "          --features transition",
            maintainer,
        )
        self.assertIn(
            "cargo clippy -p automatestig --all-targets --no-default-features\n"
            "          --features maintainer -- -D warnings",
            maintainer,
        )
        self.assertIn(
            "cargo clippy -p automatestig --all-targets --no-default-features\n"
            "          --features transition -- -D warnings",
            maintainer,
        )
        self.assertIn("--no-default-features", e2e)
        self.assertNotIn("--features maintainer", e2e)
        self.assertIn("--features transition --bin automatestig-transition", e2e)
        self.assertIn("--no-default-features", release)
        self.assertNotIn("--features maintainer", release)
        self.assertNotIn("--features transition", release)
        self.assertNotIn("automatestig-transition", release)

    def test_product_e2e_exercises_only_the_current_default_surface(self):
        workflow = (REPO / ".github/workflows/ci.yml").read_text()
        e2e_job = workflow.split("  e2e:", 1)[1].split("  fmt:", 1)[0]
        self.assertIn("scripts/e2e-acceptance.py", e2e_job)
        self.assertIn("--no-default-features", e2e_job)

        acceptance = (REPO / "scripts/e2e-acceptance.py").read_text()
        for invocation in (
            'run_cli("status")',
            'run_cli(\n        "evaluate"',
            'run_cli("scanner", "verify-handoff"',
            'run_transition_cli("migration", "inventory"',
            'run_transition_cli("migration", "export"',
            'scripts" / "scanner_scenarios" / "run_localhost.py"',
        ):
            with self.subTest(invocation=invocation):
                self.assertIn(invocation, acceptance)
        for retired in (
            "disa-import",
            "library",
            "build-pack",
            "convert",
            "summary",
            "gen-answer",
            "export",
            "coverage",
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(f'run_cli("{retired}"', acceptance)
        self.assertIn('"maintainer_commands_exercised": False', acceptance)
        self.assertIn('"protected_transition_binary_exercised": True', acceptance)
        for transition_actions in (
            '("inventory", "export", "bind-run")',
            '("generate-signing-key", "sign-handoff")',
        ):
            with self.subTest(transition_actions=transition_actions):
                self.assertIn(transition_actions, acceptance)

        equivalence = (
            REPO / "scripts/validate-release-binary-equivalence.py"
        ).read_text()
        self.assertIn('PROHIBITED_ARCHIVE_MEMBERS = {"automatestig-transition"}', equivalence)

        for script in (
            "scripts/e2e-acceptance.py",
            "scripts/scanner_scenarios/run_localhost.py",
            "scripts/adapter_tooling.py",
            "scripts/scaffold-target-adapter.py",
            "scripts/validate-adapter-contract.py",
            "scripts/generate-target-scorecards.py",
        ):
            with self.subTest(py_compile=script):
                self.assertIn(script, workflow)

    def test_transition_runbook_uses_only_the_separate_protected_binary(self):
        runbook = (REPO / "docs/migration-transition.md").read_text()
        self.assertIn(
            "--features transition --bin automatestig-transition",
            runbook,
        )
        self.assertIn("migration bind-run", runbook)
        self.assertIn("AUTOMATESTIG_STIGMAN_CLIENT_SECRET", runbook)
        self.assertNotRegex(runbook, r"(?m)^automatestig --db\b")
        self.assertIn(
            "protected executable is deliberately absent from normal product release",
            runbook,
        )

    def test_ssh_dependency_and_audit_have_no_rsa_exception(self):
        import tomllib

        workspace = tomllib.loads((REPO / "Cargo.toml").read_text())
        russh = workspace["workspace"]["dependencies"]["russh"]
        self.assertIs(russh["default-features"], False)
        self.assertEqual(russh["features"], ["aws-lc-rs"])

        lockfile = tomllib.loads((REPO / "Cargo.lock").read_text())
        package_names = {package["name"] for package in lockfile["package"]}
        self.assertNotIn("rsa", package_names)

        workflow = (REPO / ".github/workflows/ci.yml").read_text()
        audit_job = workflow.split("  dependency-audit:", 1)[1].split(
            "  build-release:", 1
        )[0]
        self.assertIn("- run: cargo audit", audit_job)
        self.assertNotIn("cargo audit --ignore", audit_job)

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

    def test_live_device_workflow_supplies_protected_cisco_policy_inputs(self):
        workflow = (
            REPO / ".github/workflows/live-device-acceptance.yml"
        ).read_text()
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, automatestig-live-devices]",
            workflow,
        )
        self.assertIn("toolchain: 1.94.0", workflow)
        self.assertIn("targets: x86_64-unknown-linux-gnu", workflow)
        self.assertIn(
            "cargo build --release --locked\n"
            "          --target x86_64-unknown-linux-gnu",
            workflow,
        )
        self.assertIn(
            "--binary target/x86_64-unknown-linux-gnu/release/automatestig",
            workflow,
        )
        for name in (
            "AUTOMATESTIG_LIVE_CISCO_IOS_XE_ORGANIZATION_POLICY",
            "AUTOMATESTIG_LIVE_CISCO_IOS_XE_ORGANIZATION_POLICY_SIGNATURE",
            "AUTOMATESTIG_LIVE_CISCO_IOS_XE_ORGANIZATION_POLICY_SHA256",
            "AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR",
        ):
            with self.subTest(name=name):
                self.assertIn(f"{name}: ${{{{ vars.{name} }}}}", workflow)

    def test_release_evidence_allows_only_evidence_after_approval(self):
        cases = (
            (False, False, False, False, False, False, False, False, False, False),
            (True, False, False, False, False, False, False, False, False, False),
            (False, True, False, False, False, False, False, False, False, False),
            (False, False, True, False, False, False, False, False, False, False),
            (False, False, False, True, False, False, False, False, False, False),
            (False, False, False, False, True, False, False, False, False, False),
            (False, False, False, False, False, True, False, False, False, False),
            (False, False, False, False, False, False, True, False, False, False),
            (False, False, False, False, False, False, False, True, False, False),
            (False, False, False, False, False, False, False, False, True, False),
            (False, False, False, False, False, False, False, False, False, True),
        )
        for (
            add_unapproved_code,
            wrong_benchmark_binding,
            wrong_key_binding,
            wrong_oracle_result,
            wrong_policy_binding,
            untrusted_policy,
            wrong_evaluated_pack,
            wrong_evaluation_plan,
            wrong_evaluated_input,
            missing_manager_cli_binding,
        ) in cases:
            with self.subTest(
                add_unapproved_code=add_unapproved_code,
                wrong_benchmark_binding=wrong_benchmark_binding,
                wrong_key_binding=wrong_key_binding,
                wrong_oracle_result=wrong_oracle_result,
                wrong_policy_binding=wrong_policy_binding,
                untrusted_policy=untrusted_policy,
                wrong_evaluated_pack=wrong_evaluated_pack,
                wrong_evaluation_plan=wrong_evaluation_plan,
                wrong_evaluated_input=wrong_evaluated_input,
                missing_manager_cli_binding=missing_manager_cli_binding,
            ), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                init_repo(root)
                (root / "schemas").mkdir()
                for schema_name in (
                    "release-evidence.schema.json",
                    "first-use-ux-study.schema.json",
                    "handoff-key-custody-ceremony.schema.json",
                    "handoff-receiver-ceremony.schema.json",
                ):
                    (root / "schemas" / schema_name).write_bytes(
                        (REPO / "schemas" / schema_name).read_bytes()
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
                    "evaluated_benchmark_sha256": "8" * 64,
                    "oracle_evaluated_benchmark_sha256": "8" * 64,
                    "benchmark_rule_set_sha256": "2" * 64,
                    "automated_vuln_set_sha256": "3" * 64,
                    "check_pack_sha256": "4" * 64,
                    "evaluated_check_pack_sha256": (
                        "e" * 64 if wrong_evaluated_pack else "4" * 64
                    ),
                    "input_sha256": "a" * 64,
                    "evaluated_input_sha256": (
                        "e" * 64 if wrong_evaluated_input else "a" * 64
                    ),
                    "source_state_sha256": "b" * 64,
                    "scenario_bindings_sha256": "d" * 64,
                    "oracle_sha256": "c" * 64,
                    "oracle_pinned_sha256": "c" * 64,
                    "oracle_adjudicated_at": now,
                    "oracle_adjudicator": "independent-reviewer",
                    "oracle_expected_status_sha256": status_digest,
                    "observed_status_sha256": status_digest,
                }
                if wrong_oracle_result:
                    result_template["observed_status_sha256"] = "f" * 64
                policy_sha256 = "5" * 64
                cisco_policy_result = {
                    "organization_policy_sha256": policy_sha256,
                    "organization_policy_pinned_sha256": policy_sha256,
                    "oracle_organization_policy_sha256": (
                        "9" * 64 if wrong_policy_binding else policy_sha256
                    ),
                    "evaluated_organization_policy_sha256": policy_sha256,
                    "organization_policy_signature_sha256": "6" * 64,
                    "oracle_organization_policy_signature_sha256": "6" * 64,
                    "organization_policy_id": "site-policy",
                    "organization_policy_version": "1",
                    "organization_policy_signer_fingerprint": (
                        f"SHA256:{'7' * 64}"
                    ),
                    "oracle_organization_policy_signer_fingerprint": (
                        f"SHA256:{'7' * 64}"
                    ),
                    "organization_policy_signature_verified": not untrusted_policy,
                }
                benchmark_identity = {
                    "ontap": ("NetApp_ONTAP_DSC_9-x_STIG", "V2R4"),
                    "freebsd": ("General_Purpose_Operating_System", "V3R3"),
                    "cisco_ios_xe": ("Cisco_IOS-XE_Router_NDM_STIG", "V3R7"),
                }
                if wrong_benchmark_binding:
                    benchmark_identity["ontap"] = (
                        "NetApp_ONTAP_DSC_9-x_STIG",
                        "V1R1",
                    )

                def evaluation_plan(target):
                    payload = {
                        "stig_id": benchmark_identity[target][0],
                        "stig_release": benchmark_identity[target][1],
                        "benchmark_sha256": result_template[
                            "evaluated_benchmark_sha256"
                        ],
                        "check_pack_sha256": result_template[
                            "check_pack_sha256"
                        ],
                        "organization_policy_sha256": (
                            policy_sha256 if target == "cisco_ios_xe" else None
                        ),
                    }
                    return hashlib.sha256(
                        json.dumps(
                            payload,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=False,
                        ).encode()
                    ).hexdigest()

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
                            "evaluation_plan_sha256": (
                                "f" * 64
                                if wrong_evaluation_plan
                                else evaluation_plan(target)
                            ),
                            **(
                                cisco_policy_result
                                if target == "cisco_ios_xe"
                                else {}
                            ),
                            **(
                                {
                                    "server_key_fingerprint": (
                                        "SHA256:" + ("A" * 43)
                                    ),
                                    "oracle_server_key_fingerprint": (
                                        "SHA256:" + ("A" * 43)
                                    ),
                                }
                                if target != "cisco_ios_xe"
                                else {}
                            ),
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
                handoff_raw = b"bounded producer-authenticated handoff fixture"
                handoff_sha = hashlib.sha256(handoff_raw).hexdigest()
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
                    "automatestig_cli_sha256": (
                        None if missing_manager_cli_binding else "d" * 64
                    ),
                    "automatestig_gui_sha256": "f" * 64,
                    "benchmark_sha256": "1" * 64,
                    "config_fixture_sha256": "2" * 64,
                    "checks": [
                        {
                            "name": (
                                "STIG Manager rig creates the existing exact "
                                "Cisco V3R7 assignment"
                            ),
                            "passed": True,
                        },
                        {
                            "name": (
                                "AutomateSTIG completes disconnected Cisco "
                                "scanner run with signed policy"
                            ),
                            "passed": True,
                        },
                        {
                            "name": (
                                "scanner run retains verified "
                                "organization-policy provenance"
                            ),
                            "passed": True,
                        },
                        {
                            "name": "automatestig scanner verify-handoff accepts selected-run bundle",
                            "passed": True,
                        },
                        {
                            "name": "fallback CKLB contains scanner-owned reviewed rows only",
                            "passed": True,
                        },
                        {
                            "name": "retired direct-push route returns 410",
                            "passed": True,
                        },
                        {
                            "name": "AutomateSTIG makes zero direct STIG Manager review writes",
                            "passed": True,
                        },
                        {
                            "name": "receiving operator revalidates the existing exact assignment",
                            "passed": True,
                        },
                        {
                            "name": "receiving operator reconciles only sparse-reviews.json",
                            "passed": True,
                        },
                        {
                            "name": "STIG Manager rule/status round-trip matches sparse handoff",
                            "passed": True,
                        },
                    ],
                    "metrics": {
                        "review_count": 2,
                        "source_finding_count": 2,
                        "fallback_sparse_rule_count": 2,
                        "automatestig_direct_review_writes": 0,
                        "receiving_operator_review_writes": 2,
                        "boundary": "disconnected-selected-run-handoff",
                        "producer_handoff_filename": "producer-handoff.zip",
                        "assignment_revision": "V3R7",
                        "full_assignment_rule_count": 42,
                        "full_ckl_rule_count": 42,
                        "handoff_sha256": handoff_sha,
                        "handoff_manifest_sha256": "d" * 64,
                        "rule_set_sha256": "8" * 64,
                        "benchmark_id": "Cisco_IOS-XE_Router_NDM_STIG",
                        "organization_policy_sha256": "9" * 64,
                        "organization_policy_signature_sha256": "a" * 64,
                        "organization_policy_signer_fingerprint": (
                            f"SHA256:{'b' * 64}"
                        ),
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
                handoff_key_path = (
                    artifact_root / "handoff-producer-public-key.pub"
                )
                handoff_key_path.write_bytes(b"H" * 32)
                handoff_key_sha = hashlib.sha256(
                    handoff_key_path.read_bytes()
                ).hexdigest()
                handoff_path = artifact_root / "producer-handoff.zip"
                handoff_path.write_bytes(handoff_raw)
                handoff_signature_path = (
                    artifact_root / "producer-handoff.zip.signature.json"
                )
                handoff_signature_sha = write_json_artifact(
                    handoff_signature_path,
                    {
                        "schema": (
                            "automatestig.selected-run-handoff-signature.v1"
                        ),
                        "algorithm": "ed25519-sha256",
                        "handoff_schema": (
                            "automatestig.selected-run-handoff.v4"
                        ),
                        "run_id": "123e4567-e89b-42d3-a456-426614174000",
                        "handoff_sha256": handoff_sha,
                        "signing_key_fingerprint": (
                            f"SHA256:{handoff_key_sha}"
                        ),
                        "signature": "1" * 128,
                    },
                )
                handoff_custody_path = (
                    artifact_root / "handoff-key-custody-ceremony.json"
                )
                handoff_custody_sha = write_json_artifact(
                    handoff_custody_path,
                    {
                        "schema": (
                            "automatestig-handoff-key-custody-ceremony/v1"
                        ),
                        "source_commit": approved,
                        "signed_at": now,
                        "producer_key_fingerprint": (
                            f"SHA256:{handoff_key_sha}"
                        ),
                        "public_key_sha256": handoff_key_sha,
                        "handoff_sha256": handoff_sha,
                        "signature_sidecar_sha256": handoff_signature_sha,
                        "key_custodian": "handoff-custodian",
                        "receiver_approver": "handoff-receiver",
                        "signing_host_reference": "host:signing-17",
                        "primary_key_media_reference": "media:primary-17",
                        "backup_key_media_reference": "media:backup-17",
                        "private_key_entered_ci": False,
                        "private_key_entered_scanner_runtime": False,
                        "private_key_material_recorded": False,
                        "revocation_status_checked": True,
                    },
                )
                handoff_ceremony_path = (
                    artifact_root / "handoff-receiver-ceremony.json"
                )
                handoff_ceremony_sha = write_json_artifact(
                    handoff_ceremony_path,
                    {
                        "schema": "automatestig-handoff-receiver-ceremony/v1",
                        "passed": True,
                        "producer_signature_verified": True,
                        "trusted_cli_verification_succeeded": True,
                        "key_custody_ceremony_verified": True,
                        "completed_at": now,
                        "source_commit": approved,
                        "repository": "ibadukefan/AutomateSTIG",
                        "workflow_run_id": "1006",
                        "staging_workflow_run_id": "1003",
                        "protected_environment": "handoff-receiver-ceremony",
                        "automatestig_cli_sha256": "d" * 64,
                        "verification_output_sha256": "e" * 64,
                        "staging_evidence_sha256": manager_sha,
                        "handoff_filename": "producer-handoff.zip",
                        "handoff_sha256": handoff_sha,
                        "signature_filename": (
                            "producer-handoff.zip.signature.json"
                        ),
                        "signature_sha256": handoff_signature_sha,
                        "public_key_filename": (
                            "handoff-producer-public-key.pub"
                        ),
                        "public_key_sha256": handoff_key_sha,
                        "producer_key_fingerprint": (
                            f"SHA256:{handoff_key_sha}"
                        ),
                        "key_custody_filename": (
                            "handoff-key-custody-ceremony.json"
                        ),
                        "key_custody_sha256": handoff_custody_sha,
                        "participants": [
                            {
                                "role": "key_custodian",
                                "github_login": "handoff-custodian",
                            },
                            {
                                "role": "receiver_approver",
                                "github_login": "handoff-receiver",
                            },
                        ],
                    },
                )
                first_use_path = artifact_root / "first-use-ux-study.json"
                first_use_sha = write_json_artifact(
                    first_use_path,
                    {
                        "schema": "automatestig-first-use-ux-study/v1",
                        "passed": True,
                        "executed_at": now,
                        "source_commit": approved,
                        "product_version": "v1.2.3",
                        "repository": "ibadukefan/AutomateSTIG",
                        "workflow_run_id": "1007",
                        "protected_environment": "first-use-ux-study",
                        "automatestig_gui_sha256": "f" * 64,
                        "scenario": {
                            "id": "prepared-cisco-scan",
                            "version": "1",
                            "target_profile": "cisco-ios-xe-router-ndm",
                            "prepared_scan_fixture_sha256": "a" * 64,
                            "task_definition_sha256": "b" * 64,
                        },
                        "representative_roles": [
                            "cybersecurity_analyst",
                            "cybersecurity_manager",
                        ],
                        "study_team": {
                            "facilitator": {
                                "github_login": "study-facilitator",
                                "attested_at": now,
                            },
                            "independent_observer": {
                                "github_login": "study-observer",
                                "attested_at": now,
                            },
                            "independent_approver": {
                                "github_login": "study-approver",
                                "attested_at": now,
                            },
                        },
                        "participants": [
                            {
                                "participant_id": f"P{index + 1:02d}",
                                "role": (
                                    "cybersecurity_analyst"
                                    if index < 3
                                    else "cybersecurity_manager"
                                ),
                                "role_experience_band": (
                                    "less_than_2_years"
                                    if index < 2
                                    else "more_than_5_years"
                                ),
                                "first_time_user": True,
                                "completed_prepared_scan": index < 4,
                                "external_documentation_used": False,
                                "assistance_received": False,
                                "outcome_notes": (
                                    "Completed unaided."
                                    if index < 4
                                    else "Did not complete before the time limit."
                                ),
                            }
                            for index in range(5)
                        ],
                        "metrics": {
                            "numerator": 4,
                            "denominator": 5,
                            "required_threshold_percent": 80,
                        },
                    },
                )

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
                        "ontap": gate(device_path, device_sha, "V2R4"),
                        "freebsd": gate(device_path, device_sha, "V3R3"),
                        "cisco_ios_xe": gate(device_path, device_sha, "V3R7"),
                        "stig_viewer": gate(viewer_path, viewer_sha, "3.5"),
                        "stig_manager": gate(manager_path, manager_sha, "1.6.13+1"),
                    },
                    "first_use_ux": {
                        **gate(first_use_path, first_use_sha, "v1.2.3"),
                        "environment": "first-use-ux-study",
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
                    "producer_authenticated_handoff": {
                        "fingerprint_sha256": handoff_key_sha,
                        "ceremony_reference": (
                            handoff_ceremony_path.relative_to(root).as_posix()
                        ),
                        "ceremony_sha256": handoff_ceremony_sha,
                        "public_key_reference": (
                            handoff_key_path.relative_to(root).as_posix()
                        ),
                        "public_key_sha256": handoff_key_sha,
                        "handoff_reference": (
                            handoff_path.relative_to(root).as_posix()
                        ),
                        "handoff_sha256": handoff_sha,
                        "signature_reference": (
                            handoff_signature_path.relative_to(root).as_posix()
                        ),
                        "signature_sha256": handoff_signature_sha,
                        "key_custody_reference": (
                            handoff_custody_path.relative_to(root).as_posix()
                        ),
                        "key_custody_sha256": handoff_custody_sha,
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
                elif wrong_policy_binding:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("policy snapshot", result.stderr)
                elif untrusted_policy:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("trusted signature", result.stderr)
                elif wrong_evaluated_pack:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("check-pack provenance", result.stderr)
                elif wrong_evaluation_plan:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("evaluation-plan provenance", result.stderr)
                elif wrong_evaluated_input:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("evaluated input provenance", result.stderr)
                elif missing_manager_cli_binding:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("automatestig_cli_sha256", result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_release_manifest_validates_bound_companions(self):
        targets = {
            "x86_64-unknown-linux-gnu": "tar.gz",
            "aarch64-unknown-linux-gnu": "tar.gz",
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
                inventory_path = root / f"cargo-metadata-{target}.json"
                inventory_path.write_text(json.dumps(inventory))
                cli_sha = hashlib.sha256(f"cli:{target}".encode()).hexdigest()
                gui_sha = hashlib.sha256(f"gui:{target}".encode()).hexdigest()
                backup_sha = hashlib.sha256(
                    f"backup:{target}".encode()
                ).hexdigest()
                equivalence_path = root / f"release-equivalence-{target}.json"
                equivalence = {
                    "schema": "automatestig-release-artifact-equivalence/v1",
                    "target": target,
                    "version": "0.3.0",
                    "source_commit": commit,
                    "archive": {
                        "name": package.name,
                        "sha256": archive_hash,
                        "size": package.stat().st_size,
                        "format": "tar.gz",
                    },
                    "binaries": {
                        "cli": {
                            "name": "automatestig",
                            "pre_package_sha256": cli_sha,
                            "archive_member_sha256": cli_sha,
                            "size": 11,
                        },
                        "gui": {
                            "name": "automatestig-gui",
                            "pre_package_sha256": gui_sha,
                            "archive_member_sha256": gui_sha,
                            "size": 12,
                        },
                    },
                    "operational_tools": {
                        "backup_restore": {
                            "name": "automatestig-backup-restore",
                            "pre_package_sha256": backup_sha,
                            "archive_member_sha256": backup_sha,
                            "size": 13,
                        }
                    },
                }
                equivalence_path.write_text(json.dumps(equivalence))
                sbom_path = root / f"automatestig-{target}.cdx.json"
                sbom_path.write_text(json.dumps({
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {"component": {
                        "name": "automatestig",
                        "version": "0.3.0",
                        "properties": [
                            {"name": "target", "value": target},
                            {
                                "name": "automatestig:release-archive",
                                "value": package.name,
                            },
                            {
                                "name": "automatestig:release-archive-sha256",
                                "value": archive_hash,
                            },
                            {
                                "name": "automatestig:binary-equivalence-manifest",
                                "value": equivalence_path.name,
                            },
                            {
                                "name": "automatestig:binary-equivalence-manifest-sha256",
                                "value": hashlib.sha256(equivalence_path.read_bytes()).hexdigest(),
                            },
                            {
                                "name": "automatestig:release-scope",
                                "value": "analyst-product",
                            },
                            {
                                "name": "automatestig:transition-cli-included",
                                "value": "false",
                            },
                        ],
                    }},
                    "components": [
                        {"name": "serde", "version": "1"},
                        {
                            "bom-ref": f"urn:automatestig:release-binary:{target}:cli",
                            "name": "automatestig",
                            "version": "0.3.0",
                            "hashes": [{"alg": "SHA-256", "content": cli_sha}],
                        },
                        {
                            "bom-ref": f"urn:automatestig:release-binary:{target}:gui",
                            "name": "automatestig-gui",
                            "version": "0.3.0",
                            "hashes": [{"alg": "SHA-256", "content": gui_sha}],
                        },
                        {
                            "bom-ref": f"urn:automatestig:release-tool:{target}:backup_restore",
                            "name": "automatestig-backup-restore",
                            "version": "0.3.0",
                            "hashes": [
                                {"alg": "SHA-256", "content": backup_sha}
                            ],
                        },
                    ],
                }))
                (root / f"provenance-{target}.json").write_text(json.dumps({
                    "schema": "automatestig-release-provenance/v1",
                    "target": target,
                    "version": "0.3.0",
                    "repository": "ibadukefan/AutomateSTIG",
                    "ref": "refs/tags/v0.3.0",
                    "sha": commit,
                    "workflow": "CI",
                    "run_id": run_id,
                    "run_attempt": "1",
                    "artifact": {
                        "name": package.name,
                        "sha256": archive_hash,
                        "size": package.stat().st_size,
                    },
                    "binary_equivalence_manifest": {
                        "name": equivalence_path.name,
                        "sha256": hashlib.sha256(equivalence_path.read_bytes()).hexdigest(),
                    },
                    "binaries": {
                        "cli": {"name": "automatestig", "sha256": cli_sha, "size": 11},
                        "gui": {"name": "automatestig-gui", "sha256": gui_sha, "size": 12},
                    },
                    "operational_tools": {
                        "backup_restore": {
                            "name": "automatestig-backup-restore",
                            "sha256": backup_sha,
                            "size": 13,
                        }
                    },
                    "sbom": {
                        "name": sbom_path.name,
                        "sha256": hashlib.sha256(sbom_path.read_bytes()).hexdigest(),
                    },
                    "dependency_inventory": {
                        "name": inventory_path.name,
                        "sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
                    },
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
                4,
            )

            (root / "release-manifest.json").unlink()
            unexpected = (
                root / "automatestig-v0.3.0-x86_64-pc-windows-msvc.zip"
            )
            unexpected.write_text("Windows release artifacts must not be published")
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
