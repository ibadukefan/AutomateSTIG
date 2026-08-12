import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock


REPO = pathlib.Path(__file__).resolve().parents[3]


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EQUIVALENCE = load_script(
    "release_binary_equivalence",
    "validate-release-binary-equivalence.py",
)
PROVENANCE = load_script(
    "release_provenance",
    "generate-release-provenance.py",
)


class ReleaseBinaryEquivalenceTests(unittest.TestCase):
    def write_archive(self, path, cli=b"cli-binary", gui=b"gui-binary", extra=()):
        members = [
            ("automatestig", cli, 0o755),
            ("automatestig-gui", gui, 0o755),
            ("automatestig-backup-restore", b"backup-restore", 0o755),
            ("README.md", b"readme", 0o644),
            ("LICENSE", b"license", 0o644),
            ("quickstart.md", b"quickstart", 0o644),
            ("installation.md", b"installation", 0o644),
            *extra,
        ]
        with tarfile.open(path, "w:gz") as archive:
            for name, payload, mode in members:
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = mode
                archive.addfile(info, io.BytesIO(payload))

    def prepare_equivalence(self, root):
        repo = root / "repo"
        repo.mkdir()
        (repo / "Cargo.toml").write_text(
            '[workspace]\n[workspace.package]\nversion = "1.2.3"\n',
            encoding="utf-8",
        )
        cli = root / "automatestig"
        gui = root / "automatestig-gui"
        backup_restore = root / "automatestig-backup-restore"
        cli.write_bytes(b"cli-binary")
        gui.write_bytes(b"gui-binary")
        backup_restore.write_bytes(b"backup-restore")
        snapshot = root / "snapshot.json"
        EQUIVALENCE.snapshot_binaries(
            repo=repo,
            target="x86_64-unknown-linux-gnu",
            source_commit="a" * 40,
            cli=cli,
            gui=gui,
            backup_restore=backup_restore,
            output=snapshot,
        )
        archive = root / "automatestig-v1.2.3-x86_64-unknown-linux-gnu.tar.gz"
        self.write_archive(archive)
        manifest = root / "release-equivalence-x86_64-unknown-linux-gnu.json"
        EQUIVALENCE.finalize_equivalence(
            snapshot=snapshot,
            archive=archive,
            output=manifest,
        )
        checksum = pathlib.Path(f"{archive}.sha256")
        checksum.write_text(
            f"{EQUIVALENCE.sha256_file(archive)}  {archive.name}\n",
            encoding="utf-8",
        )
        return archive, manifest, checksum

    def test_snapshot_finalize_and_verify_bind_both_binaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive, manifest, checksum = self.prepare_equivalence(root)
            document = EQUIVALENCE.verify_equivalence(
                manifest=manifest,
                archive=archive,
                checksum=checksum,
                target="x86_64-unknown-linux-gnu",
                source_commit="a" * 40,
                tag="v1.2.3",
            )
            self.assertEqual(set(document["binaries"]), {"cli", "gui"})
            self.assertEqual(
                set(document["operational_tools"]),
                {"backup_restore"},
            )
            for record in document["binaries"].values():
                self.assertEqual(
                    record["pre_package_sha256"],
                    record["archive_member_sha256"],
                )
            self.assertEqual(
                document["archive"]["sha256"],
                hashlib.sha256(archive.read_bytes()).hexdigest(),
            )

    def test_recovery_smoke_executes_a_real_backup_restore_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            EQUIVALENCE.recovery_smoke(
                REPO / "scripts" / "backup-restore.py",
                pathlib.Path(temporary).resolve(),
            )

    def test_execute_versions_runs_the_exact_extracted_recovery_entrypoint(self):
        extracted = {
            "automatestig": b"cli-bytes",
            "automatestig-gui": b"gui-bytes",
            "automatestig-backup-restore": b"packaged-recovery-bytes",
        }
        observed = []

        def inspect_recovery(binary, _root):
            observed.append(binary.read_bytes())

        with mock.patch.object(EQUIVALENCE, "cli_version"), mock.patch.object(
            EQUIVALENCE, "gui_version"
        ), mock.patch.object(
            EQUIVALENCE,
            "recovery_smoke",
            side_effect=inspect_recovery,
        ) as recovery:
            EQUIVALENCE.execute_versions(extracted, "1.2.3")

        recovery.assert_called_once()
        self.assertEqual(observed, [b"packaged-recovery-bytes"])

    def test_finalize_rejects_a_changed_gui_and_unsafe_or_extra_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive, _manifest, _checksum = self.prepare_equivalence(root)
            snapshot = root / "snapshot.json"

            changed = root / "changed.tar.gz"
            self.write_archive(changed, gui=b"changed-gui")
            with self.assertRaisesRegex(ValueError, "packaged gui bytes differ"):
                EQUIVALENCE.finalize_equivalence(
                    snapshot=snapshot,
                    archive=changed,
                    output=root / "changed.json",
                )

            extra = root / "extra.tar.gz"
            self.write_archive(extra, extra=[("unexpected", b"no", 0o644)])
            with self.assertRaisesRegex(ValueError, "member set is not closed"):
                EQUIVALENCE.archive_binary_bytes(extra)

            transition = root / "transition.tar.gz"
            self.write_archive(
                transition,
                extra=[("automatestig-transition", b"protected", 0o755)],
            )
            with self.assertRaisesRegex(ValueError, "protected transition tooling"):
                EQUIVALENCE.archive_binary_bytes(transition)

            duplicate = root / "duplicate.tar.gz"
            self.write_archive(
                duplicate,
                extra=[("./automatestig", b"different", 0o755)],
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                EQUIVALENCE.archive_binary_bytes(duplicate)

    def test_verify_rejects_archive_checksum_version_and_manifest_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive, manifest, checksum = self.prepare_equivalence(root)
            checksum.write_text(f"{'0' * 64}  {archive.name}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum"):
                EQUIVALENCE.verify_equivalence(
                    manifest=manifest,
                    archive=archive,
                    checksum=checksum,
                )

            checksum.write_text(
                f"{EQUIVALENCE.sha256_file(archive)}  {archive.name}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "version"):
                EQUIVALENCE.verify_equivalence(
                    manifest=manifest,
                    archive=archive,
                    checksum=checksum,
                    tag="v1.2.4",
                )

            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["binaries"]["gui"]["archive_member_sha256"] = "0" * 64
            manifest.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "gui digest binding"):
                EQUIVALENCE.verify_equivalence(
                    manifest=manifest,
                    archive=archive,
                    checksum=checksum,
                )

    def test_live_digest_is_bound_to_all_three_device_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = pathlib.Path(temporary)
            tag = "v1.2.3"
            approved = "a" * 40
            binary_sha = hashlib.sha256(b"binary").hexdigest()
            artifact_dir = repo / "release-evidence" / "artifacts" / tag
            artifact_dir.mkdir(parents=True)
            artifact = artifact_dir / "devices.json"
            artifact.write_text(
                json.dumps(
                    {
                        "schema": "automatestig-live-device-acceptance/v1",
                        "source_commit": approved,
                        "binary_sha256": binary_sha,
                    }
                ),
                encoding="utf-8",
            )
            artifact_sha = EQUIVALENCE.sha256_file(artifact)
            reference = artifact.relative_to(repo).as_posix()
            gate = {
                "evidence_reference": reference,
                "evidence_sha256": artifact_sha,
            }
            release = {
                "schema": "automatestig-release-evidence/v1",
                "tag": tag,
                "approved_commit": approved,
                "acceptance": {
                    "ontap": gate,
                    "freebsd": gate,
                    "cisco_ios_xe": gate,
                },
            }
            (repo / "release-evidence" / f"{tag}.json").write_text(
                json.dumps(release),
                encoding="utf-8",
            )
            self.assertEqual(EQUIVALENCE.live_binary_digest(repo, tag), binary_sha)

            other_artifact = artifact_dir / "other.json"
            other_artifact.write_text(artifact.read_text(encoding="utf-8"))
            release["acceptance"]["freebsd"] = {
                "evidence_reference": other_artifact.relative_to(repo).as_posix(),
                "evidence_sha256": EQUIVALENCE.sha256_file(other_artifact),
            }
            (repo / "release-evidence" / f"{tag}.json").write_text(
                json.dumps(release),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "one exact"):
                EQUIVALENCE.live_binary_digest(repo, tag)

    def test_provenance_binds_archive_manifest_binaries_sbom_and_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive, manifest, _checksum = self.prepare_equivalence(root)
            sbom = root / "automatestig-x86_64-unknown-linux-gnu.cdx.json"
            inventory = root / "cargo-metadata-x86_64-unknown-linux-gnu.json"
            sbom.write_text("{}\n", encoding="utf-8")
            inventory.write_text("{}\n", encoding="utf-8")
            output = root / "provenance.json"
            document = PROVENANCE.generate(
                archive=archive,
                equivalence_manifest=manifest,
                sbom=sbom,
                inventory=inventory,
                target="x86_64-unknown-linux-gnu",
                repository="ibadukefan/AutomateSTIG",
                ref="refs/tags/v1.2.3",
                commit="a" * 40,
                workflow="CI",
                run_id="123",
                run_attempt="1",
                output=output,
            )
            self.assertEqual(document["artifact"]["sha256"], EQUIVALENCE.sha256_file(archive))
            self.assertEqual(set(document["binaries"]), {"cli", "gui"})
            self.assertEqual(
                document["operational_tools"]["backup_restore"]["name"],
                "automatestig-backup-restore",
            )
            self.assertEqual(
                document["binary_equivalence_manifest"]["sha256"],
                EQUIVALENCE.sha256_file(manifest),
            )
            sbom.write_text('{"tampered":true}\n', encoding="utf-8")
            self.assertNotEqual(document["sbom"]["sha256"], PROVENANCE.digest(sbom))


if __name__ == "__main__":
    unittest.main()
