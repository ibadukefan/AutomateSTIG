import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest


REPO = pathlib.Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "release_binary_equivalence",
    REPO / "scripts/validate-release-binary-equivalence.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseBinaryEquivalenceTests(unittest.TestCase):
    def write_archive(self, path, members):
        with tarfile.open(path, "w:gz") as archive:
            for name, payload in members:
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(payload))

    def test_extracts_only_the_exact_regular_root_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "release.tar.gz"
            payload = b"live-tested-cli"
            self.write_archive(
                archive,
                [
                    ("./automatestig", payload),
                    ("./README.md", b"readme"),
                ],
            )
            self.assertEqual(
                MODULE.release_cli_digest(archive),
                hashlib.sha256(payload).hexdigest(),
            )

            duplicate = pathlib.Path(temporary) / "duplicate.tar.gz"
            self.write_archive(
                duplicate,
                [
                    ("./automatestig", payload),
                    ("automatestig", b"different"),
                ],
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                MODULE.release_cli_digest(duplicate)

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
            artifact_sha = MODULE.sha256_file(artifact)
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
            self.assertEqual(MODULE.live_binary_digest(repo, tag), binary_sha)

            other = dict(gate)
            other_artifact = artifact_dir / "other.json"
            other_artifact.write_text(
                json.dumps(
                    {
                        "schema": "automatestig-live-device-acceptance/v1",
                        "source_commit": approved,
                        "binary_sha256": binary_sha,
                    }
                ),
                encoding="utf-8",
            )
            other["evidence_reference"] = other_artifact.relative_to(repo).as_posix()
            other["evidence_sha256"] = MODULE.sha256_file(other_artifact)
            release["acceptance"]["freebsd"] = other
            (repo / "release-evidence" / f"{tag}.json").write_text(
                json.dumps(release),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "one exact"):
                MODULE.live_binary_digest(repo, tag)


if __name__ == "__main__":
    unittest.main()
