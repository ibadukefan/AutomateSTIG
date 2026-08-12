import hashlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
from types import SimpleNamespace
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "backup-restore.py"
SPEC = importlib.util.spec_from_file_location("backup_restore", SCRIPT)
BACKUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BACKUP)


class BackupRestoreTests(unittest.TestCase):
    def make_directory_symlink(self, target: Path, link: Path) -> None:
        try:
            os.symlink(target, link, target_is_directory=True)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"directory symlinks unavailable: {error}")

    def make_state(self, root: Path) -> Path:
        state = root / "source"
        state.mkdir(mode=0o700)
        database = sqlite3.connect(state / "data.db")
        database.executescript(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE app_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE scan_runs (id TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO app_config VALUES ('stigman_config', 'enc:must-reenter');
            INSERT INTO scan_runs VALUES ('run-1', 'preserved');
            """
        )
        database.commit()
        self.addCleanup(database.close)
        (state / "secret.key").write_text("a" * 64)
        os.chmod(state / "secret.key", 0o600)
        (state / "known_hosts").write_text("device.example:22 SHA256:sample\n")
        os.chmod(state / "known_hosts", 0o600)
        trust = state / "handoff_trusted_keys"
        trust.mkdir(mode=0o700)
        (trust / "producer.pub").write_bytes(b"trusted-public-key")
        os.chmod(trust / "producer.pub", 0o600)
        library = state / "library"
        library.mkdir(mode=0o700)
        (library / "index.json").write_text('{"schema":1}')
        nested = library / "nested"
        nested.mkdir(mode=0o700)
        deeper = nested / "deeper"
        deeper.mkdir(mode=0o700)
        (deeper / "content.json").write_text('{"content":true}')
        return state

    def test_backup_captures_wal_and_restore_requires_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = self.make_state(root)
            archive = root / "state.zip"
            restored = root / "restored"
            BACKUP.create_backup(state, archive)
            BACKUP.restore_backup(archive, restored)
            database = sqlite3.connect(restored / "data.db")
            self.assertEqual(
                database.execute("SELECT value FROM scan_runs WHERE id='run-1'").fetchone(),
                ("preserved",),
            )
            self.assertIsNone(
                database.execute("SELECT value FROM app_config WHERE key='stigman_config'").fetchone()
            )
            database.close()
            self.assertEqual((restored / "secret.key").read_text(), "a" * 64)
            self.assertTrue((restored / "handoff_trusted_keys/producer.pub").is_file())
            self.assertFalse((restored / "data.db-wal").exists())
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
            for directory in (
                restored / "library",
                restored / "library/nested",
                restored / "library/nested/deeper",
            ):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    def test_backup_rejects_symlinks_in_managed_state(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = self.make_state(root)
            (root / "external").write_text("outside")
            os.symlink(root / "external", state / "trusted_keys")
            with self.assertRaisesRegex(BACKUP.BackupError, "symlink"):
                BACKUP.create_backup(state, root / "state.zip")

    def test_backup_rejects_a_real_data_directory_reached_through_a_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real_parent = root / "real-source-parent"
            real_parent.mkdir(mode=0o700)
            self.make_state(real_parent)
            alias = root / "source-parent-alias"
            self.make_directory_symlink(real_parent, alias)

            with self.assertRaisesRegex(BACKUP.BackupError, "symlink|reparse"):
                BACKUP.create_backup(alias / "source", root / "state.zip")

    def test_backup_rejects_a_real_output_parent_reached_through_a_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = self.make_state(root)
            real_parent = root / "real-output-parent"
            nested = real_parent / "nested"
            nested.mkdir(mode=0o700, parents=True)
            alias = root / "output-parent-alias"
            self.make_directory_symlink(real_parent, alias)

            with self.assertRaisesRegex(BACKUP.BackupError, "symlink|reparse"):
                BACKUP.create_backup(state, alias / "nested" / "state.zip")

    def test_restore_rejects_tampered_declared_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = self.make_state(root)
            original = root / "state.zip"
            tampered = root / "tampered.zip"
            BACKUP.create_backup(state, original)
            with zipfile.ZipFile(original) as source, zipfile.ZipFile(tampered, "w") as output:
                for info in source.infolist():
                    body = source.read(info)
                    if info.filename.endswith("/known_hosts"):
                        body += b"tampered"
                    output.writestr(info, body)
            with self.assertRaisesRegex(BACKUP.BackupError, "integrity"):
                BACKUP.restore_backup(tampered, root / "restored")

    def test_restore_rejects_undeclared_and_traversal_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = self.make_state(root)
            original = root / "state.zip"
            BACKUP.create_backup(state, original)
            for name in ("automatestig-backup/files/undeclared", "../escape"):
                changed = root / (hashlib.sha256(name.encode()).hexdigest() + ".zip")
                with zipfile.ZipFile(original) as source, zipfile.ZipFile(changed, "w") as output:
                    for info in source.infolist():
                        output.writestr(info, source.read(info))
                    output.writestr(name, b"unexpected")
                with self.assertRaises(BACKUP.BackupError):
                    BACKUP.restore_backup(changed, root / ("restore-" + changed.stem))

    def test_restore_never_overwrites_existing_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = self.make_state(root)
            archive = root / "state.zip"
            BACKUP.create_backup(state, archive)
            target = root / "existing"
            target.mkdir()
            marker = target / "keep"
            marker.write_text("preserve")
            with self.assertRaisesRegex(BACKUP.BackupError, "must not already exist"):
                BACKUP.restore_backup(archive, target)
            self.assertEqual(marker.read_text(), "preserve")

    def test_restore_rejects_a_real_archive_reached_through_a_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = self.make_state(root)
            real_parent = root / "real-archive-parent"
            nested = real_parent / "nested"
            nested.mkdir(mode=0o700, parents=True)
            archive = nested / "state.zip"
            BACKUP.create_backup(state, archive)
            alias = root / "archive-parent-alias"
            self.make_directory_symlink(real_parent, alias)

            with self.assertRaisesRegex(BACKUP.BackupError, "symlink|reparse"):
                BACKUP.restore_backup(alias / "nested" / "state.zip", root / "restored")

    def test_restore_rejects_a_real_target_parent_reached_through_a_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = self.make_state(root)
            archive = root / "state.zip"
            BACKUP.create_backup(state, archive)
            real_parent = root / "real-restore-parent"
            nested = real_parent / "nested"
            nested.mkdir(mode=0o700, parents=True)
            alias = root / "restore-parent-alias"
            self.make_directory_symlink(real_parent, alias)

            with self.assertRaisesRegex(BACKUP.BackupError, "symlink|reparse"):
                BACKUP.restore_backup(archive, alias / "nested" / "restored")

    def test_python_version_requirement_is_explicit(self):
        with self.assertRaisesRegex(BACKUP.BackupError, "Python 3.10 or newer"):
            BACKUP.require_supported_python((3, 9, 19))
        BACKUP.require_supported_python((3, 10, 0))

    def test_windows_reparse_attribute_is_treated_as_an_unsafe_link(self):
        metadata = SimpleNamespace(
            st_mode=stat.S_IFDIR,
            st_file_attributes=getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024),
        )
        self.assertTrue(BACKUP.is_link_or_reparse(metadata))


if __name__ == "__main__":
    unittest.main()
