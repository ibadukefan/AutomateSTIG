import json
import pathlib
import tempfile
import unittest

from scripts.disa_corpus import validate_corpus_regression as mod


class ValidateCorpusRegressionTests(unittest.TestCase):
    def _write_manifest(self, root: pathlib.Path, name: str, rules: list[dict]) -> None:
        path = root / 'content' / 'coverage' / 'disa-authoritative' / name / 'manifest.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'rules': rules}), encoding='utf-8')

    def _write_artifacts(self, root: pathlib.Path, count: int) -> None:
        path = root / 'content' / 'disa-corpus' / 'artifacts.manifest.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'fixtures': [{'id': f'a-{i}'} for i in range(count)]}), encoding='utf-8')

    def test_passes_when_current_metrics_meet_committed_floor(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self._write_artifacts(root, 2)
            self._write_manifest(root, 'one', [
                {'classification': 'automated'},
                {'classification': 'unsupported'},
            ])
            baseline = root / 'baseline.json'
            baseline.write_text(json.dumps({
                'min_public_disa_artifacts': 2,
                'min_authoritative_manifests': 1,
                'min_authoritative_rules': 2,
                'min_automated_or_mapped_rules': 1,
                'max_unsupported_rules': 1,
            }), encoding='utf-8')

            metrics = mod.validate(root, baseline)

            self.assertEqual(metrics['public_disa_artifacts'], 2)
            self.assertEqual(metrics['authoritative_rules'], 2)

    def test_manual_classification_counts_as_mapped_coverage(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self._write_artifacts(root, 1)
            self._write_manifest(root, 'one', [
                {'classification': 'manual'},
                {'classification': 'manual_evidence'},
                {'classification': 'not_applicable'},
            ])
            baseline = root / 'baseline.json'
            baseline.write_text(json.dumps({
                'min_public_disa_artifacts': 1,
                'min_authoritative_manifests': 1,
                'min_authoritative_rules': 3,
                'min_automated_or_mapped_rules': 3,
                'max_unsupported_rules': 0,
            }), encoding='utf-8')

            metrics = mod.validate(root, baseline)

            self.assertEqual(metrics['automated_or_mapped_rules'], 3)
            self.assertEqual(metrics['unsupported_rules'], 0)

    def test_fails_when_corpus_artifact_count_regresses(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self._write_artifacts(root, 1)
            self._write_manifest(root, 'one', [{'classification': 'automated'}])
            baseline = root / 'baseline.json'
            baseline.write_text(json.dumps({
                'min_public_disa_artifacts': 2,
                'min_authoritative_manifests': 1,
                'min_authoritative_rules': 1,
                'min_automated_or_mapped_rules': 1,
                'max_unsupported_rules': 0,
            }), encoding='utf-8')

            with self.assertRaisesRegex(SystemExit, 'public_disa_artifacts'):
                mod.validate(root, baseline)

    def test_fails_when_automated_coverage_regresses(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self._write_artifacts(root, 2)
            self._write_manifest(root, 'one', [
                {'classification': 'automated'},
                {'classification': 'unsupported'},
            ])
            baseline = root / 'baseline.json'
            baseline.write_text(json.dumps({
                'min_public_disa_artifacts': 2,
                'min_authoritative_manifests': 1,
                'min_authoritative_rules': 2,
                'min_automated_or_mapped_rules': 2,
                'max_unsupported_rules': 1,
            }), encoding='utf-8')

            with self.assertRaisesRegex(SystemExit, 'automated_or_mapped_rules'):
                mod.validate(root, baseline)

    def test_fails_when_unsupported_count_exceeds_ratchet(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self._write_artifacts(root, 2)
            self._write_manifest(root, 'one', [
                {'classification': 'automated'},
                {'classification': 'unsupported'},
                {'classification': 'unsupported'},
            ])
            baseline = root / 'baseline.json'
            baseline.write_text(json.dumps({
                'min_public_disa_artifacts': 2,
                'min_authoritative_manifests': 1,
                'min_authoritative_rules': 3,
                'min_automated_or_mapped_rules': 1,
                'max_unsupported_rules': 1,
            }), encoding='utf-8')

            with self.assertRaisesRegex(SystemExit, 'unsupported_rules'):
                mod.validate(root, baseline)


if __name__ == '__main__':
    unittest.main()
