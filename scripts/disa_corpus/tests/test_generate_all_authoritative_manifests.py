import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

mod_path = Path(__file__).resolve().parents[1] / 'generate_all_authoritative_manifests.py'
spec = importlib.util.spec_from_file_location('generate_all_authoritative_manifests', mod_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class GenerateAllAuthoritativeManifestsTests(unittest.TestCase):
    def test_load_check_ids_includes_validated_generated_candidate_packs(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            candidate_root = repo / 'content' / 'check_packs' / 'generated-candidates'
            candidate_root.mkdir(parents=True)
            (candidate_root / 'example.candidates.json').write_text(json.dumps({
                'stig_id': 'example',
                'platform': 'windows',
                'version': 'candidate-planned',
                'checks': [{'vuln_id': 'V-1'}],
            }))
            evidence_root = repo / 'fixtures' / 'generated-candidate-evidence'
            evidence_root.mkdir(parents=True)
            (evidence_root / 'example.candidates.evidence.json').write_text(json.dumps({
                'source_check_pack': str(candidate_root / 'example.candidates.json'),
                'candidate_checks': 1,
                'validated_candidates': 1,
                'status': 'fixture_validated_candidates',
                'cases': [{'vuln_id': 'V-1'}],
            }))

            ids = mod.load_check_ids(repo)

            self.assertIn('V-1', ids)
            self.assertEqual(ids['V-1']['path'], 'content/check_packs/generated-candidates/example.candidates.json')
            self.assertEqual(ids['V-1']['name'], 'generated-candidates/example.candidates')
            self.assertTrue(ids['V-1']['fixture_validated'])

    def test_candidate_pack_without_evidence_is_not_loaded(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            candidate_root = repo / 'content' / 'check_packs' / 'generated-candidates'
            candidate_root.mkdir(parents=True)
            (candidate_root / 'example.candidates.json').write_text(json.dumps({
                'checks': [{'vuln_id': 'V-1'}],
            }))

            ids = mod.load_check_ids(repo)

            self.assertNotIn('V-1', ids)


if __name__ == '__main__':
    unittest.main()
