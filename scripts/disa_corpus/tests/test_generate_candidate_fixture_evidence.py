import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

mod_path = Path(__file__).resolve().parents[1] / 'generate_candidate_fixture_evidence.py'
spec = importlib.util.spec_from_file_location('generate_candidate_fixture_evidence', mod_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class GenerateCandidateFixtureEvidenceTests(unittest.TestCase):
    def test_generates_pass_and_fail_evidence_for_registry_and_feature_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pack = root / 'packs' / 'windows.candidates.json'
            out = root / 'fixtures'
            pack.parent.mkdir()
            pack.write_text(json.dumps({
                'stig_id': 'Windows Candidate STIG',
                'platform': 'windows',
                'version': 'candidate-planned',
                'checks': [
                    {
                        'vuln_id': 'V-1',
                        'platform': 'windows',
                        'check': {'type': 'registry', 'path': 'HKLM\\Software\\Example', 'value_name': 'Enabled'},
                        'expected': {'type': 'equals', 'value': 1},
                        'description': 'registry check',
                    },
                    {
                        'vuln_id': 'V-2',
                        'platform': 'windows',
                        'check': {'type': 'windows_feature', 'name': 'Fax', 'should_be_installed': False},
                        'expected': {'type': 'is_false'},
                        'description': 'feature check',
                    },
                ],
            }))

            written = mod.generate_fixture_evidence(pack.parent, out)

            self.assertEqual(written, 1)
            evidence = json.loads((out / 'windows.candidates.evidence.json').read_text())
            self.assertEqual(evidence['candidate_checks'], 2)
            self.assertEqual(evidence['validated_candidates'], 2)
            by_vuln = {case['vuln_id']: case for case in evidence['cases']}
            self.assertEqual(by_vuln['V-1']['pass_fixture']['registry']['HKLM\\Software\\Example\\Enabled'], 1)
            self.assertNotEqual(by_vuln['V-1']['fail_fixture']['registry']['HKLM\\Software\\Example\\Enabled'], 1)
            self.assertFalse(by_vuln['V-2']['pass_fixture']['packages']['Fax'])
            self.assertTrue(by_vuln['V-2']['fail_fixture']['packages']['Fax'])


if __name__ == '__main__':
    unittest.main()
