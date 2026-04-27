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
    def test_generates_pass_and_fail_evidence_for_candidate_types(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pack = root / 'packs' / 'mixed.candidates.json'
            out = root / 'fixtures'
            pack.parent.mkdir()
            pack.write_text(json.dumps({
                'stig_id': 'Mixed Candidate STIG',
                'platform': 'generic',
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
                    },
                    {
                        'vuln_id': 'V-3',
                        'platform': 'linux',
                        'check': {'type': 'sysctl', 'key': 'kernel.kexec_load_disabled'},
                        'expected': {'type': 'equals', 'value': '1'},
                    },
                    {
                        'vuln_id': 'V-4',
                        'platform': 'linux',
                        'check': {'type': 'package', 'name': 'krb5-workstation', 'should_be_installed': False},
                        'expected': {'type': 'is_false'},
                    },
                    {
                        'vuln_id': 'V-5',
                        'platform': 'linux',
                        'check': {'type': 'file_content', 'path': '/etc/example.conf', 'pattern': 'expected', 'is_regex': False},
                        'expected': {'type': 'contains'},
                    },
                ],
            }))

            written = mod.generate_fixture_evidence(pack.parent, out)

            self.assertEqual(written, 1)
            evidence = json.loads((out / 'mixed.candidates.evidence.json').read_text())
            self.assertEqual(evidence['candidate_checks'], 5)
            self.assertEqual(evidence['validated_candidates'], 5)
            cases = {case['vuln_id']: case for case in evidence['cases']}
            self.assertEqual(cases['V-1']['pass_fixture']['registry']['HKLM\\Software\\Example\\Enabled'], 1)
            self.assertNotEqual(cases['V-1']['fail_fixture']['registry']['HKLM\\Software\\Example\\Enabled'], 1)
            self.assertFalse(cases['V-2']['pass_fixture']['packages']['Fax'])
            self.assertTrue(cases['V-2']['fail_fixture']['packages']['Fax'])
            self.assertEqual(cases['V-3']['pass_fixture']['sysctl']['kernel.kexec_load_disabled'], '1')
            self.assertNotEqual(cases['V-3']['fail_fixture']['sysctl']['kernel.kexec_load_disabled'], '1')
            self.assertFalse(cases['V-4']['pass_fixture']['packages']['krb5-workstation'])
            self.assertTrue(cases['V-4']['fail_fixture']['packages']['krb5-workstation'])
            self.assertIn('expected', cases['V-5']['pass_fixture']['files']['/etc/example.conf'])
            self.assertNotIn('expected', cases['V-5']['fail_fixture']['files']['/etc/example.conf'])


if __name__ == '__main__':
    unittest.main()
