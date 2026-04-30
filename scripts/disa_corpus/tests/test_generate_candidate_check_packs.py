import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

mod_path = Path(__file__).resolve().parents[1] / 'generate_candidate_check_packs.py'
spec = importlib.util.spec_from_file_location('generate_candidate_check_packs', mod_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class GenerateCandidateCheckPacksTests(unittest.TestCase):
    def test_emits_check_pack_for_specs_with_candidate_checks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            specs = root / 'specs' / 'sample_stig'
            specs.mkdir(parents=True)
            (specs / 'v-1.json').write_text(json.dumps({
                'vuln_id': 'V-1',
                'rule_id': 'SV-1_rule',
                'stig_id': 'Sample_STIG',
                'title': 'Registry rule',
                'classification': 'automated',
                'implementation_status': 'planned',
                'collector_type': 'windows_collector',
                'candidate_check': {
                    'vuln_id': 'V-1',
                    'platform': 'windows',
                    'check': {'type': 'registry', 'path': 'HKLM\\Software\\Example', 'value_name': 'Enabled'},
                    'expected': {'type': 'equals', 'value': 1},
                    'description': 'Registry rule'
                }
            }))
            (specs / 'v-2.json').write_text(json.dumps({
                'vuln_id': 'V-2', 'rule_id': 'SV-2_rule', 'stig_id': 'Sample_STIG',
                'title': 'Manual rule', 'classification': 'manual', 'implementation_status': 'planned',
                'collector_type': 'manual_evidence_workflow'
            }))
            out = root / 'packs'
            written = mod.generate_candidate_packs(root / 'specs', out)
            self.assertEqual(written, 1)
            pack = json.loads((out / 'sample_stig.candidates.json').read_text())
            self.assertEqual(pack['stig_id'], 'Sample_STIG')
            self.assertEqual(pack['platform'], 'windows')
            self.assertEqual(len(pack['checks']), 1)
            self.assertEqual(pack['checks'][0]['vuln_id'], 'V-1')


if __name__ == '__main__':
    unittest.main()
