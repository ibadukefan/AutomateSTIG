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

    def test_manual_generated_spec_maps_to_manual_evidence_without_check_pack(self):
        manual_specs = {
            'V-999001': {
                'path': 'content/rule-implementations/generated/example_stig/v-999001.json',
                'collector_type': 'manual_evidence_workflow',
            }
        }
        inv = {
            'benchmark_id': 'Example_STIG',
            'rules': [{
                'vuln_id': 'V-999001',
                'rule_id': 'SV-999001r1_rule',
                'title': 'Example rule requires documented approval.',
                'severity': 'medium',
            }],
        }

        manifest = mod.manifest_from_inventory(inv, 'fixtures/example.zip', {}, manual_specs)

        rule = manifest['rules'][0]
        self.assertEqual(rule['classification'], 'manual')
        self.assertEqual(rule['check_pack'], '')
        self.assertEqual(rule['check_id'], 'V-999001')
        self.assertEqual(rule['tracking_issue'], '')
        self.assertIn('Generated manual evidence workflow', rule['reason'])
        self.assertIn('content/rule-implementations/generated/example_stig/v-999001.json', rule['validated_by'])

    def test_scap_xccdf_group_ids_map_to_canonical_vuln_candidates(self):
        check_ids = {
            'V-230239': {
                'name': 'generated-candidates/rhel_8_stig.candidates',
                'path': 'content/check_packs/generated-candidates/rhel_8_stig.candidates.json',
                'fixture_validated': True,
            }
        }
        inv = {
            'benchmark_id': 'SCAP_mil.disa.stig_collection_U_RHEL_8_V2R7_STIG_SCAP_1-3_Benchmark',
            'rules': [{
                'vuln_id': 'xccdf_mil.disa.stig_group_V-230239',
                'rule_id': 'xccdf_mil.disa.stig_rule_SV-230239r1_rule',
                'title': 'RHEL 8 must configure a kernel setting.',
                'severity': 'medium',
            }],
        }

        manifest = mod.manifest_from_inventory(inv, 'fixtures/u_rhel_8_scap.zip', check_ids)

        rule = manifest['rules'][0]
        self.assertEqual(rule['vuln_id'], 'V-230239')
        self.assertEqual(rule['classification'], 'automated')
        self.assertEqual(rule['check_id'], 'V-230239')
        self.assertIn('canonical DISA Vuln ID', rule['reason'])


if __name__ == '__main__':
    unittest.main()
