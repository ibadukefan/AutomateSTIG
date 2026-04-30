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
                    {
                        'vuln_id': 'V-6',
                        'platform': 'linux',
                        'check': {'type': 'service', 'name': 'telnet', 'expected_status': 'disabled'},
                        'expected': {'type': 'equals', 'value': 'disabled'},
                    },
                    {
                        'vuln_id': 'V-7',
                        'platform': 'linux',
                        'check': {'type': 'file_permission', 'path': '/var/log/audit/audit.log', 'owner': None, 'group': None, 'mode': '600'},
                        'expected': {'type': 'is_true'},
                    },
                    {
                        'vuln_id': 'V-8',
                        'platform': 'windows',
                        'check': {'type': 'audit_policy', 'subcategory': 'User Account Management', 'setting': 'Success'},
                        'expected': {'type': 'contains', 'substring': 'Success'},
                    },
                    {
                        'vuln_id': 'V-9',
                        'platform': 'windows',
                        'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeLockMemoryPrivilege'},
                        'expected': {'type': 'equals', 'value': ''},
                    },
                    {
                        'vuln_id': 'V-10',
                        'platform': 'windows',
                        'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeDenyInteractiveLogonRight'},
                        'expected': {'type': 'matches', 'pattern': '(?=.*S-1-5-32-546)'},
                    },
                ],
            }))

            written = mod.generate_fixture_evidence(pack.parent, out)

            self.assertEqual(written, 1)
            evidence = json.loads((out / 'mixed.candidates.evidence.json').read_text())
            self.assertEqual(evidence['candidate_checks'], 10)
            self.assertEqual(evidence['validated_candidates'], 10)
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
            self.assertEqual(cases['V-6']['pass_fixture']['services']['telnet'], 'disabled')
            self.assertNotEqual(cases['V-6']['fail_fixture']['services']['telnet'], 'disabled')
            self.assertEqual(cases['V-7']['pass_fixture']['file_permissions']['/var/log/audit/audit.log']['mode'], '600')
            self.assertNotEqual(cases['V-7']['fail_fixture']['file_permissions']['/var/log/audit/audit.log']['mode'], '600')
            self.assertEqual(cases['V-8']['evidence_type'], 'windows_audit_policy_contains')
            self.assertEqual(cases['V-8']['pass_fixture']['audit_policy']['User Account Management'], 'Success')
            self.assertEqual(cases['V-8']['fail_fixture']['audit_policy']['User Account Management'], 'No Auditing')
            self.assertEqual(cases['V-9']['evidence_type'], 'windows_security_policy_equals')
            self.assertEqual(cases['V-9']['pass_fixture']['security_policy']['Privilege Rights\\SeLockMemoryPrivilege'], '')
            self.assertNotEqual(cases['V-9']['fail_fixture']['security_policy']['Privilege Rights\\SeLockMemoryPrivilege'], '')
            self.assertEqual(cases['V-10']['evidence_type'], 'windows_security_policy_matches')
            self.assertIn('S-1-5-32-546', cases['V-10']['pass_fixture']['security_policy']['Privilege Rights\\SeDenyInteractiveLogonRight'])
            self.assertNotIn('S-1-5-32-546', cases['V-10']['fail_fixture']['security_policy']['Privilege Rights\\SeDenyInteractiveLogonRight'])

    def test_builds_command_output_fixture_case(self):
        case = mod.build_case({
            'vuln_id': 'V-256393',
            'platform': 'generic',
            'description': 'SSH tunnel setting',
            'check': {'type': 'command_output', 'command': '/usr/lib/vmware/openssh/bin/sshd -T|grep permittunnel'},
            'expected': {'type': 'equals', 'value': 'permittunnel no'},
        })
        self.assertEqual(case['evidence_type'], 'command_output_equals')
        self.assertEqual(case['pass_fixture']['command_outputs'], {'/usr/lib/vmware/openssh/bin/sshd -T|grep permittunnel': 'permittunnel no'})
        self.assertNotEqual(case['fail_fixture']['command_outputs']['/usr/lib/vmware/openssh/bin/sshd -T|grep permittunnel'], 'permittunnel no')

    def test_builds_file_content_absent_fixture_case(self):
        case = mod.build_case({
            'vuln_id': 'V-251712',
            'platform': 'linux',
            'description': 'sudo password bypass',
            'check': {'type': 'file_content', 'path': '/etc/pam.d/sudo', 'pattern': 'pam_succeed_if', 'is_regex': False},
            'expected': {'type': 'is_false'},
        })
        self.assertEqual(case['evidence_type'], 'linux_file_content_absent')
        self.assertNotIn('pam_succeed_if', case['pass_fixture']['files']['/etc/pam.d/sudo'])
        self.assertIn('pam_succeed_if', case['fail_fixture']['files']['/etc/pam.d/sudo'])

    def test_builds_command_output_contains_fixture_case(self):
        case = mod.build_case({
            'vuln_id': 'V-258230',
            'platform': 'linux',
            'description': 'FIPS mode',
            'check': {'type': 'command_output', 'command': 'fips-mode-setup --check'},
            'expected': {'type': 'contains', 'substring': 'FIPS mode is enabled.'},
        })
        self.assertEqual(case['evidence_type'], 'command_output_contains')
        self.assertEqual(case['pass_fixture']['command_outputs'], {'fips-mode-setup --check': 'before\nFIPS mode is enabled.\nafter\n'})
        self.assertEqual(case['fail_fixture']['command_outputs'], {'fips-mode-setup --check': 'before\nafter\n'})


if __name__ == '__main__':
    unittest.main()
