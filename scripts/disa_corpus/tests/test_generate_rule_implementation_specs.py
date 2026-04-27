import importlib.util
import tempfile
import unittest
from pathlib import Path

mod_path = Path(__file__).resolve().parents[1] / 'generate_rule_implementation_specs.py'
spec = importlib.util.spec_from_file_location('generate_rule_implementation_specs', mod_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class GenerateRuleImplementationSpecsTests(unittest.TestCase):
    def test_generates_planned_specs_for_unsupported_rules_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            coverage = root / 'coverage' / 'sample.json'
            coverage.parent.mkdir()
            coverage.write_text('''{
              "stig_id": "Sample_STIG",
              "benchmark": "Sample",
              "version": "V1R1",
              "total_rules": 2,
              "generated_from": "fixtures/sample.zip",
              "rules": [
                {"vuln_id":"V-1","rule_id":"SV-1_rule","title":"Passwords must be configured.","classification":"unsupported","severity":"medium"},
                {"vuln_id":"V-2","rule_id":"SV-2_rule","title":"Already automated.","classification":"automated","severity":"low"}
              ]
            }''')
            out = root / 'impl'
            count = mod.generate_specs(coverage.parent, out)
            self.assertEqual(count, 1)
            files = list(out.rglob('*.json'))
            self.assertEqual(len(files), 1)
            text = files[0].read_text()
            self.assertIn('"implementation_status": "planned"', text)
            self.assertIn('"vuln_id": "V-1"', text)
            self.assertNotIn('V-2', text)

    def test_classifies_policy_language_as_manual_evidence_workflow(self):
        classification, collector = mod.classify_rule('The organization must document an approval process.')
        self.assertEqual(classification, 'manual')
        self.assertEqual(collector, 'manual_evidence_workflow')

    def test_infers_registry_candidate_check_from_disa_check_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254382',
            'title': 'WinRM service must not allow unencrypted traffic.',
            'check_content': '''If the following registry value does not exist or is not configured as specified, this is a finding:
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\
Value Name: AllowUnencryptedTraffic
Type: REG_DWORD
Value: 0x00000000 (0)'''
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service')
        self.assertEqual(candidate['check']['value_name'], 'AllowUnencryptedTraffic')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 0})

    def test_infers_windows_feature_candidate_check_from_powershell_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254269',
            'title': 'Windows Server 2022 must not have the Fax Server role installed.',
            'check_content': 'Enter "Get-WindowsFeature | Where Name -eq Fax". If "Installed State" is "Installed", this is a finding.'
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['check'], {'type': 'windows_feature', 'name': 'Fax', 'should_be_installed': False})
        self.assertEqual(candidate['expected'], {'type': 'is_false'})

    def test_infers_linux_sysctl_candidate_check_from_rhel_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230266',
            'title': 'RHEL 8 must prevent the loading of a new kernel for later execution.',
            'check_content': 'Check the status of the "kernel.kexec_load_disabled" kernel parameter with the following command: $ sudo sysctl kernel.kexec_load_disabled kernel.kexec_load_disabled = 1 If the returned line does not have a value of "1", this is a finding.'
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'sysctl', 'key': 'kernel.kexec_load_disabled'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '1'})

    def test_infers_linux_package_absent_candidate_check_from_rhel_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230239',
            'title': 'The krb5-workstation package must not be installed on RHEL 8.',
            'check_content': 'Verify the krb5-workstation package has not been installed on the system with the following command: $ sudo dnf list --installed krb5-workstation If the krb5-workstation package is installed, this is a finding.'
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'package', 'name': 'krb5-workstation', 'should_be_installed': False})
        self.assertEqual(candidate['expected'], {'type': 'is_false'})

    def test_infers_linux_file_content_candidate_check_from_grep_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230236',
            'title': 'RHEL 8 rescue mode must require authentication.',
            'check_content': 'Check with the following command: $ sudo grep sulogin-shell /usr/lib/systemd/system/rescue.service ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue If the line is not returned, this is a finding.'
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_content', 'path': '/usr/lib/systemd/system/rescue.service', 'pattern': 'sulogin-shell', 'is_regex': False})
        self.assertEqual(candidate['expected'], {'type': 'contains'})


if __name__ == '__main__':
    unittest.main()
