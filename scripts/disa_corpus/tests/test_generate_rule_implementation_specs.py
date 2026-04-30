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

    def test_infers_chrome_registry_policy_candidate_from_windows_method(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-221586',
            'title': 'Deletion of browser history must be disabled.',
            'check_content': '''Universal method:
1. In the omnibox type chrome://policy
2. If the policy "AllowDeletingBrowserHistory" is not shown or is not set to false, this is a finding.

Windows method:
1. Start regedit
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
3. If the "AllowDeletingBrowserHistory" value name does not exist or its value data is not set to "0", this is a finding.'''
        }, 'Google_Chrome_Current_Windows')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKLM\\Software\\Policies\\Google\\Chrome')
        self.assertEqual(candidate['check']['value_name'], 'AllowDeletingBrowserHistory')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 0})

    def test_infers_chrome_policy_value_from_boolean_false_text(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-245538',
            'title': 'Use of the QUIC protocol must be disabled.',
            'check_content': '''Universal method:
If QuicAllowed is not displayed under the Policy Name column or it is not set to False under the Policy Value column, this is a finding.
Windows method:
1. Start regedit.
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\.
3. If the QuicAllowed value name does not exist or its value data is not set to 0, this is a finding.'''
        }, 'Google_Chrome_Current_Windows')
        self.assertEqual(candidate['check'], {'type': 'registry', 'path': 'HKLM\\Software\\Policies\\Google\\Chrome', 'value_name': 'QuicAllowed'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 0})

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

    def test_infers_linux_service_disabled_candidate_from_systemctl_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251234',
            'title': 'RHEL must not have the telnet service enabled.',
            'check_content': 'Verify the telnet service is disabled with the following command: $ systemctl is-enabled telnet.service If the service is enabled, this is a finding.'
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'telnet', 'expected_status': 'disabled'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'disabled'})

    def test_infers_linux_file_permission_candidate_from_stat_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251235',
            'title': 'RHEL audit logs must have mode 0600.',
            'check_content': 'Check the permissions with the following command: $ stat -c "%a %U %G" /var/log/audit/audit.log If the mode is not "600", this is a finding.'
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_permission', 'path': '/var/log/audit/audit.log', 'owner': None, 'group': None, 'mode': '600'})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_infers_linux_sshd_config_keyword_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230555',
            'title': 'RHEL 8 remote X connections for interactive users must be disabled.',
            'check_content': '''Verify X11Forwarding is disabled with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*x11forwarding'

X11Forwarding no

If the "X11Forwarding" keyword is set to "yes" and is not documented with the information system security officer (ISSO) as an operational requirement or is missing, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_content', 'path': '/etc/ssh/sshd_config', 'pattern': 'X11Forwarding no', 'is_regex': False})
        self.assertEqual(candidate['expected'], {'type': 'contains'})

    def test_infers_linux_grep_expected_line_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230485',
            'title': 'RHEL 8 must disable the chrony daemon from acting as a server.',
            'check_content': '''Verify RHEL 8 disables the chrony daemon from acting as a server with the following command:

$ sudo grep -w 'port' /etc/chrony.conf
port 0

If the "port" option is not set to "0", is commented out or missing, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_content', 'path': '/etc/chrony.conf', 'pattern': 'port 0', 'is_regex': False})
        self.assertEqual(candidate['expected'], {'type': 'contains'})

    def test_infers_windows_audit_policy_candidate_from_auditpol_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254304',
            'title': 'Windows Server 2022 must be configured to audit Account Management - User Account Management successes.',
            'check_content': '''Use the "AuditPol" tool to review the current Audit Policy configuration:

Enter "AuditPol /get /category:*"

Compare the "Account Management - User Account Management" audit policy setting with the following:
User Account Management  Success

If the system is not configured to audit successes, this is a finding.'''
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'audit_policy', 'subcategory': 'User Account Management', 'setting': 'Success'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'Success'})

    def test_infers_windows_user_right_security_policy_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254506',
            'title': 'Windows Server 2022 lock pages in memory user right must not be assigned to any groups or accounts.',
            'check_content': '''Verify the effective setting in Local Group Policy Editor.

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Lock pages in memory" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs are granted the "SeLockMemoryPrivilege" user right, this is a finding.'''
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeLockMemoryPrivilege'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_windows_user_right_required_sid_list_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254438',
            'title': 'Windows Server 2022 Deny log on locally user right must include required groups.',
            'check_content': '''Verify the effective setting in Local Group Policy Editor.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If the following SIDs are not defined for the "SeDenyInteractiveLogonRight" user right, this is a finding:

Domain Systems Only:
S-1-5-root domain-519 (Enterprise Admins)
S-1-5-domain-512 (Domain Admins)

All Systems:
S-1-5-32-546 (Guests)'''
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeDenyInteractiveLogonRight'})
        self.assertEqual(candidate['expected'], {'type': 'matches', 'pattern': '(?=.*S-1-5-32-546)'})


if __name__ == '__main__':
    unittest.main()
