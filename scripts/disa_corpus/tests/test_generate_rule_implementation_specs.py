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

    def test_infers_registry_candidate_check_from_concrete_string_value(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254433',
            'title': 'Windows Server must restrict remote calls to the Security Account Manager.',
            'check_content': '''If the following registry value does not exist or is not configured as specified, this is a finding:
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\
Value Name: RestrictRemoteSAM
Value Type: REG_SZ
Value: O:BAG:BAD:(A;;RC;;;BA)'''
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa')
        self.assertEqual(candidate['check']['value_name'], 'RestrictRemoteSAM')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'O:BAG:BAD:(A;;RC;;;BA)'})

    def test_infers_office_registry_not_finding_when_value_for_quoted_name_is_exact_dword(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223313',
            'title': 'Dynamic Data Exchange (DDE) server lookup in Excel must be blocked.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> External Content >> Don't allow Dynamic Data Exchange (DDE) server lookup in Excel is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\external content

If the value for "disableddeserverlookup" is REG_DWORD = 1, this is not a finding.'''
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\external content')
        self.assertEqual(candidate['check']['value_name'], 'disableddeserverlookup')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 1})

    def test_infers_registry_candidate_when_check_and_fix_repeat_same_authoritative_fields(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-213117',
            'title': 'Adobe Acrobat enhanced security must be enabled.',
            'check_content': '''Utilizing the Registry Editor, navigate to the following:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown\\
Value Name: bEnhancedSecurityStandalone
Type: REG_DWORD
Value: 1

If the value is not set to 1, this is a finding.

Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown\\
Value Name: bEnhancedSecurityStandalone
Type: REG_DWORD
Value: 1'''
        }, 'Adobe_Acrobat_Pro_DC_Continuous_STIG')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKLM\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown')
        self.assertEqual(candidate['check']['value_name'], 'bEnhancedSecurityStandalone')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 1})

    def test_skips_registry_candidate_when_repeated_authoritative_fields_disagree(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-213117',
            'title': 'Adobe Acrobat enhanced security must be enabled.',
            'check_content': '''Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown\\
Value Name: bEnhancedSecurityStandalone
Type: REG_DWORD
Value: 1''',
            'fix_text': '''Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown\\
Value Name: bEnhancedSecurityInBrowser
Type: REG_DWORD
Value: 1'''
        }, 'Adobe_Acrobat_Pro_DC_Continuous_STIG')
        self.assertIsNone(candidate)

    def test_infers_defender_registry_candidate_from_explicit_criteria_not_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278668',
            'title': 'Microsoft Defender AV must enable script scanning.',
            'check_content': '''Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> Turn on script scanning is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "DisableScriptScanning" is REG_DWORD = 0, this is not a finding.

If the value is 1, this is a finding.'''
        }, 'MS_Defender_Antivirus')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection')
        self.assertEqual(candidate['check']['value_name'], 'DisableScriptScanning')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 0})

    def test_infers_office_registry_candidate_from_unprefixed_not_finding_statement(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223397',
            'title': 'Visio 2003-2010 Binary Drawings, Templates and Stencils must be blocked.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Visio 2016 >> Visio Options >> Security >> Trust Center >> File Block Settings "Visio 2003-2010 Binary Drawings, Templates and Stencils" is set to "Enabled" and "Open/Save blocked".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\visio\\security\\fileblock

If the value "visio2003files" is REG_DWORD = 2, this is not a finding.'''
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\visio\\security\\fileblock')
        self.assertEqual(candidate['check']['value_name'], 'visio2003files')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 2})

    def test_infers_office_registry_candidate_from_value_for_not_finding_statement(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223339',
            'title': 'Excel must open database files in Protected View.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Open database files in Protected View is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\protectedview

If the value for enabledatabasefileprotectedview is REG_DWORD = 1, this is not a finding.'''
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\protectedview')
        self.assertEqual(candidate['check']['value_name'], 'enabledatabasefileprotectedview')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 1})

    def test_infers_office_registry_candidate_from_unquoted_value_name_not_finding_statement(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223315',
            'title': 'Open/save of Dif and Sylk format files must be blocked.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> File Block Settings "Dif and Sylk files" is set to "Enabled: Open/Save blocked, use open policy".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\excel\\security\\fileblock

If the value DifandSylkFiles is REG_DWORD = 2, this is not a finding.'''
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\excel\\security\\fileblock')
        self.assertEqual(candidate['check']['value_name'], 'DifandSylkFiles')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 2})

    def test_infers_office_registry_candidate_from_windows_registry_without_editor(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223354',
            'title': 'Internet must not be included in Safe Zone for picture download in Outlook.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Automatic Picture Download Settings >> Include Internet in Safe Zones for Automatic Picture Download is set to "Disabled".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\options\\mail

If the value for Internet is set to REG_DWORD = 0, this is not a finding.'''
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\options\\mail')
        self.assertEqual(candidate['check']['value_name'], 'Internet')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 0})

    def test_infers_required_user_right_candidate_from_sid_parenthetical_plural(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254422',
            'title': 'Windows Server 2022 Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access.',
            'check_content': '''This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a batch job" user right, this is a finding:

- Guests Group

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If the following SID(s) are not defined for the "SeDenyBatchLogonRight" user right, this is a finding:

S-1-5-32-546 (Guests)'''
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeDenyBatchLogonRight'})
        self.assertEqual(candidate['expected'], {'type': 'matches', 'pattern': '(?=.*S-1-5-32-546)'})

    def test_infers_windows_feature_candidate_check_from_powershell_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254269',
            'title': 'Windows Server 2022 must not have the Fax Server role installed.',
            'check_content': 'Enter "Get-WindowsFeature | Where Name -eq Fax". If "Installed State" is "Installed", this is a finding.'
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['check'], {'type': 'windows_feature', 'name': 'Fax', 'should_be_installed': False})
        self.assertEqual(candidate['expected'], {'type': 'is_false'})

    def test_infers_windows_feature_candidate_check_from_name_argument(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278023',
            'title': 'Windows Server 2025 must not have the Server Message Block (SMB) v1 protocol installed.',
            'check_content': '''Different methods are available to disable SMBv1 on Windows Server 2025.

Open Windows PowerShell with elevated privileges (run as administrator).

Enter "Get-WindowsFeature -Name FS-SMB1".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.'''
        }, 'MS_Windows_Server_2025_STIG')
        self.assertEqual(candidate['check'], {'type': 'windows_feature', 'name': 'FS-SMB1', 'should_be_installed': False})
        self.assertEqual(candidate['expected'], {'type': 'is_false'})

    def test_infers_registry_candidate_from_compact_authoritative_fields(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278085',
            'title': 'Windows Server 2025 must be configured to ignore NetBIOS name release requests except from WINS servers.',
            'check_content': '''If the following registry value does not exist or is not configured as specified, this is a finding:

Registry HiveHKEY_LOCAL_MACHINE
Registry Path\\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters\\

Value NameNoNameReleaseOnDemand

Value TypeREG_DWORD
Value0x00000001 (1)'''
        }, 'MS_Windows_Server_2025_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {
            'type': 'registry',
            'path': 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters',
            'value_name': 'NoNameReleaseOnDemand',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 1})

    def test_skips_compact_registry_value_with_or_less_semantics(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278181',
            'title': 'Windows Server 2025 must limit cached logons.',
            'check_content': '''Registry HiveHKEY_LOCAL_MACHINE
Registry Path\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\
Value NameCachedLogonsCount
Value TypeREG_SZ
Value4 (or less)'''
        }, 'MS_Windows_Server_2025_STIG')
        self.assertIsNone(candidate)

    def test_skips_registry_candidate_when_value_line_lists_multiple_allowed_values(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278103',
            'title': 'Windows Server 2025 Telemetry must be configured to limit diagnostic data sent to Microsoft.',
            'check_content': '''Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\
Value Name: AllowTelemetry
Type: REG_DWORD
Value0x00000000 (0), 0x00000001 (1)'''
        }, 'MS_Windows_Server_2025_STIG')
        self.assertIsNone(candidate)

    def test_skips_registry_candidate_when_multiple_authoritative_paths_disagree(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-213133',
            'title': 'Adobe Acrobat Pro DC Continuous Repair Installation must be disabled.',
            'check_content': '''Value Name: DisableMaintenance
Type: REG_DWORD
Value: 1''',
            'fix_text': '''For 32 bit:
Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Adobe\\Adobe Acrobat\\DC\\Installer

For 64 bit:
Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\SOFTWARE\\Wow6432Node\\Adobe\\Adobe Acrobat\\DC\\Installer

Value Name: DisableMaintenance
Type: REG_DWORD
Value: 1'''
        }, 'Adobe_Acrobat_Pro_DC_Continuous_STIG')
        self.assertIsNone(candidate)

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

    def test_infers_windows_browser_registry_policy_candidate_from_registry_editor_key(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-235756',
            'title': 'The Password Manager must be disabled.',
            'check_content': '''The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Password manager and protection/Enable saving passwords to the password manager" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "PasswordManagerEnabled" is not set to "REG_DWORD = 0", this is a finding.'''
        }, 'MS_Edge_STIG')
        self.assertEqual(candidate['check'], {'type': 'registry', 'path': 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge', 'value_name': 'PasswordManagerEnabled'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 0})

    def test_infers_windows_admin_template_registry_key_candidate_from_gpedit_alternative(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271429',
            'title': 'Windows Server 2019 must be configured for named-based strong mappings for certificates.',
            'check_content': '''Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".
Or
Using the registry, check HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\KDC\\Parameters, Key: UseStrongNameMatches.
Or
Using GPRESULT, check the applicable GPO for "Allow name-based strong mappings for certificates".

Navigate to Local Computer Policy >> Computer Configuration >> Administrative Template >> System >> KDC >> Allow name-based strong mappings for certificates.

If "Allow name-based strong mappings for certificates" is not "Enabled", this is a finding.'''
        }, 'Windows_Server_2019_STIG')
        self.assertEqual(candidate['check'], {'type': 'registry', 'path': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\KDC\\Parameters', 'value_name': 'UseStrongNameMatches'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 1})

    def test_infers_linux_sysctl_candidate_check_from_rhel_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230266',
            'title': 'RHEL 8 must prevent the loading of a new kernel for later execution.',
            'check_content': 'Check the status of the "kernel.kexec_load_disabled" kernel parameter with the following command: $ sudo sysctl kernel.kexec_load_disabled kernel.kexec_load_disabled = 1 If the returned line does not have a value of "1", this is a finding.'
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'sysctl', 'key': 'kernel.kexec_load_disabled'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '1'})

    def test_infers_linux_sysctl_candidate_check_from_sles_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-235015',
            'title': 'The SUSE operating system must not forward Internet Protocol version 6 source-routed packets.',
            'check_content': '''Verify the SUSE operating system does not accept IPv6 source-routed packets.

Check the value of the IPv6 accept source route variable with the following command:

> sudo sysctl net.ipv6.conf.all.accept_source_route
net.ipv6.conf.all.accept_source_route = 0

If the network parameter "ipv6.conf.all.accept_source_route" is not equal to "0" or nothing is returned, this is a finding.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'sysctl', 'key': 'net.ipv6.conf.all.accept_source_route'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '0'})

    def test_infers_windows_optional_feature_candidate_check_from_powershell_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-220729',
            'title': 'The Server Message Block (SMB) v1 protocol must be disabled on the system.',
            'check_content': '''Run "Windows PowerShell" with elevated privileges (run as administrator). Enter the following:

Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol

If "State : Enabled" is returned, this is a finding.'''
        }, 'MS_Windows_10_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'windows_feature', 'name': 'SMB1Protocol', 'should_be_installed': False})
        self.assertEqual(candidate['expected'], {'type': 'is_false'})

    def test_infers_linux_package_absent_candidate_check_from_rhel_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230239',
            'title': 'The krb5-workstation package must not be installed on RHEL 8.',
            'check_content': 'Verify the krb5-workstation package has not been installed on the system with the following command: $ sudo dnf list --installed krb5-workstation If the krb5-workstation package is installed, this is a finding.'
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'package', 'name': 'krb5-workstation', 'should_be_installed': False})
        self.assertEqual(candidate['expected'], {'type': 'is_false'})

    def test_infers_linux_package_candidate_from_yum_list_installed_without_dash_dash(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230489',
            'title': 'RHEL 8 must not have the sendmail package installed.',
            'check_content': '''Check to see if the sendmail package is installed with the following command:

$ sudo yum list installed sendmail

If the sendmail package is installed, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'package', 'name': 'sendmail', 'should_be_installed': False})
        self.assertEqual(candidate['expected'], {'type': 'is_false'})

    def test_infers_linux_package_candidate_from_quoted_dnf_package_name(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257837',
            'title': 'RHEL 9 must not have a graphical display manager installed unless approved.',
            'check_content': '''Verify the xorg-x11-server-common package is not installed with the following command:

$ dnf list --installed "xorg-x11-server-common"
Error: No matching Packages to list

If the "xorg-x11-server-common" package is installed, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'package', 'name': 'xorg-x11-server-common', 'should_be_installed': False})
        self.assertEqual(candidate['expected'], {'type': 'is_false'})

    def test_infers_sles_package_candidate_from_single_zypper_info_command(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234966',
            'title': 'The audit-audispd-plugins must be installed on the SUSE operating system.',
            'check_content': '''Verify that the "audit-audispd-plugins" package is installed on the SUSE operating system.

Check that the "audit-audispd-plugins" package is installed on the SUSE operating system with the following command:

> zypper info audit-audispd-plugins | grep Installed

If the "audit-audispd-plugins" package is not installed, this is a finding.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate['check'], {'type': 'package', 'name': 'audit-audispd-plugins', 'should_be_installed': True})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_infers_sles_package_candidate_from_single_zypper_search_command(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-256983',
            'title': 'The SUSE operating system must be configured to allow sending email notifications.',
            'check_content': '''Verify that the operating system is configured to allow sending email notifications.

Note: The "mailx" package provides the "mail" command that is used to send email messages.

Verify that the "mailx" package is installed on the system:

> sudo zypper se mailx

i | mailx | A MIME-Capable Implementation of the mailx Command | package

If "mailx" is not installed, this is a finding.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate['check'], {'type': 'package', 'name': 'mailx', 'should_be_installed': True})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_infers_linux_package_absent_candidate_from_dpkg_grep_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-238326',
            'title': 'The Ubuntu operating system must not have the telnet package installed.',
            'check_content': 'Verify that the telnet package is not installed by running: $ dpkg -l | grep telnetd If the package is installed, this is a finding.'
        }, 'Canonical_Ubuntu_20-04_LTS_STIG')
        self.assertEqual(candidate['check'], {'type': 'package', 'name': 'telnetd', 'should_be_installed': False})
        self.assertEqual(candidate['expected'], {'type': 'is_false'})

    def test_infers_linux_sysctl_candidate_from_fix_text_config_line(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230543',
            'title': 'RHEL 8 must not allow interfaces to perform ICMP redirects by default.',
            'check_content': 'Verify settings are applied with sysctl --system.',
            'fix_text': '''Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.default.send_redirects = 0

Load settings from all system configuration files with the following command:
$ sudo sysctl --system'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'sysctl', 'key': 'net.ipv4.conf.default.send_redirects'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '0'})

    def test_infers_linux_file_content_candidate_check_from_grep_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230236',
            'title': 'RHEL 8 rescue mode must require authentication.',
            'check_content': 'Check with the following command: $ sudo grep sulogin-shell /usr/lib/systemd/system/rescue.service ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue If the line is not returned, this is a finding.'
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_content', 'path': '/usr/lib/systemd/system/rescue.service', 'pattern': 'sulogin-shell', 'is_regex': False})
        self.assertEqual(candidate['expected'], {'type': 'contains'})

    def test_infers_rpm_verify_command_as_empty_output_requirement(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271481',
            'title': 'OL 9 cryptographic policy files must match files shipped with the operating system.',
            'check_content': '''Verify that OL 9 crypto-policies package has not been modified with the following command:

$ rpm -V crypto-policies

If the command has any output, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'rpm -V crypto-policies'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_rpm_va_command_when_any_output_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257823',
            'title': 'RHEL 9 must be configured so that cryptographic hashes of system files match vendor values.',
            'check_content': '''List files on the system that have file hashes different from what is expected by the RPM database with the following command:

$ sudo rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != "c"'

If there is output, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'rpm -Va --noconfig | awk \'$1 ~ /..5/ && $2 != "c"\''})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_find_command_when_displays_any_output_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-238337',
            'title': 'The Ubuntu operating system must generate error messages without revealing exploitable information.',
            'check_content': '''Verify the Ubuntu operating system has all system log files under the "/var/log" directory with a permission set to "640" or less permissive by using the following command:

$ sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \\;

If the command displays any output, this is a finding.'''
        }, 'Canonical_Ubuntu_20-04_LTS_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'find /var/log -perm /137 ! -name \'*[bw]tmp\' ! -name \'*lastlog\' -type f -exec stat -c "%n %a" {} \\;'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_grep_command_when_produces_any_output_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-256445',
            'title': 'The ESXi host must not be configured to override virtual machine (VM) logger settings.',
            'check_content': '''From an ESXi shell, run the following command:

# grep "^vmx\\.log" /etc/vmware/config

If the command produces any output, this is a finding.'''
        }, 'VMW_vSphere_7-0_ESXi_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'grep "^vmx\\.log" /etc/vmware/config'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_grep_pipeline_when_this_produces_any_output_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234898',
            'title': 'The SUSE operating system must not be configured to allow blank or null passwords.',
            'check_content': '''Verify the SUSE operating system is not configured to allow blank or null passwords.

Check that blank or null passwords cannot be used by running the following command:

> grep pam_unix.so /etc/pam.d/* | grep nullok

If this produces any output, it may be possible to log on with accounts with empty passwords.

If null passwords can be used, this is a finding.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'grep pam_unix.so /etc/pam.d/* | grep nullok'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_esxi_absolute_command_when_output_is_not_literal_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-256430',
            'title': 'The ESXi host must enable Secure Boot.',
            'check_content': '''From an ESXi shell, run the following command:

# /usr/lib/vmware/secureboot/bin/secureBoot.py -s

If the output is not "Enabled", this is a finding.'''
        }, 'VMW_vSphere_7-0_ESXi_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': '/usr/lib/vmware/secureboot/bin/secureBoot.py -s'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'Enabled'})

    def test_infers_quoted_netsh_portproxy_command_when_displays_any_results_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257593',
            'title': 'Windows 10 must not have portproxy enabled or in use.',
            'check_content': '''Check the registry key for existence of proxied ports:
HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\.

If the key contains v4tov4\\tcp\\ or is populated v4tov4\\tcp\\, this is a finding.

Run "netsh interface portproxy show all".

If the command displays any results, this is a finding.'''
        }, 'MS_Windows_10_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'netsh interface portproxy show all'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_absolute_pipeline_when_command_does_not_return_literal_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259430',
            'title': 'The macOS system must enforce SSH to display the Standard Mandatory DOD Notice and Consent Banner.',
            'check_content': '''Verify the macOS system is configured to display the contents of "/etc/banner" before granting access to the system with the following command:

/usr/sbin/sshd -G | /usr/bin/grep -c "^banner /etc/banner"

If the command does not return "1", this is a finding.'''
        }, 'Apple_macOS_14_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': '/usr/sbin/sshd -G | /usr/bin/grep -c "^banner /etc/banner"'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '1'})

    def test_skips_absolute_pipeline_literal_when_rule_has_additional_banner_text_requirement(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-268431',
            'title': 'The macOS system must display the Standard Mandatory DOD Notice and Consent Banner at the login window.',
            'check_content': '''Verify the macOS system is configured to display a policy banner with the following command:

/bin/ls -ld /Library/Security/PolicyBanner.rtf* | /usr/bin/wc -l | /usr/bin/tr -d ' '

If the command does not return "1", this is a finding.

The banner text of the document must read:

"You are accessing a U.S. Government (USG) Information System (IS)."

If the text is not worded exactly this way, this is a finding.'''
        }, 'Apple_macOS_15_STIG')
        self.assertIsNone(candidate)

    def test_infers_grep_command_output_candidate_from_authoritative_sample_line(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230358',
            'title': 'RHEL 8 must enforce password complexity by requiring a lowercase character.',
            'check_content': '''Verify the value for "lcredit" with the following command:

$ sudo grep -r lcredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:lcredit = -1

If the value of "lcredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'grep -r lcredit /etc/security/pwquality.conf*'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'lcredit = -1'})

    def test_infers_commented_grep_sample_when_uncommented_line_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-244526',
            'title': 'The RHEL 8 SSH daemon must be configured to use system-wide crypto policies.',
            'check_content': '''Verify that system-wide crypto policies are in effect:

$ sudo grep CRYPTO_POLICY /etc/sysconfig/sshd
# CRYPTO_POLICY=

If the "CRYPTO_POLICY" is uncommented, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'grep CRYPTO_POLICY /etc/sysconfig/sshd'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': '# CRYPTO_POLICY='})

    def test_skips_grep_sample_candidate_when_authoritative_output_has_multiple_lines(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270784',
            'title': 'Ubuntu must generate audit records for xattr syscalls.',
            'check_content': '''Verify audit records with the following command:

$ sudo grep -r xattr audit-rules/*
-a always,exit -F arch=b32 -S setxattr -k perm_mod
-a always,exit -F arch=b64 -S setxattr -k perm_mod

If the command does not return audit rules for the xattr syscalls, or the lines are commented out, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertIsNone(candidate)

    def test_skips_grep_sample_candidate_when_finding_text_does_not_reference_sample_key(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-999999',
            'title': 'RHEL must verify a derived example.',
            'check_content': '''Verify the setting with the following command:

$ sudo grep -r example /etc/example.conf*
example = enabled

If a different unrelated setting is missing, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertIsNone(candidate)

    def test_skips_grep_sample_candidate_when_command_is_piped(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271525',
            'title': 'OL 9 repositories must enable gpgcheck.',
            'check_content': '''Verify repositories enable gpgcheck with the following command:

$ grep gpgcheck /etc/yum.repos.d/*.repo | more
gpgcheck=1

If "gpgcheck" is not set to "1", this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertIsNone(candidate)

    def test_skips_grep_sample_candidate_when_command_is_find_exec_grep(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258050',
            'title': 'RHEL 9 SSH daemon must use approved algorithms.',
            'check_content': '''Verify SSH configuration with the following command:

$ sudo find /etc/ssh -type f -exec grep -i ciphers {} \\\;
Ciphers aes256-ctr

If "Ciphers" is not set to the approved value, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertIsNone(candidate)

    def test_skips_grep_sample_candidate_when_sample_contains_placeholder(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270751',
            'title': 'Ubuntu must compare clocks to an authoritative time source.',
            'check_content': '''Verify Ubuntu is configured to compare the system clock with the following command:

$ sudo grep -ir maxpoll /etc/chrony*
server [source] iburst maxpoll 16

If the parameter "server" is not set, is not set to an authoritative DOD time source, or is commented out, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertIsNone(candidate)

    def test_skips_command_output_candidate_with_unresolved_partition_placeholder(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257928',
            'title': 'All RHEL 9 world-writable directories must be owned by root, sys, bin, or an application user.',
            'check_content': '''Run it once for each local partition [PART]:

$ sudo find  PART  -xdev -type d -perm -0002 -uid +0 -print

If there is output, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertIsNone(candidate)

    def test_infers_gsettings_literal_output_from_authoritative_single_quoted_result(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258019',
            'title': 'RHEL 9 must lock the session when the smart card is removed.',
            'check_content': '''Verify the operating system locks a session when a smart card is removed with the following command:

$ gsettings get org.gnome.settings-daemon.peripherals.smartcard removal-action
'lock-screen'

If the result is not 'lock-screen', this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'gsettings get org.gnome.settings-daemon.peripherals.smartcard removal-action'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': "'lock-screen'"})

    def test_infers_gsettings_empty_logout_action_candidate_from_bound_action_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270711',
            'title': 'Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.',
            'check_content': '''Verify Ubuntu 24.04 LTS is not configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface with the following command:

$ gsettings get org.gnome.settings-daemon.plugins.media-keys logout
['']

If the "logout" key is bound to an action, is commented out, or is missing, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'gsettings get org.gnome.settings-daemon.plugins.media-keys logout'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': "['']"})

    def test_infers_gsettings_empty_logout_action_candidate_from_shutdown_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258031',
            'title': 'RHEL 9 must disable the ability of a user to accidentally press Ctrl-Alt-Del and cause a system to shut down or reboot.',
            'check_content': '''Verify RHEL 9 is configured to ignore the Ctrl-Alt-Del sequence in the GNOME desktop with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.settings-daemon.plugins.media-keys logout 

"['']"

If the GNOME desktop is configured to shut down when Ctrl-Alt-Del is pressed, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'gsettings get org.gnome.settings-daemon.plugins.media-keys logout'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '"[\'\']"'})

    def test_infers_grep_literal_output_from_authoritative_output_statement(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271687',
            'title': 'OL 9 must lock the session when the smart card is removed.',
            'check_content': '''Verify that OL 9 locks the logout setting with the following command:

$ grep logout /etc/dconf/db/local.d/locks/*
/org/gnome/settings-daemon/plugins/media-keys/logout

If the output is not "/org/gnome/settings-daemon/plugins/media-keys/logout", the line is commented out, or the line is missing, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'grep logout /etc/dconf/db/local.d/locks/*'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '/org/gnome/settings-daemon/plugins/media-keys/logout'})

    def test_infers_empty_output_for_any_output_returned_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257788',
            'title': 'RHEL 9 must disable the ability of systemd to spawn an interactive boot process.',
            'check_content': '''Check that the current GRUB 2 configuration disables the ability of systemd to spawn an interactive boot process with the following command:

$ sudo grubby --info=ALL | grep args | grep 'systemd.confirm_spawn'

If any output is returned, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': "grubby --info=ALL | grep args | grep 'systemd.confirm_spawn'"})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_xmllint_xpath_empty_expected_result_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259043',
            'title': 'The vCenter Lookup service must disable stack tracing.',
            'check_content': '''At the command prompt, run the following command:

# xmllint --xpath "//Connector[@allowTrace = 'true']" /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

XPath set is empty

If any connectors are returned, this is a finding.'''
        }, 'VMW_vSphere_8-0_VCSA_Lookup_Svc_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-259043',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'xmllint --xpath "//Connector[@allowTrace = \'true\']" /usr/lib/vmware-lookupsvc/conf/server.xml',
            },
            'expected': {'type': 'equals', 'value': 'XPath set is empty'},
            'description': 'The vCenter Lookup service must disable stack tracing.',
        })

    def test_skips_xmllint_xpath_empty_expected_result_with_malformed_xpath(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259047',
            'title': 'The vCenter Lookup service must set URIEncoding to UTF-8.',
            'check_content': '''At the command prompt, run the following command:

# xmllint --xpath "//Connector[@URIEncoding != 'UTF-8'] | //Connector[not[@URIEncoding]]" /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

XPath set is empty

If any connectors are returned, this is a finding.'''
        }, 'VMW_vSphere_8-0_VCSA_Lookup_Svc_STIG')
        self.assertIsNone(candidate)

    def test_infers_dconf_grep_candidate_from_exact_authoritative_sample(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271690',
            'title': 'OL 9 must lock the session when the smart card is removed.',
            'check_content': '''Verify that OL 9 enables a user's session lock with the following command:

$ grep -R removal-action /etc/dconf/db/*
/etc/dconf/db/distro.d/20-authselect:removal-action='lock-screen'

If the "removal-action" setting is not set to "lock-screen", is missing or commented out, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'grep -R removal-action /etc/dconf/db/*'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': "removal-action='lock-screen'"})

    def test_infers_dconf_grep_candidate_when_exact_setting_sample_is_required(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271690',
            'title': 'OL 9 must lock the session when the smart card is removed.',
            'check_content': '''Verify that OL 9 enables a user's session lock with the following command:

$ grep -R removal-action /etc/dconf/db/*
/etc/dconf/db/distro.d/20-authselect:removal-action='lock-screen'

If the "removal-action='lock-screen'" setting is missing or commented out from the dconf database files, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'grep -R removal-action /etc/dconf/db/*'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': "removal-action='lock-screen'"})

    def test_infers_linux_findmnt_option_candidate_from_authoritative_sample(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257864',
            'title': 'RHEL 9 must mount /dev/shm with the noexec option.',
            'check_content': '''Verify "/dev/shm" is mounted with the "noexec" option with the following command:

$ findmnt /dev/shm
TARGET   SOURCE FSTYPE OPTIONS
/dev/shm tmpfs  tmpfs  rw,nodev,nosuid,noexec,seclabel 0 0

If the /dev/shm file system is mounted without the "noexec" option, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'findmnt /dev/shm'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'noexec'})

    def test_skips_linux_findmnt_candidate_when_multiple_findmnt_commands_are_present(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257864',
            'title': 'RHEL 9 must mount /dev/shm with the noexec option.',
            'check_content': '''$ findmnt /dev/shm
TARGET   SOURCE FSTYPE OPTIONS
/dev/shm tmpfs  tmpfs  rw,nodev,nosuid,noexec,seclabel 0 0

$ findmnt /tmp
TARGET SOURCE FSTYPE OPTIONS
/tmp tmpfs tmpfs rw,nodev,nosuid,noexec,seclabel 0 0

If the /dev/shm file system is mounted without the "noexec" option, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertIsNone(candidate)

    def test_skips_linux_findmnt_candidate_when_required_option_is_not_in_options_column(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257864',
            'title': 'RHEL 9 must mount /dev/shm with the noexec option.',
            'check_content': '''$ findmnt /dev/shm
TARGET   SOURCE FSTYPE OPTIONS
/dev/shm noexec tmpfs rw,nodev,nosuid,seclabel 0 0

If the /dev/shm file system is mounted without the "noexec" option, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertIsNone(candidate)

    def test_infers_linux_file_content_candidate_from_cat_pipe_grep_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251713',
            'title': 'RHEL 8 must ensure the password complexity module is enabled in the system-auth file.',
            'check_content': '''Check for the use of "pwquality" in the system-auth file with the following command:

$ sudo cat /etc/pam.d/system-auth | grep pam_pwquality

password requisite pam_pwquality.so

If the command does not return a line containing the value "pam_pwquality.so" as shown, or the line is commented out, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_content', 'path': '/etc/pam.d/system-auth', 'pattern': 'pam_pwquality.so', 'is_regex': False})
        self.assertEqual(candidate['expected'], {'type': 'contains'})

    def test_infers_linux_file_content_absent_candidate_from_grep_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251712',
            'title': 'The RHEL 8 operating system must not be configured to bypass password requirements for privilege escalation.',
            'check_content': 'Verify the operating system is not configured to bypass password requirements for privilege escalation. Check the configuration of the "/etc/pam.d/sudo" file with the following command: $ sudo grep pam_succeed_if /etc/pam.d/sudo If any occurrences of "pam_succeed_if" is returned from the command, this is a finding.'
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_content', 'path': '/etc/pam.d/sudo', 'pattern': 'pam_succeed_if', 'is_regex': False})
        self.assertEqual(candidate['expected'], {'type': 'is_false'})

    def test_infers_linux_auditctl_expected_rule_candidate_from_grep_command(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270686',
            'title': 'Ubuntu must generate audit records for account modifications that affect /etc/shadow.',
            'check_content': '''Verify Ubuntu generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/shadow" with the following command:

$ sudo auditctl -l | grep shadow
-w /etc/shadow -p wa -k usergroup_modification

If the command does not return a line that matches the example or the line is commented out, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': '-w /etc/shadow -p wa -k usergroup_modification'})

    def test_infers_linux_auditctl_expected_rule_candidate_from_egrep_command(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258222',
            'title': 'RHEL 9 must generate audit records for account modifications that affect /etc/passwd.',
            'check_content': '''Verify RHEL 9 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/passwd" with the following command:

$ sudo auditctl -l | egrep '(/etc/passwd)'

-w /etc/passwd -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': '-w /etc/passwd -p wa -k identity'})

    def test_infers_linux_auditctl_single_rule_after_chained_grep_command(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258215',
            'title': 'Successful/unsuccessful uses of the umount system call in RHEL 9 must generate an audit record.',
            'check_content': '''To determine if the system is configured to audit calls to the umount system call, run the following command:

$ sudo auditctl -l | grep b32 | grep 'umount\\b'

-a always,exit -S arch=b32 -S umount -F auid>=1000 -F auid!=-1 -F key=privileged-umount

If the command does not return a line, or the line is commented out, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': '-a always,exit -S arch=b32 -S umount -F auid>=1000 -F auid!=-1 -F key=privileged-umount'})

    def test_infers_linux_auditctl_multiline_rules_when_no_line_is_returned_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258216',
            'title': 'Successful/unsuccessful uses of the umount2 system call in RHEL 9 must generate an audit record.',
            'check_content': '''To determine if the system is configured to audit calls to the umount2 system call, run the following command:

$ sudo auditctl -l | grep umount2

-a always,exit -S arch=b64 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount
-a always,exit -S arch=b32 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount

If no line is returned, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '-a always,exit -S arch=b64 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount\n-a always,exit -S arch=b32 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount',
        })

    def test_infers_linux_auditctl_multiline_expected_rules_when_keys_are_authoritative(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258177',
            'title': 'RHEL 9 must audit all uses of the chmod, fchmod, and fchmodat system calls.',
            'check_content': '''Verify RHEL 9 is configured to audit the execution of the "chmod", "fchmod", and "fchmodat" system calls with the following command:

$ sudo auditctl -l | grep chmod

-a always,exit -S arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -S arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod

If both the "b32" and "b64" audit rules are not defined for the "chmod", "fchmod", and "fchmodat" system calls, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '-a always,exit -S arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n-a always,exit -S arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod',
        })

    def test_infers_linux_auditctl_multiline_rules_from_audit_rules_for_phrase(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-260633',
            'title': 'Ubuntu 22.04 LTS must generate audit records for chmod syscalls.',
            'check_content': '''Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "chmod", "fchmod", and "fchmodat" syscalls with the following command:

$ sudo auditctl -l | grep chmod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod

If the command does not return audit rules for the "chmod", "fchmod", and "fchmodat" syscalls, this is a finding.'''
        }, 'CAN_Ubuntu_22-04_LTS_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod\n-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod',
        })

    def test_infers_linux_auditctl_same_line_multirule_examples(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270805',
            'title': 'Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module syscalls.',
            'check_content': '''Verify Ubuntu 24.04 LTS generates an audit record for any successful/unsuccessful attempts to use the "init_module" and "finit_module" syscalls with the following command:

$ sudo auditctl -l | grep init_module -a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng -a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng

If the command does not return audit rules for the "init_module" and "finit_module" syscalls, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng\n-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng',
        })

    def test_infers_linux_auditctl_multiline_rules_when_key_is_arbitrary(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270786',
            'title': 'Ubuntu must audit chmod syscalls.',
            'check_content': '''$ sudo auditctl -l | grep chmod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_chng
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_chng

If the command does not return audit rules for the "chmod", "fchmod" and "fchmodat" syscalls or the lines are commented out, this is a finding.

Notes:
- The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1\n-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1',
        })

    def test_infers_linux_auditctl_single_rule_when_key_identifier_is_arbitrary(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234901',
            'title': 'The SUSE operating system must audit modifications to /etc/shadow.',
            'check_content': '''Verify the SUSE operating system generates an audit record when modifications occur to the "/etc/shadow" file.

Check that the file is being audited by performing the following command:

> sudo auditctl -l | grep -w '/etc/shadow'

-w /etc/shadow -p wa -k account_mod

If the command does not return a line, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': '-w /etc/shadow -p wa'})

    def test_infers_linux_auditctl_multiline_rules_across_blank_separated_blocks(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271536',
            'title': 'OL 9 must audit all uses of the setxattr syscalls.',
            'check_content': '''Verify that OL 9 is configured to audit the execution of the setxattr syscalls with the following command:

$ sudo auditctl -l | grep xattr
-a always,exit -F arch=b32 -S setxattr,fsetxattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b32 -S setxattr,fsetxattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr -F auid=0 -k perm_mod

If both the "b32" and "b64" audit rules are not defined for the setxattr system calls, or any of the lines returned are commented out, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '-a always,exit -F arch=b32 -S setxattr,fsetxattr -F auid>=1000 -F auid!=unset -k perm_mod\n-a always,exit -F arch=b64 -S setxattr,fsetxattr -F auid>=1000 -F auid!=unset -k perm_mod\n-a always,exit -F arch=b32 -S setxattr,fsetxattr -F auid=0 -k perm_mod\n-a always,exit -F arch=b64 -S setxattr,fsetxattr -F auid=0 -k perm_mod',
        })

    def test_infers_linux_grep_pipeline_no_output_candidate_when_found_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230554',
            'title': 'RHEL 8 network interfaces must not be in promiscuous mode.',
            'check_content': '''Verify network interfaces are not in promiscuous mode unless approved by the ISSO and documented.

Check for the status with the following command:

$ sudo ip link | grep -i promisc

If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'ip link | grep -i promisc'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_linux_service_disabled_candidate_from_systemctl_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251234',
            'title': 'RHEL must not have the telnet service enabled.',
            'check_content': 'Verify the telnet service is disabled with the following command: $ systemctl is-enabled telnet.service If the service is enabled, this is a finding.'
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'telnet', 'expected_status': 'disabled'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'disabled'})

    def test_infers_linux_service_disabled_candidate_from_systemctl_is_enabled_masked_output(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271639',
            'title': 'OL 9 file system automount function must be disabled unless required.',
            'check_content': '''Verify that OL 9 file system automount function has been disabled and masked with the following command:

$ systemctl is-enabled  autofs
masked

If the returned value is not "masked" and is not documented as operational requirement with the information system security officer (ISSO), this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'autofs', 'expected_status': 'disabled'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'disabled'})

    def test_infers_linux_service_running_candidate_when_systemctl_is_active_returns_inactive_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270657',
            'title': 'Ubuntu 24.04 LTS must produce audit records in near real time.',
            'check_content': '''Verify the audit service is properly running and active on the system with the following command:

$ systemctl is-active auditd.service
active

If the command above returns "inactive", this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'auditd', 'expected_status': 'running'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'running'})

    def test_infers_linux_service_stopped_candidate_from_systemctl_status_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230502',
            'title': 'The RHEL 8 file system automounter must be disabled.',
            'check_content': '''Check to see if automounter service is active with the following command:

$ sudo systemctl status autofs

o autofs.service - Automounts filesystems on demand
   Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
   Active: inactive (dead)

If the "autofs" status is set to "active", this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'autofs', 'expected_status': 'stopped'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'stopped'})

    def test_infers_linux_service_stopped_candidate_when_active_requires_documented_exception(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248836',
            'title': 'The OL 8 file system automounter must be disabled unless required.',
            'check_content': '''Determine if the automounter service is active with the following command:

$ sudo systemctl status autofs

autofs.service - Automounts filesystems on demand
Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
Active: inactive (dead)

If the "autofs" status is set to "active" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'''
        }, 'Oracle_Linux_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'autofs', 'expected_status': 'stopped'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'stopped'})

    def test_infers_linux_service_stopped_candidate_when_active_requires_documentation(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230310',
            'title': 'RHEL 8 must disable kernel dumps unless needed.',
            'check_content': '''Verify RHEL 8 kernel core dumps are disabled unless needed with the following command:

$ sudo systemctl status kdump.service

o kdump.service - Crash recovery kernel arming
   Loaded: loaded (/usr/lib/systemd/system/kdump.service; disabled; vendor preset: enabled)
   Active: inactive (dead)

If the "kdump" service is active, ask the system administrator if the use of the service is required and documented with the information system security officer (ISSO).

If the service is active and is not documented, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'kdump', 'expected_status': 'stopped'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'stopped'})

    def test_infers_linux_service_stopped_candidate_from_is_active_inactive_documented_exception(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-238334',
            'title': 'The Ubuntu operating system must disable kernel core dumps so that it can fail to a secure state.',
            'check_content': '''Verify that kernel core dumps are disabled unless needed.

Check if "kdump" service is active with the following command:

$ systemctl is-active kdump.service
inactive

If the "kdump" service is active, ask the SA if the use of the service is required and documented with the ISSO.

If the service is active and is not documented, this is a finding.'''
        }, 'Canonical_Ubuntu_20-04_LTS_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'kdump', 'expected_status': 'stopped'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'stopped'})

    def test_skips_linux_service_stopped_candidate_when_active_requires_configuration(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-204628',
            'title': 'The Red Hat Enterprise Linux operating system access control program must be configured to grant or deny system access to specific hosts and services.',
            'check_content': '''Check to see if "firewalld" is active with the following command:

# systemctl status firewalld
firewalld.service - firewalld - dynamic firewall daemon
Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
Active: active (running)

If "firewalld" is active and is not configured to grant access to specific hosts, this is a finding.'''
        }, 'RHEL_7_STIG')
        self.assertIsNone(candidate)

    def test_infers_linux_masked_systemctl_status_candidate_as_disabled(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230532',
            'title': 'The debug-shell systemd service must be disabled on RHEL 8.',
            'check_content': '''Verify RHEL 8 is configured to mask the debug-shell systemd service with the following command:

$ sudo systemctl status debug-shell.service

debug-shell.service
Loaded: masked (Reason: Unit debug-shell.service is masked.)
Active: inactive (dead)

If the "debug-shell.service" is loaded and not masked, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'debug-shell', 'expected_status': 'disabled'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'disabled'})

    def test_infers_linux_masked_target_status_candidate_when_not_masked_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270712',
            'title': 'Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.',
            'check_content': '''Verify Ubuntu 24.04 LTS is not configured to reboot the system when Ctrl-Alt-Delete is pressed with the following command:

$ systemctl status ctrl-alt-del.target
o   ctrl-alt-del.target
     Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
     Active: inactive (dead)

If the "ctrl-alt-del.target" is not masked, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'ctrl-alt-del', 'expected_status': 'disabled'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'disabled'})

    def test_infers_linux_masked_service_from_systemctl_show_loadstate_and_unitfilestate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257818',
            'title': 'The kdump service on RHEL 9 must be disabled.',
            'check_content': '''Verify that the kdump service is disabled in system boot configuration with the following command:

$ sudo systemctl is-enabled  kdump

disabled

Verify that the kdump service is not active (i.e., not running) through current runtime configuration with the following command:

$ sudo systemctl is-active kdump

masked

Verify that the kdump service is masked with the following command:

$ sudo systemctl show  kdump  | grep "LoadState\\|UnitFileState"

LoadState=masked
UnitFileState=masked

If the "kdump" service is loaded or active, and is not masked, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'kdump', 'expected_status': 'disabled'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'disabled'})

    def test_infers_linux_service_running_candidate_from_systemctl_status_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-244545',
            'title': 'The RHEL 8 fapolicy module must be enabled.',
            'check_content': '''Verify the RHEL 8 "fapolicyd" is enabled and running with the following command:

$ sudo systemctl status fapolicyd.service

fapolicyd.service - File Access Policy Daemon
Loaded: loaded (/usr/lib/systemd/system/fapolicyd.service; enabled; vendor preset: disabled)
Active: active (running)

If fapolicyd is not enabled and running, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'fapolicyd', 'expected_status': 'running'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'running'})

    def test_infers_linux_service_running_candidate_from_systemctl_is_active_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271502',
            'title': 'OL 9 must enable the chronyd service.',
            'check_content': '''Verify that OL 9 chronyd service is set to active with the following command:

$ systemctl is-active chronyd
active

If the chronyd service is not active, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'chronyd', 'expected_status': 'running'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'running'})

    def test_infers_linux_service_running_candidate_from_systemctl_status_inactive_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-260516',
            'title': 'Ubuntu 22.04 LTS must have an application firewall enabled.',
            'check_content': '''Verify the Uncomplicated Firewall (ufw) is enabled on the system with the following command:

$ systemctl status ufw.service | grep -i "active:"
Active: active (exited) since Thu 2022-12-25 00:00:01 NZTD; 365 days 11h ago

If "ufw.service" is "inactive", this is a finding.

If the ufw is not installed, ask the system administrator if another application firewall is installed. If no application firewall is installed, this is a finding.'''
        }, 'CAN_Ubuntu_22-04_LTS_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'ufw', 'expected_status': 'running'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'running'})

    def test_infers_linux_systemctl_get_default_candidate_from_authoritative_sample(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251718',
            'title': 'The graphical display manager must not be the default target on RHEL 8 unless approved.',
            'check_content': '''Verify that the system is configured to boot to the command line:

$ systemctl get-default
multi-user.target

If the system default target is not set to "multi-user.target" and the Information System Security Officer (ISSO) lacks a documented requirement for a graphical user interface, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'systemctl get-default'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'multi-user.target'})

    def test_infers_linux_service_running_candidate_from_enabled_and_active_commands(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230285',
            'title': 'RHEL 8 must enable the hardware random number generator entropy gatherer service.',
            'check_content': '''Verify the rngd service is enabled and active with the following commands:

$ sudo systemctl is-enabled rngd
enabled

$ sudo systemctl is-active rngd
active

If the service is not "enabled" and "active", this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'rngd', 'expected_status': 'running'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'running'})

    def test_infers_linux_auditctl_arbitrary_key_candidate_when_no_output_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234941',
            'title': 'The SUSE operating system must generate audit records for all uses of the chmod command.',
            'check_content': '''Verify the SUSE operating system generates an audit record for all uses of the "chmod" command.

Check that the command is being audited by performing the following command:

> sudo auditctl -l | grep -w '/usr/bin/chmod'

-a always,exit -S all -F path=/usr/bin/chmod -F perm=x -F auid>=1000 -F auid!=-1 -k prim_mod

If the command does not return any output, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '-a always,exit -S all -F path=/usr/bin/chmod -F perm=x -F auid>=1000 -F auid!=-1',
        })

    def test_infers_linux_auditctl_single_rule_candidate_when_an_audit_rule_is_required(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271568',
            'title': 'OL 9 must audit all uses of umount system calls.',
            'check_content': '''Verify that OL 9 is configured to audit the execution of the umount command with the following command:

$ sudo auditctl -l | grep umount
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount

If the command does not return an audit rule for umount or any of the lines returned are commented out, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount',
        })

    def test_infers_linux_service_running_candidate_when_active_output_must_be_returned(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257936',
            'title': 'The firewalld service on RHEL 9 must be active.',
            'check_content': '''Verify that "firewalld" is active with the following command:

$ systemctl is-active firewalld

active

If "active" is not returned, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'firewalld', 'expected_status': 'running'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'running'})

    def test_skips_linux_systemctl_status_target_units(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230529',
            'title': 'The Ctrl-Alt-Delete burst action must be disabled.',
            'check_content': '''Verify the ctrl-alt-del.target is not active with the following command:

$ sudo systemctl status ctrl-alt-del.target

If the ctrl-alt-del.target status is active, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertIsNone(candidate)

    def test_skips_linux_service_masked_candidate_until_masked_status_is_supported(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230532',
            'title': 'The debug-shell systemd service must be disabled.',
            'check_content': '''Verify debug-shell.service is masked with the following command:

$ sudo systemctl status debug-shell.service

If the debug-shell.service is loaded and not masked, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertIsNone(candidate)

    def test_infers_linux_file_permission_candidate_from_stat_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251235',
            'title': 'RHEL audit logs must have mode 0600.',
            'check_content': 'Check the permissions with the following command: $ stat -c "%a %U %G" /var/log/audit/audit.log If the mode is not "600", this is a finding.'
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_permission', 'path': '/var/log/audit/audit.log', 'owner': None, 'group': None, 'mode': '600'})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_infers_linux_file_permission_owner_candidate_from_stat_output(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270769',
            'title': 'Ubuntu must configure /var/log/syslog file to be owned by syslog.',
            'check_content': '''Verify that Ubuntu configures the /var/log/syslog file to be owned by "syslog" with the following command:

$ stat -c "%n %U" /var/log/syslog
/var/log/syslog syslog

If the "/var/log/syslog" file is not owned by syslog, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_permission', 'path': '/var/log/syslog', 'owner': 'syslog', 'group': None, 'mode': None})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_infers_linux_file_permission_group_candidate_from_stat_output(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270768',
            'title': 'Ubuntu must configure the /var/log/syslog file to be group-owned by adm.',
            'check_content': '''Verify that Ubuntu configures the /var/log/syslog file to be group-owned by "adm" with the following command:

$ stat -c "%n %G" /var/log/syslog
/var/log/syslog adm

If the "/var/log/syslog" file is not group-owned by adm, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_permission', 'path': '/var/log/syslog', 'owner': None, 'group': 'adm', 'mode': None})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_infers_linux_file_permission_candidate_from_find_exec_stat_output(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270759',
            'title': 'Ubuntu 24.04 LTS must be configured so that the "journalctl" command is owned by "root".',
            'check_content': '''Verify the journalctl command is owned by "root" with the following command:

$ sudo find /usr/bin/journalctl -exec stat -c "%n %U" {} \\;
/usr/bin/journalctl root

If journalctl is not owned by "root", this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_permission', 'path': '/usr/bin/journalctl', 'owner': 'root', 'group': None, 'mode': None})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_infers_linux_file_permission_owner_candidate_from_single_field_stat_output(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248555',
            'title': 'The OL 8 "/var/log/messages" file must be owned by root.',
            'check_content': '''Verify that the /var/log/messages file is owned by root with the following command:

$ sudo stat -c "%U" /var/log/messages
root

If "root" is not returned as a result, this is a finding.'''
        }, 'Oracle_Linux_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_permission', 'path': '/var/log/messages', 'owner': 'root', 'group': None, 'mode': None})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_infers_linux_file_permission_group_candidate_from_single_field_stat_output(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248556',
            'title': 'The OL 8 "/var/log/messages" file must be group-owned by root.',
            'check_content': '''Verify the "/var/log/messages" file is group-owned by root with the following command:

$ sudo stat -c "%G" /var/log/messages
root

If "root" is not returned as a result, this is a finding.'''
        }, 'Oracle_Linux_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_permission', 'path': '/var/log/messages', 'owner': None, 'group': 'root', 'mode': None})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_skips_linux_file_permission_single_field_stat_when_sample_does_not_match_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248556',
            'title': 'The OL 8 "/var/log/messages" file must be group-owned by root.',
            'check_content': '''Verify the "/var/log/messages" file is group-owned by root with the following command:

$ sudo stat -c "%G" /var/log/messages
wheel

If "root" is not returned as a result, this is a finding.'''
        }, 'Oracle_Linux_8_STIG')
        self.assertIsNone(candidate)

    def test_infers_linux_file_permission_owner_candidate_from_stat_output_with_path_after_owner(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257900',
            'title': 'RHEL 9 /etc/group- file must be owned by root.',
            'check_content': '''Verify the ownership of the "/etc/group-" file with the following command:

$ sudo stat -c "%U %n" /etc/group-

root /etc/group-

If "/etc/group-" file does not have an owner of "root", this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_permission', 'path': '/etc/group-', 'owner': 'root', 'group': None, 'mode': None})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_infers_linux_sshd_config_keyword_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230555',
            'title': 'RHEL 8 remote X connections for interactive users must be disabled.',
            'check_content': '''Verify X11Forwarding is disabled with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\\s*x11forwarding'

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

    def test_infers_linux_grep_unquoted_key_expected_line_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230390',
            'title': 'The RHEL 8 System must take appropriate action when an audit processing failure occurs.',
            'check_content': '''Check that RHEL 8 takes the appropriate action when an audit processing failure occurs with the following command:

$ sudo grep disk_error_action /etc/audit/auditd.conf

disk_error_action = HALT

If the value of the "disk_error_action" option is not "SYSLOG", "SINGLE", or "HALT", or the line is commented out, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_content', 'path': '/etc/audit/auditd.conf', 'pattern': 'disk_error_action = HALT', 'is_regex': False})
        self.assertEqual(candidate['expected'], {'type': 'contains'})

    def test_infers_explicit_expected_command_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-256393',
            'title': 'The ESXi host SSH daemon must not permit tunnels.',
            'check_content': '''From an ESXi shell, run the following command:

# /usr/lib/vmware/openssh/bin/sshd -T|grep permittunnel

Expected result:

permittunnel no

If the output does not match the expected result, this is a finding.'''
        }, 'VMW_vSphere_7-0_ESXi_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': '/usr/lib/vmware/openssh/bin/sshd -T|grep permittunnel'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'permittunnel no'})

    def test_infers_fips_mode_command_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258230',
            'title': 'RHEL 9 must enable FIPS mode.',
            'check_content': '''Verify that RHEL 9 is in FIPS mode with the following command:

$ sudo fips-mode-setup --check

FIPS mode is enabled.

If FIPS mode is not enabled, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'fips-mode-setup --check'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'FIPS mode is enabled.'})

    def test_infers_absolute_command_result_equals_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259512',
            'title': 'The macOS system must enable Gatekeeper.',
            'check_content': '''Verify the macOS system is configured to enable Gatekeeper with the following command:

/usr/sbin/spctl --status | /usr/bin/grep -c "assessments enabled"

If the result is not "1", this is a finding.'''
        }, 'Apple_macOS_14_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': '/usr/sbin/spctl --status | /usr/bin/grep -c "assessments enabled"'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '1'})

    def test_infers_macos_absolute_command_substitution_result_equals_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259432',
            'title': 'The macOS system must configure audit log files to not contain access control lists.',
            'check_content': '''Verify the macOS system is configured without ACLs applied to log files with the following command:

/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"

If the result is not "0", this is a finding.'''
        }, 'Apple_macOS_14_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': "/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c \":\""})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '0'})

    def test_skips_result_literal_when_no_shell_command_is_present(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-NO-COMMAND',
            'title': 'A manual prose rule must not be inferred as command output.',
            'check_content': 'Review the setting manually. If the result is not "true", this is a finding.'
        }, 'Apple_macOS_14_STIG')
        self.assertIsNone(candidate)

    def test_infers_linux_gsettings_get_candidate_from_false_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-244536',
            'title': 'RHEL 8 must disable the user list at logon for graphical user interfaces.',
            'check_content': '''Verify the operating system disables the user logon list for graphical user interfaces with the following command:

$ sudo gsettings get org.gnome.login-screen disable-user-list
true

If the setting is "false", this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'gsettings get org.gnome.login-screen disable-user-list'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'true'})

    def test_infers_linux_gsettings_writable_candidate_from_true_result_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-274871',
            'title': 'Ubuntu 24.04 LTS must conceal session lock information with a public image.',
            'check_content': '''To verify the screensaver is configured to be blank, run the following command:

$ gsettings writable org.gnome.desktop.screensaver picture-uri
 
false
 
If "picture-uri" is writable and the result is "true", this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'gsettings writable org.gnome.desktop.screensaver picture-uri'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'false'})

    def test_infers_linux_gsettings_get_candidate_from_quoted_key_false_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258029',
            'title': 'RHEL 9 must disable the ability of a user to restart the system from the login screen.',
            'check_content': '''Verify RHEL 9 disables a user's ability to restart the system with the following command:

$ gsettings get org.gnome.login-screen disable-restart-buttons
 
true
 
If "disable-restart-buttons" is "false", this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'gsettings get org.gnome.login-screen disable-restart-buttons'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'true'})

    def test_infers_linux_gsettings_get_candidate_from_quoted_key_set_to_false_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258016',
            'title': 'RHEL 9 must disable the graphical user interface autorun function unless required.',
            'check_content': '''Verify RHEL 9 disables the graphical user interface autorun function with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.desktop.media-handling autorun-never 

true

If "autorun-never" is set to "false", and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'gsettings get org.gnome.desktop.media-handling autorun-never'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'true'})

    def test_infers_linux_gsettings_get_false_candidate_from_true_setting_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258014',
            'title': 'RHEL 9 must disable the graphical user interface automount function unless required.',
            'check_content': '''Verify RHEL 9 disables the graphical user interface automount function with the following command:

$ gsettings get org.gnome.desktop.media-handling automount-open

false

If "automount-open" is set to "true", and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'gsettings get org.gnome.desktop.media-handling automount-open'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'false'})

    def test_infers_no_output_command_candidate_from_find_file_absence_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230283',
            'title': 'There must be no shosts.equiv files on the RHEL 8 operating system.',
            'check_content': '''Verify there are no "shosts.equiv" files on RHEL 8 with the following command:

$ sudo find / -name shosts.equiv

If a "shosts.equiv" file is found, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'find / -name shosts.equiv'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_no_output_command_candidate_from_find_exec_returned_item_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251708',
            'title': 'RHEL 8 library directories must be owned by root.',
            'check_content': '''Verify the system-wide shared library directories are owned by "root" with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \\;

If any system-wide shared library directory is returned, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%n %U" \'{}\' \\;'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_no_output_command_candidate_from_find_output_that_indicates_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230318',
            'title': 'All RHEL 8 world-writable directories must be owned by root, sys, bin, or an application user.',
            'check_content': '''Verify RHEL 8 world writable directories are owned by root, a system account, or an application account with the following command:

$ sudo find / -xdev -type d -perm -0002 -uid +999 -exec stat -c "%U, %u, %A, %n" {} \\; 2>/dev/null

If there is output that indicates world-writable directories are owned by any account other than root or an approved system account, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'find / -xdev -type d -perm -0002 -uid +999 -exec stat -c "%U, %u, %A, %n" {} \\; 2>/dev/null'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_no_output_command_candidate_from_find_found_directory_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270824',
            'title': 'Ubuntu 24.04 LTS must have directories that contain system commands set to a mode of "0755" or less permissive.',
            'check_content': '''Verify the system commands directories have mode "0755" or less permissive with the following command:

$ find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \\;

If any directories are found to be group-writable or world-writable, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" \'{}\' \\;'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_no_output_command_candidate_from_output_produced_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-244541',
            'title': 'RHEL 8 must not allow blank or null passwords in the password-auth file.',
            'check_content': '''To verify that null passwords cannot be used, run the following command:

$ sudo grep -i nullok /etc/pam.d/password-auth

If output is produced, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'grep -i nullok /etc/pam.d/password-auth'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_skips_no_output_candidate_when_returned_items_are_qualified(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271901',
            'title': 'OL 9 must only allow DOD PKI-established certificate authorities.',
            'check_content': '''Verify OL 9 only allows the use of DOD PKI-established certificate authorities using the following command:

$ trust list

pkcs11:id=%7C%42;type=cert
    label: Example Root

If any nonapproved CAs are returned, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertIsNone(candidate)

    def test_preserves_balanced_quotes_in_command_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-256447',
            'title': 'The ESXi host must implement Secure Boot enforcement.',
            'check_content': '''From an ESXi shell, run the following command:

# esxcli system settings encryption get|grep "Secure Boot"

Expected result:

Require Secure Boot: true

If the output does not match the expected result, this is a finding.'''
        }, 'VMW_vSphere_7-0_ESXi_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'esxcli system settings encryption get|grep "Secure Boot"'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'Require Secure Boot: true'})

    def test_infers_passwd_status_locked_root_candidate_from_second_field_text(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270724',
            'title': 'Ubuntu 24.04 LTS must prevent direct login to the root account.',
            'check_content': '''Verify Ubuntu 24.04 LTS prevents direct logins to the root account with the following command:

$ sudo passwd -S root
root L 04/08/2024 0 99999 7 -1

If the output does not contain "L" in the second field to indicate the account is locked, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'passwd -S root'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'root L'})

    def test_infers_selinux_getenforce_enforcing_candidate_from_authoritative_sample(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248548',
            'title': 'OL 8 must use a Linux Security Module configured to enforce limits on system services.',
            'check_content': '''Check if "SELinux" is in "Enforcing" mode with the following command:

$ getenforce
Enforcing

If "SELinux" is not in "Enforcing" mode, this is a finding.'''
        }, 'Oracle_Linux_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'getenforce'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'Enforcing'})

    def test_infers_selinux_sestatus_targeted_policy_candidate_from_authoritative_sample(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258079',
            'title': 'RHEL 9 must enable the SELinux targeted policy.',
            'check_content': '''Verify the SELINUX on RHEL 9 is using the targeted policy with the following command:

$ sestatus | grep "policy name"

Loaded policy name:             targeted

If the loaded policy name is not "targeted", this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'sestatus | grep "policy name"'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'Loaded policy name:             targeted'})

    def test_infers_selinux_sestatus_targeted_policy_candidate_from_unquoted_policy_grep(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271453',
            'title': 'OL 9 must enable the SELinux targeted policy.',
            'check_content': '''Verify that OL 9 enables the SELinux targeted policy with the following command:

$ sestatus | grep policy
Loaded policy name:             targeted

If the loaded policy name is not "targeted", this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'sestatus | grep policy'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'Loaded policy name:             targeted'})

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

    def test_infers_windows_advanced_audit_policy_candidate_from_gpo_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278947',
            'title': 'Windows Server 2022 must be configured to audit registry successes.',
            'check_content': '''Verify that Audit Registry auditing has been enabled:

Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access >> Audit Registry.

If "Audit Registry" is not set to "Success", this is a finding.'''
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'audit_policy', 'subcategory': 'Registry', 'setting': 'Success'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'Success'})

    def test_infers_windows_advanced_audit_policy_candidate_from_fix_text_only_scap(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'xccdf_mil.disa.stig_group_V-278946',
            'title': 'Windows Server 2022 must be configured to audit registry failures.',
            'fix_text': 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit Registry" with "Failure" selected.'
        }, 'scap_mil.disa.stig_collection_U_MS_Windows_Server_2022_V2R8_STIG_SCAP_1-3_Benchmark')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'audit_policy', 'subcategory': 'Registry', 'setting': 'Failure'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'Failure'})

    def test_infers_windows_advanced_audit_policy_candidate_from_singular_system_audit_policy_path(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257770',
            'title': 'Windows 11 must have command line process auditing events enabled for failures.',
            'check_content': '''Ensure Audit Process Creation auditing has been enabled:

Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policy >> Detailed Tracking >> Audit Process Creation.

If "Audit Process Creation" is not set to "Failure", this is a finding.'''
        }, 'Microsoft_Windows_11_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'audit_policy', 'subcategory': 'Process Creation', 'setting': 'Failure'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'Failure'})

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

    def test_infers_windows_account_policy_candidate_from_fix_text(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254291',
            'title': 'Windows Server 2022 minimum password length must be configured to 14 characters.',
            'check_content': '',
            'fix_text': 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Minimum password length" to "14" characters.',
        }, 'scap_mil.disa.stig_collection_U_MS_Windows_Server_2022_V2R8_STIG_SCAP_1-3_Benchmark')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'System Access', 'key': 'MinimumPasswordLength'})
        self.assertEqual(candidate['expected'], {'type': 'greater_or_equal', 'value': 14})

    def test_infers_windows_security_option_candidate_from_explicit_disabled_value(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254465',
            'title': 'Windows Server must not allow anonymous SID/Name translation.',
            'check_content': '''Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Network access: Allow anonymous SID/Name translation" is not set to "Disabled", this is a finding.''',
            'fix_text': 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network access: Allow anonymous SID/Name translation to "Disabled".',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Security Options', 'key': 'Network access: Allow anonymous SID/Name translation'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'Disabled'})

    def test_infers_windows_security_option_candidate_from_scap_fix_text_only(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254474',
            'title': 'Windows Server 2022 must be configured to prevent the storage of the LAN Manager hash of passwords.',
            'check_content': '',
            'fix_text': 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network security: Do not store LAN Manager hash value on next password change to "Enabled".',
        }, 'scap_mil.disa.stig_collection_U_MS_Windows_Server_2022_V2R8_STIG_SCAP_1-3_Benchmark')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Security Options', 'key': 'Network security: Do not store LAN Manager hash value on next password change'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'Enabled'})

    def test_infers_windows_security_option_less_or_equal_candidate_from_fix_text(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278181',
            'title': 'Windows Server 2025 must limit the caching of logon credentials to four or less on domain-joined member servers.',
            'check_content': '''If the following registry value does not exist or is not configured as specified, this is a finding:

Registry HiveHKEY_LOCAL_MACHINE
Registry Path\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value NameCachedLogonsCount

Value TypeREG_SZ
Value4 (or less)''',
            'fix_text': 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Interactive Logon: Number of previous logons to cache (in case Domain Controller is not available) to "4" logons or less.',
        }, 'MS_Windows_Server_2025_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Security Options', 'key': 'Interactive Logon: Number of previous logons to cache (in case Domain Controller is not available)'})
        self.assertEqual(candidate['expected'], {'type': 'less_or_equal', 'value': 4})

    def test_infers_windows_blank_user_right_candidate_from_scap_fix_text(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'xccdf_mil.disa.stig_group_V-254506',
            'title': 'Windows Server 2022 lock pages in memory user right must not be assigned to any groups or accounts.',
            'check_content': '',
            'fix_text': 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Lock pages in memory to be defined but containing no entries (blank).',
        }, 'scap_mil.disa.stig_collection_U_MS_Windows_Server_2022_V2R8_STIG_SCAP_1-3_Benchmark')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeLockMemoryPrivilege'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_linux_rpm_verify_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257999',
            'title': "RHEL 9 SSH server configuration files' permissions must not be modified.",
            'check_content': '''Verify the permissions of the "/etc/ssh/sshd_config" file with the following command:

$ sudo rpm --verify openssh-server

If the command returns any output, this is a finding.''',
        }, 'RHEL_9_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'rpm --verify openssh-server'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_linux_rpm_verify_filtered_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257888',
            'title': 'RHEL 9 permissions of cron configuration files and directories must not be modified from the operating system defaults.',
            'check_content': '''Run the following command to verify that the owner, group, and mode of cron configuration files and directories match the operating system defaults:

$ rpm --verify cronie crontabs | awk '! ($2 == "c" && $1 ~ /^.\\..\\.\\.\\.\\..\\./) {print $0}'

If the command returns any output, this is a finding.''',
        }, 'RHEL_9_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'rpm --verify cronie crontabs | awk \'! ($2 == "c" && $1 ~ /^.\\..\\.\\.\\.\\..\\./) {print $0}\''})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_linux_ufw_status_active_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270655',
            'title': 'Ubuntu 24.04 LTS must enable and run the Uncomplicated Firewall (ufw).',
            'check_content': '''Verify the ufw is enabled on the system with the following command:

$ sudo ufw status
Status: active

If the above command returns the status as "inactive" or any type of error, this is a finding.''',
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'ufw status'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'Status: active'})

    def test_infers_shadow_blank_password_command_returns_any_results_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258120',
            'title': 'RHEL 9 must not have accounts configured with blank or null passwords.',
            'check_content': '''Verify that null or blank passwords cannot be used with the following command:

$ sudo awk -F: '!$2 {print $1}' /etc/shadow

If the command returns any results, this is a finding.''',
        }, 'RHEL_9_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': "awk -F: '!$2 {print $1}' /etc/shadow"})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})


if __name__ == '__main__':
    unittest.main()
