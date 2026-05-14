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

    def test_preserves_manifest_canonical_vuln_id_when_artifact_uses_xccdf_group_id(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            coverage = root / 'coverage' / 'sample.json'
            coverage.parent.mkdir()
            coverage.write_text('''{
              "stig_id": "scap_mil.disa.stig_collection_U_RHEL_8_V2R7_STIG_SCAP_1-3_Benchmark",
              "benchmark": "Sample",
              "version": "V1R1",
              "rules": [
                {"vuln_id":"V-230543","rule_id":"xccdf_mil.disa.stig_rule_SV-230543r1_rule","title":"RHEL 8 must not allow interfaces to perform ICMP redirects by default.","classification":"unsupported","severity":"medium"}
              ]
            }''')
            original = mod._artifact_rule_map
            mod._artifact_rule_map = lambda manifest, repo_root, cache: {
                'V-230543': {
                    'vuln_id': 'xccdf_mil.disa.stig_group_V-230543',
                    'rule_id': 'xccdf_mil.disa.stig_rule_SV-230543r1_rule',
                    'fix_text': 'Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:\n\nnet.ipv4.conf.default.send_redirects = 0',
                }
            }
            try:
                count = mod.generate_specs(coverage.parent, root / 'impl', root)
            finally:
                mod._artifact_rule_map = original
            self.assertEqual(count, 1)
            generated = next((root / 'impl').rglob('*.json')).read_text()
            self.assertIn('"vuln_id": "V-230543"', generated)
            self.assertNotIn('xccdf_mil.disa.stig_group_V-230543', generated)

    def test_infers_windows_user_right_allowlist_before_server_core_instructions(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254434',
            'title': 'Windows Server 2022 Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and standalone or nondomain-joined systems.',
            'check_content': '''Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".
Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" user right, this is a finding:

- Administrators
- Authenticated Users

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Access this computer from the network" to only include the following groups or accounts:

- Administrators
- Authenticated Users''',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-254434',
            'platform': 'windows',
            'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeNetworkLogonRight'},
            'expected': {'type': 'equals', 'value': '*S-1-5-32-544,*S-1-5-11'},
            'description': 'Windows Server 2022 Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and standalone or nondomain-joined systems.',
        })

    def test_infers_windows_secedit_sid_allowlist_user_right_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254418',
            'title': 'Windows Server 2022 Access this computer from the network user right must only be assigned to fixed groups on domain controllers.',
            'check_content': '''Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" right, this is a finding.

- Administrators
- Authenticated Users
- Enterprise Domain Controllers

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeNetworkLogonRight" user right, this is a finding.

S-1-5-32-544 (Administrators)
S-1-5-11 (Authenticated Users)
S-1-5-9 (Enterprise Domain Controllers)''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Access this computer from the network to include only the following accounts or groups:

- Administrators
- Authenticated Users
- Enterprise Domain Controllers''',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-254418',
            'platform': 'windows',
            'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeNetworkLogonRight'},
            'expected': {'type': 'equals', 'value': '*S-1-5-32-544,*S-1-5-11,*S-1-5-9'},
            'description': 'Windows Server 2022 Access this computer from the network user right must only be assigned to fixed groups on domain controllers.',
        })

    def test_infers_ubuntu_ssh_confirm_banner_exact_script_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270694',
            'title': 'Ubuntu 24.04 LTS must be configured to enforce the acknowledgement of the Standard Mandatory DOD Notice and Consent Banner for all SSH connections.',
            'check_content': '''Verify Ubuntu 24.04 LTS is configured to prompt a user to acknowledge the Standard Mandatory DOD Notice and Consent Banner before granting access with the following command:

$ less /etc/profile.d/ssh_confirm.sh
#!/bin/bash

if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
        while true; do
                read -p " 

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

Do you agree? [y/N] " yn
                case $yn in
                        [Yy]* ) break ;;
                        [Nn]* ) exit 1 ;;
                esac
        done
fi

If the output does not match the text above, this is a finding.''',
            'fix_text': '''Configure Ubuntu 24.04 LTS to prompt a user to acknowledge the Standard Mandatory DOD Notice and Consent Banner before granting access:

$ sudo vi /etc/profile.d/ssh_confirm.sh
#!/bin/bash

if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
        while true; do
                read -p " 

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

Do you agree? [y/N] " yn
                case $yn in
                        [Yy]* ) break ;;
                        [Nn]* ) exit 1 ;;
                esac
        done
fi

Note: The "ssh_confirm.sh" script is provided as a supplemental file to this document.''',
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-270694',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'cat /etc/profile.d/ssh_confirm.sh'},
            'expected': {'type': 'equals', 'value': '''#!/bin/bash

if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
        while true; do
                read -p " 

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

Do you agree? [y/N] " yn
                case $yn in
                        [Yy]* ) break ;;
                        [Nn]* ) exit 1 ;;
                esac
        done
fi'''} ,
            'description': 'Ubuntu 24.04 LTS must be configured to enforce the acknowledgement of the Standard Mandatory DOD Notice and Consent Banner for all SSH connections.',
        })

    def test_infers_windows_enabled_local_admin_password_age_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-253476',
            'title': 'Passwords for enabled local Administrator accounts must be changed at least every 60 days.',
            'check_content': '''If there are no enabled local Administrator accounts, this is Not Applicable.

Review the password last set date for the enabled local Administrator account.

Open PowerShell.

Enter "Get-LocalUser -Name * | Select-Object *"

If the PasswordLastSet date is more than 60 days old for the enabled local Administrator account, this is a finding.''',
            'fix_text': 'Change the enabled local Administrator account password at least every 60 days.',
        }, 'Microsoft_Windows_11_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-253476',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': 'powershell -NoProfile -Command "Get-LocalUser | Where-Object { $_.SID -like \'S-1-5-*-500\' -and $_.Enabled -eq $true -and $_.PasswordLastSet -lt (Get-Date).AddDays(-60) } | Select-Object -ExpandProperty Name"',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'Passwords for enabled local Administrator accounts must be changed at least every 60 days.',
        })

    def test_infers_office_single_registry_dword_for_all_installed_programs_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223287',
            'title': 'Custom user interface (UI) code must be blocked from loading in all Office applications.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Global Options >> Customize >> Disable UI extending from documents and templates is set to Enabled.

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\toolbars

If the value noextensibilitycustomizationfromdocument is REG_DWORD = 1 for all installed Office programs, this is not a finding.''',
            'fix_text': 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Global Options >> Customize >> Disable UI extending from documents and templates to Enabled: Disallow in Word; Excel; PowerPoint; Access; Outlook; Publisher; Project; Visio; InfoPath.',
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-223287',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\toolbars',
                'value_name': 'noextensibilitycustomizationfromdocument',
            },
            'expected': {'type': 'equals', 'value': 1},
            'description': 'Custom user interface (UI) code must be blocked from loading in all Office applications.',
        })

    def test_infers_postgresql_log_timezone_utc_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233532',
            'title': 'PostgreSQL must record time stamps, in audit records and application data that can be mapped to Coordinated Universal Time (UTC, formerly GMT).',
            'check_content': '''As the database administrator, check the current log_timezone setting by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_timezone"

log_timezone
--------------
UTC
(1 row)

If log_timezone is not set to the desired time zone, this is a finding.''',
            'fix_text': '''To change log_timezone in postgresql.conf to use a different time zone for logs, as the database administrator, run the following:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_timezone='UTC'

Next, restart the database.''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-233532',
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -tAc "SHOW log_timezone"'},
            'expected': {'type': 'equals', 'value': 'UTC'},
            'description': 'PostgreSQL must record time stamps, in audit records and application data that can be mapped to Coordinated Universal Time (UTC, formerly GMT).',
        })

    def test_infers_kubernetes_kubelet_config_value_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242434',
            'title': 'Kubernetes Kubelet must enable kernel protection.',
            'check_content': '''On the Control Plane, run the command:
ps -ef | grep kubelet

If the "--protect-kernel-defaults" option exists, this is a finding.

Note the path to the config file (identified by --config).

Run the command:
grep -i protectKernelDefaults <path_to_config_file>

If the setting "protectKernelDefaults" is not set or is set to false, this is a finding.''',
            'fix_text': '''Remove the "--protect-kernel-defaults" option if present.

Edit the Kubernetes Kubelet config file:
Set "protectKernelDefaults" to "true".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet''',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242434',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "sh -c \"if ps -ef | grep '[k]ubelet' | grep -q -- '--protect-kernel-defaults'; then exit 0; fi; cfg=\\$(ps -ef | grep '[k]ubelet' | tr ' ' '\\n' | sed -n 's/^--config=//p' | head -n1); test -n \\\"\\$cfg\\\" && sed -n 's/^[[:space:]]*protectKernelDefaults:[[:space:]]*//p' \\\"\\$cfg\\\" | head -n1\"",
            },
            'expected': {'type': 'equals', 'value': 'true'},
            'description': 'Kubernetes Kubelet must enable kernel protection.',
        })

    def test_infers_apache_windows_httpd_conf_directive_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-214327',
            'title': 'The Apache web server must encrypt passwords during transmission.',
            'check_content': '''Review the <'INSTALL PATH'>\\conf\\httpd.conf file.

Ensure SSL is enabled by looking at the "SSLVerifyClient" directive.

If the value of "SSLVerifyClient" is not set to "require", this is a finding.''',
            'fix_text': 'Configure the SSLVerifyClient directive in httpd.conf to require.',
        }, 'Apache_Server_2-4_Windows_Server_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-214327',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$p=Join-Path $env:ProgramFiles 'Apache24\\conf\\httpd.conf'; $line=Select-String -Path $p -Pattern '^\\s*SSLVerifyClient\\s+require\\s*(?:#.*)?$' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($line) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The Apache web server must encrypt passwords during transmission.',
        })

    def test_infers_apache_windows_max_keepalive_requests_minimum_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-214306',
            'title': 'The Apache web server must limit the number of allowed simultaneous session requests.',
            'check_content': '''With an editor, open the configuration file:

<installed path>\\Apache24\\conf\\extra\\httpd-default

Search for the following directive:

MaxKeepAliveRequests

Verify the value is "100" or greater.

If the "MaxKeepAliveRequests" directive is not "100" or greater, this is a finding.''',
            'fix_text': '''With an editor, open the configuration file:

<installed path>\\conf\\extra\\httpd-default

Search for the following directive:

MaxKeepAliveRequests

Set the "MaxKeepAliveRequests" directive to a value of "100" or greater. Add the "MaxKeepAliveRequests" directive if it does not exist.''',
        }, 'Apache_Server_2-4_Windows_Server_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-214306',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$p=Join-Path $env:ProgramFiles 'Apache24\\conf\\extra\\httpd-default'; $line=Select-String -Path $p -Pattern '^\\s*MaxKeepAliveRequests\\s+(\\d+)\\s*(?:#.*)?$' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($line -and [int]$line.Matches[0].Groups[1].Value -ge 100) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The Apache web server must limit the number of allowed simultaneous session requests.',
        })

    def test_infers_apache_windows_session_max_age_maximum_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-214341',
            'title': 'The Apache web server must set an absolute timeout for sessions.',
            'check_content': '''Review the <'INSTALL PATH'>\\conf\\httpd.conf file.

Search for the following directive:

SessionMaxAge

Verify the value of "SessionMaxAge" is set to "600" or less.

If the "SessionMaxAge" does not exist or is set to more than "600", this is a finding.''',
            'fix_text': '''Open the <'INSTALL PATH'>\\conf\\httpd.conf file.

Set the "SessionMaxAge" directive to a value of "600" or less; add the directive if it does not exist.

Restart the Apache service.''',
        }, 'Apache_Server_2-4_Windows_Server_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-214341',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$p=Join-Path $env:ProgramFiles 'Apache24\\conf\\httpd.conf'; $line=Select-String -Path $p -Pattern '^\\s*SessionMaxAge\\s+(\\d+)\\s*(?:#.*)?$' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($line -and [int]$line.Matches[0].Groups[1].Value -le 600) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The Apache web server must set an absolute timeout for sessions.',
        })

    def test_infers_apache_windows_proxyrequests_not_on_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-214320',
            'title': 'The Apache web server must not be a proxy server.',
            'check_content': '''If the server has been approved to be a proxy server, this requirement is Not Applicable.

Open the <'INSTALL PATH'>\\conf\\httpd.conf file with an editor and search for the following directive:

ProxyRequests

If the ProxyRequests directive is set to "On", this is a finding.''',
            'fix_text': '''Open the <'INSTALL PATH'>\\conf\\httpd.conf file with an editor and search for the following directive:

ProxyRequests

Set the directive to a value of "off".

Restart the Apache service.''',
        }, 'Apache_Server_2-4_Windows_Server_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-214320',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$p=Join-Path $env:ProgramFiles 'Apache24\\conf\\httpd.conf'; $lines=Select-String -Path $p -Pattern '^\\s*ProxyRequests\\s+On\\s*(?:#.*)?$' -ErrorAction SilentlyContinue; if (-not $lines) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The Apache web server must not be a proxy server.',
        })

    def test_infers_apache_windows_ssl_module_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-214308',
            'title': 'The Apache web server must use encryption strength in accordance with the categorization of data hosted by the Apache web server when remote connections are provided.',
            'check_content': '''In a command line, navigate to "<'INSTALLED PATH'>\\bin". Run "httpd -M" to view a list of installed modules.

If the "ssl_module" is not enabled, this is a finding.''',
            'fix_text': 'Load the ssl_module in the Apache configuration.',
        }, 'Apache_Server_2-4_Windows_Server_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-214308',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$m=& httpd -M 2>$null; if (($m -match 'ssl_module')) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The Apache web server must use encryption strength in accordance with the categorization of data hosted by the Apache web server when remote connections are provided.',
        })

    def test_infers_windows_host_firewall_enabled_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254265',
            'title': 'Windows Server 2022 must have a host-based firewall installed and enabled.',
            'check_content': 'Determine if a host-based firewall is installed and enabled on the system. If a host-based firewall is not installed and enabled on the system, this is a finding.',
            'fix_text': 'Install and enable a host-based firewall on the system.',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-254265',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$profiles=Get-NetFirewallProfile -ErrorAction SilentlyContinue; if ($profiles -and -not ($profiles | Where-Object { -not $_.Enabled })) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'Windows Server 2022 must have a host-based firewall installed and enabled.',
        })

    def test_infers_windows_host_firewall_is_installed_and_enabled_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-220724',
            'title': 'A host-based firewall must be installed and enabled on the system.',
            'check_content': 'Determine if a host-based firewall is installed and enabled on the system.  If a host-based firewall is not installed and enabled on the system, this is a finding.\n\nThe configuration requirements will be determined by the applicable firewall STIG.',
            'fix_text': 'Install and enable a host-based firewall on the system.',
        }, 'MS_Windows_10_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-220724',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$profiles=Get-NetFirewallProfile -ErrorAction SilentlyContinue; if ($profiles -and -not ($profiles | Where-Object { -not $_.Enabled })) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'A host-based firewall must be installed and enabled on the system.',
        })

    def test_infers_windows_uefi_bios_mode_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-253256',
            'title': 'Windows 11 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.',
            'check_content': '''For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Verify the system firmware is configured to run in UEFI mode, not Legacy BIOS.

Run "System Information".

Under "System Summary", if "BIOS Mode" does not display "UEFI", this is a finding.''',
            'fix_text': 'Configure UEFI firmware and run the system in UEFI mode, not Legacy BIOS.',
        }, 'Microsoft_Windows_11_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-253256',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$info=Get-ComputerInfo -Property BiosFirmwareType -ErrorAction SilentlyContinue; if ($info.BiosFirmwareType -eq 'Uefi') { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'Windows 11 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.',
        })

    def test_infers_windows_secure_boot_enabled_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-253257',
            'title': 'Secure Boot must be enabled on Windows 11 systems.',
            'check_content': '''Verify the system firmware is configured for Secure Boot.

Run "System Information".

Under "System Summary", if "Secure Boot State" does not display "On", this is a finding.''',
            'fix_text': 'Enable Secure Boot in the system firmware.',
        }, 'Microsoft_Windows_11_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-253257',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$secure=$false; try { $secure=Confirm-SecureBootUEFI -ErrorAction Stop } catch { $secure=$false }; if ($secure) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'Secure Boot must be enabled on Windows 11 systems.',
        })

    def test_infers_windows_tpm_ready_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-205848',
            'title': 'Windows Server 2019 domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.',
            'check_content': '''Verify domain-joined systems have a TPM enabled and ready for use.

For standalone systems, this is NA.

Run "tpm.msc".
Review the sections in the center pane.
"Status" must indicate it has been configured with a message such as "The TPM is ready for use" or "The TPM is on and ownership has been taken".''',
            'fix_text': 'Enable and initialize a TPM that is ready for use.',
        }, 'Windows_Server_2019_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-205848',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$tpm=Get-Tpm -ErrorAction SilentlyContinue; if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'Windows Server 2019 domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.',
        })

    def test_infers_windows_legal_notice_text_registry_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254457',
            'title': 'Windows Server required legal notice must be configured to display before console logon.',
            'check_content': '''If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: LegalNoticeText

Value Type: REG_SZ
Value: See message text below

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing. See User Agreement for details.''',
            'fix_text': 'Configure the policy value for Interactive Logon: Message text for users attempting to log on.',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-254457',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
                'value_name': 'LegalNoticeText',
            },
            'expected': {'type': 'equals', 'value': 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing. See User Agreement for details.'},
            'description': 'Windows Server required legal notice must be configured to display before console logon.',
        })

    def test_infers_linux_issue_banner_exact_text_candidate(self):
        text = '''You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing. See User Agreement for details.'''
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271455',
            'title': 'OL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.',
            'check_content': f'''Verify that OL 9 displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the operating system via a command line user logon.

Check that a banner is displayed at the command line login screen with the following command:

$ cat /etc/issue

If the banner is set correctly it will return the following text:

"{text}"

If the banner text does not match the Standard Mandatory DOD Notice and Consent Banner exactly, or the line is commented out, this is a finding.''',
            'fix_text': f'''Configure OL 9 to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via command line logon.

Edit the "/etc/issue" file to replace the default text with the Standard Mandatory DOD Notice and Consent Banner. The DOD-required text is:

"{text}"''',
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-271455',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'cat /etc/issue'},
            'expected': {'type': 'equals', 'value': text},
            'description': 'OL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.',
        })

    def test_infers_linux_passwd_home_directory_assigned_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258051',
            'title': 'All RHEL 9 local interactive users must have a home directory assigned in the /etc/passwd file.',
            'check_content': """Verify that interactive users on the system have a home directory assigned with the following command:

$ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd

smithk:x:1000:1000:smithk:/home/smithk:/bin/bash

Inspect the output and verify that all interactive users (normally users with a user identifier (UID) greater that 1000) have a home directory defined.

If users home directory is not defined, this is a finding.""",
            'fix_text': 'Create and assign home directories to all local interactive users on RHEL 9 that currently do not have a home directory assigned.',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-258051',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "awk -F: '($3>=1000)&&($7 !~ /nologin/)&&($6==\"\"){print $1}' /etc/passwd",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'All RHEL 9 local interactive users must have a home directory assigned in the /etc/passwd file.',
        })

    def test_infers_linux_fixed_mount_option_candidate_from_authoritative_fstab_text(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257873',
            'title': 'RHEL 9 must mount /var/log/audit with the nodev option.',
            'check_content': 'Verify /var/log/audit is mounted with the "nodev" option. If /var/log/audit is not mounted with the nodev option, this is a finding.',
            'fix_text': 'Modify "/etc/fstab" to use the "nodev" option on the "/var/log/audit" directory.',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-257873',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "findmnt -nkT '/var/log/audit' | awk 'NR==1{print $4}' | grep -Eq '(^|,)nodev(,|$)' && printf 'Compliant'",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'RHEL 9 must mount /var/log/audit with the nodev option.',
        })

    def test_infers_linux_removable_media_mount_option_candidate_from_authoritative_fstab_text(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257857',
            'title': 'RHEL 9 must prevent code from being executed on file systems that are used with removable media.',
            'check_content': '''Verify RHEL 9 file systems that are used for removable media are mounted with the "noexec" option with the following command:

$ more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid,nodev,noexec 0 0

If a file system found in "/etc/fstab" refers to removable media and it does not have the "noexec" option set, this is a finding.''',
            'fix_text': 'Configure the "/etc/fstab" to use the "noexec" option on file systems that are associated with removable media.',
        }, 'RHEL_9_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['vuln_id'], 'V-257857')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check']['type'], 'command_output')
        self.assertIn('/etc/fstab', candidate['check']['command'])
        self.assertIn('noexec', candidate['check']['command'])
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_sles_removable_media_mount_option_variant_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234999',
            'title': 'SUSE operating system file systems that are used with removable media must be mounted to prevent files with the setuid and setgid bit set from being executed.',
            'check_content': '''Verify SUSE operating system file systems used for removable media are mounted with the "nosuid" option.

Check the file systems that are mounted at boot time with the following command:

> more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid 0 0

If a file system found in "/etc/fstab" refers to removable media and it does not have the "nosuid" option set, this is a finding.''',
            'fix_text': 'Configure the SUSE operating system "/etc/fstab" file to use the "nosuid" option on file systems that are associated with removable media.',
        }, 'SLES_15_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['vuln_id'], 'V-234999')
        self.assertIn('nosuid', candidate['check']['command'])
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_rejects_removable_media_mount_option_without_authoritative_finding_sentence(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257857',
            'title': 'RHEL 9 must prevent code from being executed on file systems that are used with removable media.',
            'check_content': 'Review /etc/fstab for removable media entries that mention noexec.',
            'fix_text': 'Configure the "/etc/fstab" to use the "noexec" option on file systems that are associated with removable media.',
        }, 'RHEL_9_STIG')
        self.assertIsNone(candidate)

    def test_infers_linux_interactive_home_mount_option_violation_scan_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230302',
            'title': 'RHEL 8 must prevent code from being executed on file systems that contain user home directories.',
            'check_content': '''Verify file systems that contain user home directories are mounted with the "noexec" option.

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is automatically a finding as the "noexec" option cannot be used on the "/" system.

Find the file system(s) that contain the user home directories with the following command:

$ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd

Check the file systems that are mounted at boot time with the following command:

$ sudo more /etc/fstab

If a file system found in "/etc/fstab" refers to the user home directory and it does not have the "noexec" option set, this is a finding.''',
            'fix_text': 'Configure the "/etc/fstab" to use the "noexec" option on file systems that contain user home directories for interactive users.',
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-230302',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd | while IFS= read -r home; do [ -z \"$home\" ] && continue; mount=$(findmnt -nkT \"$home\" | awk 'NR==1{print $1 \" \" $4}'); [ -z \"$mount\" ] && continue; target=${mount%% *}; opts=${mount#* }; if [ \"$target\" = \"/\" ] || ! printf '%s' \"$opts\" | grep -Eq '(^|,)noexec(,|$)'; then printf '%s\\n' \"$home $target $opts\"; fi; done",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 8 must prevent code from being executed on file systems that contain user home directories.',
        })

    def test_infers_macos_policy_banner_exact_text_and_mode_candidate(self):
        text = '''You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'''
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-268431',
            'title': 'The macOS system must display the Standard Mandatory DOD Notice and Consent Banner at the login window.',
            'check_content': f'''Verify the macOS system is configured to display a policy banner with the following command:

/bin/ls -ld /Library/Security/PolicyBanner.rtf* | /usr/bin/wc -l | /usr/bin/tr -d ' '

If the command does not return "1", this is a finding.

If the permissions for "PolicyBanner.rtfd" are not "644", this is a finding.

The banner text of the document must read:

"{text}"

If the text is not worded exactly this way, this is a finding.''',
            'fix_text': 'Configure the macOS system to display a policy banner by creating an RTF file containing the required text. Name the file "PolicyBanner.rtfd" and place it in "/Library/Security/". Update the permissions of the "/Library/Security/PolicyBanner.rtfd" file with the following command: /usr/bin/sudo /bin/chmod 644 /Library/Security/PolicyBanner.rtfd',
        }, 'Apple_macOS_15_STIG')
        expected_command = "/bin/sh -c 'p=/Library/Security/PolicyBanner.rtfd; [ -e \"$p\" ] && [ \"$(/usr/bin/stat -f %Lp \"$p\")\" = 644 ] && /usr/bin/textutil -convert txt -stdout \"$p\" 2>/dev/null'"
        self.assertEqual(candidate, {
            'vuln_id': 'V-268431',
            'platform': 'macos',
            'check': {'type': 'command_output', 'command': expected_command},
            'expected': {'type': 'equals', 'value': text},
            'description': 'The macOS system must display the Standard Mandatory DOD Notice and Consent Banner at the login window.',
        })

    def test_infers_macos_remote_login_banner_exact_text_candidate(self):
        text = '''You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing. See User Agreement for details.'''
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-268429',
            'title': 'The macOS system must display a policy banner at remote login.',
            'check_content': f'''Verify the macOS system is configured to display the Standard Mandatory DOD Notice and Consent Banner before granting remote access to the operating system.

Verify the operating system has the correct text listed in the "/etc/banner" file with the following command:

/usr/bin/more /etc/banner

The command must return the following text:

"{text}"

If the text is not worded exactly this way, this is a finding.''',
            'fix_text': f'Configure the macOS system to display the Standard Mandatory DOD Notice and Consent Banner before granting remote access by creating the /etc/banner file containing exactly:\n\n"{text}"',
        }, 'Apple_macOS_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-268429',
            'platform': 'macos',
            'check': {'type': 'command_output', 'command': '/usr/bin/more /etc/banner'},
            'expected': {'type': 'equals', 'value': text},
            'description': 'The macOS system must display a policy banner at remote login.',
        })

    def test_infers_windows_network_logon_exact_allowlist_with_punctuated_principals(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278183',
            'title': 'Windows Server 2025 "Access this computer from the network" user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and stand-alone or nondomain-joined systems.',
            'check_content': '''This applies to member servers and stand-alone or nondomain-joined systems.

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" user right, this is a finding:
- Administrators.
- Authenticated Users.

For server core installations, run the following command:
Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Access this computer from the network to include only the following accounts or groups:
- Administrators.
- Authenticated Users.''',
        }, 'MS_Windows_Server_2025_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-278183',
            'platform': 'windows',
            'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeNetworkLogonRight'},
            'expected': {'type': 'equals', 'value': '*S-1-5-32-544,*S-1-5-11'},
            'description': 'Windows Server 2025 "Access this computer from the network" user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and stand-alone or nondomain-joined systems.',
        })

    def test_infers_rhel9_audit_backlog_limit_minimum_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258173',
            'title': 'RHEL 9 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon.',
            'check_content': '''Verify RHEL 9 allocates a sufficient audit_backlog_limit to capture processes that start prior to the audit daemon with the following command:

$ sudo grubby --info=ALL | grep args | grep 'audit_backlog_limit'

If the command returns any outputs, and audit_backlog_limit is less than "8192", this is a finding.''',
            'fix_text': 'Configure RHEL 9 to allocate sufficient audit_backlog_limit to capture processes that start prior to the audit daemon with the following command:\n\n$ sudo grubby --update-kernel=ALL --args=audit_backlog_limit=8192',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-258173',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "grubby --info=ALL | awk '/^args=/{ if ($0 !~ /audit_backlog_limit=/) { print $0; next } while (match($0, /audit_backlog_limit=([0-9]+)/, m)) { if (m[1] + 0 < 8192) print $0; $0=substr($0, RSTART+RLENGTH) } }'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 9 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon.',
        })

    def test_infers_windows_network_logon_exact_allowlist_with_blank_lines_between_bullets(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254434',
            'title': 'Windows Server 2022 Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on member servers.',
            'check_content': '''Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" user right, this is a finding:

- Administrators
- Authenticated Users

For server core installations, run the following command:
Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Access this computer from the network to include only the following accounts or groups:

- Administrators
- Authenticated Users''',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-254434',
            'platform': 'windows',
            'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeNetworkLogonRight'},
            'expected': {'type': 'equals', 'value': '*S-1-5-32-544,*S-1-5-11'},
            'description': 'Windows Server 2022 Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on member servers.',
        })

    def test_infers_firefox_autoplay_default_block_audio_video_policy_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251565',
            'title': 'Firefox autoplay must be disabled.',
            'check_content': '''Type "about:policies" in the browser address bar.

If "Permissions" is not displayed under Policy Name or the Policy Value is not "Autoplay" with a value of "Default" and "Block-audio-video", this is a finding.''',
            'fix_text': '''Linux "policies.json" file:
Add the following in the policies section:
"Permissions": {
  "Autoplay": {
    "Default": "block-audio-video"
  }
}''',
        }, 'MOZ_Firefox_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-251565',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'python3 -c "import json, pathlib; p=pathlib.Path(\'/usr/lib/firefox/distribution/policies.json\'); policies=json.loads(p.read_text()).get(\'policies\', {}) if p.exists() else {}; permissions=policies.get(\'Permissions\') or {}; autoplay=permissions.get(\'Autoplay\') or {}; print(str(autoplay.get(\'Default\')).lower())"',
            },
            'expected': {'type': 'equals', 'value': 'block-audio-video'},
            'description': 'Firefox autoplay must be disabled.',
        })

    def test_infers_firefox_nested_boolean_policy_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251567',
            'title': 'Firefox fingerprinting protection must be enabled.',
            'check_content': '''Type "about:policies" in the browser address bar.

If "EnableTrackingProtection" is not displayed under Policy Name or the Policy Value is not "Fingerprinting"  with a value of "true", this is a finding.''',
            'fix_text': '''Linux "policies.json" file:
Add the following in the policies section:
"EnableTrackingProtection": {
  "Fingerprinting": true
}''',
        }, 'MOZ_Firefox_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-251567',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'python3 -c "import json, pathlib; p=pathlib.Path(\'/usr/lib/firefox/distribution/policies.json\'); policies=json.loads(p.read_text()).get(\'policies\', {}) if p.exists() else {}; parent=policies.get(\'EnableTrackingProtection\') or {}; print(str(parent.get(\'Fingerprinting\')).lower())"',
            },
            'expected': {'type': 'equals', 'value': 'true'},
            'description': 'Firefox fingerprinting protection must be enabled.',
        })

    def test_infers_firefox_flat_has_value_boolean_policy_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-252908',
            'title': 'Pocket must be disabled.',
            'check_content': '''Type "about:policies" in the browser address bar.

If "DisablePocket" is not displayed under Policy Name or the Policy Value does not have a value of "true", this is a finding.''',
            'fix_text': '''Linux "policies.json" file:
Add the following in the policies section:
"DisablePocket": true''',
        }, 'MOZ_Firefox_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-252908',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'python3 -c "import json, pathlib; p=pathlib.Path(\'/usr/lib/firefox/distribution/policies.json\'); policies=json.loads(p.read_text()).get(\'policies\', {}) if p.exists() else {}; print(str(policies.get(\'DisablePocket\')).lower())"',
            },
            'expected': {'type': 'equals', 'value': 'true'},
            'description': 'Pocket must be disabled.',
        })

    def test_infers_firefox_preferences_value_status_locked_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251569',
            'title': 'Firefox Enhanced Tracking Protection must be enabled.',
            'check_content': '''Type "about:policies" in the browser address bar.

If "Preferences" is not displayed under Policy Name or the Policy Value does not include "browser.contentblocking.category" with a value of  "strict" and status of "locked", this is a finding.''',
            'fix_text': '''Linux "policies.json" file:
Add the following in the policies section:
"Preferences": {
  "browser.contentblocking.category": {
    "Value": "strict",
    "Status": "locked"
  }
}''',
        }, 'MOZ_Firefox_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['vuln_id'], 'V-251569')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'configured'})
        self.assertIn("browser.contentblocking.category", candidate['check']['command'])
        self.assertIn("strict", candidate['check']['command'])
        self.assertIn("locked", candidate['check']['command'])

    def test_infers_firefox_multiple_nested_boolean_policy_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251581',
            'title': 'Firefox encrypted media extensions must be disabled.',
            'check_content': '''Type "about:policies" in the browser address bar.

If "EncryptedMediaExtensions" is not displayed under Policy Name or the Policy Value does not have "Enabled" set to "false" or the Policy Value does not have "Locked" set to "true", this is a finding.''',
            'fix_text': '''Linux "policies.json" file:
Add the following in the policies section:
"EncryptedMediaExtensions": {
  "Enabled": false,
  "Locked": true
}''',
        }, 'MOZ_Firefox_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['vuln_id'], 'V-251581')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'configured'})
        self.assertIn("EncryptedMediaExtensions", candidate['check']['command'])
        self.assertIn("Enabled", candidate['check']['command'])
        self.assertIn("Locked", candidate['check']['command'])

    def test_infers_adobe_dc_repair_installation_dual_registry_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-213133',
            'title': 'Adobe Acrobat Pro DC Continuous Repair Installation must be disabled.',
            'check_content': '''Verify the following registry configuration:

Using the Registry Editor, navigate to the following: 

For 32 bit:
HKEY_LOCAL_MACHINE\\Software\\Adobe\\Adobe Acrobat\\DC\\Installer

For 64 bit:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Adobe\\Adobe Acrobat\\DC\\Installer

Value Name: DisableMaintenance
Type: REG_DWORD
Value: 1

If the value for DisableMaintenance is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.''',
            'fix_text': '''Configure the following registry value:

For 32 bit:
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
Value: 1''',
        }, 'Adobe_Acrobat_Pro_DC_Continuous_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-213133',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$paths=@('HKLM:\\Software\\Adobe\\Adobe Acrobat\\DC\\Installer','HKLM:\\SOFTWARE\\Wow6432Node\\Adobe\\Adobe Acrobat\\DC\\Installer'); $ok=$true; foreach ($p in $paths) { $v=(Get-ItemProperty -Path $p -Name 'DisableMaintenance' -ErrorAction SilentlyContinue).DisableMaintenance; if ($v -ne 1) { $ok=$false } }; if ($ok) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'Adobe Acrobat Pro DC Continuous Repair Installation must be disabled.',
        })

    def test_infers_windows_ftp_anonymous_authentication_disabled_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278027',
            'title': 'Windows Server 2025 FTP servers must be configured to prevent anonymous logons.',
            'check_content': '''If FTP is not installed on the system, this is not applicable.

Open Internet Information Services (IIS) Manager.

Select the server.

Double-click "FTP Authentication".

If the "Anonymous Authentication" status is "Enabled", this is a finding.''',
            'fix_text': '''Configure the FTP service to prevent anonymous logons.

Open "Internet Information Services (IIS) Manager".

Select the server.

Double-click "FTP Authentication".

Select "Anonymous Authentication".

Select "Disabled" under "Actions".''',
        }, 'MS_Windows_Server_2025_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-278027',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"Import-Module WebAdministration -ErrorAction SilentlyContinue; $value=(Get-WebConfigurationProperty -PSPath 'IIS:\\' -Filter '/system.ftpServer/security/authentication/anonymousAuthentication' -Name enabled -ErrorAction SilentlyContinue).Value; if ($value -eq $false) { 'Disabled' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Disabled'},
            'description': 'Windows Server 2025 FTP servers must be configured to prevent anonymous logons.',
        })

    def test_infers_windows_event_log_file_acl_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254298',
            'title': 'Windows Server 2022 permissions for the System event log must prevent access by nonprivileged accounts.',
            'check_content': '''Navigate to the System event log file.

The default location is the "%SystemRoot%\\System32\\winevt\\Logs" folder. However, the logs may have been moved to another folder.

If the permissions for the "System.evtx" file are not as restrictive as the default permissions listed below, this is a finding:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control''',
            'fix_text': '''Configure the permissions on the System event log file (System.evtx) to prevent access by nonprivileged accounts. The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\System32\\winevt\\Logs" folder.''',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-254298',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$log='System'; $line=wevtutil gl $log | Select-String -Pattern '^\\s*logFileName:' | Select-Object -First 1; $p=($line.Line -replace '^\\s*logFileName:\\s*',''); $p=[Environment]::ExpandEnvironmentVariables($p); $acl=Get-Acl -LiteralPath $p; $need=@('NT SERVICE\\EventLog','NT AUTHORITY\\SYSTEM','BUILTIN\\Administrators'); $ok=$true; foreach ($n in $need) { if (-not ($acl.Access | Where-Object { $_.IdentityReference -eq $n -and $_.FileSystemRights.ToString() -match 'FullControl' })) { $ok=$false } }; if ($ok) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'Windows Server 2022 permissions for the System event log must prevent access by nonprivileged accounts.',
        })

    def test_infers_windows_directory_service_max_conn_idle_time_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278147',
            'title': 'Windows Server 2025 directory service must be configured to terminate LDAP-based network connections to the directory server after five minutes of inactivity.',
            'check_content': '''This applies to domain controllers. It is not applicable for other systems.

Open an elevated command prompt (run as administrator).
Enter "ntdsutil".
At the "ntdsutil:" prompt, enter "LDAP policies".
At the "ldap policy:" prompt, enter "show values".

If the value for MaxConnIdleTime is greater than "300" (5 minutes) or is not specified, this is a finding.

Alternately, Dsquery can be used to display MaxConnIdleTime:
dsquery * "cn=Default Query Policy,cn=Query-Policies,cn=Directory Service,cn=Windows NT,cn=Services,cn=Configuration,dc=example,dc=mil" -scope base -attr LDAPAdminLimits''',
            'fix_text': '''Configure the directory service to terminate LDAP-based network connections to the directory server after 5 minutes of inactivity.

Open an elevated command prompt (run as administrator).
Enter "ntdsutil".
Set MaxConnIdleTime to 300.
Commit Changes.''',
        }, 'MS_Windows_Server_2025_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-278147',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$root=[ADSI]'LDAP://RootDSE'; $cfg=$root.configurationNamingContext; $p=[ADSI]('LDAP://CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,'+$cfg); $v=@($p.Properties['LDAPAdminLimits']) | Where-Object { $_ -match '^MaxConnIdleTime=(\\d+)$' } | Select-Object -First 1; if ($v -match '^MaxConnIdleTime=(\\d+)$' -and [int]$Matches[1] -le 300) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'Windows Server 2025 directory service must be configured to terminate LDAP-based network connections to the directory server after five minutes of inactivity.',
        })

    def test_infers_ol9_crypto_policy_not_overridden_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271479',
            'rule_id': 'SV-271479r1092621_rule',
            'title': 'OL 9 must not allow the cryptographic policy to be overridden.',
            'check_content': '''Verify that OL 9 cryptographic policies are not overridden.

Verify that the configured policy matches the generated policy with the following command:

$ sudo update-crypto-policies --check && echo PASS
The configured policy matches the generated policy
PASS

If the last line is not "PASS", this is a finding.

List all of the crypto backends configured on the system with the following command:

$ ls -l /etc/crypto-policies/back-ends/
lrwxrwxrwx. 1 root root  40 Nov 13 16:29 bind.config -> /usr/share/crypto-policies/FIPS/bind.txt
-rw-r--r--. 1 root root 398 Nov 13 16:29 nss.config
lrwxrwxrwx. 1 root root  43 Nov 13 16:29 openssl.config -> /usr/share/crypto-policies/FIPS/openssl.txt

If the paths do not point to the respective files under /usr/share/crypto-policies/FIPS path, this is a finding.

Note: nss.config should not be hyperlinked.''',
            'fix_text': '''Configure OL 9 to correctly implement the systemwide cryptographic policies by reinstalling the crypto-policies package contents.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS''',
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-271479',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'sh -c \'update-crypto-policies --check >/dev/null && test -z "$(find /etc/crypto-policies/back-ends -maxdepth 1 -type l ! -lname "/usr/share/crypto-policies/FIPS/*" -print -quit)" && echo PASS\'',
            },
            'expected': {'type': 'equals', 'value': 'PASS'},
            'description': 'OL 9 must not allow the cryptographic policy to be overridden.',
        })

    def test_infers_vcenter_lookup_optional_xml_value_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259059',
            'title': 'The vCenter Lookup service directory listings parameter must be disabled.',
            'check_content': '''At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/parent::init-param' -

If the "listings" parameter is specified and is not "false", this is a finding.

If the "listings" parameter does not exist, this is not a finding.''',
            'fix_text': '''Navigate to and open /usr/lib/vmware-lookupsvc/conf/web.xml.

Set the listings param-value to false.''',
        }, 'VMW_vSphere_8-0_VCSA_Lookup_Svc_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-259059',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': "sh -c \"xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=\\\".*\\\"//g' | xmllint --xpath 'string(//param-name[text()=\\\"listings\\\"]/parent::init-param/param-value)' - 2>/dev/null | awk 'NF{print \\\"listings=\\\" $0}'\"",
            },
            'expected': {'type': 'matches', 'pattern': '^(?:|listings=false)$'},
            'description': 'The vCenter Lookup service directory listings parameter must be disabled.',
        })

    def test_infers_vcenter_lookup_removed_webapp_directory_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259069',
            'title': 'The vCenter Lookup service manager webapp must be removed.',
            'check_content': '''At the command prompt, run the following command:

# ls -l /var/opt/apache-tomcat/webapps/manager

If the manager folder exists or contains any content, this is a finding.''',
            'fix_text': '''At the command prompt, run the following command:

# rm -rf /var/opt/apache-tomcat/webapps/manager''',
        }, 'VMW_vSphere_8-0_VCSA_Lookup_Svc_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-259069',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': "sh -c '[ ! -e /var/opt/apache-tomcat/webapps/manager ] || [ -z \"$(ls -A /var/opt/apache-tomcat/webapps/manager 2>/dev/null)\" ] && printf Compliant'",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The vCenter Lookup service manager webapp must be removed.',
        })

    def test_infers_linux_gnome_login_banner_exact_text_candidate(self):
        banner = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions: '
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270174',
            'title': 'RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.',
            'check_content': f'''Check that the operating system displays the exact Standard Mandatory DOD Notice and Consent Banner text with the command:

$ gsettings get org.gnome.login-screen banner-message-text

banner-message-text=
'{banner}'

If the banner does not match the Standard Mandatory DOD Notice and Consent Banner exactly, this is a finding.''',
            'fix_text': f'''Add the following lines to the [org/gnome/login-screen] section of the "/etc/dconf/db/local.d/01-banner-message":

banner-message-text='{banner}'

Run the following command to update the database:

$ sudo dconf update''',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-270174',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'gsettings get org.gnome.login-screen banner-message-text',
            },
            'expected': {'type': 'contains', 'substring': banner},
            'description': 'RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.',
        })

    def test_infers_linux_dconf_login_banner_exact_text_candidate(self):
        banner = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions: '
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248528',
            'title': 'OL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.',
            'check_content': f'''Check that the operating system displays the exact Standard Mandatory DoD Notice and Consent Banner text with the command:

$ sudo grep banner-message-text /etc/dconf/db/local.d/*

banner-message-text=
'{banner}'

If the banner does not match the Standard Mandatory DoD Notice and Consent Banner exactly, this is a finding.''',
            'fix_text': f'''Add the following lines to the [org/gnome/login-screen] section of the "/etc/dconf/db/local.d/01-banner-message":

banner-message-text='{banner}'

Run the following command to update the database:

$ sudo dconf update''',
        }, 'Oracle_Linux_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-248528',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'grep banner-message-text /etc/dconf/db/local.d/*',
            },
            'expected': {'type': 'contains', 'substring': banner},
            'description': 'OL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.',
        })

    def test_infers_windows_secondary_logon_service_disabled_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-253289',
            'title': 'The Secondary Logon service must be disabled on Windows 11.',
            'check_content': '''Run "Services.msc".

Locate the "Secondary Logon" service.

If the "Startup Type" is not "Disabled" or the "Status" is "Running", this is a finding.''',
            'fix_text': 'Configure the "Secondary Logon" service "Startup Type" to "Disabled".',
        }, 'Microsoft_Windows_11_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-253289',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$svc=Get-CimInstance Win32_Service -Filter \\\"Name='seclogon'\\\" -ErrorAction SilentlyContinue; if ($svc -and $svc.StartMode -eq 'Disabled' -and $svc.State -ne 'Running') { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The Secondary Logon service must be disabled on Windows 11.',
        })

    def test_infers_windows_absent_simple_tcpip_services_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-253277',
            'title': 'Simple TCP/IP Services must not be installed on the system.',
            'check_content': '''Verify Simple TCP/IP Services has not been installed.

Run "Services.msc".

If "Simple TCP/IP Services" is listed, this is a finding.''',
            'fix_text': 'Uninstall "Simple TCPIP Services (i.e. echo, daytime etc.)" from the system.',
        }, 'Microsoft_Windows_11_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-253277',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"if (-not (Get-Service -Name 'SimpTcp' -ErrorAction SilentlyContinue)) { 'Absent' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Absent'},
            'description': 'Simple TCP/IP Services must not be installed on the system.',
        })

    def test_infers_linux_interactive_home_directory_mode_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257890',
            'title': 'All RHEL 9 local interactive user home directories must have mode 0750 or less permissive.',
            'check_content': '''Verify the assigned home directory of all interactive users on RHEL 9 has a mode of "0750" or less permissive with the following command:

$ stat -L -c '%a %n' $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd) 2>/dev/null

If home directories referenced in "/etc/passwd" do not have a mode of "0750" or less permissive, this is a finding.''',
            'fix_text': 'Change the mode of interactive user home directories to "0750" or less permissive.',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-257890',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "find $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd) -maxdepth 0 -type d -perm /027 -exec stat -c \"%a %n\" {} \\; 2>/dev/null",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'All RHEL 9 local interactive user home directories must have mode 0750 or less permissive.',
        })

    def test_infers_linux_interactive_home_directory_ls_mode_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234993',
            'title': 'All SUSE operating system local interactive user home directories must have mode 0750 or less permissive.',
            'check_content': '''Verify the assigned home directory of all interactive users on the SUSE operating system has a mode of "0750" or less permissive with the following command:

> ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)

If home directories referenced in "/etc/passwd" do not have a mode of "0750" or less permissive, this is a finding.''',
            'fix_text': 'Change the mode of interactive user home directories to "0750" or less permissive.',
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-234993',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "find $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd) -maxdepth 0 -type d -perm /027 -exec stat -c \"%a %n\" {} \\; 2>/dev/null",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'All SUSE operating system local interactive user home directories must have mode 0750 or less permissive.',
        })

    def test_infers_linux_sudoers_default_include_directory_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251711',
            'title': 'RHEL 8 must specify the default "include" directory for the /etc/sudoers file.',
            'check_content': '''Note: If the "include" and "includedir" directives are not present in the /etc/sudoers file, this requirement is not applicable.

Verify the operating system specifies only the default "include" directory for the /etc/sudoers file with the following command:

$ sudo grep include /etc/sudoers

#includedir /etc/sudoers.d

If the results are not "/etc/sudoers.d" or additional files or directories are specified, this is a finding.

Verify the operating system does not have nested "include" files or directories within the /etc/sudoers.d directory with the following command:

$ sudo grep -r include /etc/sudoers.d

If results are returned, this is a finding.''',
            'fix_text': '''Configure the /etc/sudoers file to only include the /etc/sudoers.d directory.

Edit the /etc/sudoers file with the following command:

$ sudo visudo

Add or modify the following line:
#includedir /etc/sudoers.d''',
        }, 'RHEL_8_STIG')
        command = r"""awk '/^[[:space:]]*#?(include|includedir)[[:space:]]+/ { if ($0 !~ /^[[:space:]]*#includedir[[:space:]]+[/]etc[/]sudoers[.]d[[:space:]]*$/) print FILENAME ":" $0 }' /etc/sudoers 2>/dev/null; grep -R -n -E '^[[:space:]]*#?(include|includedir)[[:space:]]+' /etc/sudoers.d 2>/dev/null"""
        self.assertEqual(candidate, {
            'vuln_id': 'V-251711',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': command,
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 8 must specify the default "include" directory for the /etc/sudoers file.',
        })

    def test_infers_linux_sha_crypt_rounds_floor_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271627',
            'title': 'OL 9 shadow password suite must be configured to use a sufficient number of hashing rounds.',
            'check_content': '''Verify that OL 9 has a minimum number of hash rounds configured with the following command:

$ grep -i sha_crypt /etc/login.defs

If "SHA_CRYPT_MIN_ROUNDS" or "SHA_CRYPT_MAX_ROUNDS" is less than "100000", this is a finding.''',
            'fix_text': '''Configure OL 9 to encrypt all stored passwords with a strong cryptographic hash.

Edit/modify the following line in the "/etc/login.defs" file and set "SHA_CRYPT_MIN_ROUNDS" to a value no lower than "100000":

SHA_CRYPT_MIN_ROUNDS 100000
SHA_CRYPT_MAX_ROUNDS 100000''',
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-271627',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'grep -i sha_crypt /etc/login.defs'},
            'expected': {
                'type': 'matches',
                'pattern': r'(?ims)^(?!.*^\s*SHA_CRYPT_(?:MIN|MAX)_ROUNDS\s+(?:[0-9]{1,5})\b).*^\s*SHA_CRYPT_(?:MIN|MAX)_ROUNDS\s+(?:[1-9][0-9]{5,})\b.*$',
            },
            'description': 'OL 9 shadow password suite must be configured to use a sufficient number of hashing rounds.',
        })

    def test_infers_linux_sha_crypt_rounds_floor_candidate_with_egrep_anchor(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234888',
            'title': 'The SUSE operating system must employ FIPS 140-3 approved cryptographic hashing algorithms for all stored passwords.',
            'check_content': '''Verify the SUSE operating system configures the shadow password suite configuration to encrypt passwords using a strong cryptographic hash.

Check that a minimum number of hash rounds is configured by running the following command:

> egrep "^SHA_CRYPT_" /etc/login.defs

If only one of "SHA_CRYPT_MIN_ROUNDS" or "SHA_CRYPT_MAX_ROUNDS" is set, and this value is below "100000", this is a finding.

If both "SHA_CRYPT_MIN_ROUNDS" and "SHA_CRYPT_MAX_ROUNDS" are set, and the highest value for either is below "100000", this is a finding.''',
            'fix_text': '''Configure the SUSE operating system to encrypt all stored passwords with a strong cryptographic hash.

Edit/modify the following line in the "/etc/login.defs" file and set "SHA_CRYPT_MIN_ROUNDS" to a value no lower than "100000":

SHA_CRYPT_MIN_ROUNDS 100000''',
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-234888',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'egrep "^SHA_CRYPT_" /etc/login.defs'},
            'expected': {
                'type': 'matches',
                'pattern': r'(?ims)^(?!.*^\s*SHA_CRYPT_(?:MIN|MAX)_ROUNDS\s+(?:[0-9]{1,5})\b).*^\s*SHA_CRYPT_(?:MIN|MAX)_ROUNDS\s+(?:[1-9][0-9]{5,})\b.*$',
            },
            'description': 'The SUSE operating system must employ FIPS 140-3 approved cryptographic hashing algorithms for all stored passwords.',
        })

    def test_infers_linux_interactive_shadow_sha512_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258231',
            'title': 'RHEL 9 must employ FIPS 140-3 approved cryptographic hashing algorithms for all stored passwords.',
            'check_content': '''Verify all interactive user password hashes are using a FIPS 140-3 approved cryptographic hashing algorithm with the following command:

$ sudo cut -d: -f2 /etc/shadow

Password hashes "!" or "*" indicate inactive accounts and are not evaluated.

If any interactive user password hash does not begin with "$6$", this is a finding.''',
            'fix_text': 'Lock all interactive user accounts not using SHA-512 until the passwords can be regenerated with a FIPS 140-3 approved cryptographic hashing algorithm.',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-258231',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "awk -F: 'NR==FNR{shell[$1]=$7; uid[$1]=$3; next} uid[$1]>=1000 && shell[$1] !~ /(nologin|false)$/ && $2 !~ /^[!*]/ && $2 !~ /^\\$6\\$/ {print $1}' /etc/passwd /etc/shadow",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 9 must employ FIPS 140-3 approved cryptographic hashing algorithms for all stored passwords.',
        })

    def test_infers_linux_shadow_minimum_password_lifetime_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230364',
            'title': 'RHEL 8 passwords must have a 24 hours/1 day minimum password lifetime restriction in /etc/shadow.',
            'check_content': '''Check whether the minimum time period between password changes for each user account is one day or greater.

$ sudo awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.''',
            'fix_text': '''Configure non-compliant accounts to enforce a 24 hours/1 day minimum password lifetime:

$ sudo chage -m 1 [user]''',
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-230364',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "awk -F: 'NR==FNR{uid[$1]=$3; shell[$1]=$7; next} ($1 in uid) && uid[$1]>=1000 && shell[$1] !~ /(nologin|false)$/ && $4 < 1 {print $1 \" \" $4}' /etc/passwd /etc/shadow",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 8 passwords must have a 24 hours/1 day minimum password lifetime restriction in /etc/shadow.',
        })

    def test_infers_linux_shadow_maximum_password_lifetime_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230367',
            'title': 'RHEL 8 user account passwords must be configured so that existing passwords are restricted to a 60-day maximum lifetime.',
            'check_content': '''Check whether the maximum time period for existing passwords is restricted to 60 days with the following commands:

$ sudo awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow

$ sudo awk -F: '$5 <= 0 {print $1 " " $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.''',
            'fix_text': '''Configure non-compliant accounts to enforce a 60-day maximum password lifetime restriction.

$ sudo chage -M 60 [user]''',
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-230367',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "awk -F: 'NR==FNR{uid[$1]=$3; shell[$1]=$7; next} ($1 in uid) && uid[$1]>=1000 && shell[$1] !~ /(nologin|false)$/ && ($5 > 60 || $5 <= 0) {print $1 \" \" $5}' /etc/passwd /etc/shadow",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 8 user account passwords must be configured so that existing passwords are restricted to a 60-day maximum lifetime.',
        })

    def test_infers_linux_shadow_minimum_password_lifetime_printf_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258105',
            'title': 'RHEL 9 passwords must have a 24 hours minimum password lifetime restriction in /etc/shadow.',
            'check_content': '''Verify that RHEL 9 has configured the minimum time period between password changes for each user account as one day or greater with the following command:

$ sudo awk -F: '$4 < 1 {printf "%s %d\\n", $1, $4}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.''',
            'fix_text': '''Configure noncompliant accounts to enforce a 24 hour minimum password lifetime:

$ sudo passwd -n 1 [user]''',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-258105',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "awk -F: 'NR==FNR{uid[$1]=$3; shell[$1]=$7; next} ($1 in uid) && uid[$1]>=1000 && shell[$1] !~ /(nologin|false)$/ && $4 < 1 {print $1 \" \" $4}' /etc/passwd /etc/shadow",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 9 passwords must have a 24 hours minimum password lifetime restriction in /etc/shadow.',
        })

    def test_infers_linux_shadow_maximum_password_lifetime_printf_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258042',
            'title': 'RHEL 9 user account passwords must have a 60-day maximum password lifetime restriction.',
            'check_content': '''Verify the maximum time period for existing passwords is restricted to 60 days with the following commands:

$ sudo awk -F: '$5 > 60 {printf "%s %d\\n", $1, $5}' /etc/shadow

$ sudo awk -F: '$5 <= 0 {printf "%s %d\\n", $1, $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.''',
            'fix_text': '''Configure noncompliant accounts to enforce a 60-day maximum password lifetime restriction.

passwd -x 60 [user]''',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-258042',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "awk -F: 'NR==FNR{uid[$1]=$3; shell[$1]=$7; next} ($1 in uid) && uid[$1]>=1000 && shell[$1] !~ /(nologin|false)$/ && ($5 > 60 || $5 <= 0) {print $1 \" \" $5}' /etc/passwd /etc/shadow",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 9 user account passwords must have a 60-day maximum password lifetime restriction.',
        })

    def test_enriches_scap_artifact_rules_by_canonical_vuln_id(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / 'sample.xml'
            artifact.write_text('''<Benchmark id="sample"><title>Sample</title>
              <Group id="xccdf_mil.disa.stig_group_V-234890"><Rule id="xccdf_mil.disa.stig_rule_SV-234890r1_rule" severity="medium">
                <version>SLES-15-040200</version><title>SLES password minimum</title>
                <check><check-content>authoritative check</check-content></check>
                <fixtext>authoritative fix</fixtext>
              </Rule></Group>
            </Benchmark>''')
            manifest = {'generated_from': str(artifact)}
            mapped = mod._artifact_rule_map(manifest, root, {})
            self.assertIn('V-234890', mapped)
            self.assertEqual(mapped['V-234890']['check_content'], 'authoritative check')

    def test_infers_sles_shadow_minimum_password_lifetime_colon_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234890',
            'title': 'The SUSE operating system must employ user passwords with a minimum lifetime of 24 hours (one day).',
            'check_content': '''Check the minimum time period between password changes for each user account with the following command:

> sudo awk -F: '$4 < 1 {print $1 ":" $4}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.''',
            'fix_text': 'Change the minimum time period between password changes for each [USER] account to "1" day with the command:\n\n> sudo passwd -n 1 [USER]',
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-234890',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "awk -F: 'NR==FNR{uid[$1]=$3; shell[$1]=$7; next} ($1 in uid) && uid[$1]>=1000 && shell[$1] !~ /(nologin|false)$/ && $4 < 1 {print $1 \" \" $4}' /etc/passwd /etc/shadow",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The SUSE operating system must employ user passwords with a minimum lifetime of 24 hours (one day).',
        })

    def test_infers_sles_shadow_maximum_password_lifetime_colon_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234892',
            'title': 'The SUSE operating system must employ user passwords with a maximum lifetime of 60 days.',
            'check_content': '''Check that the SUSE operating system enforces 60 days or less as the maximum user password age with the following command:

> sudo awk -F: '$5 > 60 || $5 == "" {print $1 ":" $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.''',
            'fix_text': 'Configure the SUSE operating system to enforce a maximum password age of each [USER] account to 60 days.\n\n> sudo passwd -x 60 [USER]',
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-234892',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "awk -F: 'NR==FNR{uid[$1]=$3; shell[$1]=$7; next} ($1 in uid) && uid[$1]>=1000 && shell[$1] !~ /(nologin|false)$/ && ($5 > 60 || $5 <= 0) {print $1 \" \" $5}' /etc/passwd /etc/shadow",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The SUSE operating system must employ user passwords with a maximum lifetime of 60 days.',
        })

    def test_infers_sles_ctrl_alt_del_burst_action_dropin_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234990',
            'title': 'The SUSE operating system must disable the systemd Ctrl-Alt-Delete burst key sequence.',
            'check_content': '''Verify the SUSE operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed seven times within two seconds with the following command:

> systemd-analyze cat-config systemd/system.conf

# /etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction.conf
CtrlAltDelBurstAction=none

If the "CtrlAltDelBurstAction" is not set to "none", commented out, or is missing, this is a finding.
If the setting is not configured in a drop in file, this is a finding.''',
            'fix_text': 'Configure the system to disable the CtrlAltDelBurstAction by adding it to a drop file in a "/etc/systemd/system.conf.d/" configuration file:\n\nCtrlAltDelBurstAction=none',
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-234990',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': r'''systemd-analyze cat-config systemd/system.conf 2>/dev/null | awk '/^# \/etc\/systemd\/system\.conf\.d\//{drop=1; next} drop && /^CtrlAltDelBurstAction=none$/{print "Compliant"; exit}' '''.strip(),
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The SUSE operating system must disable the systemd Ctrl-Alt-Delete burst key sequence.',
        })

    def test_infers_sles_mfa_required_packages_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234854',
            'title': 'The SUSE operating system must have the packages required for multifactor authentication to be installed.',
            'check_content': '''Verify the SUSE operating system has the packages required for multifactor authentication installed with the following commands:

zypper info pam_pkcs11 | grep -i installed
zypper info mozilla-nss | grep -i installed
zypper info mozilla-nss-tools | grep -i installed
zypper info pcsc-ccid | grep -i installed
zypper info pcsc-lite | grep -i installed
zypper info pcsc-tools | grep -i installed
zypper info opensc | grep -i installed
zypper info coolkey | grep -i installed

If any of the packages required for multifactor authentication are not installed, this is a finding.''',
            'fix_text': '''Install the packages required for multifactor authentication:

zypper install pam_pkcs11
zypper install mozilla-nss
zypper install mozilla-nss-tools
zypper install pcsc-ccid
zypper install pcsc-lite
zypper install pcsc-tools
zypper install opensc
zypper install coolkey''',
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-234854',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'missing=0; for pkg in pam_pkcs11 mozilla-nss mozilla-nss-tools pcsc-ccid pcsc-lite pcsc-tools opensc coolkey; do rpm -q "$pkg" >/dev/null 2>&1 || { echo "$pkg"; missing=1; }; done; exit 0',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The SUSE operating system must have the packages required for multifactor authentication to be installed.',
        })

    def test_infers_kubernetes_manifest_flag_presence_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242402',
            'title': 'The Kubernetes API Server must have an audit log path set.',
            'check_content': '''Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
grep -i audit-log-path *

If the "--audit-log-path" is not set, this is a finding.''',
            'fix_text': 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--audit-log-path" to a secure location for the audit logs to be written.',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242402',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'grep -i audit-log-path /etc/kubernetes/manifests/*'},
            'expected': {'type': 'not_equals', 'value': ''},
            'description': 'The Kubernetes API Server must have an audit log path set.',
        })

    def test_infers_kubernetes_manifest_boolean_flag_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242423',
            'title': 'Kubernetes etcd must enable client authentication to secure service.',
            'check_content': '''Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
grep -i client-cert-auth *

If the setting client-cert-auth is not configured in the Kubernetes etcd manifest file or set to "false", this is a finding.''',
            'fix_text': 'Edit the Kubernetes etcd manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--client-cert-auth" to "true" for the etcd.',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242423',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'grep -i client-cert-auth /etc/kubernetes/manifests/*'},
            'expected': {'type': 'contains', 'substring': 'true'},
            'description': 'Kubernetes etcd must enable client authentication to secure service.',
        })

    def test_infers_kubernetes_manifest_absent_flag_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-245543',
            'title': 'Kubernetes API Server must disable token authentication to protect information in transit.',
            'check_content': '''Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i token-auth-file *

If "--token-auth-file" is set in the Kubernetes API server manifest file, this is a finding.''',
            'fix_text': 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Remove the setting "--token-auth-file".',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-245543',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'grep -i token-auth-file /etc/kubernetes/manifests/*'},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'Kubernetes API Server must disable token authentication to protect information in transit.',
        })


    def test_infers_firefox_policies_json_boolean_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251564',
            'title': 'Firefox search suggestions must be disabled.',
            'check_content': '''Type "about:policies" in the browser window.

If "SearchSuggestEnabled" is not displayed under Policy Name or the Policy Value is not "false", this is a finding.''',
            'fix_text': '''Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".

macOS "plist" file:
Add the following:
<key>SearchSuggestEnabled</key>
<false/>

Linux "policies.json" file:
Add the following in the policies section:
"SearchSuggestEnabled": false''',
        }, 'MOZ_Firefox_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-251564',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'python3 -c "import json, pathlib; p=pathlib.Path(\'/usr/lib/firefox/distribution/policies.json\'); policies=json.loads(p.read_text()).get(\'policies\', {}) if p.exists() else {}; print(str(policies.get(\'SearchSuggestEnabled\')).lower())"',
            },
            'expected': {'type': 'equals', 'value': 'false'},
            'description': 'Firefox search suggestions must be disabled.',
        })

    def test_infers_edge_download_restrictions_allowed_registry_values_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-235752',
            'title': 'Download restrictions must be configured.',
            'check_content': '''The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow download restrictions" must be set to "Enabled" with the option value set to "BlockDangerousDownloads", "Block potentially dangerous or unwanted downloads", or "BlockMaliciousDownloads". The more restrictive option, "Block all downloads", is also acceptable.

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "DownloadRestrictions" is set to "REG_DWORD = 0", this is a finding.''',
            'fix_text': 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow download restrictions" to "Enabled" and select one of the following: "BlockDangerousDownloads", "Block potentially dangerous or unwanted downloads", "BlockAllDownloads", or "BlockMaliciousDownloads".',
        }, 'MS_Edge_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-235752',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge',
                'value_name': 'DownloadRestrictions',
            },
            'expected': {'type': 'matches', 'pattern': '^(?:1|2|3|4)$'},
            'description': 'Download restrictions must be configured.',
        })

    def test_infers_defender_policy_registry_absent_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-213428',
            'title': 'Microsoft Defender AV must be configured to run and scan for malware and other potentially unwanted software.',
            'check_content': '''Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Windows Defender

Criteria: If the value "DisableAntiSpyware" does not exist, this is not a finding.''',
            'fix_text': 'Set the policy value for Microsoft Defender Antivirus "Turn off Microsoft Defender Antivirus" to "Not Configured".',
        }, 'MS_Defender_Antivirus')
        self.assertEqual(candidate, {
            'vuln_id': 'V-213428',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$p='HKLM:\\Software\\Policies\\Microsoft\\Windows Defender'; if (-not (Get-ItemProperty -Path $p -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue)) { 'Absent' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Absent'},
            'description': 'Microsoft Defender AV must be configured to run and scan for malware and other potentially unwanted software.',
        })

    def test_infers_defender_signature_due_days_one_through_seven_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-213453',
            'title': 'Microsoft Defender AV virus definition age must not exceed 7 days.',
            'check_content': '''Procedure: Use the Windows Registry Editor to navigate to the following key:

HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Signature Updates

Criteria: If the value "AVSignatureDue" is REG_DWORD = 7, this is not a finding.

A value of 1 - 6 is also acceptable and not a finding.

A value of 0 is a finding.
A value of 8 or more is a finding.''',
            'fix_text': 'Set the policy value to Enabled and select 7 or less, excluding 0.',
        }, 'MS_Defender_Antivirus')
        self.assertEqual(candidate, {
            'vuln_id': 'V-213453',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Signature Updates',
                'value_name': 'AVSignatureDue',
            },
            'expected': {'type': 'matches', 'pattern': '^(?:1|2|3|4|5|6|7)$'},
            'description': 'Microsoft Defender AV virus definition age must not exceed 7 days.',
        })

    def test_infers_defender_signature_due_days_higher_than_seven_wording_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-213452',
            'title': 'Microsoft Defender AV spyware definition age must not exceed 7 days.',
            'check_content': '''Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Security Intelligence Updates >> "Define the number of days before spyware security intelligence considered out of date" is set to "Enabled" and "7" or less is selected in the drop-down box (excluding "0", which is unacceptable).

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Signature Updates

Criteria: If the value "ASSignatureDue" is REG_DWORD = 7, this is not a finding.

A value of 1 - 6 is also acceptable and not a finding.

A value of 0 is a finding.

A value higher than 7 is a finding.''',
            'fix_text': 'Set the policy value to Enabled and select "7" or less in the drop-down box. Do not select a value of 0.',
        }, 'MS_Defender_Antivirus')
        self.assertEqual(candidate, {
            'vuln_id': 'V-213452',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Signature Updates',
                'value_name': 'ASSignatureDue',
            },
            'expected': {'type': 'matches', 'pattern': '^(?:1|2|3|4|5|6|7)$'},
            'description': 'Microsoft Defender AV spyware definition age must not exceed 7 days.',
        })

    def test_infers_defender_maps_reporting_allowed_registry_values_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-213434',
            'title': 'Microsoft Defender AV must join Microsoft MAPS.',
            'check_content': '''Procedure: Use the Windows Registry Editor to navigate to the following key:

HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet

Criteria: If the value "SpynetReporting" is REG_DWORD = 1, or REG_DWORD = 2, this is not a finding.''',
            'fix_text': 'Set the policy value to Enabled and select Advanced MAPS from the drop-down box.',
        }, 'MS_Defender_Antivirus')
        self.assertEqual(candidate, {
            'vuln_id': 'V-213434',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet',
                'value_name': 'SpynetReporting',
            },
            'expected': {'type': 'matches', 'pattern': '^(?:1|2)$'},
            'description': 'Microsoft Defender AV must join Microsoft MAPS.',
        })


    def test_infers_windows_legal_notice_caption_allowed_titles_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254458',
            'title': 'Windows Server title for legal banner dialog box must be configured with the appropriate text.',
            'check_content': 'If the following registry value does not exist or is not configured as specified, this is a finding:\n\nRegistry Hive: HKEY_LOCAL_MACHINE \nRegistry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\\n\nValue Name: LegalNoticeCaption\n\nValue Type: REG_SZ\nValue: See message title options below\n\n"DoD Notice and Consent Banner", "US Department of Defense Warning Statement", or an organization-defined equivalent. \n\nAutomated tools may only search for the titles defined above. If an organization-defined title is used, a manual review will be required.',
            'fix_text': 'Configure the policy value for Interactive Logon: Message title for users attempting to log on.',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-254458',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
                'value_name': 'LegalNoticeCaption',
            },
            'expected': {'type': 'matches', 'pattern': '^(?:DoD\\ Notice\\ and\\ Consent\\ Banner|US\\ Department\\ of\\ Defense\\ Warning\\ Statement)$'},
            'description': 'Windows Server title for legal banner dialog box must be configured with the appropriate text.',
        })

    def test_infers_windows_legal_notice_caption_legacy_title_above_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-220922',
            'title': 'The Windows dialog box title for the legal banner must be configured.',
            'check_content': 'If the following registry value does not exist or is not configured as specified, this is a finding:\n\nRegistry Hive: HKEY_LOCAL_MACHINE\nRegistry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\\n\nValue Name: LegalNoticeCaption\n\nValue Type: REG_SZ\nValue: See message title above\n\n"DoD Notice and Consent Banner", "US Department of Defense Warning Statement" or a site-defined equivalent, this is a finding. If a site-defined title is used, it can in no case contravene or modify the language of the banner text required in WN10-SO-000075.',
            'fix_text': 'Configure the policy value for Interactive logon: Message title for users attempting to log on to "DoD Notice and Consent Banner", "US Department of Defense Warning Statement", or a site-defined equivalent.',
        }, 'MS_Windows_10_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-220922',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
                'value_name': 'LegalNoticeCaption',
            },
            'expected': {'type': 'matches', 'pattern': '^(?:DoD\\ Notice\\ and\\ Consent\\ Banner|US\\ Department\\ of\\ Defense\\ Warning\\ Statement)$'},
            'description': 'The Windows dialog box title for the legal banner must be configured.',
        })

    def test_infers_windows_legal_notice_caption_dod_uppercase_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278208',
            'title': 'Windows Server 2025 title for legal banner dialog box must be configured with the appropriate text.',
            'check_content': 'If the following registry value does not exist or is not configured as specified, this is a finding:\n\nRegistry Hive: HKEY_LOCAL_MACHINE \nRegistry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\\n\nValue Name: LegalNoticeCaption\n\nValue Type: REG_SZ\nValue: See message title options below\n\n"DOD Notice and Consent Banner", "US Department of Defense Warning Statement", or an organization-defined equivalent. \n\nIf an organization-defined title is used, it can in no case contravene or modify the language of the banner text required in WN25-SO-000150.\n\nAutomated tools may only search for the titles defined above. If an organization-defined title is used, a manual review will be required.',
            'fix_text': 'Configure the policy value for Interactive Logon: Message title for users attempting to log on.',
        }, 'MS_Windows_Server_2025_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-278208',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
                'value_name': 'LegalNoticeCaption',
            },
            'expected': {'type': 'matches', 'pattern': '^(?:DOD\\ Notice\\ and\\ Consent\\ Banner|US\\ Department\\ of\\ Defense\\ Warning\\ Statement)$'},
            'description': 'Windows Server 2025 title for legal banner dialog box must be configured with the appropriate text.',
        })

    def test_infers_kubernetes_validating_admission_webhook_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242436',
            'title': 'The Kubernetes API server must have the ValidatingAdmissionWebhook enabled.',
            'check_content': '''Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
 grep -i ValidatingAdmissionWebhook *

If a line is not returned that includes enable-admission-plugins and ValidatingAdmissionWebhook, this is a finding.''',
            'fix_text': 'Edit the Kubernetes API server manifest to include ValidatingAdmissionWebhook in enable-admission-plugins.',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242436',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'grep -i ValidatingAdmissionWebhook /etc/kubernetes/manifests/*',
            },
            'expected': {'type': 'contains', 'substring': 'enable-admission-plugins'},
            'description': 'The Kubernetes API server must have the ValidatingAdmissionWebhook enabled.',
        })

    def test_infers_kubernetes_dynamic_file_mode_candidate_from_authoritative_placeholder_path(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242447',
            'title': 'The Kubernetes Kube Proxy kubeconfig must have file permissions set to 644 or more restrictive.',
            'check_content': '''Check if Kube-Proxy is running and obtain --kubeconfig parameter use the following command:
ps -ef | grep kube-proxy

If Kube-Proxy exists:
Review the permissions of the Kubernetes Kube Proxy by using the command:
stat -c %a <location from --kubeconfig>

If the file has permissions more permissive than "644", this is a finding.''',
            'fix_text': 'Change the permissions of the Kube Proxy to "644" by executing the command:\n\nchmod 644 <location from kubeconfig>.',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242447',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "sh -c 'path=$(ps -ef | sed -n \"s/.*--kubeconfig[= ]\\([^ ]*\\).*/\\1/p\" | head -n 1); [ -z \"$path\" ] || find \"$path\" -perm /133 -exec stat -c \"%a %n\" {} \\;'",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Kubernetes Kube Proxy kubeconfig must have file permissions set to 644 or more restrictive.',
        })

    def test_infers_kubernetes_fixed_owner_candidate_from_authoritative_default_path(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242454',
            'title': 'The Kubernetes kubeadm.conf must be owned by root.',
            'check_content': '''Review the Kubeadm.conf file :

Get the path for Kubeadm.conf by running:
sytstemctl status kubelet

Note the configuration file installed by the kubeadm is written to
(Default Location: /etc/systemd/system/kubelet.service.d/10-kubeadm.conf)
stat -c %U:%G <kubeadm.conf path> | grep -v root:root

If the command returns any non root:root file permissions, this is a finding.''',
            'fix_text': 'Change the ownership of the kubeadm.conf to root: root by executing the command:\n\nchown root:root <kubeadm.conf path>',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242454',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "sh -c 'stat -c \"%U:%G\" /etc/systemd/system/kubelet.service.d/10-kubeadm.conf 2>/dev/null | grep -v root:root'",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Kubernetes kubeadm.conf must be owned by root.',
        })

    def test_infers_windows_user_right_exact_allowlist_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254418',
            'title': 'Windows Server 2022 Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and Enterprise Domain Controllers groups on domain controllers.',
            'check_content': '''This applies to domain controllers. It is NA for other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" right, this is a finding.

- Administrators
- Authenticated Users
- Enterprise Domain Controllers''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Access this computer from the network to include only the following accounts or groups:

- Administrators
- Authenticated Users
- Enterprise Domain Controllers''',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-254418',
            'platform': 'windows',
            'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeNetworkLogonRight'},
            'expected': {'type': 'equals', 'value': '*S-1-5-32-544,*S-1-5-11,*S-1-5-9'},
            'description': 'Windows Server 2022 Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and Enterprise Domain Controllers groups on domain controllers.',
        })

    def test_infers_defender_threat_severity_default_action_allowed_registry_values_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-213455',
            'title': 'Microsoft Defender AV must be configured for automatic remediation action to be taken for threat alert level Severe.',
            'check_content': '''Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction

Criteria: If the value "5" is REG_SZ = 2 (or 3), this is not a finding.''',
            'fix_text': '''Select the "Show…" option box and enter "5" in the "Value name" field and enter "2" in the "Value" field.''',
        }, 'MS_Defender_Antivirus')
        self.assertEqual(candidate, {
            'vuln_id': 'V-213455',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction',
                'value_name': '5',
            },
            'expected': {'type': 'matches', 'pattern': '^(?:2|3)$'},
            'description': 'Microsoft Defender AV must be configured for automatic remediation action to be taken for threat alert level Severe.',
        })

    def test_infers_chrome_download_restrictions_allowed_registry_values_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-221588',
            'title': 'Download restrictions must be configured.',
            'check_content': '''If the system is on the SIPRNet, this requirement is Not Applicable.

Universal method:
1. In the omnibox (address bar) type "chrome:// policy".
2. If "DownloadRestrictions" is not displayed under the "Policy Name" column or it is set to "0", this is a finding.

Windows method:
1. Start "regedit".
2. Navigate to "HKLM\\Software\\Policies\\Google\\Chrome\".
3. If the "DownloadRestrictions" value name does not exist or its value data is set to "0", this is a finding.''',
            'fix_text': '''Windows group policy:
1. Open the group policy editor tool with gpedit.msc.
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
Policy Name: Allow download restrictions
Policy State: 1, 2, or 4
Policy Value: N/A''',
        }, 'Google_Chrome_Current_Windows')
        self.assertEqual(candidate, {
            'vuln_id': 'V-221588',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\Software\\Policies\\Google\\Chrome',
                'value_name': 'DownloadRestrictions',
            },
            'expected': {'type': 'matches', 'pattern': '^(?:1|2|4)$'},
            'description': 'Download restrictions must be configured.',
        })

    def test_infers_chrome_default_cookies_setting_path_terminal_value_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-245539',
            'title': 'Session only based cookies must be enabled.',
            'check_content': '''Universal method:
1. In the omnibox (address bar), type chrome://policy
2. If the policy "DefaultCookiesSetting" is not shown or is not set to "4", this is a finding.

Windows method:
1. Start regedit.
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\DefaultCookiesSetting.
3. If this key does not exist, or is not set to "4", this is a finding.''',
            'fix_text': '''Windows group policy:
1. Open the group policy editor tool with gpedit.msc
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Content Settings.
- Policy Name: Default cookies setting
- Policy State: Enabled
- Policy Value: Keep cookies for the duration of the session''',
        }, 'Google_Chrome_Current_Windows')
        self.assertEqual(candidate, {
            'vuln_id': 'V-245539',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\Software\\Policies\\Google\\Chrome',
                'value_name': 'DefaultCookiesSetting',
            },
            'expected': {'type': 'equals', 'value': 4},
            'description': 'Session only based cookies must be enabled.',
        })

    def test_infers_office_registry_dword_primary_value_with_additional_acceptable_values_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223282',
            'title': 'VBA macros not digitally signed must be blocked in Access.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Access 2016 >> Application Settings >> Security >> Trust Center >> VBA Macro Notification Settings is set to "Disable all except digitally signed macros".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\Microsoft\\office\\16.0\\access\\security

If the value vbawarnings is REG_DWORD = 3, this is not a finding. A value of REG_DWORD = 2 or REG_DWORD =  4 is also acceptable. If the registry key does not exist, or is not configured properly, this is a finding.''',
            'fix_text': 'Set User Configuration >> Administrative Templates >> Microsoft Access 2016 >> Application Settings >> Security >> Trust Center >> VBA Macro Notification Settings to "Disable all except digitally signed macros".',
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-223282',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKCU\\software\\policies\\Microsoft\\office\\16.0\\access\\security',
                'value_name': 'vbawarnings',
            },
            'expected': {'type': 'matches', 'pattern': '^(?:2|3|4)$'},
            'description': 'VBA macros not digitally signed must be blocked in Access.',
        })

    def test_infers_office_registry_value_with_registry_phrase_without_editor_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223365',
            'title': 'When a custom action is executed that uses the Outlook object model, Outlook must automatically deny it.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Custom Form Security >> Set Outlook object model custom actions execution prompt is set to "Enabled" and "Automatically Deny".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for "promptoomcustomaction" is set to "REG_DWORD = 0", this is not a finding.''',
            'fix_text': 'Set the policy value to "Enabled" and "Automatically Deny".',
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-223365',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security',
                'value_name': 'promptoomcustomaction',
            },
            'expected': {'type': 'equals', 'value': 0},
            'description': 'When a custom action is executed that uses the Outlook object model, Outlook must automatically deny it.',
        })

    def test_infers_office_registry_value_absent_or_zero_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223401',
            'title': 'In Word, encrypted macros must be scanned.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> Scan encrypted macros in Word Open XML documents is set to "Enabled" "Scan encrypted macros (default)".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\word\\security

If the value WordBypassEncryptedMacroScan does not exist, this is not a finding. If the value is REG_DWORD = 0, this is not a finding.''',
            'fix_text': 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> Scan encrypted macros in Word Open XML documents to "Enabled" "Scan encrypted macros (default)".',
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-223401',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKCU\\software\\policies\\microsoft\\office\\16.0\\word\\security',
                'value_name': 'WordBypassEncryptedMacroScan',
            },
            'expected': {'type': 'equals', 'value': 0},
            'description': 'In Word, encrypted macros must be scanned.',
        })

    def test_infers_office_registry_value_zero_or_absent_reverse_order_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223340',
            'title': 'Files from Internet zone must be opened in Excel in Protected View mode.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Enable Protected View for files originating from the Internet is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\protectedview

If the value DisableInternetFilesInPV is REG_DWORD = 0, this is not a finding.
If the value does not exist, this is not a finding.
If the value is REG_DWORD = 1, this is a finding.''',
            'fix_text': 'Set the policy value to "Enabled".',
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-223340',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\protectedview',
                'value_name': 'DisableInternetFilesInPV',
            },
            'expected': {'type': 'equals', 'value': 0},
            'description': 'Files from Internet zone must be opened in Excel in Protected View mode.',
        })

    def test_infers_office_registry_single_dword_candidate_without_the_prefix(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223332',
            'title': 'File extensions must be enabled to match file types in Excel.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> File Block Settings >> Set default file block behavior is set to "Enabled" "Blocked files are not opened".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security

If value for extensionhardening is REG_DWORD = 2, this is not a finding.''',
            'fix_text': 'Set the policy value to "Enabled" "Blocked files are not opened".',
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-223332',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security',
                'value_name': 'extensionhardening',
            },
            'expected': {'type': 'equals', 'value': 2},
            'description': 'File extensions must be enabled to match file types in Excel.',
        })

    def test_infers_defender_registry_absent_or_zero_dword_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-213445',
            'title': 'Microsoft Defender AV must be configured to always enable real-time protection.',
            'check_content': '''Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Turn off real-time protection" is set to "Disabled" or "Not Configured".

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "DisableRealtimeMonitoring" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.''',
            'fix_text': 'Set the policy value to "Disabled" or "Not Configured".',
        }, 'MS_Defender_Antivirus')
        self.assertEqual(candidate, {
            'vuln_id': 'V-213445',
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection',
                'value_name': 'DisableRealtimeMonitoring',
            },
            'expected': {'type': 'equals', 'value': 0},
            'description': 'Microsoft Defender AV must be configured to always enable real-time protection.',
        })

    def test_infers_sql_server_sa_login_renamed_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-274445',
            'title': 'The SQL Server default account [sa] must have its name changed.',
            'check_content': '''Verify the SQL Server default [sa] (system administrator) account name has been changed by executing the following query:
USE master;
GO
SELECT *
FROM sys.sql_logins
WHERE [name] = 'sa' OR [principal_id] = 1;
GO

If the login account name "SA" or "sa" appears in the query output, this is a finding.''',
            'fix_text': 'Rename the SQL Server default [sa] account.',
        }, 'MS_SQL_Server_2022_Instance_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-274445',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': "sqlcmd -Q \"SET NOCOUNT ON; SELECT name FROM sys.sql_logins WHERE [name] = 'sa' OR [principal_id] = 1;\"",
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The SQL Server default account [sa] must have its name changed.',
        })

    def test_infers_windows_system32_telnet_absent_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-220721',
            'title': 'The Telnet Client must not be installed on the system.',
            'check_content': '''Verify the Telnet Client is not installed.

Navigate to the Windows\\System32 directory.

If the "telnet" application exists, this is a finding.''',
            'fix_text': 'Remove the Telnet Client from the system.',
        }, 'MS_Windows_10_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-220721',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': 'powershell -NoProfile -Command "Test-Path \\"$env:windir\\System32\\telnet.exe\\""',
            },
            'expected': {'type': 'equals', 'value': 'False'},
            'description': 'The Telnet Client must not be installed on the system.',
        })

    def test_infers_windows_system32_tftp_absent_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-220722',
            'title': 'The TFTP Client must not be installed on the system.',
            'check_content': '''Verify the TFTP Client is not installed.

Navigate to the Windows\\System32 directory.

If the "TFTP" application exists, this is a finding.''',
            'fix_text': 'Remove the TFTP Client from the system.',
        }, 'MS_Windows_10_STIG')
        self.assertEqual(candidate['check']['command'], 'powershell -NoProfile -Command "Test-Path \\"$env:windir\\System32\\tftp.exe\\""')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'False'})

    def test_infers_windows_system32_snmp_absent_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-253276',
            'title': 'Simple Network Management Protocol (SNMP) must not be installed on the system.',
            'check_content': '''Verify SNMP has not been installed.

Navigate to the Windows\\System32 directory.

If the "SNMP" application exists, this is a finding.''',
            'fix_text': 'Uninstall "Simple Network Management Protocol (SNMP)" from the system.',
        }, 'Microsoft_Windows_11_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-253276',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': 'powershell -NoProfile -Command "Test-Path \\"$env:windir\\System32\\snmp.exe\\""',
            },
            'expected': {'type': 'equals', 'value': 'False'},
            'description': 'Simple Network Management Protocol (SNMP) must not be installed on the system.',
        })

    def test_infers_oracle_linux_pam_pwquality_retry_upper_bound_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-252658',
            'title': 'OL 8 systems below version 8.4 must ensure the password complexity module in the system-auth file is configured for three retries or less.',
            'check_content': '''Note: This requirement applies to OL versions 8.0 through 8.3. If the system is OL version 8.4 or newer, this requirement is not applicable.

Verify the operating system is configured to limit the "pwquality" retry option to 3.

Check for the use of the "pwquality" retry option in the system-auth file with the following command:

     $ sudo cat /etc/pam.d/system-auth | grep pam_pwquality

     password requisite pam_pwquality.so retry=3

If the value of "retry" is set to "0" or greater than "3", this is a finding.''',
        }, 'Oracle_Linux_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-252658',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'cat /etc/pam.d/system-auth | grep pam_pwquality'},
            'expected': {'type': 'matches', 'pattern': r'^password\s+requisite\s+pam_pwquality\.so\b.*\bretry=[1-3]\b.*$'},
            'description': 'OL 8 systems below version 8.4 must ensure the password complexity module in the system-auth file is configured for three retries or less.',
        })

    def test_infers_oracle_linux_networkmanager_dns_mode_allowed_value_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271860',
            'title': 'OL 9 must configure a DNS processing mode set be Network Manager.',
            'check_content': '''Verify that OL 9 has a DNS mode configured in Network Manager.

$ NetworkManager --print-config
[main]
dns=none

If the DNS key under main does not exist or is not set to "none" or "default", this is a finding.''',
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-271860',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'NetworkManager --print-config | grep -E "^dns=(none|default)$"'},
            'expected': {'type': 'matches', 'pattern': r'^dns=(?:default|none)$'},
            'description': 'OL 9 must configure a DNS processing mode set be Network Manager.',
        })

    def test_infers_ubuntu_rsyslog_remote_access_methods_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270681',
            'title': 'Ubuntu 24.04 LTS must monitor remote access methods.',
            'check_content': '''Verify that Ubuntu 24.04 LTS monitors all remote access methods with the following command:

$  grep -E -r '^(auth,authpriv\\.\\*|daemon\\.\\*)' /etc/rsyslog.*
/etc/rsyslog.d/50-default.conf:auth,authpriv.* /var/log/auth.log
/etc/rsyslog.d/50-default.conf:daemon.* /var/log/messages

If "auth.*", "authpriv.*", or "daemon.*" are not configured to be logged in at least one of the config files, this is a finding.''',
            'fix_text': '''Configure rsyslog to log remote access methods by adding or updating:

auth,authpriv.* /var/log/auth.log
daemon.* /var/log/messages''',
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-270681',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': "sh -c 'grep -Ehr \"^(auth\\.\\*,authpriv\\.\\*|auth,authpriv\\.\\*|daemon\\.\\*)[[:space:]]+\" /etc/rsyslog.* /etc/rsyslog.d/* 2>/dev/null | awk '\"'\"'BEGIN{auth=0;daemon=0} /^[[:space:]]*#/ {next} /^(auth\\.\\*,authpriv\\.\\*|auth,authpriv\\.\\*)[[:space:]]+/ {auth=1} /^daemon\\.\\*[[:space:]]+/ {daemon=1} END{if(auth && daemon) print \"configured\"}'\"'\"''",
            },
            'expected': {'type': 'equals', 'value': 'configured'},
            'description': 'Ubuntu 24.04 LTS must monitor remote access methods.',
        })

    def test_infers_ubuntu_graphical_session_lock_multi_gsettings_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270678',
            'title': 'Ubuntu 24.04 LTS must initiate a graphical session lock after 10 minutes of inactivity.',
            'check_content': '''Note: If Ubuntu 24.04 LTS does not have a graphical user interface installed, this requirement is not applicable.

Verify the Ubuntu operation system has a graphical user interface session lock configured to activate after 10 minutes of inactivity with the following commands:

Set the following settings to verify the graphical user interface session is configured to lock the graphical user session after 10 minutes of inactivity:

**$ gsettings get org.gnome.desktop.screensaver lock-enabled
true

$ gsettings get org.gnome.desktop.screensaver lock-delay
uint32 0

$ gsettings get org.gnome.desktop.session idle-delay
uint32 600

Note: If "lock-enabled" is not set to "true", this is a finding.

If "lock-delay" is set to a value greater than "0", or if "idle-delay" is set to a value greater than "600", or either settings are missing, this is a finding.''',
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-270678',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'gsettings get org.gnome.desktop.screensaver lock-enabled && gsettings get org.gnome.desktop.screensaver lock-delay && gsettings get org.gnome.desktop.session idle-delay',
            },
            'expected': {'type': 'equals', 'value': 'true\nuint32 0\nuint32 600'},
            'description': 'Ubuntu 24.04 LTS must initiate a graphical session lock after 10 minutes of inactivity.',
        })

    def test_infers_rhel_networkmanager_dns_mode_allowed_value_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257949',
            'title': 'RHEL 9 must configure a DNS processing mode in Network Manager.',
            'check_content': '''Verify that RHEL 9 has a DNS mode configured in Network Manager.

$ NetworkManager --print-config
[main]
dns=none

If the dns key under main does not exist or is not set to "none" or "default", this is a finding.''',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-257949',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'NetworkManager --print-config | grep -E "^dns=(none|default)$"'},
            'expected': {'type': 'matches', 'pattern': r'^dns=(?:default|none)$'},
            'description': 'RHEL 9 must configure a DNS processing mode in Network Manager.',
        })

    def test_infers_sles_gsettings_logout_key_disabled_and_locked_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234989',
            'title': 'The SUSE operating system must disable the x86 Ctrl-Alt-Delete key sequence for Graphical User Interfaces.',
            'check_content': '''Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Verify the SUSE operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed in the graphical user interface.

Check that the dconf setting was disabled to allow the Ctrl-Alt-Delete sequence in the graphical user interface with the following command:

Check the default logout key sequence:

> sudo gsettings get org.gnome.settings-daemon.plugins.media-keys logout
''

Check that the value is not writable and cannot be changed by the user:

> sudo gsettings writable org.gnome.settings-daemon.plugins.media-keys logout
false

If the logout value is not [''] and the writable status is not false, this is a finding.''',
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-234989',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'gsettings get org.gnome.settings-daemon.plugins.media-keys logout && gsettings writable org.gnome.settings-daemon.plugins.media-keys logout',
            },
            'expected': {'type': 'equals', 'value': "''\nfalse"},
            'description': 'The SUSE operating system must disable the x86 Ctrl-Alt-Delete key sequence for Graphical User Interfaces.',
        })

    def test_infers_linux_gsettings_uint32_positive_maximum_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230352',
            'title': 'RHEL 8 must automatically lock graphical user sessions after 15 minutes of inactivity.',
            'check_content': '''Verify RHEL 8 initiates a session lock after a 15-minute period of inactivity for graphical user interfaces with the following command:

$ sudo gsettings get org.gnome.desktop.session idle-delay

uint32 900

If "idle-delay" is set to "0" or a value greater than "900", this is a finding.''',
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-230352',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'gsettings get org.gnome.desktop.session idle-delay'},
            'expected': {'type': 'matches', 'pattern': r'^uint32 (?:[1-9]|[1-9][0-9]|[1-8][0-9]{2}|900)$'},
            'description': 'RHEL 8 must automatically lock graphical user sessions after 15 minutes of inactivity.',
        })

    def test_infers_linux_gsettings_uint32_not_greater_than_maximum_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-244535',
            'title': 'RHEL 8 must initiate a session lock for graphical user interfaces when the screensaver is activated.',
            'check_content': '''Verify the operating system initiates a session lock a for graphical user interfaces when the screensaver is activated with the following command:

$ sudo gsettings get org.gnome.desktop.screensaver lock-delay

uint32 5

If the "uint32" setting is missing, or is not set to "5" or less, this is a finding.''',
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-244535',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'gsettings get org.gnome.desktop.screensaver lock-delay'},
            'expected': {'type': 'matches', 'pattern': r'^uint32 [1-5]$'},
            'description': 'RHEL 8 must initiate a session lock for graphical user interfaces when the screensaver is activated.',
        })

    def test_infers_linux_local_initialization_files_mode_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230325',
            'title': 'All RHEL 8 local initialization files must have mode 0740 or less permissive.',
            'check_content': '''Verify that all local initialization files have a mode of "0740" or less permissive with the following command:

$ sudo ls -al /home/smithj/.[^.]* | more

If any local initialization files have a mode more permissive than "0740", this is a finding.''',
            'fix_text': '''Set the mode of the local initialization files to "0740" with the following command:

$ sudo chmod 0740 /home/smithj/.<INIT_FILE>''',
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-230325',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': '''awk -F: '($3>=1000)&&($7 !~ /(nologin|false)$/){print $6}' /etc/passwd | while IFS= read -r home; do [ -d "$home" ] && find "$home" -maxdepth 1 -type f -name ".*" ! -name "." ! -name ".." -perm /037 -print; done''',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'All RHEL 8 local initialization files must have mode 0740 or less permissive.',
        })

    def test_infers_linux_audit_log_file_mode_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258167',
            'title': 'RHEL 9 audit logs file must have mode 0600 or less permissive to prevent unauthorized access to the audit log.',
            'check_content': '''Verify the audit logs have a mode of "0600".

Determine where the audit logs are stored with the following command:

$ sudo find /var/log/audit/ -type f -exec stat -c '%a %n' {} \\;

600 /var/log/audit/audit.log

Using the location of the audit log file, determine the mode of each audit log with the following command:

$ sudo find /var/log/audit/ -type f -exec stat -c '%a %n' {} \\;

600 /var/log/audit/audit.log

If the audit logs have a mode more permissive than "0600", this is a finding.''',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-258167',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /var/log/audit/ -type f -perm /7177 -exec stat -c "%a %n" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 9 audit logs file must have mode 0600 or less permissive to prevent unauthorized access to the audit log.',
        })

    def test_infers_linux_cron_directory_mode_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271827',
            'title': 'OL 9 cron configuration directories must have a mode of 0700 or less permissive.',
            'check_content': '''Verify that OL 9 configures permissions of the cron directories with the following command:

$ find /etc/cron* -type d | xargs stat -c "%a %n"
700 /etc/cron.d
700 /etc/cron.daily
700 /etc/cron.hourly
700 /etc/cron.monthly
700 /etc/cron.weekly

If any cron configuration directory is more permissive than "700", this is a finding.''',
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-271827',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/cron* -type d -perm /077 -exec stat -c "%a %n" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'OL 9 cron configuration directories must have a mode of 0700 or less permissive.',
        })

    def test_infers_ubuntu_audit_configuration_file_owner_group_mode_no_output_candidates(self):
        cases = [
            (
                'V-270776',
                'Ubuntu 24.04 LTS must permit only authorized accounts to own the audit configuration files.',
                'owned by "root" account',
                'If the /etc/audit/audit.rules, /etc/audit/rules.d/*, or /etc/audit/auditd.conf file is owned by a user other than "root", this is a finding.',
                'find /etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf -type f ! -user root -exec stat -c "%U %n" {} \\;',
            ),
            (
                'V-270777',
                'Ubuntu 24.04 LTS must permit only authorized groups to own the audit configuration files.',
                'owned by "root" group',
                'If the "/etc/audit/audit.rules", "/etc/audit/rules.d/*", or "/etc/audit/auditd.conf" file is owned by a group other than "root", this is a finding.',
                'find /etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf -type f ! -group root -exec stat -c "%G %n" {} \\;',
            ),
            (
                'V-270775',
                'Ubuntu 24.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users.',
                'have a mode of "0640" or less permissive',
                'If /etc/audit/audit.rule, /etc/audit/rules.d/*, or /etc/audit/auditd.conf files have a mode more permissive than "0640", this is a finding.',
                'find /etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf -type f -perm /0137 -exec stat -c "%a %n" {} \\;',
            ),
        ]
        for vuln_id, title, requirement, finding, expected_command in cases:
            with self.subTest(vuln_id=vuln_id):
                candidate = mod.infer_candidate_check({
                    'vuln_id': vuln_id,
                    'title': title,
                    'check_content': f'''Verify /etc/audit/audit.rules, /etc/audit/rules.d/*, and /etc/audit/auditd.conf files {requirement} with the following command:

$ sudo ls -al /etc/audit/ /etc/audit/rules.d/
/etc/audit/:
-rw-r-----   1 root root   804 Nov 25 11:01 auditd.conf
-rw-r-----   1 root root  9128 Dec 27 09:56 audit.rules
-rw-r-----   1 root root   127 Feb  7  2018 audit-stop.rules
drwxr-x---   2 root root  4096 Dec 27 09:56 rules.d

/etc/audit/rules.d/:
-rw-r----- 1 root root 244 Dec 27 09:56 audit.rules
-rw-r----- 1 root root 10357 Dec 27 09:56 stig.rules

{finding}'''
                }, 'CAN_Ubuntu_24-04_STIG')
                self.assertEqual(candidate['check'], {'type': 'command_output', 'command': expected_command})
                self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_linux_audit_rules_file_mode_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258171',
            'title': 'RHEL 9 audit rule configuration files must have mode 0640 or less permissive.',
            'check_content': '''Verify that the files in directory "/etc/audit/rules.d/" and "/etc/audit/auditd.conf" file have a mode of "0640" or less permissive with the following command:

$ sudo find /etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf -type f -exec stat -c "%a %n" {} \\;

600 /etc/audit/rules.d/audit.rules
640 /etc/audit/audit.rules
640 /etc/audit/auditd.conf''',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-258171',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf -type f -perm /0137 -exec stat -c "%a %n" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 9 audit rule configuration files must have mode 0640 or less permissive.',
        })

    def test_classifies_policy_language_as_manual_evidence_workflow(self):
        classification, collector = mod.classify_rule('The organization must document an approval process.')
        self.assertEqual(classification, 'manual')
        self.assertEqual(collector, 'manual_evidence_workflow')

    def test_infers_vcenter_lookup_service_grep_expected_property_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259046',
            'title': 'The vCenter Lookup service must be configured to fail to a known safe state if system initialization fails.',
            'check_content': '''At the command line, run the following command:

# grep EXIT_ON_INIT_FAILURE /usr/lib/vmware-lookupsvc/conf/catalina.properties

Example result:

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

If there are no results, or if the "org.apache.catalina.startup.EXIT_ON_INIT_FAILURE" is not set to "true", this is a finding.''',
        }, 'VMW_vSphere_8-0_VCSA_Lookup_Svc_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-259046',
            'platform': 'generic',
            'check': {
                'type': 'file_content',
                'path': '/usr/lib/vmware-lookupsvc/conf/catalina.properties',
                'pattern': 'org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true',
                'is_regex': False,
            },
            'expected': {'type': 'contains'},
            'description': 'The vCenter Lookup service must be configured to fail to a known safe state if system initialization fails.',
        })

    def test_infers_vcenter_lookup_service_absent_or_expected_property_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259067',
            'title': 'The vCenter Lookup service must disable "ALLOW_BACKSLASH".',
            'check_content': '''At the command line, run the following command:

# grep ALLOW_BACKSLASH /usr/lib/vmware-lookupsvc/conf/catalina.properties

Example result:

org.apache.catalina.connector.ALLOW_BACKSLASH=false

If the "org.apache.catalina.connector.ALLOW_BACKSLASH" setting does not exist, this is not a finding.

If the "org.apache.catalina.connector.ALLOW_BACKSLASH" is not set to "false", this is a finding.''',
        }, 'VMW_vSphere_8-0_VCSA_Lookup_Svc_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-259067',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': "sh -c \"grep '^org.apache.catalina.connector.ALLOW_BACKSLASH=' /usr/lib/vmware-lookupsvc/conf/catalina.properties || true\"",
            },
            'expected': {
                'type': 'matches',
                'pattern': r'^(?:|org\.apache\.catalina\.connector\.ALLOW_BACKSLASH=false)$',
            },
            'description': 'The vCenter Lookup service must disable "ALLOW_BACKSLASH".',
        })

    def test_infers_postgresql_shared_preload_libraries_pgaudit_contains_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233600',
            'title': 'PostgreSQL must provide the means for individuals in authorized roles to change the auditing to be performed on all application components, based on all selectable event criteria within organization-defined time thresholds.',
            'check_content': '''First, as the database administrator, check if pgaudit is present in shared_preload_libraries:

$ sudo su - postgres
$ psql -c "SHOW shared_preload_libraries"

If pgaudit is not present in the result from the query, this is a finding.''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-233600',
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -c "SHOW shared_preload_libraries"'},
            'expected': {'type': 'contains', 'substring': 'pgaudit'},
            'description': 'PostgreSQL must provide the means for individuals in authorized roles to change the auditing to be performed on all application components, based on all selectable event criteria within organization-defined time thresholds.',
        })

    def test_infers_postgresql_shared_preload_libraries_pgaudit_output_contains_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233568',
            'title': 'PostgreSQL must generate audit records when privileges/permissions are deleted.',
            'check_content': '''First, as the database administrator, verify pgaudit is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW shared_preload_libraries"

If the output does not contain pgaudit, this is a finding.''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-233568',
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -c "SHOW shared_preload_libraries"'},
            'expected': {'type': 'contains', 'substring': 'pgaudit'},
            'description': 'PostgreSQL must generate audit records when privileges/permissions are deleted.',
        })

    def test_infers_postgresql_shared_preload_libraries_pgaudit_quoted_output_contains_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233557',
            'title': 'PostgreSQL must generate audit records when unsuccessful attempts to delete categorized information occur.',
            'check_content': '''First, as the database administrator, verify pgaudit is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW shared_preload_libraries"

If the output does not contain "pgaudit", this is a finding.''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-233557',
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -c "SHOW shared_preload_libraries"'},
            'expected': {'type': 'contains', 'substring': 'pgaudit'},
            'description': 'PostgreSQL must generate audit records when unsuccessful attempts to delete categorized information occur.',
        })

    def test_infers_postgresql_client_min_messages_error_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233516',
            'title': 'PostgreSQL must provide non-privileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.',
            'check_content': '''As the database administrator, run the following SQL:

SELECT current_setting('client_min_messages');

If client_min_messages is not set to error, this is a finding.''',
            'fix_text': '''Change the client_min_messages parameter to be "error":

client_min_messages = error''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': "psql -tAc \"SELECT current_setting('client_min_messages');\""})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'error'})

    def test_infers_postgresql_show_ssl_on_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233611',
            'title': 'PostgreSQL must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.',
            'check_content': '''To check if PostgreSQL is configured to use ssl, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW ssl"

If this is not set to on, this is a finding.''',
            'fix_text': '''To configure PostgreSQL to use SSL, as a database owner (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi $PGDATA/postgresql.conf

Change the following setting:

ssl = on''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'psql -c "SHOW ssl"'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'on'})

    def test_infers_postgresql_pgaudit_log_literal_contains_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233551',
            'title': 'PostgreSQL must generate audit records when categorized information (e.g., classification levels/security levels) is accessed.',
            'check_content': '''As the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW pgaudit.log"

If pgaudit.log does not contain, "ddl, write, role", this is a finding.''',
            'fix_text': '''With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'ddl, write, role'

Next, as the system administrator, reload the server with the new configuration.''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-233551',
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -c "SHOW pgaudit.log"'},
            'expected': {'type': 'contains', 'substring': 'ddl, write, role'},
            'description': 'PostgreSQL must generate audit records when categorized information (e.g., classification levels/security levels) is accessed.',
        })

    def test_infers_postgresql_log_file_mode_literal_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233531',
            'title': 'The audit information produced by PostgreSQL must be protected from unauthorized deletion.',
            'check_content': '''As the database administrator, run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_file_mode"

If the permissions are not 0600, this is a finding.''',
            'fix_text': '''Configure PostgreSQL to protect audit logs from unauthorized deletion:

log_file_mode = 0600''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-233531',
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -c "SHOW log_file_mode"'},
            'expected': {'type': 'contains', 'substring': '0600'},
            'description': 'The audit information produced by PostgreSQL must be protected from unauthorized deletion.',
        })

    def test_infers_postgresql_log_connections_on_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233558',
            'title': 'PostgreSQL must generate audit records when successful logons or connections occur.',
            'check_content': '''As the database administrator, run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_connections"

If log_connections is off, this is a finding.''',
            'fix_text': '''Configure PostgreSQL to log connections:

log_connections = on''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'psql -c "SHOW log_connections"'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'on'})

    def test_infers_postgresql_password_encryption_scram_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233596',
            'title': 'If passwords are used for authentication, PostgreSQL must store only hashed, salted representations of passwords.',
            'check_content': '''As the database administrator, run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW password_encryption"

If password_encryption is not "scram-sha-256", this is a finding.''',
            'fix_text': '''Configure PostgreSQL to use SCRAM password encryption:

password_encryption = 'scram-sha-256' ''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'psql -c "SHOW password_encryption"'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'scram-sha-256'})

    def test_does_not_infer_postgresql_show_literal_without_fix_confirmation(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-999999',
            'title': 'PostgreSQL example.',
            'check_content': '''$ psql -c "SHOW log_connections"

If log_connections is off, this is a finding.''',
            'fix_text': 'Review the site configuration and configure it as required.',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertIsNone(candidate)

    def test_infers_linux_snmp_default_community_strings_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-204627',
            'title': 'SNMP community strings on the Red Hat Enterprise Linux operating system must be changed from the default.',
            'check_content': '''Verify that a system using SNMP is not using default community strings.

Check to see if the "/etc/snmp/snmpd.conf" file exists with the following command:

# ls -al /etc/snmp/snmpd.conf
-rw-------   1 root root      52640 Mar 12 11:08 snmpd.conf

If the file does not exist, this is Not Applicable.

If the file does exist, check for the default community strings with the following commands:

# grep public /etc/snmp/snmpd.conf
# grep private /etc/snmp/snmpd.conf

If either of these commands returns any output, this is a finding.''',
        }, 'RHEL_7_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-204627',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "grep -E 'public|private' /etc/snmp/snmpd.conf"},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'SNMP community strings on the Red Hat Enterprise Linux operating system must be changed from the default.',
        })

    def test_infers_linux_keytab_listing_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230238',
            'title': 'RHEL 8 must prevent system daemons from using Kerberos for authentication.',
            'check_content': '''Verify that RHEL 8 prevents system daemons from using Kerberos for authentication.

If the system is a server utilizing krb5-server-1.17-18.el8.x86_64 or newer, this requirement is not applicable.
If the system is a workstation utilizing krb5-workstation-1.17-18.el8.x86_64 or newer, this requirement is not applicable.

Check if there are available keytabs with the following command:

$ sudo ls -al /etc/*.keytab

If this command produces any file(s), this is a finding.''',
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-230238',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'ls -al /etc/*.keytab'},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 8 must prevent system daemons from using Kerberos for authentication.',
        })

    def test_infers_rhel7_dconf_automount_literal_files_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-219059',
            'title': 'The Red Hat Enterprise Linux operating system must disable the graphical user interface automounter unless required.',
            'check_content': '''Note: If the operating system does not have a graphical user interface installed, this requirement is Not Applicable.

Verify the operating system disables the ability to automount devices in a graphical user interface.

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

Check to see if automounter service is disabled with the following commands:
# cat /etc/dconf/db/local.d/00-No-Automount

[org/gnome/desktop/media-handling]

automount=false

automount-open=false

autorun-never=true

If the output does not match the example above, this is a finding.

# cat /etc/dconf/db/local.d/locks/00-No-Automount

/org/gnome/desktop/media-handling/automount

/org/gnome/desktop/media-handling/automount-open

/org/gnome/desktop/media-handling/autorun-never

If the output does not match the example, this is a finding.''',
        }, 'RHEL_7_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-219059',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'cat /etc/dconf/db/local.d/00-No-Automount && cat /etc/dconf/db/local.d/locks/00-No-Automount',
            },
            'expected': {
                'type': 'contains',
                'substring': '[org/gnome/desktop/media-handling]\nautomount=false\nautomount-open=false\nautorun-never=true\n/org/gnome/desktop/media-handling/automount\n/org/gnome/desktop/media-handling/automount-open\n/org/gnome/desktop/media-handling/autorun-never',
            },
            'description': 'The Red Hat Enterprise Linux operating system must disable the graphical user interface automounter unless required.',
        })

    def test_infers_linux_sshd_x11_forwarding_no_literal_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270708',
            'title': 'Ubuntu 24.04 LTS must be configured so that remote X connections are disabled.',
            'check_content': '''Verify that X11Forwarding is disabled with the following command:

$ sudo grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v "^#"
X11Forwarding no

If the "X11Forwarding" keyword is set to "yes" and is not documented with the information system security officer (ISSO) as an operational requirement, is missing, or multiple conflicting results are returned, this is a finding.''',
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-270708',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v "^#"'},
            'expected': {'type': 'equals', 'value': 'X11Forwarding no'},
            'description': 'Ubuntu 24.04 LTS must be configured so that remote X connections are disabled.',
        })

    def test_infers_ubuntu_sshd_macs_exact_literal_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270668',
            'title': 'Ubuntu 24.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3 approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.',
            'check_content': '''Verify the SSH daemon is configured to only use MACs that employ FIPS 140-3 approved ciphers with the following command:

$ grep -irs macs /etc/ssh/sshd_config*
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

If any algorithms other than "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" are listed, the returned line is commented out, or if conflicting results are returned, this is a finding.''',
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-270668',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'grep -irs macs /etc/ssh/sshd_config*'},
            'expected': {'type': 'equals', 'value': 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256'},
            'description': 'Ubuntu 24.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3 approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.',
        })

    def test_infers_linux_find_named_file_found_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248597',
            'title': 'There must be no "shosts.equiv" files on the OL 8 operating system.',
            'check_content': '''Verify there are no "shosts.equiv" files on OL 8 with the following command:

$ sudo find / -name shosts.equiv

If an "shosts.equiv" file is found, this is a finding.''',
        }, 'Oracle_Linux_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-248597',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'find / -name shosts.equiv'},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'There must be no "shosts.equiv" files on the OL 8 operating system.',
        })

    def test_infers_linux_update_crypto_policies_check_literal_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258236',
            'title': 'RHEL 9 cryptographic policy must not be overridden.',
            'check_content': '''Verify that RHEL 9 cryptographic policies are not overridden.

Verify that the configured policy matches the generated policy with the following command:

$ sudo update-crypto-policies --check
The configured policy matches the generated policy

If the returned message does not match the above, but instead matches the following, this is a finding:
The configured policy does NOT match the generated policy''',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-258236',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'update-crypto-policies --check'},
            'expected': {'type': 'equals', 'value': 'The configured policy matches the generated policy'},
            'description': 'RHEL 9 cryptographic policy must not be overridden.',
        })

    def test_infers_linux_krb5_crypto_policy_symlink_contains_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258237',
            'title': 'RHEL 9 must use mechanisms meeting the requirements of applicable federal laws, executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.',
            'check_content': '''Verify that the symlink exists and targets the correct Kerberos cryptographic policy with the following command:

$ file /etc/crypto-policies/back-ends/krb5.config

If command output shows the following line, Kerberos is configured to use the systemwide crypto policy:

/etc/crypto-policies/back-ends/krb5.config: symbolic link to /usr/share/crypto-policies/FIPS/krb5.txt

If the symlink does not exist or points to a different target, this is a finding.''',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-258237',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'file /etc/crypto-policies/back-ends/krb5.config'},
            'expected': {
                'type': 'contains',
                'substring': '/etc/crypto-policies/back-ends/krb5.config: symbolic link to /usr/share/crypto-policies/FIPS/krb5.txt',
            },
            'description': 'RHEL 9 must use mechanisms meeting the requirements of applicable federal laws, executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.',
        })

    def test_infers_oracle_linux_krb5_crypto_policy_symlink_without_intro_phrase(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271762',
            'title': 'OL 9 must use mechanisms meeting the requirements of applicable federal laws, executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.',
            'check_content': '''Verify that OL 9 configures Kerberos to use the systemwide crypto policy with the following command:

$ file /etc/crypto-policies/back-ends/krb5.config
/etc/crypto-policies/back-ends/krb5.config: symbolic link to  /usr/share/crypto-policies/FIPS/krb5.txt

If the symlink does not exist or points to a different target, this is a finding.''',
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-271762',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'file /etc/crypto-policies/back-ends/krb5.config'},
            'expected': {
                'type': 'contains',
                'substring': '/etc/crypto-policies/back-ends/krb5.config: symbolic link to /usr/share/crypto-policies/FIPS/krb5.txt',
            },
            'description': 'OL 9 must use mechanisms meeting the requirements of applicable federal laws, executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.',
        })

    def test_infers_linux_getsebool_literal_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-250313',
            'title': 'The Red Hat Enterprise Linux operating system must not allow privileged accounts to utilize SSH.',
            'check_content': '''Verify the operating system prevents privileged accounts from utilizing SSH. Check the SELinux ssh_sysadm_login boolean with the following command:

$ sudo getsebool ssh_sysadm_login
ssh_sysadm_login --> off

If the "ssh_sysadm_login" boolean is not "off" and is not documented with the ISSO as an operational requirement, this is a finding.''',
        }, 'RHEL_7_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-250313',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'getsebool ssh_sysadm_login'},
            'expected': {'type': 'equals', 'value': 'ssh_sysadm_login --> off'},
            'description': 'The Red Hat Enterprise Linux operating system must not allow privileged accounts to utilize SSH.',
        })

    def test_infers_linux_cron_stat_group_root_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257927',
            'title': 'RHEL 9 cron configuration files directory must be group-owned by root.',
            'check_content': '''Verify the group ownership of all cron configuration files with the following command:

$ stat -c "%G %n" /etc/cron*
root /etc/cron.d
root /etc/cron.daily
root /etc/cron.deny
root /etc/cron.hourly
root /etc/cron.monthly
root /etc/crontab
root /etc/cron.weekly

If any crontab is not group owned by root, this is a finding.''',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-257927',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/cron* ! -group root -exec stat -c "%G %n" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'RHEL 9 cron configuration files directory must be group-owned by root.',
        })

    def test_infers_kubernetes_multiple_root_owned_conf_stat_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242446',
            'title': 'The Kubernetes conf files must be owned by root.',
            'check_content': '''Review the Kubernetes conf files by using the command:

stat -c %U:%G /etc/kubernetes/admin.conf | grep -v root:root
stat -c %U:%G /etc/kubernetes/scheduler.conf | grep -v root:root
stat -c %U:%G /etc/kubernetes/controller-manager.conf | grep -v root:root

If the command returns any non root:root file permissions, this is a finding.''',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242446',
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'stat -c %U:%G /etc/kubernetes/admin.conf /etc/kubernetes/scheduler.conf /etc/kubernetes/controller-manager.conf | grep -v root:root'},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Kubernetes conf files must be owned by root.',
        })

    def test_infers_kubernetes_multiple_fixed_kubeconfig_mode_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242460',
            'title': 'The Kubernetes admin kubeconfig must have file permissions set to 644 or more restrictive.',
            'check_content': '''Review the permissions of the Kubernetes config files by using the command:

stat -c %a /etc/kubernetes/admin.conf
stat -c %a /etc/kubernetes/scheduler.conf
stat -c %a /etc/kubernetes/controller-manager.conf

If any of the files are have permissions more permissive than "644", this is a finding.''',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242460',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/kubernetes/admin.conf /etc/kubernetes/scheduler.conf /etc/kubernetes/controller-manager.conf -perm /133 -exec stat -c "%a %n" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Kubernetes admin kubeconfig must have file permissions set to 644 or more restrictive.',
        })

    def test_infers_kubernetes_kubelet_config_fixed_mode_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242456',
            'title': 'The Kubernetes kubelet config must have file permissions set to 644 or more restrictive.',
            'check_content': '''Review the permissions of the Kubernetes config.yaml by using the command:

stat -c %a /var/lib/kubelet/config.yaml

If any of the files are have permissions more permissive than "644", this is a finding.''',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242456',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'find /var/lib/kubelet/config.yaml -perm /133 -exec stat -c "%a %n" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Kubernetes kubelet config must have file permissions set to 644 or more restrictive.',
        })

    def test_infers_kubernetes_pki_key_mode_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242467',
            'title': 'The Kubernetes PKI keys must have file permissions set to 600 or more restrictive.',
            'check_content': '''Review the permissions of the Kubernetes PKI key files by using the command:

sudo find /etc/kubernetes/pki -name "*.key" | xargs stat -c '%n %a'

If any of the files have permissions more permissive than "600", this is a finding.''',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242467',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/kubernetes/pki -name "*.key" -perm /177 -exec stat -c "%n %a" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Kubernetes PKI keys must have file permissions set to 600 or more restrictive.',
        })

    def test_infers_linux_yum_repo_gpgcheck_all_returned_lines_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271525',
            'title': 'OL 9 must have GPG signature verification enabled for all software repositories.',
            'check_content': '''Verify that OL 9 software repositories defined in "/etc/yum.repos.d/" have been configured with "gpgcheck" enabled:

$ grep gpgcheck /etc/yum.repos.d/*.repo | more
gpgcheck = 1

If "gpgcheck" is not set to "1" for all returned lines, this is a finding.''',
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-271525',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "grep gpgcheck /etc/yum.repos.d/*.repo | grep -v -E '^gpgcheck\\s*=\\s*1$'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'OL 9 must have GPG signature verification enabled for all software repositories.',
        })

    def test_infers_linux_apt_allowunauthenticated_true_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-238359',
            'title': 'The Ubuntu operating system\'s Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.',
            'check_content': '''Verify that APT is configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.

Check that the "AllowUnauthenticated" variable is not set at all or is set to "false" with the following command:

$ grep AllowUnauthenticated /etc/apt/apt.conf.d/*
/etc/apt/apt.conf.d/01-vendor-Ubuntu:APT::Get::AllowUnauthenticated "false";

If any of the files returned from the command with "AllowUnauthenticated" are set to "true", this is a finding.''',
        }, 'Canonical_Ubuntu_20-04_LTS_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-238359',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "grep AllowUnauthenticated /etc/apt/apt.conf.d/* | grep -i 'true'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Ubuntu operating system\'s Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.',
        })

    def test_infers_linux_nmcli_device_wireless_disabled_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-204634',
            'title': 'The Red Hat Enterprise Linux operating system must be configured so that all wireless network adapters are disabled.',
            'check_content': '''Verify that there are no wireless interfaces configured on the system.

This is N/A for systems that do not have wireless network adapters.

Check for the presence of active wireless interfaces with the following command:

# nmcli device
DEVICE TYPE STATE
eth0 ethernet connected
wlp3s0 wifi disconnected
lo loopback unmanaged

If a wireless interface is configured and its use on the system is not documented with the Information System Security Officer (ISSO), this is a finding.''',
        }, 'RHEL_7_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-204634',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "nmcli -t -f TYPE device status | grep -Fx 'wifi'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Red Hat Enterprise Linux operating system must be configured so that all wireless network adapters are disabled.',
        })

    def test_infers_oracle_linux_nmcli_allows_no_wireless_interfaces_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271859',
            'title': 'OL 9 wireless network adapters must be disabled.',
            'check_content': '''Note: For systems that do not have physical wireless network radios, this requirement is Not Applicable.

Verify that OL 9 allows no wireless interfaces to be configured on the system with the following command:

$ nmcli device status
DEVICE           TYPE       STATE         CONNECTION
virbr0           bridge     connected     virbr0
wlp7s0           wifi       connected     wifiSSID
enp6s0           ethernet   disconnected  --
p2p-dev-wlp7s0   wifi-p2p   disconnected  --
lo               loopback   unmanaged     --
virbr0-nic       tun        unmanaged     --

If a wireless interface is configured and has not been documented and approved by the information system security officer (ISSO), this is a finding.''',
            'fix_text': '''Configure the system to disable all wireless network interfaces with the following command:

$ sudo nmcli radio all off''',
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-271859',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "nmcli -t -f TYPE device status | grep -Fx 'wifi'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'OL 9 wireless network adapters must be disabled.',
        })

    def test_infers_linux_sysfs_wireless_interface_absent_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-252704',
            'title': 'The Ubuntu operating system must disable all wireless network adapters.',
            'check_content': '''Note: This requirement is Not Applicable for systems that do not have physical wireless network radios.

Verify that there are no wireless interfaces configured on the system with the following command:

$ ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename

If a wireless interface is configured and has not been documented and approved by the ISSO, this is a finding.''',
        }, 'Canonical_Ubuntu_20-04_LTS_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-252704',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename'},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Ubuntu operating system must disable all wireless network adapters.',
        })

    def test_infers_linux_timedatectl_timezone_utc_or_gmt_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-238308',
            'title': 'The Ubuntu operating system must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).',
            'check_content': '''Verify the operating system is configured to record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT) with the following command:

$ timedatectl status | grep -i "time zone"
                Time zone: Etc/UTC (UTC, +0000)

If "Timezone" is not set to UTC or GMT, this is a finding.''',
        }, 'Canonical_Ubuntu_20-04_LTS_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-238308',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'timedatectl status | grep -i "time zone" | grep -E "UTC|GMT"'},
            'expected': {'type': 'not_equals', 'value': ''},
            'description': 'The Ubuntu operating system must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).',
        })

    def test_infers_rpm_xorg_server_absent_unless_approved_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230553',
            'title': 'The graphical display manager must not be installed on RHEL 8 unless approved.',
            'check_content': '''Verify that a graphical user interface is not installed:

$ rpm -qa | grep xorg | grep server

Ask the System Administrator if use of a graphical user interface is an operational requirement.

If the use of a graphical user interface on the system is not documented with the ISSO, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'rpm -qa | grep xorg | grep server'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_oracle_linux_rpm_xorg_server_absent_unless_documented_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248898',
            'title': 'The graphical display manager must not be installed on OL 8 unless approved.',
            'check_content': '''Verify that if the system has a display server installed, it is authorized.

Check for the display server package with the following example command:

$ sudo rpm -qa | grep xorg | grep server

Ask the System Administrator if use of the display server is an operational requirement.

If the use of a display server on the system is not documented with the Information System Security Officer (ISSO), this is a finding.'''
        }, 'Oracle_Linux_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'rpm -qa | grep xorg | grep server'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_linux_service_running_candidate_when_systemctl_is_active_returns_inactive_without_sample(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-238355',
            'title': 'The Ubuntu operating system must enable and run the uncomplicated firewall(ufw).',
            'check_content': '''Verify the Uncomplicated Firewall is enabled on the system by running the following command:

$ systemctl is-enabled ufw

If the above command returns the status as "disabled", this is a finding.

Verify the Uncomplicated Firewall is active on the system by running the following command:

$ systemctl is-active ufw

If the above command returns "inactive" or any kind of error, this is a finding.

If the Uncomplicated Firewall is not installed, ask the System Administrator if another application firewall is installed.

If no application firewall is installed, this is a finding.'''
        }, 'Canonical_Ubuntu_20-04_LTS_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-238355',
            'platform': 'linux',
            'check': {'type': 'service', 'name': 'ufw', 'expected_status': 'running'},
            'expected': {'type': 'equals', 'value': 'running'},
            'description': 'The Ubuntu operating system must enable and run the uncomplicated firewall(ufw).',
        })

    def test_infers_socket_is_active_command_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258125',
            'title': 'The pcscd service on RHEL 9 must be active.',
            'check_content': '''Verify that the "pcscd" socket is active with the following command:

$ systemctl is-active pcscd.socket

active

If the pcscd socket is not active, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'systemctl is-active pcscd.socket'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'active'})

    def test_infers_esxi_active_directory_authentication_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-256402',
            'title': 'The ESXi host must use Active Directory for local user authentication.',
            'check_content': '''For systems that do not use Active Directory and have no local user accounts other than root and/or service accounts, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Authentication Services.

Verify the "Directory Services Type" is set to "Active Directory".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-VMHostAuthentication

For systems that do not use Active Directory and do have local user accounts, other than root and/or service accounts, this is a finding.

If the Directory Services Type is not set to "Active Directory", this is a finding.'''
        }, 'VMW_vSphere_7-0_ESXi_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-256402',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'Get-VMHost | Get-VMHostAuthentication',
            },
            'expected': {'type': 'contains', 'substring': 'Active Directory'},
            'description': 'The ESXi host must use Active Directory for local user authentication.',
        })

    def test_infers_esxi_disabled_vmhost_service_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-256448',
            'title': 'The ESXi Common Information Model (CIM) service must be disabled.',
            'check_content': '''From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Locate the "CIM Server" service and verify the "Daemon" is "Stopped" and the "Startup Policy" is set to "Start and stop manually".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"}

If the "CIM Server" service does not have a "Policy" of "off" or is running, this is a finding.''',
            'fix_text': '''From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"} | Set-VMHostService -Policy Off
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"} | Stop-VMHostService'''
        }, 'VMW_vSphere_7-0_ESXi_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-256448',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'Get-VMHost | Get-VMHostService | Where-Object {$_.Label -eq "CIM Server"} | ForEach-Object { "$($_.Policy)`n$($_.Running)" }',
            },
            'expected': {'type': 'equals', 'value': 'off\nFalse'},
            'description': 'The ESXi Common Information Model (CIM) service must be disabled.',
        })

    def test_infers_esxi_disabled_vmhost_service_candidate_without_quoted_finding_label(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-256435',
            'title': 'The ESXi host OpenSLP service must be disabled.',
            'check_content': '''From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"}

If the slpd service does not have a "Policy" of "off" or is running, this is a finding.''',
            'fix_text': '''Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"} | Set-VMHostService -Policy Off
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"} | Stop-VMHostService'''
        }, 'VMW_vSphere_7-0_ESXi_STIG')
        self.assertEqual(candidate['vuln_id'], 'V-256435')
        self.assertEqual(candidate['check']['command'], 'Get-VMHost | Get-VMHostService | Where-Object {$_.Label -eq "slpd"} | ForEach-Object { "$($_.Policy)`n$($_.Running)" }')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'off\nFalse'})

    def test_infers_esxi_syslog_persistent_log_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-256408',
            'title': 'The ESXi host must enable a persistent log location for all locally stored logs.',
            'check_content': '''From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Syslog.global.logDir" value and verify it is set to a persistent location.

If the value of the setting is "[] /scratch/logs", verify the advanced setting "ScratchConfig.CurrentScratchLocation" is not set to "/tmp/scratch". This is a nonpersistent location.

If "Syslog.global.logDir" is not configured to a persistent location, this is a finding.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.syslog.config.get.Invoke() | Select LocalLogOutput,LocalLogOutputIsPersistent

If the "LocalLogOutputIsPersistent" value is not true, this is a finding.'''
        }, 'VMW_vSphere_7-0_ESXi_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-256408',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': '$esxcli = Get-EsxCli -v2; $esxcli.system.syslog.config.get.Invoke() | Select-Object -ExpandProperty LocalLogOutputIsPersistent',
            },
            'expected': {'type': 'equals', 'value': 'true'},
            'description': 'The ESXi host must enable a persistent log location for all locally stored logs.',
        })

    def test_infers_esxi_advanced_setting_exact_value_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-256379',
            'title': 'The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user.',
            'check_content': '''From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Security.AccountLockFailures" value and verify it is set to "3".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures

If the "Security.AccountLockFailures" setting is set to a value other than "3", this is a finding.'''
        }, 'VMW_vSphere_7-0_ESXi_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-256379',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Select-Object -ExpandProperty Value',
            },
            'expected': {'type': 'equals', 'value': '3'},
            'description': 'The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user.',
        })

    def test_infers_esxi_advanced_setting_not_equals_bad_value_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-256404',
            'title': 'Active Directory ESX Admin group membership must not be used when adding ESXi hosts to Active Directory.',
            'check_content': '''For systems that do not use Active Directory, this is not applicable.

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup

If the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" key is set to "ESX Admins", this is a finding.'''
        }, 'VMW_vSphere_7-0_ESXi_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-256404',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Select-Object -ExpandProperty Value',
            },
            'expected': {'type': 'not_equals', 'value': 'ESX Admins'},
            'description': 'Active Directory ESX Admin group membership must not be used when adding ESXi hosts to Active Directory.',
        })

    def test_infers_systemctl_status_socket_masked_command_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230312',
            'title': 'RHEL 8 must disable acquiring, saving, and processing core dumps.',
            'check_content': '''Verify RHEL 8 is not configured to acquire, save, or process core dumps with the following command:

$ sudo systemctl status systemd-coredump.socket
systemd-coredump.socket
Loaded: masked (Reason: Unit systemd-coredump.socket is masked.)
Active: inactive (dead)

If the "systemd-coredump.socket" is loaded and not masked and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'systemctl status systemd-coredump.socket'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'Loaded: masked'})

    def test_infers_tomcat_find_not_owner_or_group_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-222986',
            'title': '$CATALINA_HOME folder must be owned by the root user, group tomcat.',
            'check_content': '''Access the Tomcat server from the command line and execute the following OS command:

sudo find $CATALINA_HOME -follow -maxdepth 0 \\(  ! -user root -o ! -group tomcat \\) -ls

If no folders are displayed, this is not a finding.

If results indicate the $CATALINA_HOME folder ownership and group membership is not set to root:tomcat, this is a finding.'''
        }, 'Tomcat_Application_Server_9_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'find $CATALINA_HOME -follow -maxdepth 0 \\( ! -user root -o ! -group tomcat \\) -ls',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_tomcat_systemd_boolean_property_literal_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223003',
            'title': 'RECYCLE_FACADES must be set to true.',
            'check_content': '''From the Tomcat server as a privileged user, run the following command:

sudo grep -i  recycle_facades /etc/systemd/system/tomcat.service

If there are no results, or if the org.apache.catalina.connector.RECYCLE_FACADES is not ="true", this is a finding.'''
        }, 'Tomcat_Application_Server_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-223003',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'grep -i recycle_facades /etc/systemd/system/tomcat.service',
            },
            'expected': {
                'type': 'contains',
                'substring': 'org.apache.catalina.connector.RECYCLE_FACADES=true',
            },
            'description': 'RECYCLE_FACADES must be set to true.',
        })

    def test_infers_tomcat_shutdown_port_disabled_literal_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-222951',
            'title': 'The shutdown port must be disabled.',
            'check_content': '''From the Tomcat server run the following OS command:

$ sudo grep -i shutdown $CATALINA_BASE/conf/server.xml

Ensure the server shutdown port attribute in $CATALINA_BASE/conf/server.xml is set to -1.

EXAMPLE:
<Server port="-1" shutdown="SHUTDOWN">

If Server port not = "-1" shutdown="SHUTDOWN", this is a finding.'''
        }, 'Tomcat_Application_Server_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-222951',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'grep -i shutdown $CATALINA_BASE/conf/server.xml',
            },
            'expected': {'type': 'contains', 'substring': '<Server port="-1" shutdown="SHUTDOWN">'},
            'description': 'The shutdown port must be disabled.',
        })

    def test_infers_ubuntu_sshd_multi_directive_egrep_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270717',
            'title': 'Ubuntu 24.04 LTS must not allow unattended or automatic login via SSH.',
            'check_content': '''Verify unattended or automatic login via SSH is disabled with the following command:

$ egrep -r '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config
PermitEmptyPasswords no
PermitUserEnvironment no

If the "PermitEmptyPasswords" or "PermitUserEnvironment" keywords are set to a value other than "no", are commented out, are both missing, or conflicting results are returned, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': "egrep -r '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config",
        })
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': 'PermitEmptyPasswords no\nPermitUserEnvironment no',
        })

    def test_infers_sles_sshd_multi_directive_pipeline_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-235032',
            'title': 'The SUSE operating system must not allow unattended or automatic logon via SSH.',
            'check_content': '''Verify the SUSE operating system disables unattended or automatic logon via SSH.

Check that unattended or automatic logon via SSH is disabled with the following command:

> sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\\r' | tr '\\n' ' ' | xargs sudo grep -iEH '^\\s*(permit(.*?)(passwords|environment))'

PermitEmptyPasswords no
PermitUserEnvironment no

If "PermitEmptyPasswords" or "PermitUserEnvironment" keywords are not set to "no", are missing completely, or are commented out, this is a finding.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': "sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\\r' | tr '\\n' ' ' | xargs grep -iEH '^\\s*(permit(.*?)(passwords|environment))'",
        })
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': 'PermitEmptyPasswords no\nPermitUserEnvironment no',
        })

    def test_infers_windows_hardened_unc_paths_registry_pair_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-250319',
            'title': 'Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\\\*\\SYSVOL and \\\\*\\NETLOGON shares.',
            'check_content': '''This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is NA.

If the following registry values do not exist or are not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths\\

Value Name: \\\\*\\NETLOGON
Value Type: REG_SZ
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Value Name: \\\\*\\SYSVOL
Value Type: REG_SZ
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Additional entries would not be a finding.''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Network Provider >> "Hardened UNC Paths" to "Enabled" with at least the following configured in "Hardened UNC Paths:" (click the "Show" button to display).

Value Name: \\\\*\\SYSVOL
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Value Name: \\\\*\\NETLOGON
Value: RequireMutualAuthentication=1, RequireIntegrity=1'''
        }, 'MS_Windows_10_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check']['type'], 'command_output')
        self.assertIn('HardenedPaths', candidate['check']['command'])
        self.assertIn('NETLOGON', candidate['check']['command'])
        self.assertIn('SYSVOL', candidate['check']['command'])
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '\\\\*\\NETLOGON=RequireMutualAuthentication=1, RequireIntegrity=1\n\\\\*\\SYSVOL=RequireMutualAuthentication=1, RequireIntegrity=1',
        })

    def test_infers_windows_ad_smartcard_required_no_listed_users_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254415',
            'title': 'Windows Server 2022 Active Directory user accounts must require CAC authentication.',
            'check_content': '''This applies to domain controllers. It is NA for other systems.

Open "PowerShell".

Enter the following:

"Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)} | FT Name"
("DistinguishedName" may be substituted for "Name" for more detailed output.)

If any user accounts, including administrators, are listed, this is a finding.'''
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)} | FT Name',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_windows_accounts_password_required_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254257',
            'title': 'Windows Server 2022 accounts must require passwords.',
            'check_content': '''Review the password required status for enabled user accounts.

Open "PowerShell".

Domain Controllers:

Enter "Get-Aduser -Filter * -Properties Passwordnotrequired |FT Name, Passwordnotrequired, Enabled".

Exclude disabled accounts (e.g., DefaultAccount, Guest) and Trusted Domain Objects (TDOs).

If "Passwordnotrequired" is "True" or blank for any enabled user account, this is a finding.

Member servers and standalone or nondomain-joined systems:

Enter 'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount'.

Exclude disabled accounts (e.g., DefaultAccount, Guest).

If any enabled user accounts are returned with a "PasswordRequired" status of "False", this is a finding.''',
            'fix_text': 'Configure all enabled accounts to require passwords.',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-254257',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': 'powershell -NoProfile -Command "if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { Get-ADUser -Filter * -Properties PasswordNotRequired,Enabled | Where-Object { $_.Enabled -eq $true -and $_.PasswordNotRequired -eq $true -and $_.Name -notin @(\'DefaultAccount\',\'Guest\') } | Select-Object -ExpandProperty Name } else { Get-CimInstance -Class Win32_UserAccount -Filter \'PasswordRequired=False and LocalAccount=True\' | Where-Object { $_.Disabled -ne $true -and $_.Name -notin @(\'DefaultAccount\',\'Guest\') } | Select-Object -ExpandProperty Name }"',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'Windows Server 2022 accounts must require passwords.',
        })

    def test_infers_windows_krbtgt_password_age_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254427',
            'title': 'The password for the krbtgt account on a domain must be reset at least every 180 days.',
            'check_content': '''This requirement is applicable to domain controllers; it is NA for other systems.

Open "Windows PowerShell".

Enter "Get-ADUser krbtgt -Property PasswordLastSet".

If the "PasswordLastSet" date is more than 180 days old, this is a finding.''',
            'fix_text': 'Reset the password for the krbtgt account a least every 180 days.',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-254427',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': 'powershell -NoProfile -Command "if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { $d=(Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet; if (((Get-Date)-$d).TotalDays -gt 180) { \'PasswordLastSetOlderThan180Days\' } }"',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The password for the krbtgt account on a domain must be reset at least every 180 days.',
        })

    def test_infers_windows_certificate_store_thumbprint_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-220903',
            'title': 'The DoD Root CA certificates must be installed in the Trusted Root Store.',
            'check_content': '''Verify the DoD Root CA certificates are installed as Trusted Root Certification Authorities.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter

If the following certificate "Subject" and "Thumbprint" information is not displayed, this is a finding.

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB
NotAfter: 12/30/2029

Subject: CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: B8269F25DBD937ECAFD4C35A9838571723F2D026
NotAfter: 7/25/2032

Alternately, use the Certificates MMC snap-in:

DoD Root CA 3
Thumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB'''
        }, 'MS_Windows_10_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'Get-ChildItem -Path Cert:Localmachine\\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter',
        })
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': 'Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US\nThumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB\nNotAfter: 12/30/2029\n\nSubject: CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US\nThumbprint: B8269F25DBD937ECAFD4C35A9838571723F2D026\nNotAfter: 7/25/2032',
        })

    def test_infers_linux_dmesg_does_not_show_active_contains_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271760',
            'title': 'OL 9 must implement nonexecutable data to protect its memory from unauthorized code execution.',
            'check_content': '''Verify that OL 9 ExecShield is enabled on 64-bit systems with the following command:

$ sudo dmesg | grep '[NX|DX]*protection'
[    0.000000] NX (Execute Disable) protection: active

If "dmesg" does not show "NX (Execute Disable) protection" active, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': "dmesg | grep '[NX|DX]*protection'",
        })
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': 'NX (Execute Disable) protection: active',
        })

    def test_infers_duplicate_gid_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258061',
            'title': 'RHEL 9 groups must have unique Group ID (GID).',
            'check_content': '''Verify that RHEL 9 contains no duplicate GIDs for interactive users with the following command:

 $  cut -d : -f 3 /etc/group | uniq -d

If the system has duplicate GIDs, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'cut -d : -f 3 /etc/group | uniq -d',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_duplicate_uid_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258045',
            'title': 'RHEL 9 duplicate User IDs (UIDs) must not exist for interactive users.',
            'check_content': '''Verify that RHEL 9 contains no duplicate UIDs for interactive users with the following command:

$ sudo awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

If output is produced and the accounts listed are interactive user accounts, this is a finding.'''
        }, 'RHEL_9_STIG')

        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'awk -F ":" \'list[$3]++{print $1, $3}\' /etc/passwd',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_duplicate_uid_no_output_candidate_with_comma_after_produced(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230371',
            'title': 'RHEL 8 duplicate User IDs (UIDs) must not exist for interactive users.',
            'check_content': '''Check that the operating system contains no duplicate UIDs for interactive users with the following command:

$ sudo awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

If output is produced, and the accounts listed are interactive user accounts, this is a finding.'''
        }, 'RHEL_8_STIG')

        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'awk -F ":" \'list[$3]++{print $1, $3}\' /etc/passwd',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_audit_backlog_limit_grep_v_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271592',
            'title': 'OL 9 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon.',
            'check_content': '''Verify that OL 9 allocates a sufficient audit_backlog_limit to capture processes that start prior to the audit daemon with the following command:

$ sudo grubby --info=ALL | grep args | grep -v 'audit_backlog_limit=8192'

If the command returns any outputs, and audit_backlog_limit is less than "8192", this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': "grubby --info=ALL | grep args | grep -v 'audit_backlog_limit=8192'",
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_skips_audit_backlog_limit_presence_grep_threshold_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258173',
            'title': 'RHEL 9 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon.',
            'check_content': '''Verify RHEL 9 allocates a sufficient audit_backlog_limit to capture processes that start prior to the audit daemon with the following command:

$ sudo grubby --info=ALL | grep args | grep 'audit_backlog_limit'

If the command returns any outputs, and audit_backlog_limit is less than "8192", this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertIsNone(candidate)

    def test_infers_aide_audit_tool_selection_lines_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270831',
            'title': 'Ubuntu 24.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools.',
            'check_content': '''Verify that Advanced Intrusion Detection Environment (AIDE) is properly configured to use cryptographic mechanisms to protect the integrity of audit tools with the following command:

$ egrep '(\\/sbin\\/(audit|au))' /etc/aide/aide.conf
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512

If any of the seven audit tools do not have appropriate selection lines, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': "egrep '(\\/sbin\\/(audit|au))' /etc/aide/aide.conf",
        })
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '\n'.join([
                '/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512',
                '/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512',
                '/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512',
                '/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512',
                '/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512',
                '/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512',
            ]),
        })

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

    def test_infers_office_registry_not_finding_when_quoted_value_contains_reg_dword_assignment(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278355',
            'title': 'Sending of diagnostic data to Microsoft must be disabled.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Privacy >> Trust Center >> "Configure the level of client software diagnostic data sent by Office to Microsoft" is set to "Enabled", and "Neither" from the Options is selected.

Use the Windows Registry Editor to navigate to the following key:
HKCU\\software\\policies\\Microsoft\\office\\common\\clienttelemetry

If the value "SendTelemetry" is "REG_DWORD = 3", this is not a finding.

If the registry key does not exist or is not configured properly, this is a finding.'''
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKCU\\software\\policies\\Microsoft\\office\\common\\clienttelemetry')
        self.assertEqual(candidate['check']['value_name'], 'SendTelemetry')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 3})

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

    def test_infers_windows_security_option_exact_string_from_fix_text_only(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'xccdf_mil.disa.stig_group_V-254475',
            'title': 'Windows Server 2022 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM.',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network security: LAN Manager authentication level to "Send NTLMv2 response only. Refuse LM & NTLM".'''
        }, 'scap_mil.disa.stig_collection_U_MS_Windows_Server_2022_V2R8_STIG_SCAP_1-3_Benchmark')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {
            'type': 'security_policy',
            'section': 'Security Options',
            'key': 'Network security: LAN Manager authentication level',
        })
        self.assertEqual(candidate['expected'], {
            'type': 'equals',
            'value': 'Send NTLMv2 response only. Refuse LM & NTLM',
        })

    def test_infers_user_namespace_sysctl_from_fix_text_exact_line(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'xccdf_mil.disa.stig_group_V-257816',
            'title': 'RHEL 9 must disable the use of user namespaces.',
            'fix_text': '''Configure RHEL 9 to disable the use of user namespaces by adding the following line to a file, in the "/etc/sysctl.d" directory:

user.max_user_namespaces = 0

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'''
        }, 'scap_mil.disa.stig_collection_U_RHEL_9_V2R4_STIG_SCAP_1-3_Benchmark')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'sysctl', 'key': 'user.max_user_namespaces'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '0'})

    def test_infers_opensc_cac_card_driver_exact_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258121',
            'title': 'RHEL 9 must use the common access card (CAC) smart card driver.',
            'check_content': '''Verify that RHEL loads the CAC driver with the following command:

$ sudo opensc-tool --get-conf-entry app:default:card_drivers cac

cac

If "cac" is not listed as a card driver, or no line is returned for "card_drivers", this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'opensc-tool --get-conf-entry app:default:card_drivers cac',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'cac'})

    def test_infers_edge_registry_policy_dword_allowed_values_from_not_set_to_or_clause(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-235766',
            'title': 'Tracking of browsing activity must be disabled.',
            'check_content': '''To check that the policy is configured correctly:

Use the Windows Registry Editor to navigate to the following key:

HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "TrackingPrevention" is not set to "REG_DWORD = 2" or "REG_DWORD = 3", this is a finding.'''
        }, 'MS_Edge_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {
            'type': 'registry',
            'path': 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge',
            'value_name': 'TrackingPrevention',
        })
        self.assertEqual(candidate['expected'], {'type': 'matches', 'pattern': '^(?:2|3)$'})

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

    def test_infers_office_registry_candidate_from_multiword_unquoted_value_for_not_finding_statement(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223293',
            'title': 'Users must be prevented from creating new trusted locations in the Trust Center.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016\\Security Settings\\Trust Center >> Allow mix of policy and user locations is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\security\\trusted locations

If the value for allow user locations is set to REG_DWORD = 0, this is not a finding.'''
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['check']['path'], 'HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\security\\trusted locations')
        self.assertEqual(candidate['check']['value_name'], 'allow user locations')
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 0})

    def test_infers_user_right_candidate_when_only_administrators_are_allowed(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-220962',
            'title': 'The Create a pagefile user right must only be assigned to the Administrators group.',
            'check_content': '''Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Create a pagefile" user right, this is a finding:

Administrators''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create a pagefile" to only include the following groups or accounts:

Administrators'''
        }, 'MS_Windows_10_STIG')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeCreatePagefilePrivilege'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '*S-1-5-32-544'})

    def test_infers_user_right_candidate_when_accounts_or_groups_only_administrators_are_allowed(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254493',
            'title': 'Windows Server 2022 Allow log on locally user right must only be assigned to the Administrators group.',
            'check_content': '''Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on locally" user right, this is a finding:

- Administrators''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Allow log on locally to include only the following accounts or groups:

- Administrators'''
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeInteractiveLogonRight'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '*S-1-5-32-544'})

    def test_infers_remote_desktop_user_right_when_only_administrators_with_period_are_allowed(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278167',
            'title': 'The Windows Server 2025 "Allow log on through Remote Desktop Services" user right must only be assigned to the Administrators group on domain controllers.',
            'check_content': '''This applies to domain controllers, it is not applicable for other systems.

Verify the effective setting in Local Group Policy Editor.

Run gpedit.msc.

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on through Remote Desktop Services" user right, this is a finding:
- Administrators.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeRemoteInteractiveLogonRight" user right, this is a finding:

S-1-5-32-544 (Administrators)''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Allow log on through Remote Desktop Services to include only the following accounts or groups:
- Administrators.'''
        }, 'MS_Windows_Server_2025_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeRemoteInteractiveLogonRight'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '*S-1-5-32-544'})

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

    def test_infers_registry_candidate_when_value_line_lists_multiple_allowed_values(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278103',
            'title': 'Windows Server 2025 Telemetry must be configured to limit diagnostic data sent to Microsoft.',
            'check_content': '''Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\
Value Name: AllowTelemetry
Type: REG_DWORD
Value0x00000000 (0), 0x00000001 (1)'''
        }, 'MS_Windows_Server_2025_STIG')
        self.assertEqual(candidate['check']['type'], 'registry')
        self.assertEqual(candidate['expected'], {'type': 'matches', 'pattern': '^(?:0|1)$'})

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

    def test_infers_chrome_quoted_key_registry_policy_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-221599',
            'title': 'Chrome development tools must be disabled.',
            'check_content': '''Universal method:
1. In the omnibox (address bar) type chrome://policy
2. If the policy "DeveloperToolsAvailability" is not shown or is not set to "2", this is a finding.

Windows method:
1. Start regedit
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome
3. If the key "DeveloperToolsAvailability" does not exist or is not set to "2", this is a finding.'''
        }, 'Google_Chrome_Current_Windows')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'registry', 'path': 'HKLM\\Software\\Policies\\Google\\Chrome', 'value_name': 'DeveloperToolsAvailability'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 2})

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

    def test_infers_rhel7_openssh_server_package_from_ssh_glob_install_prose(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-204585',
            'title': 'The Red Hat Enterprise Linux operating system must be configured so that all networked systems have SSH installed.',
            'check_content': '''Check to see if sshd is installed with the following command:

# yum list installed \\*ssh\\*
libssh2.x86_64 1.4.3-8.el7 @anaconda/7.1
openssh.x86_64 6.6.1p1-11.el7 @anaconda/7.1
openssh-server.x86_64 6.6.1p1-11.el7 @anaconda/7.1

If the "SSH server" package is not installed, this is a finding.''',
            'fix_text': '''Install SSH packages onto the host with the following commands:

# yum install openssh-server.x86_64'''
        }, 'RHEL_7_STIG')
        self.assertEqual(candidate['check'], {'type': 'package', 'name': 'openssh-server', 'should_be_installed': True})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

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

    def test_infers_sles_firewalld_status_enabled_and_active_literal_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234846',
            'title': 'The SUSE operating system must have a firewall system installed to immediately disconnect or disable remote access to the whole operating system.',
            'check_content': '''Verify "firewalld" is configured to protect the SUSE operating system.

Run the following command:

> systemctl status firewalld.service
 firewalld.service - firewalld - dynamic firewall daemon
   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled; vendor preset: disabled)
   Active: active (running) since Wed 2019-11-06 10:58:11 CET; 24h ago
     Docs: man:firewalld(1)
 Main PID: 1105 (firewalld)
    Tasks: 2 (limit: 4915)
   CGroup: /system.slice/firewalld.service
           ??1105 /usr/bin/python3 -Es /usr/sbin/firewalld --nofork --nopid

If the service is not enabled, this is a finding.

If the service is not active, this is a finding.''',
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-234846',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'systemctl status firewalld.service'},
            'expected': {'type': 'contains', 'substring': 'Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled; vendor preset: disabled)\n   Active: active (running)'},
            'description': 'The SUSE operating system must have a firewall system installed to immediately disconnect or disable remote access to the whole operating system.',
        })

    def test_infers_linux_firewalld_public_target_drop_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271473',
            'title': 'OL 9 must be configured so that the firewall employs a deny-all, allow-by-exception policy for allowing connections to other systems.',
            'check_content': '''Verify that OL 9 is configured to employ a deny-all, allow-by-exception policy for allowing connections to other systems with the following commands:

$ sudo firewall-cmd --state
running

$ sudo firewall-cmd --get-active-zones
public
   interfaces: ens33

$ sudo firewall-cmd --info-zone=public | grep target
   target: DROP

$ sudo firewall-cmd --permanent --info-zone=public | grep target
   target: DROP

If no zones are active on the OL 9 interfaces or if runtime and permanent targets are set to a different option other than "DROP", this is a finding.''',
            'fix_text': 'Configure firewalld to use DROP as the target for runtime and permanent public zones.',
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-271473',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'firewall-cmd --info-zone=public | grep target && firewall-cmd --permanent --info-zone=public | grep target'},
            'expected': {'type': 'contains', 'substring': 'target: DROP\ntarget: DROP'},
            'description': 'OL 9 must be configured so that the firewall employs a deny-all, allow-by-exception policy for allowing connections to other systems.',
        })

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

    def test_infers_sles_zypper_gpgcheck_enabled_from_off_finding_and_fix_line(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234852',
            'title': 'The SUSE operating system tool zypper must have gpgcheck enabled.',
            'check_content': '''Verify the SLES 12 zypper tool has gpgcheck enabled with the following command:

> grep -i '^gpgcheck' /etc/zypp/zypp.conf

If "gpgcheck" is set to "off", this is a finding.''',
            'fix_text': '''Configure the SLES 12 zypper tool to enable gpgcheck.

Add or modify the following line in the "/etc/zypp/zypp.conf" file or remove the line completely ensuring that the default zypper setting is enabled:

gpgcheck = on'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_content', 'path': '/etc/zypp/zypp.conf', 'pattern': 'gpgcheck = on', 'is_regex': False})
        self.assertEqual(candidate['expected'], {'type': 'contains'})

    def test_infers_proc_fips_enabled_command_as_literal_one_requirement(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234859',
            'title': 'FIPS 140-2 mode must be enabled on the SUSE operating system.',
            'check_content': '''Verify the SUSE operating system is running in FIPS mode by running the following command.

> cat /proc/sys/crypto/fips_enabled

1

If nothing is returned, the file does not exist, or the value returned is "0", this is a finding.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'cat /proc/sys/crypto/fips_enabled'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '1'})

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

    def test_infers_rpm_va_grep_hash_mismatch_when_any_output_from_command_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-214799',
            'title': 'The Red Hat Enterprise Linux operating system must be configured so that the cryptographic hash of system files and commands matches vendor values.',
            'check_content': '''Verify the cryptographic hash of system files and commands match the vendor values.

Check the cryptographic hash of system files and commands with the following command:

Note: System configuration files (indicated by a "c" in the second column) are expected to change over time. Unusual modifications should be investigated through the system audit log.

# rpm -Va --noconfig | grep '^..5'

If there is any output from the command for system files or binaries, this is a finding.'''
        }, 'RHEL_7_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': "rpm -Va --noconfig | grep '^..5'"})
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

    def test_infers_find_stat_not_owned_filter_as_empty_output_requirement(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257922',
            'title': 'RHEL 9 library directories must be owned by root.',
            'check_content': '''Verify the systemwide shared library directories are owned by root with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%U %n" {} \\;

If any systemwide shared library directory is not owned by "root", this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%U %n" {} \\;'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_ssh_private_host_key_mode_glob_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230287',
            'title': 'The RHEL 8 SSH private host key files must have mode 0640 or less permissive.',
            'check_content': '''Verify the SSH private host key files have mode "0640" or less permissive with the following command:

$ sudo ls -l /etc/ssh/ssh_host*key
-rw-r----- 1 root ssh_keys 668 Nov 28 06:43 ssh_host_dsa_key
-rw-r----- 1 root ssh_keys 582 Nov 28 06:43 ssh_host_key
-rw-r----- 1 root ssh_keys 887 Nov 28 06:43 ssh_host_rsa_key

If any private host key file has a mode more permissive than "0640", this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-230287',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/ssh -maxdepth 1 -type f -name \'ssh_host*key\' -perm /137 -exec stat -c "%n %a" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The RHEL 8 SSH private host key files must have mode 0640 or less permissive.',
        })

    def test_infers_suse_ssh_private_host_key_mode_stat_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-235009',
            'title': 'The SUSE operating system SSH daemon private host key files must have mode 0640 or less permissive.',
            'check_content': '''Verify the SUSE operating system SSH daemon private host key files have mode "0640" or less permissive.

The following command will find all SSH private key files on the system:
> sudo find / -name '*ssh_host*key' -exec ls -lL {} \\;

Check the mode of the private host key files under "/etc/ssh" file with the following command:
> find /etc/ssh -name 'ssh_host*key' -exec stat -c "%a %n" {} \\;
640 /etc/ssh/ssh_host_rsa_key
640 /etc/ssh/ssh_host_dsa_key
640 /etc/ssh/ssh_host_ecdsa_key
640 /etc/ssh/ssh_host_ed25519_key

If any file has a mode more permissive than "0640", this is a finding.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-235009',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/ssh -maxdepth 1 -type f -name \'ssh_host*key\' -perm /137 -exec stat -c "%n %a" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The SUSE operating system SSH daemon private host key files must have mode 0640 or less permissive.',
        })

    def test_infers_ssh_public_host_key_mode_glob_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-235008',
            'title': 'The SUSE operating system SSH daemon public host key files must have mode 0644 or less permissive.',
            'check_content': '''Verify the SUSE operating system SSH daemon public host key files have mode "0644" or less permissive.

The following command will find all SSH public key files on the system:
> find /etc/ssh -name 'ssh_host*key.pub' -exec stat -c "%a %n" {} \\;

If any file has a mode more permissive than "0644", this is a finding.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-235008',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/ssh -maxdepth 1 -type f -name \'ssh_host*key.pub\' -perm /133 -exec stat -c "%n %a" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The SUSE operating system SSH daemon public host key files must have mode 0644 or less permissive.',
        })

    def test_infers_ssh_public_host_key_mode_find_ls_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-204596',
            'title': 'The Red Hat Enterprise Linux operating system must be configured so that the SSH public host key files have mode 0644 or less permissive.',
            'check_content': '''Verify the SSH public host key files have mode "0644" or less permissive.

Note: SSH public key files may be found in other directories on the system depending on the installation.

The following command will find all SSH public key files on the system:

# find /etc/ssh -name '*.pub' -exec ls -lL {} \\;

-rw-r--r-- 1 root root 618 Nov 28 06:43 ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 347 Nov 28 06:43 ssh_host_key.pub
-rw-r--r-- 1 root root 238 Nov 28 06:43 ssh_host_rsa_key.pub

If any file has a mode more permissive than "0644", this is a finding.'''
        }, 'RHEL_7_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-204596',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/ssh -maxdepth 1 -type f -name \'ssh_host*key.pub\' -perm /133 -exec stat -c "%n %a" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Red Hat Enterprise Linux operating system must be configured so that the SSH public host key files have mode 0644 or less permissive.',
        })

    def test_infers_ssh_public_host_key_mode_ls_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230286',
            'title': 'The RHEL 8 SSH public host key files must have mode 0644 or less permissive.',
            'check_content': '''Verify the SSH public host key files have mode "0644" or less permissive with the following command:

$ sudo ls -l /etc/ssh/*.pub

-rw-r--r-- 1 root root 618 Nov 28 06:43 ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 347 Nov 28 06:43 ssh_host_key.pub
-rw-r--r-- 1 root root 238 Nov 28 06:43 ssh_host_rsa_key.pub

If any key.pub file has a mode more permissive than "0644", this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-230286',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/ssh -maxdepth 1 -type f -name \'ssh_host*key.pub\' -perm /133 -exec stat -c "%n %a" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The RHEL 8 SSH public host key files must have mode 0644 or less permissive.',
        })

    def test_infers_oracle_linux_8_quoted_ssh_public_host_key_mode_ls_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248601',
            'title': 'The OL 8 SSH public host key files must have mode "0644" or less permissive.',
            'check_content': '''Verify the SSH public host key files have mode "0644" or less permissive with the following command:

$ sudo ls -l /etc/ssh/*.pub

-rw-r--r-- 1 root wheel 618 Nov 28 06:43 ssh_host_dsa_key.pub
-rw-r--r-- 1 root wheel 347 Nov 28 06:43 ssh_host_key.pub
-rw-r--r-- 1 root wheel 238 Nov 28 06:43 ssh_host_rsa_key.pub

If any "key.pub" file has a mode more permissive than "0644", this is a finding.'''
        }, 'Oracle_Linux_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-248601',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/ssh -maxdepth 1 -type f -name \'ssh_host*key.pub\' -perm /133 -exec stat -c "%n %a" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The OL 8 SSH public host key files must have mode "0644" or less permissive.',
        })

    def test_infers_rhel9_gsettings_uint32_lock_delay_upper_bound_with_missing_last_phrase(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258025',
            'title': 'RHEL 9 must initiate a session lock for graphical user interfaces when the screensaver is activated.',
            'check_content': '''Verify RHEL 9 initiates a session lock for graphical user interfaces when the screensaver is activated with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.desktop.screensaver lock-delay

uint32 5

If the "uint32" setting is not set to "5" or less, or is missing, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-258025',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'gsettings get org.gnome.desktop.screensaver lock-delay'},
            'expected': {'type': 'matches', 'pattern': '^uint32 [1-5]$'},
            'description': 'RHEL 9 must initiate a session lock for graphical user interfaces when the screensaver is activated.',
        })

    def test_infers_rhel7_ssh_private_host_key_mode_find_xargs_ls_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-204597',
            'title': 'The Red Hat Enterprise Linux operating system must be configured so that the SSH private host key files have mode 0640 or less permissive.',
            'check_content': '''Verify the SSH private host key files have mode "0640" or less permissive.

The following command will find all SSH private key files on the system and list their modes:

# find / -name '*ssh_host*key' | xargs ls -lL

-rw-r----- 1 root ssh_keys 112 Apr 1 11:59 ssh_host_dsa_key
-rw-r----- 1 root ssh_keys 202 Apr 1 11:59 ssh_host_key
-rw-r----- 1 root ssh_keys 352 Apr 1 11:59 ssh_host_rsa_key

If any file has a mode more permissive than "0640", this is a finding.'''
        }, 'RHEL_7_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-204597',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/ssh -maxdepth 1 -type f -name \'ssh_host*key\' -perm /137 -exec stat -c "%n %a" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Red Hat Enterprise Linux operating system must be configured so that the SSH private host key files have mode 0640 or less permissive.',
        })

    def test_infers_oracle_linux_ssh_private_host_key_mode_underscore_glob_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271771',
            'title': 'OL 9 SSH private host key files must have mode 0640 or less permissive.',
            'check_content': '''Verify that OL 9 SSH private host key files have a mode of "0640" or less permissive with the following command:

$ ls -l /etc/ssh/*_key
640 /etc/ssh/ssh_host_dsa_key
640 /etc/ssh/ssh_host_ecdsa_key
640 /etc/ssh/ssh_host_ed25519_key
640 /etc/ssh/ssh_host_rsa_key

If any private host key file has a mode more permissive than "0640", this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-271771',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/ssh -maxdepth 1 -type f -name \'ssh_host*key\' -perm /137 -exec stat -c "%n %a" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'OL 9 SSH private host key files must have mode 0640 or less permissive.',
        })

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

    def test_infers_confirm_secure_boot_powershell_literal_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278032',
            'title': 'Windows Server 2025 must have Secure Boot enabled.',
            'check_content': '''Devices that have UEFI firmware must have Secure Boot enabled.

Run "System Information". Under "System Summary", if "Secure Boot State" does not display "On", this is a finding.

On server core installations, run the following PowerShell command:

Confirm-SecureBootUEFI

If a value of "True" is not returned, this is a finding.'''
        }, 'MS_Windows_Server_2025_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'Confirm-SecureBootUEFI'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'True'})

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

    def test_infers_macos_audit_log_folder_mode_upper_bound_command_substitution(self):
        command = "/usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')"
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259461',
            'title': 'The macOS system must configure audit log folders to mode 700 or less permissive.',
            'check_content': f'''Verify the macOS system is configured with audit log folders set to mode 700 or less permissive with the following command:

{command}

If the result is not a mode of 700 or less permissive, this is a finding.''',
        }, 'Apple_macOS_14_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-259461',
            'platform': 'macos',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'matches', 'pattern': r'^[0-7]00$'},
            'description': 'The macOS system must configure audit log folders to mode 700 or less permissive.',
        })

    def test_infers_macos_audit_control_flag_count_when_flag_must_be_listed(self):
        command = "/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\\n' | /usr/bin/grep -Ec 'ad'"
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259452',
            'title': 'The macOS system must be configured to audit all administrative action events.',
            'check_content': f'''Verify the macOS system is configured to audit privileged access with the following command:

{command}

If "ad" is not listed in the output, this is a finding.'''
        }, 'Apple_macOS_14_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': command})
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

    def test_infers_macos_result_variable_shell_block_as_command_output(self):
        command = 'authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network")\nresult="1"\nfor section in ${authDBs[@]}; do\n  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath \'name(//*[contains(text(), "shared")]/following-sibling::*[1])\' -) != "false" ]]; then\n    result="0"\n  fi\ndone\necho $result'
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259515',
            'title': 'The macOS system must require administrator privileges to modify systemwide settings.',
            'check_content': f'''Verify the macOS system is configured to require administrator privileges to modify systemwide settings with the following command:

{command}

If the result is not "1", this is a finding.'''
        }, 'Apple_macOS_14_STIG')
        self.assertEqual(candidate['platform'], 'macos')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': command})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '1'})

    def test_infers_macos_pass_fail_shell_block_as_command_output(self):
        command = 'LAUNCHD_RUNNING=$(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd)\nAUDITD_RUNNING=$(/usr/sbin/audit -c | /usr/bin/grep -c "AUC_AUDITING")\nif [[ $LAUNCHD_RUNNING == 1 ]] && [[ -e /etc/security/audit_control ]] && [[ $AUDITD_RUNNING == 1 ]]; then\n  echo "pass"\nelse\n  echo "fail"\nfi'
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-268454',
            'title': 'The macOS system must enable security auditing.',
            'check_content': f'''Verify the macOS system is configured to enable the auditd service with the following command:

{command}

If the result is not "pass", this is a finding.'''
        }, 'Apple_macOS_15_STIG')
        self.assertEqual(candidate['platform'], 'macos')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': command})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'pass'})

    def test_infers_macos_authorizationdb_shell_block_with_security_path_variant(self):
        command = 'authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")\nresult="1"\nfor section in ${authDBs[@]}; do\nif [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath \'name(//*[contains(text(), "shared")]/following-sibling::*[1])\' -) != "false" ]]; then\nresult="0"\nfi\nif [[ $(security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath \'//*[contains(text(), "group")]/following-sibling::*[1]/text()\' - ) != "admin" ]]; then\nresult="0"\nfi\nif [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath \'name(//*[contains(text(), "authenticate-user")]/following-sibling::*[1])\' -) != "true" ]]; then\nresult="0"\nfi\nif [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath \'name(//*[contains(text(), "session-owner")]/following-sibling::*[1])\' -) != "false" ]]; then\nresult="0"\nfi\ndone\necho $result'
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-268514',
            'title': 'The macOS system must require an administrator password to modify systemwide preferences.',
            'check_content': f'''Verify the macOS system is configured to require administrator privileges to modify systemwide settings with the following command:

{command}

If the result is not "1", this is a finding.'''
        }, 'Apple_macOS_15_STIG')
        self.assertEqual(candidate['platform'], 'macos')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': command})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '1'})

    def test_infers_inline_macos_password_hint_pass_fail_shell_block(self):
        command = 'HINT=$(/usr/bin/dscl . -list /Users hint | /usr/bin/awk \'{ print $2 }\')\nif [ -z "$HINT" ]; then echo "PASS"\nelse echo "FAIL"\nfi'
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-268541',
            'title': 'The macOS system must remove password hints from user accounts.',
            'check_content': f'''Verify the macOS system is configured to remove password hints from user accounts with the following command:

{command}

If the result is not "PASS", this is a finding.'''
        }, 'Apple_macOS_15_STIG')
        self.assertEqual(candidate['platform'], 'macos')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': command})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'PASS'})

    def test_infers_macos_osascript_true_heredoc_with_javascript_conjunctions(self):
        command = '''/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\\
.objectForKey('DisableGuestAccount'))
let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\\
.objectForKey('EnableGuestAccount'))
if ( pref1 == true && pref2 == false ) {
return("true")
} else {
return("false")
}
}
EOS'''
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-268510',
            'title': 'The macOS system must disable the guest account.',
            'check_content': f'''Verify the macOS system is configured to disable the guest account with the following command:

{command}

If the result is not "true", this is a finding.'''
        }, 'Apple_macOS_15_STIG')
        self.assertEqual(candidate['platform'], 'macos')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': command})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'true'})

    def test_infers_inline_macos_absolute_pipeline_when_result_is_not_literal(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-268565',
            'title': 'The macOS system must enable Authenticated Root.',
            'check_content': '''Verify the macOS system is configured to enable authenticated root with the following command:  /usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c "AuthenticatedRootVolumeEnabled = 1;"  If the result is not "1", this is a finding.'''
        }, 'Apple_macOS_15_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': '/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c "AuthenticatedRootVolumeEnabled = 1;"'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '1'})

    def test_infers_update_crypto_policies_is_applied_literal_output(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-279932',
            'title': 'RHEL 8 cryptographic policy must not be overridden.',
            'check_content': '''Verify RHEL 8 cryptographic policies are not overridden.

Verify the configured policy matches the generated policy with the following command:

$ sudo update-crypto-policies --is-applied

The configured policy is applied

If the returned message does not match the above, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-279932',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'update-crypto-policies --is-applied'},
            'expected': {'type': 'equals', 'value': 'The configured policy is applied'},
            'description': 'RHEL 8 cryptographic policy must not be overridden.',
        })

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
            'check_content': r'''Verify SSH configuration with the following command:

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

    def test_infers_gsettings_picture_uri_blank_with_dconf_lock_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271676',
            'title': 'OL 9 must conceal, via the session lock, information previously visible on the display with a publicly viewable image.',
            'check_content': '''Verify that OL 9 configures the screensaver to be blank with the following command:

$ gsettings get org.gnome.desktop.screensaver picture-uri 

If properly configured, the output should be "''".

To ensure that users cannot set the screensaver background, run the following: 

$ grep picture-uri /etc/dconf/db/local.d/locks/* 

If properly configured, the output should be "/org/gnome/desktop/screensaver/picture-uri".

If it is not set or configured properly, this is a finding.''',
            'fix_text': '''Add or update the [org/gnome/desktop/screensaver] section of the "/etc/dconf/db/local.d/00-security-settings" database file and add or update the following lines:

[org/gnome/desktop/screensaver]
picture-uri=''

Add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock" to prevent user modification:

/org/gnome/desktop/screensaver/picture-uri'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'gsettings get org.gnome.desktop.screensaver picture-uri && grep picture-uri /etc/dconf/db/local.d/locks/*',
        })
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': "''\n/org/gnome/desktop/screensaver/picture-uri"})

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

    def test_infers_journal_find_stat_owner_group_negative_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270761',
            'title': 'Ubuntu 24.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal".',
            'check_content': '''Verify the /run/log/journal and /var/log/journal directories are group-owned by "systemd-journal" with the following command:

$ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %G" {} \\;
/run/log/journal systemd-journal
/var/log/journal systemd-journal
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e systemd-journal

If any output returned is not group-owned by "systemd-journal", this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'find /run/log/journal /var/log/journal -type d ! -group systemd-journal -exec stat -c "%n %G" {} \\;',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_journal_find_stat_mode_negative_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270757',
            'title': 'Ubuntu 24.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries.',
            'check_content': '''Verify the /run/log/journal and /var/log/journal directories have permissions set to "2640" or less permissive with the following command:

$ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %a" {} \\;
/run/log/journal 2640
/var/log/journal 2640
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e 2640

If any output returned has a permission set greater than 2640, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'find /run/log/journal /var/log/journal -type d -perm /5137 -exec stat -c "%n %a" {} \\;',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_sshd_config_find_stat_owner_negative_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257998',
            'title': 'The RHEL 9 SSH server configuration file must be owned by root.',
            'check_content': '''Verify the ownership of the "/etc/ssh/sshd_config" file and the contents of "/etc/ssh/sshd_config.d" with the following command:

$ sudo find /etc/ssh/sshd_config /etc/ssh/sshd_config.d -exec stat -c "%U %n" {} \\;

root /etc/ssh/sshd_config
root /etc/ssh/sshd_config.d
root /etc/ssh/sshd_config.d/50-cloud-init.conf
root /etc/ssh/sshd_config.d/50-redhat.conf

If the "/etc/ssh/sshd_config" file or "/etc/ssh/sshd_config.d" or any files in the "sshd_config.d" directory do not have an owner of "root", this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'find /etc/ssh/sshd_config /etc/ssh/sshd_config.d ! -user root -exec stat -c "%U %n" {} \\;',
        })
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

    def test_infers_xmllint_expected_xml_element_when_output_of_command_must_match(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259038',
            'title': 'The vCenter Lookup service cookies must have secure flag set.',
            'check_content': '''At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' -

Expected result:

<secure>true</secure>

If the output of the command does not match the expected result, this is a finding.'''
        }, 'VMW_vSphere_8-0_VCSA_Lookup_Svc_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-259038',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed \'s/xmlns=".*"//g\' | xmllint --xpath \'/web-app/session-config/cookie-config/secure\' -',
            },
            'expected': {'type': 'equals', 'value': '<secure>true</secure>'},
            'description': 'The vCenter Lookup service cookies must have secure flag set.',
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

    def test_infers_xmllint_single_attribute_expected_result_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259060',
            'title': 'The vCenter Lookup service deployXML attribute must be disabled.',
            'check_content': '''At the command prompt, run the following command:

# xmllint --xpath "//Host/@deployXML" /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

deployXML="false"

If "deployXML" does not equal "false", this is a finding.'''
        }, 'VMW_vSphere_8-0_VCSA_Lookup_Svc_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-259060',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'xmllint --xpath "//Host/@deployXML" /usr/lib/vmware-lookupsvc/conf/server.xml',
            },
            'expected': {'type': 'equals', 'value': 'deployXML="false"'},
            'description': 'The vCenter Lookup service deployXML attribute must be disabled.',
        })

    def test_infers_xmllint_example_xml_attribute_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259048',
            'title': 'The vCenter Lookup service "ErrorReportValve showServerInfo" must be set to "false".',
            'check_content': '''At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-lookupsvc/conf/server.xml

Example result:

<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>

If the "ErrorReportValve" element is not defined or "showServerInfo" is not set to "false", this is a finding.'''
        }, 'VMW_vSphere_8-0_VCSA_Lookup_Svc_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-259048',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'xmllint --xpath \'/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]\' /usr/lib/vmware-lookupsvc/conf/server.xml',
            },
            'expected': {'type': 'contains', 'substring': 'showServerInfo="false"'},
            'description': 'The vCenter Lookup service "ErrorReportValve showServerInfo" must be set to "false".',
        })

    def test_infers_sles_dconf_banner_message_enable_true_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234808',
            'title': 'The SUSE operating system must display a banner before granting local or remote access to the system via a graphical user logon.',
            'check_content': '''Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable.

Verify the SUSE operating system displays a banner before local or remote access to the system via a graphical user logon.

Check that the SUSE operating system displays a banner at the logon screen by performing the following command:

> grep banner-message-enable /etc/dconf/db/gdm.d/*
banner-message-enable=true

> cat /etc/dconf/profile/gdm
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults

If "banner-message-enable" is set to "false" or is missing completely, this is a finding.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-234808',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'grep banner-message-enable /etc/dconf/db/gdm.d/*'},
            'expected': {'type': 'contains', 'substring': 'banner-message-enable=true'},
            'description': 'The SUSE operating system must display a banner before granting local or remote access to the system via a graphical user logon.',
        })

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

    def test_infers_dconf_grep_candidate_from_plural_key_when_finding_text_uses_singular_typo(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271685',
            'title': 'OL 9 must disable the ability of a user to restart the system from the login screen.',
            'check_content': '''Verify that OL 9 disables a user's ability to restart the system with the following command:

$ grep -R disable-restart-buttons /etc/dconf/db/*
/etc/dconf/db/distro.d/20-authselect:disable-restart-buttons='true'

If the "disable-restart-button" setting is not set to "true", is missing or commented out from the dconf database files, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'grep -R disable-restart-buttons /etc/dconf/db/*'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': "disable-restart-buttons='true'"})

    def test_infers_linux_dconf_update_no_output_candidate_from_exact_shell_function(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258028',
            'title': 'RHEL 9 effective dconf policy must match the policy keyfiles.',
            'check_content': '''Check the last modification time of the local databases, comparing it to the last modification time of the related keyfiles. The following command will check every dconf database and compare its modification time to the related system keyfiles:

$ function dconf_needs_update { for db in $(find /etc/dconf/db -maxdepth 1 -type f); do db_mtime=$(stat -c %Y "$db"); keyfile_mtime=$(stat -c %Y "$db".d/* | sort -n | tail -1); if [ -n "$db_mtime" ] && [ -n "$keyfile_mtime" ] && [ "$db_mtime" -lt "$keyfile_mtime" ]; then echo "$db needs update"; return 1; fi; done; }; dconf_needs_update

If the command has any output, then a dconf database needs to be updated, and this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'function dconf_needs_update { for db in $(find /etc/dconf/db -maxdepth 1 -type f); do db_mtime=$(stat -c %Y "$db"); keyfile_mtime=$(stat -c %Y "$db".d/* | sort -n | tail -1); if [ -n "$db_mtime" ] && [ -n "$keyfile_mtime" ] && [ "$db_mtime" -lt "$keyfile_mtime" ]; then echo "$db needs update"; return 1; fi; done; }; dconf_needs_update',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

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

    def test_infers_linux_fstab_mount_option_candidate_from_title_and_fix_text(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'xccdf_mil.disa.stig_group_V-230518',
            'title': 'RHEL 8 must mount /var/log/audit with the nosuid option.',
            'fix_text': '''Configure the system so that /var/log/audit is mounted with the "nosuid" option by adding /modifying the /etc/fstab with the following line:

/dev/mapper/rhel-var-log-audit /var/log/audit xfs defaults,nodev,nosuid,noexec 0 0'''
        }, 'scap_mil.disa.stig_collection_U_RHEL_8_V2R7_STIG_SCAP_1-3_Benchmark')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'findmnt /var/log/audit'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'nosuid'})

    def test_infers_linux_nfs_fstab_required_option_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271642',
            'title': 'OL 9 must prevent code from being executed on file systems that are imported via Network File System (NFS).',
            'check_content': '''If no NFS mounts are configured, this requirement is Not Applicable.

Verify that OL 9 has the "noexec" option configured for all NFS mounts with the following command:

$ cat /etc/fstab | grep nfs
192.168.22.2:/mnt/export /data nfs4 rw,nosuid,nodev,noexec,sync,soft,sec=krb5:krb5i:krb5p

If the system is mounting file systems via NFS and the "noexec" option is missing, this is a finding.''',
            'fix_text': 'Update each NFS mounted file system to use the "noexec" option on file systems that are being imported via NFS.',
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': "awk '!/^\\s*#/ && $3 ~ /^nfs/ && $4 !~ /(^|,)noexec(,|$)/ {print}' /etc/fstab",
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_linux_nfs_fstab_rpcsec_gss_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271640',
            'title': 'OL 9 must be configured so that the Network File System (NFS) is configured to use RPCSEC_GSS.',
            'check_content': '''If no NFS mounts are configured, this requirement is Not Applicable.

Verify that OL 9 has the "sec" option configured for all NFS mounts with the following command:

$ cat /etc/fstab | grep nfs
192.168.22.2:/mnt/export /data nfs4 rw,nosuid,nodev,noexec,sync,soft,sec=krb5p:krb5i:krb5

If the system is mounting file systems via NFS and has the sec option without the "krb5:krb5i:krb5p" settings, the "sec" option has the "sys" setting, or the "sec" option is missing, this is a finding.''',
            'fix_text': 'Ensure the "sec" option is defined as "krb5p:krb5i:krb5".',
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': "awk '!/^\\s*#/ && $3 ~ /^nfs/ && ($4 !~ /(^|,)sec=(krb5|krb5i|krb5p)(:krb5|:krb5i|:krb5p)*(,|$)/ || $4 ~ /(^|,)sec=sys(,|$)/) {print}' /etc/fstab",
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_linux_stat_mode_zero_candidate_from_path_sample(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271804',
            'title': 'OL 9 /etc/gshadow file must have mode 0000 or less permissive to prevent unauthorized access.',
            'check_content': '''Verify that OL 9 configures the "/etc/gshadow" file to have a mode pf "0000" with the following command:

$ stat -c "%a %n" /etc/gshadow
0 /etc/gshadow

If a value of "0" is not returned, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_permission', 'path': '/etc/gshadow', 'owner': None, 'group': None, 'mode': '0000'})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_infers_linux_file_permission_candidate_from_single_file_ls_owner_group_sample(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271776',
            'title': 'OL 9 SSH server configuration file must be group-owned by root.',
            'check_content': '''Verify that OL 9 configures group ownership of the "/etc/ssh/sshd_config" file with the following command:

$ ls -al /etc/ssh/sshd_config
rw-------. 1 root root 3669 Feb 22 11:34 /etc/ssh/sshd_config

If the "/etc/ssh/sshd_config" file does not have a group owner of "root", this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_permission', 'path': '/etc/ssh/sshd_config', 'owner': None, 'group': 'root', 'mode': None})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_infers_linux_optional_file_ls_owner_other_than_root_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-204490',
            'title': 'The Red Hat Enterprise Linux operating system must be configured so that the cron.allow file, if it exists, is owned by root.',
            'check_content': '''Verify that the "cron.allow" file is owned by root.

Check the owner of the "cron.allow" file with the following command:

# ls -al /etc/cron.allow
-rw------- 1 root root 6 Mar  5  2011 /etc/cron.allow

If the "cron.allow" file exists and has an owner other than root, this is a finding.'''
        }, 'RHEL_7_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_permission', 'path': '/etc/cron.allow', 'owner': 'root', 'group': None, 'mode': None})
        self.assertEqual(candidate['expected'], {'type': 'is_true'})

    def test_skips_recursive_ls_file_permission_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-244531',
            'title': 'All RHEL 8 local interactive user home directory files must have mode 0750 or less permissive.',
            'check_content': '''Verify all files and directories contained in a local interactive user home directory have a mode of "0750".

$ sudo ls -lLR /home/smithj
-rwxr-x--- 1 smithj smithj 18 Mar 5 17:06 file1

If any files or directories are found with a mode more permissive than "0750", this is a finding.'''
        }, 'RHEL_8_STIG')
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

    def test_infers_linux_file_content_candidate_from_cat_pipe_grep_expected_sample_when_value_must_equal(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-238325',
            'title': 'The Ubuntu operating system must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm.',
            'check_content': '''Verify that the shadow password suite configuration is set to encrypt passwords with a FIPS 140-2 approved cryptographic hashing algorithm.

Check the hashing algorithm that is being used to hash passwords with the following command:

$ cat /etc/login.defs | grep -i encrypt_method

ENCRYPT_METHOD SHA512

If "ENCRYPT_METHOD" does not equal SHA512 or greater, this is a finding.''',
            'fix_text': '''Configure the Ubuntu operating system to encrypt all stored passwords.

Edit/modify the following line in the "/etc/login.defs" file and set "ENCRYPT_METHOD" to SHA512:

ENCRYPT_METHOD SHA512'''
        }, 'Canonical_Ubuntu_20-04_LTS_STIG')
        self.assertEqual(candidate['check'], {'type': 'file_content', 'path': '/etc/login.defs', 'pattern': 'ENCRYPT_METHOD SHA512', 'is_regex': False})
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

    def test_infers_linux_auditctl_candidate_when_authoritative_command_has_audtctl_typo(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270795',
            'title': 'Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chacl command.',
            'check_content': '''Verify Ubuntu 24.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "chacl" command with the following command:

$ sudo audtctl -l | grep chacl
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1',
        })

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

    def test_infers_sles_auditctl_privileged_execve_rules_when_key_is_arbitrary(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234963',
            'title': 'The SUSE operating system must generate audit records for all uses of the privileged functions.',
            'check_content': '''Verify the SUSE operating system generates an audit record for any privileged use of the "execve" system call.

> sudo auditctl -l | grep -w 'execve'

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid

If both the "b32" and "b64" audit rules for "SUID" files are not defined, this is a finding.

If both the "b32" and "b64" audit rules for "SGID" files are not defined, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.'''
        }, 'SLES_15_STIG')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {
            'type': 'contains',
            'substring': '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0\n-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0\n-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0\n-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0',
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

    def test_infers_linux_service_running_candidate_from_systemctl_status_grep_active_pipeline(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-238374',
            'title': 'The Ubuntu operating system must have an application firewall enabled.',
            'check_content': '''Verify the Uncomplicated Firewall is enabled on the system by running the following command:

$ systemctl status ufw.service | grep -i "active:"
Active: active (exited) since Mon 2016-10-17 12:30:29 CDT; 1s ago

If the above command returns the status as "inactive", this is a finding.'''
        }, 'Canonical_Ubuntu_20-04_LTS_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'ufw', 'expected_status': 'running'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'running'})

    def test_infers_kubernetes_stat_grep_root_ownership_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242457',
            'title': 'The Kubernetes kubelet config must be owned by root.',
            'check_content': '''Review the Kubernetes Kubeadm kubelet conf file by using the command:

stat -c %U:%G /var/lib/kubelet/config.yaml| grep -v root:root

If the command returns any non root:root file permissions, this is a finding.'''
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'stat -c %U:%G /var/lib/kubelet/config.yaml| grep -v root:root',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_kubernetes_stat_grep_etcd_ownership_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242445',
            'title': 'The Kubernetes component etcd must be owned by etcd.',
            'check_content': '''Review the ownership of the Kubernetes etcd files by using the command:

stat -c %U:%G /var/lib/etcd/* | grep -v etcd:etcd

If the command returns any non etcd:etcd file permissions, this is a finding.'''
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': 'stat -c %U:%G /var/lib/etcd/* | grep -v etcd:etcd',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

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

    def test_infers_tomcat_temp_permissions_find_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-222990',
            'title': '$CATALINA_BASE/temp folder permissions must be set to 750.',
            'check_content': '''Access the Tomcat server from the command line and execute the following OS command:

sudo find $CATALINA_BASE/temp -follow -maxdepth 0 -type d \\( \\! -perm 750 \\) -ls

If ISSM risk acceptance specifies deviation from requirement based on operational/application needs, this is not a finding if the permissions are set in accordance with the risk acceptance.

If no folders are displayed, this is not a finding.

If results indicate the $CATALINA_BASE/temp folder permissions are not set to 750, this is a finding.'''
        }, 'Tomcat_Application_Server_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-222990',
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'find $CATALINA_BASE/temp -follow -maxdepth 0 -type d \\( \\! -perm 750 \\) -ls',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': '$CATALINA_BASE/temp folder permissions must be set to 750.',
        })

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

    def test_infers_linux_masked_target_status_candidate_when_loaded_value_not_masked_is_finding(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248869',
            'title': 'The x86 Ctrl-Alt-Delete key sequence must be disabled on OL 8.',
            'check_content': '''Verify OL 8 is not configured to reboot the system when Ctrl-Alt-Delete is pressed with the following command:

$ sudo systemctl status ctrl-alt-del.target | grep Loaded:

Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)

If the "ctrl-alt-del.target" Loaded: value is not set to "masked", this is a finding.'''
        }, 'Oracle_Linux_8_STIG')
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

    def test_infers_linux_sshd_config_candidate_from_runtime_dump(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230555',
            'title': 'RHEL 8 remote X connections for interactive users must be disabled unless to fulfill documented and validated operational requirements.',
            'check_content': '''Verify X11Forwarding is disabled with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\\r' | tr '\\n' ' ' | xargs sudo grep -iH '^\\s*x11forwarding'
X11Forwarding no

If the "X11Forwarding" keyword is set to "yes", is missing, or is commented out, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'file_content', 'path': '/etc/ssh/sshd_config', 'pattern': 'X11Forwarding no', 'is_regex': False})
        self.assertEqual(candidate['expected'], {'type': 'contains'})

    def test_infers_linux_sshd_config_candidate_with_multi_token_expected_line(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230527',
            'title': 'RHEL 8 must force a frequent session key renegotiation for SSH connections to the server.',
            'check_content': '''Verify the SSH server is configured to force frequent session key renegotiation with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\\r' | tr '\\n' ' ' | xargs sudo grep -iH '^\\s*rekeylimit'
RekeyLimit 1G 1h

If "RekeyLimit" is not set to "1G 1h", is missing, or is commented out, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'file_content', 'path': '/etc/ssh/sshd_config', 'pattern': 'RekeyLimit 1G 1h', 'is_regex': False})
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

    def test_infers_macos_sshd_fips_count_shell_block_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259438',
            'title': 'The macOS system must limit SSHD to FIPS-compliant connections.',
            'check_content': '''Verify the macOS system is configured to limit SSHD to FIPS-compliant connections with the following command:

fips_sshd_config=("Ciphers aes128-gcm@openssh.com" "HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "KexAlgorithms ecdh-sha2-nistp256" "MACs hmac-sha2-256" "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "CASignatureAlgorithms ecdsa-sha2-nistp256")
total=0
for config in $fips_sshd_config; do
  total=$(expr $(/usr/sbin/sshd -G | /usr/bin/grep -i -c "$config") + $total)
done

echo $total

If the result is not "7", this is a finding.'''
        }, 'Apple_macOS_14_STIG')
        self.assertEqual(candidate['platform'], 'macos')
        self.assertEqual(candidate['check']['type'], 'command_output')
        self.assertTrue(candidate['check']['command'].startswith('fips_sshd_config=("Ciphers aes128-gcm@openssh.com"'))
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '7'})

    def test_skips_macos_sshd_fips_count_shell_block_with_ellipsized_items(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-268438',
            'title': 'The macOS system must limit SSHD to FIPS-compliant connections.',
            'check_content': '''Verify the macOS system is configured to limit SSHD to FIPS-compliant connections with the following command:

fips_sshd_config=("Ciphers aes128-gcm@openssh.com" "HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecd...-v01@openssh.com,ecdsa-sha2-nistp256,sk-ecd...p256@openssh.com" "KexAlgorithms ecdh-sha2-nistp256" "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-256" "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecd...-v01@openssh.com" "CASignatureAlgorithms ecdsa-sha2-nistp256,sk-ecd...p256@openssh.com")
total=0
for config in $fips_sshd_config; do
total=$(expr $(/usr/sbin/sshd -G | /usr/bin/grep -i -c "$config") + $total)
done

echo $total

If the result is not "7", this is a finding.'''
        }, 'Apple_macOS_15_STIG')
        self.assertIsNone(candidate)

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

    def test_infers_public_directory_sticky_bit_find_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-257929',
            'title': 'A sticky bit must be set on all RHEL 9 public directories.',
            'check_content': '''Verify that all world-writable directories have the sticky bit set.

Determine if all world-writable directories have the sticky bit set by running the following command:

$ sudo find / -type d \\( -perm -0002 -a ! -perm -1000 \\) -print 2>/dev/null

If any of the returned directories are world-writable and do not have the sticky bit set, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'find / -type d \\( -perm -0002 -a ! -perm -1000 \\) -print 2>/dev/null'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_pwck_home_directory_no_output_candidate_after_preceding_command(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230323',
            'title': 'All RHEL 8 local interactive user home directories defined in the /etc/passwd file must exist.',
            'check_content': '''Verify the assigned home directory of all local interactive users on RHEL 8 exists with the following command:

$ sudo ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)

drwxr-xr-x 2 smithj admin 4096 Jun 5 12:41 smithj

Check that all referenced home directories exist with the following command:

$ sudo pwck -r

user 'smithj': directory '/home/smithj' does not exist

If any home directories referenced in "/etc/passwd" are returned as not defined, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'pwck -r'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_pwck_home_directory_does_not_exist_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258052',
            'title': 'All RHEL 9 local interactive user home directories defined in the /etc/passwd file must exist.',
            'check_content': '''Verify the assigned home directories of all interactive users on the system exist with the following command:

$ sudo pwck -r

user 'mailnull': directory 'var/spool/mqueue' does not exist

The output should not return any interactive users.

If users home directory does not exist, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'pwck -r'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_pwck_home_directory_assigned_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230320',
            'title': 'All RHEL 8 local interactive users must have a home directory assigned in the /etc/passwd file.',
            'check_content': '''Verify local interactive users on RHEL 8 have a home directory assigned with the following command:

$ sudo pwck -r

user 'lp': directory '/var/spool/lpd' does not exist
user 'news': directory '/var/spool/news' does not exist
user 'uucp': directory '/var/spool/uucp' does not exist
user 'www-data': directory '/var/www' does not exist

Ask the System Administrator (SA) if any users found without home directories are local interactive users. If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command:

$ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd

If any interactive users do not have a home directory assigned, this is a finding.'''
        }, 'RHEL_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'pwck -r'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_pwck_gid_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258048',
            'title': 'All RHEL 9 interactive users must have a primary group that exists.',
            'check_content': '''Verify that all RHEL 9 interactive users have a valid GID.

Check that the interactive users have a valid GID with the following command:

$ sudo pwck -r

If pwck reports "no group" for any interactive user, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'pwck -r'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_pwck_gid_not_defined_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-204461',
            'title': 'The Red Hat Enterprise Linux operating system must be configured so that all Group Identifiers (GIDs) referenced in the /etc/passwd file are defined in the /etc/group file.',
            'check_content': '''Verify all GIDs referenced in the "/etc/passwd" file are defined in the "/etc/group" file.

Check that all referenced GIDs exist with the following command:

# pwck -r

If GIDs referenced in "/etc/passwd" file are returned as not defined in "/etc/group" file, this is a finding.'''
        }, 'RHEL_7_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'pwck -r'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_pwck_quiet_duplicate_gid_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-271834',
            'title': 'OL 9 interactive users must have a primary group that exists.',
            'check_content': '''Verify that OL 9 interactive users have a valid GID.

Check that the interactive users have a valid GID with the following command:

$ sudo pwck -qr

If the system has any interactive users with duplicate GIDs, this is a finding.'''
        }, 'Oracle_Linux_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'pwck -qr'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_no_output_candidate_when_grep_occurrences_return_from_command(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-270707',
            'title': 'Ubuntu 24.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.',
            'check_content': '''Verify the "/etc/sudoers" file has no occurrences of "!authenticate" with the following command:

$ sudo egrep -iR '!authenticate' /etc/sudoers /etc/sudoers.d/

If any occurrences of "!authenticate" return from the command, this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': "egrep -iR '!authenticate' /etc/sudoers /etc/sudoers.d/"})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_no_output_candidate_for_sudoers_nopasswd_documented_exception(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-274868',
            'title': 'Ubuntu 24.04 LTS must require users to provide a password for privilege escalation.',
            'check_content': '''Verify that "/etc/sudoers" has no occurrences of "NOPASSWD" with the following command:

$ sudo egrep -iR 'NOPASSWD' /etc/sudoers /etc/sudoers.d/

If any occurrences of "NOPASSWD" are returned from the command and have not been documented with the information system security officer (ISSO) as an organizationally defined administrative group using multifactor authentication (MFA), this is a finding.'''
        }, 'CAN_Ubuntu_24-04_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': "egrep -iR 'NOPASSWD' /etc/sudoers /etc/sudoers.d/"})
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

    def test_infers_linux_grep_no_output_candidate_when_occurrences_are_returned(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258086',
            'title': 'RHEL 9 must require users to reauthenticate for privilege escalation.',
            'check_content': '''Verify that "/etc/sudoers" has no occurrences of "!authenticate" with the following command:

$ sudo egrep -iR '!authenticate' /etc/sudoers /etc/sudoers.d/

If any occurrences of "!authenticate" are returned, this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': "egrep -iR '!authenticate' /etc/sudoers /etc/sudoers.d/"})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

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

    def test_infers_oracle_linux_private_host_key_mode_candidate_from_ls_alL(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248602',
            'title': 'The OL 8 SSH private host key files must have mode "0640" or less permissive.',
            'check_content': '''Verify the SSH private host key files have mode "0640" or less permissive with the following command:

$ sudo ls -alL /etc/ssh/ssh_host*key
-rw-r----- 1 root wheel 668 Nov 28 06:43 ssh_host_dsa_key
-rw-r----- 1 root wheel 582 Nov 28 06:43 ssh_host_key
-rw-r----- 1 root wheel 887 Nov 28 06:43 ssh_host_rsa_key

If any private host key file has a mode more permissive than "0640", this is a finding.'''
        }, 'Oracle_Linux_8_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'find -L /etc/ssh -maxdepth 1 -type f -name \'ssh_host*key\' -perm /137 -exec stat -c "%n %a" {} \\;'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_linux_audit_rules_file_cat_grep_expected_rule_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258214',
            'title': 'Successful/unsuccessful uses of the shutdown command in RHEL 9 must generate an audit record.',
            'check_content': '''Verify that RHEL 9 is configured to audit the execution of the "shutdown" command with the following command:

$ sudo cat /etc/audit/rules.d/* | grep shutdown
-a always,exit -S all -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-shutdown

If the command does not return a line, or the line is commented out, this is a finding.''',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'cat /etc/audit/rules.d/* | grep shutdown'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': '-a always,exit -S all -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-shutdown'})

    def test_infers_tomcat_auditctl_base_conf_candidate_when_check_greps_home_conf(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-222999',
            'title': 'Changes to $CATALINA_BASE/conf/ folder must be logged.',
            'check_content': '''Check the audit rules for the Tomcat folders. Run the following command from the Tomcat server as a privileged user:

sudo auditctl -l | grep $CATALINA_HOME/conf

If the results do not include "-w $CATALINA_BASE/conf -p wa -k tomcat" or if there are no results, this is a finding.'''
        }, 'Tomcat_Application_Server_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-222999',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'auditctl -l'},
            'expected': {'type': 'contains', 'substring': '-w $CATALINA_BASE/conf -p wa -k tomcat'},
            'description': 'Changes to $CATALINA_BASE/conf/ folder must be logged.',
        })

    def test_infers_tomcat_auditctl_expected_rule_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-222998',
            'title': 'Changes to $CATALINA_HOME/bin/ folder must be logged.',
            'check_content': '''Check the audit rules for the Tomcat folders. Run the following command from the Tomcat server as a privileged user:

sudo auditctl -l | grep $CATALINA_HOME/bin

If the results do not include "-w $CATALINA_HOME/bin -p wa -k tomcat" or if there are no results, this is a finding.''',
        }, 'Tomcat_Application_Server_9_STIG')
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': '-w $CATALINA_HOME/bin -p wa -k tomcat'})

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

    def test_infers_windows_deny_service_logon_blank_user_right_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254423',
            'title': 'Windows Server 2022 Deny log on as a service user right must be configured to include no accounts or groups.',
            'check_content': '''Verify the effective setting in Local Group Policy Editor.

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are defined for the "Deny log on as a service" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs are granted the "SeDenyServiceLogonRight" user right, this is a finding.''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on as a service" to include no entries (blank).''',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeDenyServiceLogonRight'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_windows_user_right_fixed_service_account_allowlist_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-253487',
            'title': 'The "Create global objects" user right must only be assigned to Administrators, Service, Local Service, and Network Service.',
            'check_content': '''Verify the effective setting in Local Group Policy Editor.

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Create global objects" user right, this is a finding:

Administrators
LOCAL SERVICE
NETWORK SERVICE
SERVICE''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create global objects" to only include the following groups or accounts:

Administrators
LOCAL SERVICE
NETWORK SERVICE
SERVICE''',
        }, 'Microsoft_Windows_11_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeCreateGlobalPrivilege'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6'})

    def test_infers_windows_user_right_change_system_time_local_service_allowlist_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-253484',
            'title': 'The "Change the system time" user right must only be assigned to Administrators and Local Service.',
            'check_content': '''Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Change the system time" user right, this is a finding:

Administrators
LOCAL SERVICE''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Change the system time" to only include the following groups or accounts:

Administrators
LOCAL SERVICE''',
        }, 'Microsoft_Windows_11_STIG')
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeSystemtimePrivilege'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '*S-1-5-32-544,*S-1-5-19'})

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

    def test_infers_windows_kerberos_policy_enabled_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254386',
            'title': 'Windows Server 2022 Kerberos user logon restrictions must be enforced.',
            'check_content': '''This applies to domain controllers. It is NA for other systems.

Verify the following is configured in the Default Domain Policy:

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the "Enforce user logon restrictions" is not set to "Enabled", this is a finding.''',
            'fix_text': 'Configure the policy value in the Default Domain Policy for Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> Enforce user logon restrictions to "Enabled".',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Kerberos Policy', 'key': 'Enforce user logon restrictions'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'Enabled'})

    def test_infers_windows_kerberos_policy_enabled_candidate_without_the_before_policy_name(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278133',
            'title': 'Windows Server 2025 Kerberos user logon restrictions must be enforced.',
            'check_content': '''This applies to domain controllers. It is not applicable for other systems.

Verify the following is configured in the Default Domain Policy:

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If "Enforce user logon restrictions" is not set to "Enabled", this is a finding.''',
            'fix_text': 'Configure the policy value in the Default Domain Policy for Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> Enforce user logon restrictions to "Enabled".',
        }, 'MS_Windows_Server_2025_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Kerberos Policy', 'key': 'Enforce user logon restrictions'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'Enabled'})

    def test_infers_windows_kerberos_policy_less_or_equal_candidate_from_fix_text(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254389',
            'title': 'Windows Server 2022 Kerberos policy user ticket renewal maximum lifetime must be limited to seven days or less.',
            'check_content': '''This applies to domain controllers. It is NA for other systems.

Verify the following is configured in the Default Domain Policy:

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the "Maximum lifetime for user ticket renewal" is greater than "7" days, this is a finding.''',
            'fix_text': 'Configure the policy value in the Default Domain Policy for Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> Maximum lifetime for user ticket renewal to a maximum of "7" days or less.',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Kerberos Policy', 'key': 'Maximum lifetime for user ticket renewal'})
        self.assertEqual(candidate['expected'], {'type': 'less_or_equal', 'value': 7})

    def test_infers_windows_kerberos_policy_nonzero_upper_bound_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254388',
            'title': 'Windows Server 2022 Kerberos user ticket lifetime must be limited to 10 hours or less.',
            'check_content': '''Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the value for "Maximum lifetime for user ticket" is "0" or greater than "10" hours, this is a finding.''',
            'fix_text': 'Configure the policy value in the Default Domain Policy for Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> Maximum lifetime for user ticket to a maximum of "10" hours but not "0", which equates to "Ticket doesn\'t expire".',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Kerberos Policy', 'key': 'Maximum lifetime for user ticket'})
        self.assertEqual(candidate['expected'], {'type': 'matches', 'pattern': '^(?:1|2|3|4|5|6|7|8|9|10)$'})

    def test_infers_linux_nmcli_wireless_interface_absent_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248842',
            'title': 'OL 8 wireless network adapters must be disabled.',
            'check_content': '''Verify there are no wireless interfaces configured on the system with the following command.

$ sudo nmcli device status

DEVICE TYPE STATE CONNECTION
virbr0 bridge connected virbr0
wlp7s0 wifi connected wifiSSID
enp6s0 ethernet disconnected --

If a wireless interface is configured and has not been documented and approved by the Information System Security Officer (ISSO), this is a finding.''',
            'fix_text': 'Configure the system to disable all wireless network interfaces.',
        }, 'Oracle_Linux_8_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': "nmcli -t -f TYPE device status | grep -Fx 'wifi'"})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_linux_ftp_server_package_glob_absent_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230558',
            'title': 'A File Transfer Protocol (FTP) server package must not be installed unless mission essential on RHEL 8.',
            'check_content': '''Verify an FTP server has not been installed on the system with the following commands:

$ sudo yum list installed *ftpd*

vsftpd.x86_64                                                     3.0.3-28.el8                                                  appstream

If an FTP server is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.''',
            'fix_text': 'Document the FTP server package with the ISSO as an operational requirement or remove it from the system with the following command:\n\n$ sudo yum remove vsftpd',
        }, 'RHEL_8_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'yum list installed *ftpd*'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_linux_ftp_server_package_pipeline_absent_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248903',
            'title': 'A File Transfer Protocol (FTP) server package must not be installed unless mission essential on OL 8.',
            'check_content': '''Verify an FTP server has not been installed on the system with the following commands:

$ sudo yum list installed | grep ftpd

vsftpd-3.0.3.el8.x86_64.rpm

If an FTP server is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.''',
            'fix_text': 'Remove the FTP server package from the system with the following command:\n\n$ sudo yum remove vsftpd',
        }, 'Oracle_Linux_8_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'yum list installed | grep ftpd'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_postgresql_session_timeout_keepalive_nonzero_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233606',
            'title': 'PostgreSQL must invalidate session identifiers upon user logout or other session termination.',
            'check_content': '''As the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW tcp_keepalives_idle"
$ psql -c "SHOW tcp_keepalives_interval"
$ psql -c "SHOW tcp_keepalives_count"
$ psql -c "SHOW statement_timeout"

If these settings are not set to something other than zero, this is a finding.''',
            'fix_text': '''Set the following parameters to organizational requirements:

statement_timeout = 10000 #milliseconds
tcp_keepalives_idle = 10 # seconds
tcp_keepalives_interval = 10 # seconds
tcp_keepalives_count = 10''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check']['type'], 'command_output')
        self.assertIn('tcp_keepalives_idle', candidate['check']['command'])
        self.assertIn('statement_timeout', candidate['check']['command'])
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_postgresql_log_line_prefix_required_tokens_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233578',
            'title': 'PostgreSQL must produce audit records containing sufficient information to establish where the events occurred.',
            'check_content': '''First, as the database administrator (shown here as "postgres"), check the current log_line_prefix setting by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_line_prefix"

If log_line_prefix does not contain "%m %u %d %s", this is a finding.''',
            'fix_text': 'Set log_line_prefix = "< %m %u %d %s >" in postgresql.conf.',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check']['type'], 'command_output')
        self.assertIn('log_line_prefix', candidate['check']['command'])
        self.assertIn('%m %u %d %s', candidate['check']['command'])
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_postgresql_log_line_prefix_identity_tokens_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-233582',
            'title': 'PostgreSQL must produce audit records containing sufficient information to establish the identity of any user/subject or process associated with the event.',
            'check_content': '''Check PostgreSQL settings and existing audit records to verify a user name associated with the event is being captured and stored with the audit records. If audit records exist without specific user information, this is a finding.

First, as the database administrator (shown here as "postgres"), verify the current setting of log_line_prefix by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_line_prefix"

If log_line_prefix does not contain %m, %u, %d, %p, %r, %a, this is a finding.''',
            'fix_text': '''To enable username, database name, process ID, remote host/port and application name in logging, as the database administrator (shown here as "postgres"), edit the following in postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_line_prefix = '< %m %u %d %p %r %a >'

Now, as the system administrator, reload the server with the new configuration.''',
        }, 'Crunchy_Data_PostgreSQL_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'generic')
        self.assertEqual(candidate['check']['type'], 'command_output')
        self.assertIn('log_line_prefix', candidate['check']['command'])
        self.assertIn('%m %u %d %p %r %a', candidate['check']['command'])
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

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

    def test_infers_windows_rename_administrator_security_option_not_equals_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278197',
            'title': 'The Windows Server 2025 built-in administrator account must be renamed.',
            'check_content': '''This applies to member servers and stand-alone or nondomain-joined systems; it is not applicable for domain controllers.

Verify the effective setting in Local Group Policy Editor. Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Rename administrator account" is not set to a value other than "Administrator", this is a finding.

For server core installations, run the following command:
Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "NewAdministratorName" is not something other than "Administrator" in the file, this is a finding.''',
            'fix_text': 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Accounts: Rename administrator account to a name other than "Administrator".',
        }, 'MS_Windows_Server_2025_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Security Options', 'key': 'Accounts: Rename administrator account'})
        self.assertEqual(candidate['expected'], {'type': 'not_equals', 'value': 'Administrator'})

    def test_infers_windows_rename_guest_security_option_from_scap_fix_text_only(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'xccdf_mil.disa.stig_group_V-254448',
            'title': 'Windows Server 2022 built-in guest account must be renamed.',
            'check_content': '',
            'fix_text': 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Accounts: Rename guest account to a name other than "Guest".',
        }, 'scap_mil.disa.stig_collection_U_MS_Windows_Server_2022_V2R8_STIG_SCAP_1-3_Benchmark')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Security Options', 'key': 'Accounts: Rename guest account'})
        self.assertEqual(candidate['expected'], {'type': 'not_equals', 'value': 'Guest'})

    def test_infers_windows_administrators_only_user_right_when_check_says_right(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-254420',
            'title': 'Windows Server 2022 Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group on domain controllers.',
            'check_content': '''Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on through Remote Desktop Services" right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeRemoteInteractiveLogonRight" user right, this is a finding.

S-1-5-32-544 (Administrators)''',
            'fix_text': '''Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Allow log on through Remote Desktop Services to include only the following accounts or groups:

- Administrators''',
        }, 'MS_Windows_Server_2022_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {'type': 'security_policy', 'section': 'Privilege Rights', 'key': 'SeRemoteInteractiveLogonRight'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': '*S-1-5-32-544'})

    def test_infers_linux_auditctl_arbitrary_key_multiline_match_examples_output(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234913',
            'title': 'The SUSE operating system must audit all uses of the sudoers file and all files in the /etc/sudoers.d/ directory.',
            'check_content': '''Verify the operating system generates audit records when successful/unsuccessful attempts to access the "/etc/sudoers" file and files in the "/etc/sudoers.d/" directory.

Check that the file and directory is being audited by performing the following command:

> sudo auditctl -l | grep -w '/etc/sudoers'

-w /etc/sudoers -p wa -k privileged-actions
-w /etc/sudoers.d -p wa -k privileged-actions

If the commands do not return output that match the examples, this is a finding.

Notes:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.'''
        }, 'SLES_15_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'auditctl -l'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': '-w /etc/sudoers -p wa\n-w /etc/sudoers.d -p wa'})

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

    def test_infers_linux_epel_repolist_no_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230492',
            'title': 'RHEL 8 must not install packages from the Extra Packages for Enterprise Linux (EPEL) repository.',
            'check_content': '''Verify that RHEL 8 is not able to install packages from the EPEL with the following command:

$ dnf repolist
rhel-8-for-x86_64-appstream-rpms                      Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
rhel-8-for-x86_64-baseos-rpms                         Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)

If any repositories containing the word "epel" in the name exist, this is a finding.''',
        }, 'RHEL_8_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'dnf repolist | grep -i epel'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})

    def test_infers_duplicate_uid_zero_root_only_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258059',
            'title': 'The root account must be the only account having unrestricted access to RHEL 9 system.',
            'check_content': '''Verify that only the "root" account has a UID "0" assignment with the following command:

$ awk -F: '$3 == 0 {print $1}' /etc/passwd

root

If any accounts other than "root" have a UID of "0", this is a finding.'''
        }, 'RHEL_9_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': "awk -F: '$3 == 0 {print $1}' /etc/passwd",
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'root'})

    def test_infers_office_registry_reg_sz_exact_value_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223292',
            'title': 'Office applications must be configured to specify encryption type in password-protected Office Open XML files.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings >> Encryption type for password protected Office Open XML files is set to Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256.

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\security

If the value OpenXMLEncryption is REG_SZ = "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256", this is not a finding.''',
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {
            'type': 'registry',
            'path': 'HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\security',
            'value_name': 'OpenXMLEncryption',
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'})

    def test_infers_office_registry_dword_greater_or_equal_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-223356',
            'title': 'The minimum encryption key length in Outlook must be at least 168.',
            'check_content': '''Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Cryptography >> Minimum encryption settings is set to "Enabled" and a Minimum key size (in bits) of "168" or above.

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for minenckey is set to 168 or above, this is not a finding.''',
        }, 'MS_Office_365_ProPlus_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'windows')
        self.assertEqual(candidate['check'], {
            'type': 'registry',
            'path': 'HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security',
            'value_name': 'minenckey',
        })
        self.assertEqual(candidate['expected'], {'type': 'matches', 'pattern': '^(?:1(?:6[8-9]|[7-9]\\d)|[2-9]\\d{2,}|\\d{4,})$'})

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


    def test_infers_find_nouser_pipeline_as_empty_command_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-230326',
            'title': 'All RHEL 8 local files and directories must have a valid owner.',
            'check_content': '''Verify all files and directories on RHEL 8 have a valid owner with the following command:

$ df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nouser

If any files on the system do not have an assigned owner, this is a finding.''',
        }, 'RHEL_8_STIG')

        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {
            'type': 'command_output',
            'command': "df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nouser",
        })
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': ''})


    def test_infers_macos_osascript_true_heredoc_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259420',
            'title': 'The macOS system must enforce session lock no more than five seconds after screen saver is started.',
            'check_content': '''Verify the macOS system is configured to initiate a session lock within five seconds of the screen saver starting with the following command:

/usr/bin/osascript -l JavaScript << EOS
function run() {
  let delay = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\\
.objectForKey('askForPasswordDelay'))
  if ( delay <= 5 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS

If the result is not "true", this is a finding.'''
        }, 'Apple_macOS_14_STIG')

        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'macos')
        self.assertEqual(candidate['check']['type'], 'command_output')
        self.assertTrue(candidate['check']['command'].startswith('/usr/bin/osascript -l JavaScript << EOS'))
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'true'})


    def test_infers_kubernetes_kubelet_hostname_override_absent_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242404',
            'title': 'Kubernetes Kubelet must deny hostname override.',
            'check_content': '''On the Control Plane and Worker nodes, run the command:
ps -ef | grep kubelet

If the option "--hostname-override" is present, this is a finding.''',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242404',
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': "ps -ef | grep '[k]ubelet' | grep -- '--hostname-override'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'Kubernetes Kubelet must deny hostname override.',
        })


    def test_infers_oracle_linux_vlock_binary_literal_output_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248678',
            'title': 'OL 8 must enable a user session lock until that user reestablishes access using established identification and authentication procedures for command line sessions.',
            'check_content': '''Verify OL 8 has the "vlock" package installed by running the following command:

$ sudo grep vlock /usr/bin/*

Binary file /usr/bin/vlock matches

If "vlock" is not installed, this is a finding.''',
            'fix_text': '''Install the "vlock" package, if it is not already installed, by running the following command:

$ sudo yum install kbd.x86_64''',
        }, 'Oracle_Linux_8_STIG')
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['platform'], 'linux')
        self.assertEqual(candidate['check'], {'type': 'command_output', 'command': 'grep vlock /usr/bin/*'})
        self.assertEqual(candidate['expected'], {'type': 'contains', 'substring': 'Binary file /usr/bin/vlock matches'})


    def test_infers_windows_run_as_different_user_context_menu_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-220801',
            'title': 'Run as different user must be removed from context menus.',
            'check_content': '''If the following registry values do not exist or are not configured as specified, this is a finding.
The policy configures the same Value Name, Type and Value under four different registry paths.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Paths:
\\SOFTWARE\\Classes\\batfile\\shell\\runasuser\\
\\SOFTWARE\\Classes\\cmdfile\\shell\\runasuser\\
\\SOFTWARE\\Classes\\exefile\\shell\\runasuser\\
\\SOFTWARE\\Classes\\mscfile\\shell\\runasuser\\

Value Name:  SuppressionPolicy

Type:  REG_DWORD
Value:  0x00001000 (4096)''',
            'fix_text': 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Remove "Run as Different User" from context menus" to "Enabled".',
        }, 'MS_Windows_10_STIG')
        command = "powershell -NoProfile -Command \"$paths=@('HKLM:\\SOFTWARE\\Classes\\batfile\\shell\\runasuser','HKLM:\\SOFTWARE\\Classes\\cmdfile\\shell\\runasuser','HKLM:\\SOFTWARE\\Classes\\exefile\\shell\\runasuser','HKLM:\\SOFTWARE\\Classes\\mscfile\\shell\\runasuser'); if (($paths | Where-Object { (Get-ItemProperty -Path $_ -Name SuppressionPolicy -ErrorAction SilentlyContinue).SuppressionPolicy -eq 4096 }).Count -eq 4) { 'Compliant' }\""
        self.assertEqual(candidate, {
            'vuln_id': 'V-220801',
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'Run as different user must be removed from context menus.',
        })

    def test_infers_linux_sssd_certmap_mapping_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-258132',
            'title': 'RHEL 9 must map the authenticated identity to the user or group account for PKI-based authentication.',
            'check_content': '''Verify the certificate of the user or group is mapped to the corresponding user or group in the "sssd.conf" file with the following command:

$ sudo find /etc/sssd/sssd.conf /etc/sssd/conf.d/ -type f -exec cat {} \\;

[certmap/testing.test/rule_name]
matchrule =<SAN>.*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

If the certmap section does not exist, ask the system administrator (SA) to indicate how certificates are mapped to accounts.
If there is no evidence of certificate mapping, this is a finding.''',
            'fix_text': '''Configure RHEL 9 to map the authenticated identity to the user or group account by adding or modifying the certmap section of the "/etc/sssd/sssd.conf" file based on the following example:

[certmap/testing.test/rule_name]
matchrule = .*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test''',
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-258132',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/sssd/sssd.conf /etc/sssd/conf.d/ -type f -exec cat {} \\; 2>/dev/null',
            },
            'expected': {'type': 'contains', 'substring': 'maprule = (userCertificate;binary={cert!bin})'},
            'description': 'RHEL 9 must map the authenticated identity to the user or group account for PKI-based authentication.',
        })

    def test_infers_systemctl_status_active_sample_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234848',
            'title': 'SUSE operating system AppArmor tool must be configured to control whitelisted applications and user home directory access control.',
            'check_content': '''Check that the "apparmor" daemon is running with the following command:

> systemctl status apparmor.service | grep -i active

Active: active (exited) since Fri 2017-01-13 01:01:01 GMT; 1day 1h ago

If something other than "Active: active" is returned, this is a finding.''',
            'fix_text': 'Enable/activate "Apparmor" and start the service with systemctl start apparmor.service.',
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-234848',
            'platform': 'linux',
            'check': {'type': 'service', 'name': 'apparmor', 'expected_status': 'running'},
            'expected': {'type': 'equals', 'value': 'running'},
            'description': 'SUSE operating system AppArmor tool must be configured to control whitelisted applications and user home directory access control.',
        })

    def test_infers_apache_windows_required_modules_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-214307',
            'title': 'The Apache web server must perform server-side session management.',
            'check_content': '''In a command line, navigate to "<'INSTALLED PATH'>\\bin". Run "httpd -M" to view a list of installed modules.

If "mod_session" module and "mod_usertrack" are not enabled, this is a finding.

session_module (shared)
usertrack_module (shared)''',
            'fix_text': '''Uncomment the "usertrack_module" module line and the "session_module" module in the <'INSTALL PATH'>\\conf\\httpd.conf file.

Restart the Apache service.''',
        }, 'Apache_Server_2-4_Windows_Server_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-214307',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$m=& httpd -M 2>$null; if (($m -match 'session_module') -and ($m -match 'usertrack_module')) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The Apache web server must perform server-side session management.',
        })

    def test_infers_apache_windows_forbidden_webdav_modules_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-214325',
            'title': 'The Apache web server must have Web Distributed Authoring (WebDAV) disabled.',
            'check_content': '''In a command line, navigate to "<'INSTALLED PATH'>\\bin". Run "httpd -M" to view a list of installed modules.

If any of the following modules are present, this is a finding:

dav_module
dav_fs_module
dav_lock_module''',
            'fix_text': '''Edit the <'INSTALL PATH'>\\conf\\httpd.conf file and remove the following modules:

dav_module
dav_fs_module
dav_lock_module''',
        }, 'Apache_Server_2-4_Windows_Server_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-214325',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$m=& httpd -M 2>$null; if (($m -notmatch 'dav_module') -and ($m -notmatch 'dav_fs_module') -and ($m -notmatch 'dav_lock_module')) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The Apache web server must have Web Distributed Authoring (WebDAV) disabled.',
        })

    def test_infers_sles_interactive_home_nosuid_findmnt_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-234998',
            'title': 'SUSE operating system file systems that contain user home directories must be mounted to prevent files with the setuid and setgid bit set from being executed.',
            'check_content': '''Verify that SUSE operating system file systems that contain user home directories are mounted with the "nosuid" option.

Print the currently active file system mount options of the file system(s) that contain the user home directories with the following command:

> for X in `awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd`; do findmnt -nkT $X; done | sort -r
/home /dev/mapper/system-home ext4 rw,nosuid,relatime,data=ordered

If a file system containing user home directories is not mounted with the FSTYPE OPTION nosuid, this is a finding.

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is not a finding as the "nosuid" option cannot be used on the "/" system.''',
            'fix_text': '''Configure the SUSE operating system "/etc/fstab" file to use the "nosuid" option on file systems that contain user home directories for interactive users.

Re-mount the filesystems.

> sudo mount -o remount /home''',
        }, 'SLES_15_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-234998',
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'awk -F: \'($3>=1000)&&($7 !~ /nologin/){print $6}\' /etc/passwd | while IFS= read -r home; do [ "$home" = "/" ] && continue; findmnt -nkT "$home"; done | awk \'$1 != "/" && $4 !~ /(^|,)nosuid(,|$)/ {print}\'',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': 'SUSE operating system file systems that contain user home directories must be mounted to prevent files with the setuid and setgid bit set from being executed.',
        })

    def test_infers_apache_windows_sslcompression_absent_or_off_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-214355',
            'title': 'The Apache web server cookies, such as session cookies, sent to the client using SSL/TLS must not be compressed.',
            'check_content': '''Search the Apache configuration files for the "SSLCompression" directive.

If the "SSLCompression" directive does not exist, this is a not a finding.

If the "SSLCompression" directive exists and is not set to "Off", this is a finding.''',
            'fix_text': 'Edit the <\'INSTALL PATH\'>\\conf\\httpd.conf file and set the SSLCompression directive to Off.',
        }, 'Apache_Server_2-4_Windows_Server_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-214355',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$p=Join-Path $env:ProgramFiles 'Apache24\\conf\\httpd.conf'; $lines=Select-String -Path $p -Pattern '^\\s*SSLCompression\\b' -ErrorAction SilentlyContinue; if ((-not $lines) -or ($lines | Where-Object { $_.Line -match '^\\s*SSLCompression\\s+off\\s*(?:#.*)?$' })) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The Apache web server cookies, such as session cookies, sent to the client using SSL/TLS must not be compressed.',
        })

    def test_infers_apache_windows_mod_unique_id_httpd_conf_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-214333',
            'title': 'The Apache web server must accept only system-generated session identifiers.',
            'check_content': '''Review the <'INSTALL PATH'>\\conf\\httpd.conf file.

Verify the "mod_unique_id" is loaded.

If it does not exist, this is a finding.''',
            'fix_text': 'Uncomment the unique_id_module module line in the <\'INSTALL PATH\'>\\conf\\httpd.conf file.',
        }, 'Apache_Server_2-4_Windows_Server_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-214333',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$p=Join-Path $env:ProgramFiles 'Apache24\\conf\\httpd.conf'; $line=Select-String -Path $p -Pattern '^\\s*LoadModule\\s+unique_id_module\\b.*mod_unique_id' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($line) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'The Apache web server must accept only system-generated session identifiers.',
        })

    def test_infers_kubernetes_kubelet_configuration_owner_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242406',
            'title': 'The Kubernetes KubeletConfiguration file must be owned by root.',
            'check_content': '''ps -ef | grep kubelet

Check the config file (path identified by: --config):

Change to the directory identified by --config and run:
ls -l kubelet

Each kubelet configuration file must be owned by root:root.

If any manifest file is not owned by root:root, this is a finding.''',
            'fix_text': 'Change ownership of the KubeletConfiguration file to root:root.',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242406',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "sh -c 'cfg=$(ps -ef | sed -n \"s/.*--config[= ]\\([^ ]*\\).*/\\1/p\" | head -n 1); [ -z \"$cfg\" ] && exit 0; path=\"$cfg\"; [ -d \"$cfg\" ] && path=\"$cfg/kubelet\"; stat -c \"%U:%G %n\" \"$path\" 2>/dev/null | grep -v \"^root:root \"'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Kubernetes KubeletConfiguration file must be owned by root.',
        })

    def test_infers_kubernetes_kubelet_configuration_mode_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-242407',
            'title': 'The Kubernetes KubeletConfiguration files must have file permissions set to 644 or more restrictive.',
            'check_content': '''ps -ef | grep kubelet

Check the config file (path identified by: --config):

Change to the directory identified by --config and run:
ls -l kubelet

Each KubeletConfiguration file must have permissions of "644" or more restrictive.

If any KubeletConfiguration file is less restrictive than "644", this is a finding.''',
            'fix_text': 'Change permissions of the KubeletConfiguration file to 644 or more restrictive.',
        }, 'Kubernetes_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-242407',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "sh -c 'cfg=$(ps -ef | sed -n \"s/.*--config[= ]\\([^ ]*\\).*/\\1/p\" | head -n 1); [ -z \"$cfg\" ] && exit 0; path=\"$cfg\"; [ -d \"$cfg\" ] && path=\"$cfg/kubelet\"; find \"$path\" -perm /133 -exec stat -c \"%a %n\" {} \\; 2>/dev/null'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'The Kubernetes KubeletConfiguration files must have file permissions set to 644 or more restrictive.',
        })

    def test_infers_tomcat_web_xml_boolean_param_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-222954',
            'title': 'DefaultServlet directory listings parameter must be disabled.',
            'check_content': '''From the Tomcat server run the following OS command:

sudo cat $CATALINA_BASE/conf/web.xml |grep -i -A10 -B2 defaultservlet

The above command will include ten lines after and two lines before the occurrence of "defaultservlet". Some systems may require that the user increase the after number (A10) in order to determine the "listings" param-value.

If the "listings" param-value for the "DefaultServlet" servlet class does not = "false", this is a finding.''',
            'fix_text': 'change the "listings" <param-value> to read "false".',
        }, 'Tomcat_Application_Server_9_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-222954',
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'grep -i -A10 -B2 defaultservlet $CATALINA_BASE/conf/web.xml'},
            'expected': {'type': 'contains', 'substring': '<param-name>listings</param-name>\n<param-value>false</param-value>'},
            'description': 'DefaultServlet directory listings parameter must be disabled.',
        })

    def test_infers_windows_bluetooth_support_service_disabled_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-278018',
            'title': 'Windows Server 2025 must not have Bluetooth enabled unless required by the organization.',
            'check_content': 'In the Windows search bar, type "Services". In the Services "Name" column look for the "Bluetooth Support Service". If this is set to "automatic", this is a finding.',
            'fix_text': 'In the Services "Name " column, look for the "Bluetooth Support Service" and set this to "Disabled".',
        }, 'MS_Windows_Server_2025_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-278018',
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$svc=Get-CimInstance Win32_Service -Filter \\\"Name='bthserv'\\\" -ErrorAction SilentlyContinue; if (-not $svc -or $svc.StartMode -eq 'Disabled' -or $svc.StartMode -eq 'Manual') { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': 'Windows Server 2025 must not have Bluetooth enabled unless required by the organization.',
        })

    def test_infers_oracle_linux_mitigations_not_off_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-248593',
            'title': 'OL 8 must not let Meltdown and Spectre exploit critical vulnerabilities in modern processors.',
            'check_content': '''Verify OL 8 is configured to enable mitigations with the following command:

$ grubby --info=/boot/vmlinuz-$(uname -r) | grep mitigations

If the "mitigations" parameter is set to "off" (mitigations=off), this is a finding.

Note: The default behavior of the kernel is to enable mitigations for vulnerabilities like Meltdown and Spectre based on hardware and system requirements. Therefore, if the "mitigation" parameter is not present or if it is set to on this is not a finding.''',
            'fix_text': 'Using the default kernel, remove the argument that sets the Meltdown mitigations to "off": grubby --update-kernel=<path-to-default-kernel> --remove-args=mitigations=off',
        }, 'Oracle_Linux_8_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-248593',
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "sh -c \"grubby --info=/boot/vmlinuz-$(uname -r) 2>/dev/null | grep -o 'mitigations=off' || true\""},
            'expected': {'type': 'equals', 'value': ''},
            'description': 'OL 8 must not let Meltdown and Spectre exploit critical vulnerabilities in modern processors.',
        })

    def test_infers_vcenter_lookup_security_listener_candidate(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-259042',
            'title': 'The vCenter Lookup service must limit privileges for creating or modifying hosted application shared files.',
            'check_content': '''At the command prompt, run the following command:

# xmllint --xpath '/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]' /usr/lib/vmware-lookupsvc/conf/server.xml

If the "org.apache.catalina.security.SecurityListener" listener is not present, this is a finding.

If the "org.apache.catalina.security.SecurityListener" listener is configured with a "minimumUmask" and is not "0007", this is a finding.''',
            'fix_text': '''Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Navigate to the <Server> node and add or update the "org.apache.catalina.security.SecurityListener" as follows:

<Listener className="org.apache.catalina.security.SecurityListener"/>''',
        }, 'VMW_vSphere_8-0_VCSA_Lookup_Svc_STIG')
        self.assertEqual(candidate, {
            'vuln_id': 'V-259042',
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': "sh -c \"xmllint --xpath '/Server/Listener[@className=\\\"org.apache.catalina.security.SecurityListener\\\"]' /usr/lib/vmware-lookupsvc/conf/server.xml >/dev/null 2>&1 || exit 0; umask=$(xmllint --xpath 'string(/Server/Listener[@className=\\\"org.apache.catalina.security.SecurityListener\\\"]/@minimumUmask)' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null); { [ -z \\\"$umask\\\" ] || [ \\\"$umask\\\" = 0007 ]; } && printf PASS\""},
            'expected': {'type': 'equals', 'value': 'PASS'},
            'description': 'The vCenter Lookup service must limit privileges for creating or modifying hosted application shared files.',
        })

if __name__ == '__main__':
    unittest.main()
