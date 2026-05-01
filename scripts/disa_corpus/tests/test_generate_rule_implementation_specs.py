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

    def test_skips_linux_auditctl_multiline_rules_when_key_is_arbitrary(self):
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
        self.assertIsNone(candidate)

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

    def test_infers_linux_service_disabled_candidate_from_systemctl_content(self):
        candidate = mod.infer_candidate_check({
            'vuln_id': 'V-251234',
            'title': 'RHEL must not have the telnet service enabled.',
            'check_content': 'Verify the telnet service is disabled with the following command: $ systemctl is-enabled telnet.service If the service is enabled, this is a finding.'
        }, 'RHEL_9_STIG')
        self.assertEqual(candidate['check'], {'type': 'service', 'name': 'telnet', 'expected_status': 'disabled'})
        self.assertEqual(candidate['expected'], {'type': 'equals', 'value': 'disabled'})

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


if __name__ == '__main__':
    unittest.main()
