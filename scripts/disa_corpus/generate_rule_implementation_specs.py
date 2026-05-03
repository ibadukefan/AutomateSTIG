#!/usr/bin/env python3
"""Generate planned implementation specs for unsupported authoritative DISA rules."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import extract_xccdf_inventory

MANUAL_HINTS = (
    'document', 'documented', 'documentation', 'approval', 'approve', 'policy',
    'procedure', 'procedures', 'process', 'reviewed', 'organization-defined',
    'system owner', 'isso', 'issm', 'authorizing official', 'written',
)
WINDOWS_HINTS = ('windows', 'registry', 'powershell', 'group policy', 'audit policy', 'event log')
LINUX_HINTS = ('rhel', 'linux', 'sshd', 'systemd', 'rpm', 'yum', 'dnf', 'auditd', 'sysctl')
NETWORK_HINTS = ('router', 'switch', 'firewall', 'cisco', 'interface', 'acl', 'snmp')


def slug(value: str) -> str:
    value = re.sub(r'[^A-Za-z0-9._-]+', '_', value.strip().lower()).strip('._-')
    return value or 'unknown'


def classify_rule(title: str) -> tuple[str, str]:
    lower = title.lower()
    if any(hint in lower for hint in MANUAL_HINTS):
        return 'manual', 'manual_evidence_workflow'
    if any(hint in lower for hint in WINDOWS_HINTS):
        return 'automated', 'windows_collector'
    if any(hint in lower for hint in LINUX_HINTS):
        return 'automated', 'linux_collector'
    if any(hint in lower for hint in NETWORK_HINTS):
        return 'automated', 'network_config_collector'
    return 'automated', 'platform_collector'


def _registry_hive_abbrev(hive: str) -> str:
    normalized = re.sub(r'[^A-Z_]', '', hive.upper())
    return {
        'HKEY_LOCAL_MACHINE': 'HKLM',
        'HKLM': 'HKLM',
        'HKEY_CURRENT_USER': 'HKCU',
        'HKCU': 'HKCU',
        'HKEY_CLASSES_ROOT': 'HKCR',
        'HKCR': 'HKCR',
        'HKEY_USERS': 'HKU',
        'HKU': 'HKU',
        'HKEY_CURRENT_CONFIG': 'HKCC',
        'HKCC': 'HKCC',
    }.get(normalized, hive.strip())


def _registry_value(check_content: str):
    match = re.search(r'^\s*Value(?!\s*(?:Name|Type))(?:\s+data)?\s*:?[ \t]*(0x[0-9a-fA-F]+|[-+]?\d+)\s*(?:\(([-+]?\d+)\))?', check_content, re.IGNORECASE | re.MULTILINE)
    if match:
        raw = match.group(2) or match.group(1)
        try:
            return int(raw, 16) if raw.lower().startswith('0x') else int(raw)
        except ValueError:
            return raw

    type_match = re.search(r'^(?:\s*Value\s+Type|\s*Type)\s*:\s*(REG_(?:SZ|MULTI_SZ))\s*$', check_content, re.IGNORECASE | re.MULTILINE)
    value_match = re.search(r'^\s*Value\s*:\s*(\S[^\n\r]*)$', check_content, re.IGNORECASE | re.MULTILINE)
    if not type_match or not value_match:
        return None
    raw = value_match.group(1).strip()
    if not raw or re.match(r'^(?:see|refer)\b', raw, re.IGNORECASE):
        return None
    return raw


def _normalize_registry_path(path: str) -> str:
    path = path.strip().strip('"“”').strip().rstrip('\\/.')
    path = re.sub(r'\\+', r'\\', path)
    for hive in ('HKEY_LOCAL_MACHINE', 'HKEY_CURRENT_USER', 'HKEY_CLASSES_ROOT', 'HKEY_USERS', 'HKEY_CURRENT_CONFIG'):
        if path.upper().startswith(hive):
            return _registry_hive_abbrev(hive) + path[len(hive):]
    return path


def _parse_expected_registry_data(text: str):
    match = re.search(r'value\s+data\s+is\s+not\s+set\s+to\s+["“]?([^"”\s,.;]+)', text, re.IGNORECASE)
    if not match:
        match = re.search(r'\bis\s+not\s+set\s+to\s+["“]?([^"”\s,.;]+)', text, re.IGNORECASE)
    if not match:
        return None
    raw = match.group(1).strip()
    lowered = raw.lower()
    if lowered in ('false', 'disabled'):
        return 0
    if lowered in ('true', 'enabled'):
        return 1
    try:
        return int(raw, 16) if lowered.startswith('0x') else int(raw)
    except ValueError:
        return raw


def _windows_registry_policy_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    path_match = re.search(r'Navigate\s+to\s+["“]?((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\n\r"”]+)', content, re.IGNORECASE)
    value_match = None
    expected_value = None
    if path_match:
        value_match = re.search(r'If\s+the\s+["“]([^"”]+)["”]\s+(?:value\s+name|key)\s+does\s+not\s+exist[^\n\r.]*?(?:value\s+data\s+)?is\s+not\s+set\s+to', content, re.IGNORECASE)
        if not value_match:
            value_match = re.search(r'If\s+([A-Za-z0-9_.-]+)\s+is\s+not\s+displayed[^\n\r.]*?or\s+it\s+is\s+not\s+set\s+to', content, re.IGNORECASE)
        expected_value = _parse_expected_registry_data(content)
    else:
        path_match = re.search(
            r'Windows\s+Registry(?:\s+Editor)?\s+to\s+navigate\s+to\s+the\s+following\s+key:\s*\n\s*((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\n\r]+)',
            content,
            re.IGNORECASE,
        )
        value_match = re.search(
            r'If\s+the\s+value\s+for\s+["“]?([A-Za-z0-9_.-]+)["”]?\s+is\s+not\s+set\s+to\s+["“]?REG_(DWORD|SZ)\s*=\s*([^"”\n\r.]+)["”]?\s*,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        if not path_match and not value_match and 'Administrative Template' in content:
            admin_registry = re.search(
                r'Using\s+the\s+registry,\s+check\s+((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^,\n\r]+),\s*Key:\s*([A-Za-z0-9_.-]+)',
                content,
                re.IGNORECASE,
            )
            admin_expected = re.search(
                r'If\s+["“][^"”]+["”]\s+is\s+not\s+["“](Enabled|Disabled)["”],\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            )
            if admin_registry and admin_expected:
                path_match = admin_registry
                value_match = admin_registry
                expected_value = 1 if admin_expected.group(1).lower() == 'enabled' else 0
        if not value_match and not re.search(
            r'does\s+not\s+exist[^.]*not\s+a\s+finding|or\s+["“]?Not\s+Configured["”]?|more\s+restrictive|also\s+(?:an\s+)?acceptable|\(or\s+\d+\)',
            content,
            re.IGNORECASE,
        ):
            value_match = re.search(
                r'(?:Criteria:\s*)?If\s+the\s+value\s+(?:(?:for\s+)?["“]([^"”]+)["”]|for\s+([A-Za-z0-9_.-]+)|([A-Za-z0-9_.-]+))\s+is\s+(?:set\s+to\s+)?REG_(DWORD|SZ)\s*=\s*([^,\.\n\r()]+)(?:\s*\([^)]*\))?\s*,?\s+this\s+is\s+not\s+a\s+finding\.',
                content,
                re.IGNORECASE,
            )
        if value_match and expected_value is None:
            if getattr(value_match, 'lastindex', 0) >= 5:
                raw_value = value_match.group(5).strip().strip('"“”')
                registry_type = value_match.group(4).upper()
            elif getattr(value_match, 'lastindex', 0) >= 4:
                raw_value = value_match.group(4).strip().strip('"“”')
                registry_type = value_match.group(3).upper()
            else:
                raw_value = value_match.group(3).strip().strip('"“”')
                registry_type = value_match.group(2).upper()
            if registry_type == 'DWORD':
                if not re.fullmatch(r'0x[0-9a-fA-F]+|[-+]?\d+', raw_value):
                    return None
                expected_value = int(raw_value, 16) if raw_value.lower().startswith('0x') else int(raw_value)
            else:
                expected_value = raw_value
    if not path_match or not value_match or expected_value is None:
        return None
    value_name = (value_match.group(1) or (value_match.group(2) if getattr(value_match, 'lastindex', 0) and value_match.lastindex >= 2 else '') or (value_match.group(3) if getattr(value_match, 'lastindex', 0) and value_match.lastindex >= 3 else '')).strip()
    if path_match is value_match and getattr(value_match, 'lastindex', 0) and value_match.lastindex >= 2:
        value_name = value_match.group(2).strip().rstrip('.')
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows' if any(token in stig_id.lower() for token in ('windows', 'chrome', 'edge', 'defender', 'office')) else 'generic',
        'check': {
            'type': 'registry',
            'path': _normalize_registry_path(path_match.group(1)),
            'value_name': value_name,
        },
        'expected': {'type': 'equals', 'value': expected_value},
        'description': rule.get('title', ''),
    }


def _linux_platform(stig_id: str) -> bool:
    lower = stig_id.lower()
    return any(token in lower for token in ('rhel', 'red_hat', 'linux', 'ubuntu', 'sles', 'suse'))


def _windows_platform(stig_id: str) -> bool:
    lower = stig_id.lower()
    return 'windows' in lower or 'ms_windows' in lower


def _windows_audit_policy_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    policy_text = '\n'.join(part for part in (content, fix_text) if part)
    has_auditpol_context = bool(re.search(r'\bauditpol\b', content, re.IGNORECASE))
    has_advanced_audit_policy_context = 'Advanced Audit Policy Configuration' in policy_text
    if not has_auditpol_context and not has_advanced_audit_policy_context:
        return None
    outcome_match = re.search(r'\b(successes|failures|success|failure)\b', title, re.IGNORECASE) or re.search(r'audit\s+(successes|failures|success|failure)', content, re.IGNORECASE)
    if not outcome_match:
        outcome_match = re.search(r'is\s+not\s+set\s+to\s+"(Success|Failure)"', content, re.IGNORECASE)
    if not outcome_match:
        outcome_match = re.search(r'with\s+"?(Success|Failure)"?\s+selected\s*\.', fix_text, re.IGNORECASE)
    if not outcome_match:
        return None
    raw_outcome = outcome_match.group(1).lower()
    outcome = 'Success' if raw_outcome.startswith('success') else 'Failure'

    candidates = []
    quoted = re.search(r'"([A-Za-z][A-Za-z /-]+?)"\s+audit policy setting', content, re.IGNORECASE)
    if quoted:
        candidates.append(quoted.group(1))
    gpo_path = re.search(r'Advanced Audit Policy Configuration\s*>>\s*System Audit Polic(?:y|ies)\s*>>\s*[^\n\r]+?\s*>>\s*"?([^"\n\r.]+?)"?\s*(?:with\s+"?(?:Success|Failure)"?\s+selected|\.)', policy_text, re.IGNORECASE)
    if gpo_path:
        candidates.append(gpo_path.group(1))
    title_policy = re.search(r'\baudit\s+(.+?)\s+(?:successes|failures|success|failure)\.?$', title, re.IGNORECASE)
    if title_policy:
        candidates.append(title_policy.group(1))
    for candidate in candidates:
        subcategory = candidate.split(' - ')[-1].strip(' ."')
        subcategory = re.sub(r'^Audit\s+', '', subcategory, flags=re.IGNORECASE)
        if subcategory:
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {'type': 'audit_policy', 'subcategory': subcategory, 'setting': outcome},
                'expected': {'type': 'contains', 'substring': outcome},
                'description': rule.get('title', ''),
            }
    return None


def _windows_security_policy_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    policy_text = '\n'.join(part for part in (content, fix_text, title) if part)
    has_secedit_context = bool(re.search(r'\bsecedit\b', content, re.IGNORECASE))

    if 'Local Policies >> Security Options' in policy_text:
        security_option = re.search(
            r'If\s+the\s+value\s+for\s+"([^"]+)"\s+is\s+not\s+set\s+to\s+"(Enabled|Disabled)"',
            content,
            re.IGNORECASE,
        )
        if not security_option:
            rename_option = re.search(
                r'If\s+the\s+value\s+for\s+"(?P<key>Accounts:\s+Rename\s+(?:administrator|guest)\s+account)"\s+is\s+not\s+set\s+to\s+a\s+value\s+other\s+than\s+"(?P<value>Administrator|Guest)",\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            )
            if not rename_option:
                rename_option = re.search(
                    r'If\s+the\s+value\s+for\s+"(?P<key>Accounts:\s+Rename\s+(?:administrator|guest)\s+account)"\s+is\s+set\s+to\s+"(?P<value>Administrator|Guest)",\s+this\s+is\s+a\s+finding',
                    content,
                    re.IGNORECASE,
                )
            if rename_option:
                return {
                    'vuln_id': rule.get('vuln_id', ''),
                    'platform': 'windows',
                    'check': {'type': 'security_policy', 'section': 'Security Options', 'key': rename_option.group('key').strip()},
                    'expected': {'type': 'not_equals', 'value': rename_option.group('value').strip()},
                    'description': rule.get('title', ''),
                }
        if not security_option:
            security_option = re.search(
                r'Configure\s+the\s+policy\s+value\s+for\s+Computer\s+Configuration\s*>>\s*Windows\s+Settings\s*>>\s*Security\s+Settings\s*>>\s*Local\s+Policies\s*>>\s*Security\s+Options\s*>>\s*"?([^"\n]+?)"?\s+to\s+"(Enabled|Disabled)"\s*\.\s*(?:\n|$)',
                policy_text,
                re.IGNORECASE,
            )
        if not security_option:
            less_or_equal_option = re.search(
                r'Configure\s+the\s+policy\s+value\s+for\s+Computer\s+Configuration\s*>>\s*Windows\s+Settings\s*>>\s*Security\s+Settings\s*>>\s*Local\s+Policies\s*>>\s*Security\s+Options\s*>>\s*"?([^"\n]+?)"?\s+to\s+"(\d+)"\s+[^.\n]*\bor\s+less\s*\.\s*(?:\n|$)',
                policy_text,
                re.IGNORECASE,
            )
            if less_or_equal_option:
                return {
                    'vuln_id': rule.get('vuln_id', ''),
                    'platform': 'windows',
                    'check': {'type': 'security_policy', 'section': 'Security Options', 'key': less_or_equal_option.group(1).strip()},
                    'expected': {'type': 'less_or_equal', 'value': int(less_or_equal_option.group(2))},
                    'description': rule.get('title', ''),
                }
        if security_option:
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {'type': 'security_policy', 'section': 'Security Options', 'key': security_option.group(1).strip()},
                'expected': {'type': 'equals', 'value': security_option.group(2).strip()},
                'description': rule.get('title', ''),
            }

    if 'Local Policies >> User Rights Assignment' in policy_text:
        blank_user_right_match = re.search(
            r'Configure\s+the\s+policy\s+value\s+for\s+Computer\s+Configuration\s*>>\s*Windows\s+Settings\s*>>\s*Security\s+Settings\s*>>\s*Local\s+Policies\s*>>\s*User\s+Rights\s+Assignment\s*>>\s*"?([^"\n]+?)"?\s+to\s+(?:be\s+defined\s+but\s+containing|include)\s+no\s+entries\s+\(blank\)\s*\.\s*(?:\n|$)',
            policy_text,
            re.IGNORECASE,
        )
        blank_right_keys = {
            'access credential manager as a trusted caller': 'SeTrustedCredManAccessPrivilege',
            'act as part of the operating system': 'SeTcbPrivilege',
            'create a token object': 'SeCreateTokenPrivilege',
            'create permanent shared objects': 'SeCreatePermanentPrivilege',
            'deny log on as a service': 'SeDenyServiceLogonRight',
            'enable computer and user accounts to be trusted for delegation': 'SeEnableDelegationPrivilege',
            'lock pages in memory': 'SeLockMemoryPrivilege',
        }
        if blank_user_right_match:
            display_name = blank_user_right_match.group(1).strip().strip('"')
            key = blank_right_keys.get(display_name.lower())
            blank_required = re.search(
                r'(?:no\s+accounts\s+or\s+groups|not\s+be\s+assigned\s+to\s+any\s+groups\s+or\s+accounts|no\s+entries\s+\(blank\))',
                policy_text,
                re.IGNORECASE,
            )
            if key and blank_required:
                return {
                    'vuln_id': rule.get('vuln_id', ''),
                    'platform': 'windows',
                    'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': key},
                    'expected': {'type': 'equals', 'value': ''},
                    'description': rule.get('title', ''),
                }

        administrators_only_right_match = re.search(
            r'If\s+any\s+(?:groups\s+or\s+accounts|accounts\s+or\s+groups)\s+other\s+than\s+the\s+following\s+are\s+granted\s+the\s+"([^"]+)"\s+user\s+right,\s+this\s+is\s+a\s+finding:\s*\n\s*-?\s*Administrators\s*(?:\n|\Z)',
            content,
            re.IGNORECASE,
        )
        administrators_only_fix = re.search(
            r'User\s+Rights\s+Assignment\s*>>\s*"?([^"\n]+?)"?\s+to\s+(?:only\s+include|include\s+only)\s+the\s+following\s+(?:groups\s+or\s+accounts|accounts\s+or\s+groups):\s*\n\s*-?\s*Administrators\s*(?:\n|\Z)',
            fix_text,
            re.IGNORECASE,
        )
        administrators_only_right_keys = {
            'back up files and directories': 'SeBackupPrivilege',
            'allow log on locally': 'SeInteractiveLogonRight',
            'create a pagefile': 'SeCreatePagefilePrivilege',
            'create symbolic links': 'SeCreateSymbolicLinkPrivilege',
            'debug programs': 'SeDebugPrivilege',
            'force shutdown from a remote system': 'SeRemoteShutdownPrivilege',
            'load and unload device drivers': 'SeLoadDriverPrivilege',
            'manage auditing and security log': 'SeSecurityPrivilege',
            'modify firmware environment values': 'SeSystemEnvironmentPrivilege',
            'perform volume maintenance tasks': 'SeManageVolumePrivilege',
            'profile single process': 'SeProfileSingleProcessPrivilege',
            'restore files and directories': 'SeRestorePrivilege',
            'take ownership of files or other objects': 'SeTakeOwnershipPrivilege',
        }
        if administrators_only_right_match and administrators_only_fix:
            check_display_name = administrators_only_right_match.group(1).strip().strip('"')
            fix_display_name = administrators_only_fix.group(1).strip().strip('"')
            if check_display_name.lower() == fix_display_name.lower():
                key = administrators_only_right_keys.get(check_display_name.lower())
                if key:
                    return {
                        'vuln_id': rule.get('vuln_id', ''),
                        'platform': 'windows',
                        'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': key},
                        'expected': {'type': 'equals', 'value': '*S-1-5-32-544'},
                        'description': rule.get('title', ''),
                    }

    if has_secedit_context:
        required_sids_match = re.search(
            r'following\s+SID(?:\(s\)|s)\s+are\s+not\s+defined\s+for\s+the\s+"(Se[A-Za-z0-9]+)"\s+user\s+right(?P<body>.*?)(?:\n\s*\n\s*If\b|\Z)',
            content,
            re.IGNORECASE | re.DOTALL,
        )
        if required_sids_match:
            key = required_sids_match.group(1)
            body = required_sids_match.group('body')
            sids = sorted(set(re.findall(r'\bS-\d+(?:-\d+)+(?!-)', body)))
            if sids:
                pattern = ''.join(f'(?=.*{sid})' for sid in sids)
                return {
                    'vuln_id': rule.get('vuln_id', ''),
                    'platform': 'windows',
                    'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': key},
                    'expected': {'type': 'matches', 'pattern': pattern},
                    'description': rule.get('title', ''),
                }

        privilege_match = re.search(r'"(Se[A-Za-z0-9]+Privilege)"\s+user\s+right', content)
        if privilege_match:
            key = privilege_match.group(1)
            expected = {'type': 'equals', 'value': ''}
            allowed_sids = re.search(r'other\s+than\s+([^\.\n\r]+)\s+are\s+granted\s+the\s+"' + re.escape(key) + r'"', content, re.IGNORECASE)
            if allowed_sids:
                sid_match = re.search(r'\*S-1-[0-9-]+', allowed_sids.group(1))
                if sid_match:
                    expected = {'type': 'equals', 'value': sid_match.group(0)}
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': key},
                'expected': expected,
                'description': rule.get('title', ''),
            }

    account_keys = {
        'LockoutBadCount': (r'LockoutBadCount|Account lockout threshold', {'type': 'less_or_equal', 'value': 3}),
        'ResetLockoutCount': (r'ResetLockoutCount|Reset account lockout counter after', {'type': 'greater_or_equal', 'value': 15}),
        'LockoutDuration': (r'LockoutDuration|Account lockout duration', {'type': 'greater_or_equal', 'value': 15}),
        'MinimumPasswordAge': (r'MinimumPasswordAge|Minimum password age', {'type': 'greater_or_equal', 'value': 1}),
        'MaximumPasswordAge': (r'MaximumPasswordAge|Maximum password age', {'type': 'less_or_equal', 'value': 60}),
        'MinimumPasswordLength': (r'MinimumPasswordLength|Minimum password length', {'type': 'greater_or_equal', 'value': 14}),
        'PasswordHistorySize': (r'PasswordHistorySize|Enforce password history', {'type': 'greater_or_equal', 'value': 24}),
        'PasswordComplexity': (r'PasswordComplexity|Password must meet complexity requirements', {'type': 'equals', 'value': '1'}),
        'ClearTextPassword': (r'ClearTextPassword|Store passwords using reversible encryption', {'type': 'equals', 'value': '0'}),
    }
    for key, (pattern, expected) in account_keys.items():
        if re.search(pattern, policy_text, re.IGNORECASE):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {'type': 'security_policy', 'section': 'System Access', 'key': key},
                'expected': expected,
                'description': rule.get('title', ''),
            }
    return None


def _sysctl_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = '\n'.join(part for part in (content, fix_text) if part)
    match = re.search(r'\bsysctl\s+([a-zA-Z0-9_.-]+)', content)
    key = None
    expected = None
    if match:
        key = match.group(1)
        value_match = re.search(rf'{re.escape(key)}\s*=\s*([^\s,.;]+)', combined)
        if not value_match:
            value_match = re.search(r'(?:value of|returned line[^.]*value of)\s+["“]([^"”]+)["”]', content, re.IGNORECASE)
        if value_match:
            expected = value_match.group(1).strip().strip('"')
    if not key or expected is None:
        config_match = re.search(
            r'^\s*((?:kernel|net|fs|vm)\.[A-Za-z0-9_.-]+)\s*=\s*([^\s#]+)\s*$',
            combined,
            re.MULTILINE,
        )
        if not config_match:
            return None
        key = config_match.group(1)
        expected = config_match.group(2).strip().strip('"')
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'sysctl', 'key': key},
        'expected': {'type': 'equals', 'value': expected},
        'description': rule.get('title', ''),
    }


def _package_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    title = rule.get('title', '') or ''
    match = re.search(r'\b(?:dnf|yum|rpm)\s+(?:list\s+(?:--installed|installed)|-q)\s+["\']?([A-Za-z0-9_.:+-]+)["\']?', content)
    if not match:
        match = re.search(r'\bdpkg\s+-l\s*\|\s*grep\s+([A-Za-z0-9_.:+-]+)', content)
    if not match:
        match = re.search(r'\bdpkg-query\s+(?:-[A-Za-z]+\s+)*([A-Za-z0-9_.:+-]+)', content)
    if not match:
        zypper_matches = re.findall(r'\bzypper\s+info\s+([A-Za-z0-9_.:+-]+)\s*\|\s*grep\s+-?i?\s*["“]?Installed["”]?', content, re.IGNORECASE)
        if len(zypper_matches) == 1 and not re.search(r'\bsystemctl\b', content, re.IGNORECASE):
            match = re.match(r'(.+)', zypper_matches[0])
    if not match:
        zypper_search_matches = re.findall(r'\bzypper\s+se\s+([A-Za-z0-9_.:+-]+)\b', content, re.IGNORECASE)
        if len(zypper_search_matches) == 1 and re.search(rf'^\s*i\s*\|\s*{re.escape(zypper_search_matches[0])}\s*\|', content, re.IGNORECASE | re.MULTILINE):
            match = re.match(r'(.+)', zypper_search_matches[0])
    if not match:
        match = re.search(r'\b([A-Za-z0-9_.:+-]+)\s+package\s+(?:has\s+)?(?:not\s+)?(?:been\s+)?installed', content, re.IGNORECASE)
    if not match:
        return None
    package = match.group(1)
    lower = f"{title}\n{content}".lower()
    should_be_installed = not bool(re.search(r'must\s+not\s+(?:have\s+\S+\s+)?be\s+installed|must\s+not\s+have\s+the\s+\S+\s+package\s+installed|has\s+not\s+been\s+installed|if\s+(?:the\s+)?["“]?(?:[a-z0-9_.:+-]+)["”]?\s+package\s+is\s+installed,?\s+this\s+is\s+a\s+finding', lower))
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'package', 'name': package, 'should_be_installed': should_be_installed},
        'expected': {'type': 'is_true' if should_be_installed else 'is_false'},
        'description': rule.get('title', ''),
    }


def _grep_file_match(content: str):
    return re.search(r'\bgrep\s+(?:-[A-Za-z]+\s+)*(?:["\']?)([^"\'\s|;]+)(?:["\']?)\s+(/[A-Za-z0-9_./:+-]+)', content)


def _file_content_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    zypper_gpgcheck = re.search(
        r'\bgrep\s+-i\s+["\']?\^?gpgcheck["\']?\s+(?P<path>/etc/zypp/zypp\.conf)\b',
        content,
        re.IGNORECASE,
    )
    if (
        zypper_gpgcheck
        and re.search(r'if\s+["“]?gpgcheck["”]?\s+is\s+set\s+to\s+["“]?off["”]?,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*gpgcheck\s*=\s*on\s*$', fix_text, re.IGNORECASE | re.MULTILINE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'file_content', 'path': zypper_gpgcheck.group('path'), 'pattern': 'gpgcheck = on', 'is_regex': False},
            'expected': {'type': 'contains'},
            'description': rule.get('title', ''),
        }
    grep = _grep_file_match(content)
    cat_pipe_grep = None
    if not grep:
        cat_pipe_grep = re.search(
            r'\bcat\s+(?P<path>/[A-Za-z0-9_./:+-]+)\s*\|\s*grep\s+(?:-[A-Za-z]+\s+)*(?P<pattern>[A-Za-z0-9_.:+-]+)',
            content,
            re.IGNORECASE,
        )
        if not cat_pipe_grep:
            return None
    if grep:
        pattern, path = grep.group(1), grep.group(2)
    else:
        path = cat_pipe_grep.group('path')
        pattern = cat_pipe_grep.group('pattern')
    lower = content.lower()
    expected = None
    if re.search(r'if\s+any\s+(?:occurrences?\s+of\s+)?["“]?[^"”\n.]+["”]?\s+(?:is|are)\s+returned[^.]*this\s+is\s+a\s+finding', lower):
        expected = {'type': 'is_false'}
    elif 'line is not returned' in lower or 'no output is returned' in lower or 'does not return' in lower:
        expected = {'type': 'contains'}
        if cat_pipe_grep:
            value_match = re.search(r'line\s+containing\s+the\s+value\s+["“]([^"”\n]+)["”]', content, re.IGNORECASE)
            if value_match:
                pattern = value_match.group(1).strip()
    if expected is None:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'file_content', 'path': path, 'pattern': pattern, 'is_regex': False},
        'expected': expected,
        'description': rule.get('title', ''),
    }


def _grep_expected_line_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    grep = re.search(r'\bgrep\s+(?:-[A-Za-z]+\s+)*(?:(?:["\'][^"\']+["\']|[^\s|;]+)\s+)?(?P<path>/[A-Za-z0-9_./:*+{}-]+)', content)
    if not grep:
        return None
    raw_path = grep.group('path')
    if any(token in raw_path for token in ('*', '{', '}')):
        return None
    after = content[grep.end():]
    expected_line = None
    for line in after.splitlines():
        line = line.strip()
        if not line or line.startswith('$'):
            continue
        if line.lower().startswith(('if ', 'note:', 'ask ', 'verify ', 'check ')):
            break
        if line.startswith('/') and ':' in line:
            path_part, value_part = line.split(':', 1)
            if path_part.startswith('/'):
                raw_path = path_part.strip()
                line = value_part.strip()
        if line and not line.startswith('#'):
            expected_line = line
            break
    if not expected_line:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'file_content', 'path': raw_path, 'pattern': expected_line, 'is_regex': False},
        'expected': {'type': 'contains'},
        'description': rule.get('title', ''),
    }


def _sshd_config_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    if '/usr/sbin/sshd' not in content or 'grep' not in content:
        return None
    keyword_match = re.search(r"grep\s+-iH\s+['\"]\^\\s\*([A-Za-z][A-Za-z0-9]+)['\"]", content, re.IGNORECASE)
    if not keyword_match:
        keyword_match = re.search(r"grep\s+-iH\s+['\"]\^\\\\s\*([A-Za-z][A-Za-z0-9]+)['\"]", content, re.IGNORECASE)
    if not keyword_match:
        return None
    keyword = keyword_match.group(1)
    expected_match = re.search(rf'^\s*({re.escape(keyword)}\s+[^\s\n\r]+)\s*$', content, re.IGNORECASE | re.MULTILINE)
    if not expected_match:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'file_content', 'path': '/etc/ssh/sshd_config', 'pattern': expected_match.group(1).strip(), 'is_regex': False},
        'expected': {'type': 'contains'},
        'description': rule.get('title', ''),
    }


def _auditctl_expected_rule_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    if not re.search(r'\bauditctl\s+-l\s*\|\s*e?grep\b', content, re.IGNORECASE):
        return None
    single_audit_rule_required = re.search(r'does\s+not\s+return\s+an?\s+audit\s+rule\s+for\b', content, re.IGNORECASE)
    if not re.search(r'does\s+not\s+return\s+(?:a\s+line|lines?)\b|does\s+not\s+return\s+(?:a\s+line|lines?)\s+that\s+match(?:es)?\s+the\s+example|does\s+not\s+return\s+audit\s+rules?\s+for|does\s+not\s+return\s+any\s+output|no\s+line\s+is\s+returned|line\s+is\s+commented\s+out|audit\s+rules?\s+are\s+not\s+defined|both\s+the\s+"b32"\s+and\s+"b64"\s+audit\s+rules\s+are\s+not\s+defined|does\s+not\s+return\s+all\s+lines', content, re.IGNORECASE) and not single_audit_rule_required:
        return None
    command_match = re.search(r'[$#>]\s*(?:sudo\s+)?auditctl\s+-l\s*\|\s*e?grep\b[^\n\r]*', content, re.IGNORECASE)
    if not command_match:
        return None

    if re.search(r'arbitrary\s+identifier|string\s+(?:after|following)\s+(?:it|"-k")\s+does\s+not\s+need\s+to\s+match', content, re.IGNORECASE):
        expected_lines = []
        for line in content[command_match.end():].splitlines():
            stripped = ' '.join(line.strip().split())
            if not stripped:
                continue
            if stripped.lower().startswith(('if ', 'note:', 'notes:')):
                break
            if stripped.startswith(('-a ', '-w ')):
                expected_lines.append(stripped)
            elif expected_lines:
                break
        if not expected_lines:
            return None
        stripped_expected_lines = []
        for expected_line in expected_lines:
            stripped_line = re.sub(r'\s+(?:-k\s+\S+|-F\s+key=\S+)\s*$', '', expected_line).strip()
            if stripped_line == expected_line:
                return None
            stripped_expected_lines.append(stripped_line)
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'auditctl -l'},
            'expected': {'type': 'contains', 'substring': '\n'.join(stripped_expected_lines)},
            'description': rule.get('title', ''),
        }

    match = re.search(
        r'[$#>]\s*(?:sudo\s+)?auditctl\s+-l\s*\|\s*e?grep\s+(?:-[A-Za-z]+\s+)?(?:"[^"]+"|\'[^\']+\'|\S+)\s+(?P<expected>-(?:w|a)\s+.*?)(?:\s+If\s+the\s+command\s+does\s+not\s+return\s+(?:a\s+line|lines?|audit\s+rules?\s+for)\b)',
        content,
        re.IGNORECASE | re.DOTALL,
    )
    if match:
        expected_line = ' '.join(match.group('expected').split())
        if not expected_line:
            return None
        expected_lines = re.split(r'\s+(?=-(?:w|a)\s+)', expected_line)
        expected_lines = [line.strip() for line in expected_lines if line.strip()]
        if not expected_lines:
            return None
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'auditctl -l'},
            'expected': {'type': 'contains', 'substring': '\n'.join(expected_lines)},
            'description': rule.get('title', ''),
        }

    expected_lines: list[str] = []
    for line in content[command_match.end():].splitlines():
        stripped = ' '.join(line.strip().split())
        if not stripped:
            continue
        if stripped.lower().startswith(('if ', 'note:', 'notes:')):
            break
        if stripped.startswith(('-a ', '-w ')):
            expected_lines.append(stripped)
        elif expected_lines:
            break
    if len(expected_lines) < 2:
        chained_grep = re.search(r'\|\s*e?grep\b.*\|\s*e?grep\b', command_match.group(0), re.IGNORECASE)
        if len(expected_lines) != 1 or (not chained_grep and not single_audit_rule_required):
            return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': 'auditctl -l'},
        'expected': {'type': 'contains', 'substring': '\n'.join(expected_lines)},
        'description': rule.get('title', ''),
    }


def _service_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    title = rule.get('title', '') or ''
    matches = list(re.finditer(r'\bsystemctl\s+(is-enabled|is-active|status|show)\s+([^\s;|&]+)', content))
    if not matches:
        return None
    lower = f"{title}\n{content}".lower()
    match = next((m for m in matches if m.group(1) == 'show' and 'loadstate=masked' in lower and 'unitfilestate=masked' in lower), None)
    if not match:
        match = next((m for m in matches if m.group(1) == 'is-active'), matches[0])
    command = match.group(1)
    raw_name = match.group(2).strip('"\'')
    masked_status = command == 'status' and re.search(r'loaded:\s+masked\b', lower) and re.search(r'(?:loaded\s+and\s+)?not\s+masked', lower)
    masked_show = command == 'show' and 'loadstate=masked' in lower and 'unitfilestate=masked' in lower and re.search(r'(?:loaded\s+or\s+active,?\s+and\s+is\s+)?not\s+masked', lower)
    sample_lines, _finding_text = _authoritative_sample_block_after_command(content, match.end())
    masked_is_enabled = (
        command == 'is-enabled'
        and sample_lines == ['masked']
        and re.search(r'returned\s+value\s+is\s+not\s+["“]masked["”]', lower)
    )
    if raw_name.endswith('.target') and not masked_status:
        return None
    if 'masked' in lower and not masked_status and not masked_show and not masked_is_enabled:
        return None
    if '.' in raw_name and not raw_name.endswith(('.service', '.target')):
        return None
    name = raw_name.removesuffix('.service').removesuffix('.target')
    if command == 'show':
        if masked_show:
            expected_status = 'disabled'
        else:
            return None
    elif command == 'is-enabled' and masked_is_enabled:
        expected_status = 'disabled'
    elif command == 'status':
        if re.search(r'if\s+["“][^"”]+["”]\s+is\s+active\s+and\s+is\s+not\s+configured\s+to\b', lower):
            return None
        if masked_status:
            expected_status = 'disabled'
        elif re.search(r'if\s+(?:the\s+)?(?:"[^"]+"\s+)?(?:service\s+)?(?:status\s+)?(?:is\s+)?(?:set\s+to\s+)?(?:"?)?(?:active|running)(?:"?)?(?:\s+and\s+is\s+not\s+documented\s+with\s+[^.\n]+?\s+as\s+an\s+operational\s+requirement|\s+and\s+is\s+not\s+documented)?,?\s+this\s+is\s+a\s+finding', lower):
            expected_status = 'stopped'
        elif (
            any(re.match(r'Active:\s+active\b', line, re.IGNORECASE) for line in sample_lines)
            and re.search(rf'If\s+["“]?{re.escape(raw_name)}["”]?\s+is\s+["“]?inactive["”]?', content, re.IGNORECASE)
        ):
            expected_status = 'running'
        elif re.search(r'(?:does\s+not\s+show\s+a\s+status\s+of|is\s+not)\s+["“]?(?:active|enabled)["”]?\s+and\s+["“]?running["”]?', lower) or re.search(r'is\s+not\s+enabled\s+and\s+(?:active|running)', lower):
            expected_status = 'running'
        else:
            return None
    elif command == 'is-active' and re.search(rf'systemctl\s+is-active\s+{re.escape(raw_name)}\s*\n\s*active\b', content, re.IGNORECASE) and (re.search(r'(?:is|service\s+is)\s+not\s+["“]?active["”]?', lower) or re.search(r'["“]?active["”]?\s+is\s+not\s+returned', lower) or re.search(r'returns\s+["“]?inactive["”]?', lower) or re.search(r'is\s+not\s+["“]?enabled["”]?\s+and\s+["“]?active["”]?', lower)):
        expected_status = 'running'
    elif command == 'is-active' and sample_lines == ['inactive'] and re.search(r'if\s+the\s+service\s+is\s+active\s+and\s+is\s+not\s+documented,?\s+this\s+is\s+a\s+finding', lower):
        expected_status = 'stopped'
    elif re.search(r'must\s+not\s+.*(?:enabled|running)|must\s+be\s+disabled|if\s+(?:the\s+)?(?:"[^"]+"\s+)?(?:service\s+)?(?:status\s+)?(?:is\s+)?(?:set\s+to\s+)?(?:"?)?(?:enabled|active|running)(?:"?)?,?\s+this\s+is\s+a\s+finding', lower):
        expected_status = 'disabled' if command == 'is-enabled' else 'stopped'
    elif 'must be enabled' in lower or 'must be running' in lower:
        expected_status = 'running'
    else:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'service', 'name': name, 'expected_status': expected_status},
        'expected': {'type': 'equals', 'value': expected_status},
        'description': rule.get('title', ''),
    }


def _normalize_command(command: str) -> str:
    command = command.strip().strip('“”')
    command = re.sub(r'^sudo\s+', '', command)
    return command.strip()


def _macos_platform(stig_id: str) -> bool:
    return 'macos' in stig_id.lower() or 'apple' in stig_id.lower()


def _command_substitutions_are_absolute(command: str) -> bool:
    substitutions = re.findall(r'\$\(([^()]*)\)', command)
    if not substitutions:
        return False
    for substitution in substitutions:
        if any(token in substitution for token in ('`', '$(', '&&', '<<', ';')):
            return False
        for segment in substitution.split('|'):
            stripped = segment.strip()
            if not re.match(r'^/[A-Za-z0-9_./:+-]+\b', stripped):
                return False
    return True


def _has_unsafe_shell_token(command: str, *, allow_command_substitution: bool = False) -> bool:
    unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", '', command)
    tokens = ('`', '&&', '<<') if allow_command_substitution else ('`', '$(', '&&', '<<')
    return any(token in unquoted for token in tokens)


def _gsettings_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    command_matches = list(re.finditer(
        r'^\s*\**\s*\$\s*(?P<command>(?:sudo\s+)?gsettings\s+(?:get|writable)\s+[A-Za-z0-9_.-]+\s+[A-Za-z0-9_.-]+)\s*$',
        content,
        re.MULTILINE,
    ))
    if len(command_matches) != 1:
        return None
    command = _normalize_command(command_matches[0].group('command'))
    expected_line = None
    for line in content[command_matches[0].end():].splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith(('if ', 'note:', '$', '#', '>')):
            break
        expected_line = stripped
        break
    if expected_line not in ('true', 'false'):
        if (
            re.fullmatch(r'gsettings\s+get\s+org\.gnome\.settings-daemon\.plugins\.media-keys\s+logout', command)
            and expected_line in ("['']", '"[\'\']"', '@as []')
            and (
                re.search(r'If\s+the\s+["“]logout["”]\s+key\s+is\s+bound\s+to\s+an\s+action', content, re.IGNORECASE)
                or re.search(r'If\s+the\s+GNOME\s+desktop\s+is\s+configured\s+to\s+shut\s+down\s+when\s+Ctrl-Alt-Del\s+is\s+pressed', content, re.IGNORECASE)
            )
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'equals', 'value': expected_line},
                'description': rule.get('title', ''),
            }
        return None
    if re.search(r'if[^.\n]+(?:setting|result|[A-Za-z0-9_.-]+["”]?)\s+is\s+(?:set\s+to\s+)?["“]false["”]', content, re.IGNORECASE):
        expected_value = 'true'
    elif re.search(r'if[^.\n]+(?:setting|result|[A-Za-z0-9_.-]+["”]?)\s+is\s+(?:set\s+to\s+)?["“]true["”]', content, re.IGNORECASE):
        expected_value = 'false'
    elif re.search(r'is\s+not\s+set\s+to\s+["“]?true["”]?', content, re.IGNORECASE):
        expected_value = 'true'
    else:
        return None
    if expected_line != expected_value:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': expected_value},
        'description': rule.get('title', ''),
    }


def _systemctl_get_default_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    command_matches = list(re.finditer(r'^\s*[$#>]\s*(?:sudo\s+)?systemctl\s+get-default\s*$', content, re.MULTILINE))
    if len(command_matches) != 1:
        return None
    shell_commands = re.findall(r'^\s*[$#>]\s*(?:sudo\s+)?(?:/[A-Za-z0-9_./:+-]+|[A-Za-z0-9_.:+-]+)\b', content, re.MULTILINE)
    if len(shell_commands) != 1:
        return None
    expected_target = None
    for line in content[command_matches[0].end():].splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith(('if ', 'note:', '$', '#', '>')):
            break
        expected_target = stripped
        break
    if not expected_target or not re.fullmatch(r'[A-Za-z0-9_.-]+\.target', expected_target):
        return None
    if not re.search(
        rf'If\s+the\s+system\s+default\s+target\s+is\s+not\s+set\s+to\s+["“]{re.escape(expected_target)}["”]',
        content,
        re.IGNORECASE,
    ):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': 'systemctl get-default'},
        'expected': {'type': 'equals', 'value': expected_target},
        'description': rule.get('title', ''),
    }


def _selinux_getenforce_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    if not re.search(r'^\s*[$#>]\s*(?:sudo\s+)?getenforce\s*$', content, re.MULTILINE):
        return None
    if not re.search(r'^\s*Enforcing\s*$', content, re.MULTILINE):
        return None
    if not re.search(r'If\s+["“]?SELinux["”]?\s+is\s+not\s+(?:active\s+and\s+not\s+)?in\s+["“]?Enforcing["”]?\s+mode,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': 'getenforce'},
        'expected': {'type': 'equals', 'value': 'Enforcing'},
        'description': rule.get('title', ''),
    }


def _selinux_sestatus_policy_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    command_match = re.search(
        r'^\s*[$#>]\s*(?P<command>(?:sudo\s+)?sestatus\s*\|\s*grep\s+(?:["“\']policy\s+name["”\']|policy))\s*$',
        content,
        re.IGNORECASE | re.MULTILINE,
    )
    if not command_match:
        return None
    sample_lines, finding_text = _authoritative_sample_block_after_command(content, command_match.end())
    if len(sample_lines) != 1:
        return None
    sample_line = sample_lines[0]
    if not re.fullmatch(r'Loaded\s+policy\s+name:\s+targeted', sample_line, re.IGNORECASE):
        return None
    if not re.search(r'If\s+the\s+loaded\s+policy\s+name\s+is\s+not\s+["“]targeted["”],?\s+this\s+is\s+a\s+finding', finding_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': _normalize_command(command_match.group('command'))},
        'expected': {'type': 'contains', 'substring': sample_line},
        'description': rule.get('title', ''),
    }


def _findmnt_option_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    command_matches = list(re.finditer(r'^\s*[$#>]\s*(?:sudo\s+)?findmnt\s+(?P<path>/[A-Za-z0-9_./:+-]+)\s*$', content, re.MULTILINE))
    if len(command_matches) != 1:
        return None
    command_match = command_matches[0]
    mount_path = command_match.group('path')
    required_match = re.search(
        rf'If\s+the\s+{re.escape(mount_path)}\s+file\s+system\s+is\s+mounted\s+without\s+the\s+["“]([A-Za-z0-9_-]+)["”]\s+option',
        content,
        re.IGNORECASE,
    )
    if not required_match:
        return None
    required_option = required_match.group(1)
    sample_options = None
    for line in content[command_match.end():].splitlines():
        stripped = line.strip()
        if not stripped or stripped.upper().startswith('TARGET'):
            continue
        if stripped.lower().startswith('if '):
            break
        fields = stripped.split()
        if fields and fields[0] == mount_path and len(fields) >= 4:
            options_field = fields[3]
            sample_options = options_field if required_option in options_field.split(',') else None
            break
    if not sample_options:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': f'findmnt {mount_path}'},
        'expected': {'type': 'contains', 'substring': required_option},
        'description': rule.get('title', ''),
    }


def _dconf_grep_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    command_matches = list(re.finditer(
        r'^\s*[$#>]\s*(?:sudo\s+)?(?P<command>grep\s+-R\s+(?P<key>[A-Za-z0-9_.-]+)\s+/etc/dconf/db/\*)\s*$',
        content,
        re.MULTILINE,
    ))
    if len(command_matches) != 1:
        return None
    command_match = command_matches[0]
    command = _normalize_command(command_match.group('command'))
    key = command_match.group('key')
    sample_line = None
    for line in content[command_match.end():].splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith(('if ', 'note:', '$', '#', '>')):
            break
        if stripped.startswith('/etc/dconf/db/') and ':' in stripped:
            sample_line = stripped.split(':', 1)[1].strip()
            break
    if not sample_line or not sample_line.startswith(f'{key}='):
        return None
    value_match = re.match(rf'{re.escape(key)}=(["\']?)(?P<value>[^"\'\n]+)\1$', sample_line)
    if not value_match:
        return None
    expected_value = value_match.group('value')
    explicit_value_required = re.search(
        rf'If\s+the\s+["“]{re.escape(key)}["”]\s+setting\s+is\s+not\s+set\s+to\s+["“]{re.escape(expected_value)}["”]',
        content,
        re.IGNORECASE,
    )
    exact_sample_required = re.search(
        rf'If\s+the\s+["“]{re.escape(sample_line)}["”]\s+setting\s+is\s+missing\s+or\s+commented\s+out',
        content,
        re.IGNORECASE,
    )
    if not explicit_value_required and not exact_sample_required:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'contains', 'substring': sample_line},
        'description': rule.get('title', ''),
    }


def _authoritative_sample_block_after_command(content: str, command_end: int) -> tuple[list[str], str]:
    sample_lines = []
    tail_lines = []
    in_tail = False
    for line in content[command_end:].splitlines():
        stripped = line.strip()
        if not stripped:
            if sample_lines:
                in_tail = True
            continue
        if stripped.startswith(('$', '>')) or stripped.lower().startswith(('note:', 'notes:', 'ask ', 'verify ', 'check ')):
            break
        if stripped.lower().startswith('if '):
            in_tail = True
        if in_tail:
            tail_lines.append(stripped)
            continue
        sample_lines.append(stripped)
    return sample_lines, ' '.join(tail_lines)


def _sample_key_referenced_by_finding_text(sample_line: str, finding_text: str) -> bool:
    if sample_line.startswith('#') and re.search(r'\buncommented\b', finding_text, re.IGNORECASE):
        key = sample_line.lstrip('#').split('=', 1)[0].strip()
        return bool(key and key.lower() in finding_text.lower())
    key_match = re.match(r'([A-Za-z0-9_.:-]+)\s*(?:=|\s)', sample_line)
    if not key_match:
        return bool(re.search(r'does\s+not\s+return', finding_text, re.IGNORECASE))
    key = key_match.group(1)
    return key.lower() in finding_text.lower()


def _literal_command_output_candidate(rule: dict, stig_id: str, command: str, command_end: int) -> dict | None:
    content = rule.get('check_content', '') or ''
    if re.match(r'^systemctl\b', command):
        return None
    sample_lines, finding_text = _authoritative_sample_block_after_command(content, command_end)
    if len(sample_lines) != 1:
        return None
    sample_line = sample_lines[0]
    if re.search(r'\[[A-Za-z0-9_ -]+\]|<[A-Za-z0-9_ -]+>', sample_line):
        return None
    literal_match = re.search(
        r'If\s+the\s+(?:result|output)\s+is\s+not\s+(?P<quote>["“\'])(?P<value>[^"”\'\n]+)(?:["”\'])',
        finding_text,
        re.IGNORECASE,
    )
    if not literal_match:
        return None
    literal = literal_match.group('value').strip()
    sample_without_outer_quotes = sample_line.strip().strip('"“”\'')
    if sample_line != literal and sample_without_outer_quotes != literal:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux' if _linux_platform(stig_id) else 'generic',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': sample_line},
        'description': rule.get('title', ''),
    }


def _grep_sample_line_candidate(rule: dict, stig_id: str, command: str, command_end: int) -> dict | None:
    content = rule.get('check_content', '') or ''
    if not re.match(r'^grep\b', command) or '|' in command or any(token in command for token in ('egrep', 'awk', ' xargs ')):
        return None
    sample_lines, finding_text = _authoritative_sample_block_after_command(content, command_end)
    if len(sample_lines) != 1:
        return None
    sample_line = sample_lines[0]
    if re.search(r'\[[A-Za-z0-9_ -]+\]|<[A-Za-z0-9_ -]+>', sample_line):
        return None
    if '*' not in command and not sample_line.startswith('#'):
        return None
    finding_text_is_explicit = re.search(
        r'commented\s+out|missing|does\s+not\s+return|not\s+set\s+to|uncommented|other\s+than',
        finding_text,
        re.IGNORECASE,
    )
    if sample_line.startswith('/') and ':' in sample_line:
        sample_line = sample_line.split(':', 1)[1].strip()
    if not finding_text_is_explicit or not _sample_key_referenced_by_finding_text(sample_line, finding_text):
        return None
    if not sample_line:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux' if _linux_platform(stig_id) else 'generic',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'contains', 'substring': sample_line},
        'description': rule.get('title', ''),
    }


def _command_output_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    dconf_candidate = _dconf_grep_candidate(rule, stig_id)
    if dconf_candidate:
        return dconf_candidate
    findmnt_candidate = _findmnt_option_candidate(rule, stig_id)
    if findmnt_candidate:
        return findmnt_candidate
    selinux_sestatus_candidate = _selinux_sestatus_policy_candidate(rule, stig_id)
    if selinux_sestatus_candidate:
        return selinux_sestatus_candidate
    selinux_candidate = _selinux_getenforce_candidate(rule, stig_id)
    if selinux_candidate:
        return selinux_candidate
    if _windows_platform(stig_id) and re.search(r'^\s*Confirm-SecureBootUEFI\s*$', content, re.MULTILINE) and re.search(
        r'If\s+a\s+value\s+of\s+["“]True["”]\s+is\s+not\s+returned,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': 'Confirm-SecureBootUEFI'},
            'expected': {'type': 'equals', 'value': 'True'},
            'description': rule.get('title', ''),
        }
    command_matches = list(re.finditer(r'^\s*[$#>]\s*(?P<command>(?:sudo\s+)?(?:/[A-Za-z0-9_./:+-]+|[A-Za-z0-9_.:+-]+)\b[^\n\r]*)$', content, re.MULTILINE))
    command = None
    command_end = None
    if command_matches:
        command = _normalize_command(command_matches[0].group('command'))
        command_end = command_matches[0].end()
    else:
        absolute_command = re.search(r'^\s*(?P<command>/[A-Za-z0-9_./:+-]+\b[^\n\r]*)$', content, re.MULTILINE)
        inline_absolute_command = re.search(
            r'following\s+commands?:\s+(?P<command>/[A-Za-z0-9_./:+-]+\b.*?)(?=\s+If\s+the\s+(?:results?\s+(?:is|are)\s+not|command\s+does\s+not\s+return)\s+["“])',
            content,
            re.IGNORECASE | re.DOTALL,
        )
        if (absolute_command or inline_absolute_command) and re.search(
            r'If\s+the\s+(?:results?\s+(?:is|are)\s+not|command\s+does\s+not\s+return)\s+["“][^"”\n]+["”]',
            content,
            re.IGNORECASE,
        ):
            selected_command = absolute_command or inline_absolute_command
            command = _normalize_command(selected_command.group('command'))
            command_end = selected_command.end()
        quoted_netsh_command = re.search(r'\bRun\s+["“](?P<command>netsh\s+interface\s+portproxy\s+show\s+all)["”]', content, re.IGNORECASE)
        if not command and quoted_netsh_command and re.search(r'If\s+the\s+command\s+displays\s+any\s+results,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            command = _normalize_command(quoted_netsh_command.group('command'))
            command_end = quoted_netsh_command.end()
    allow_macos_command_substitution = bool(
        command
        and _macos_platform(stig_id)
        and command.startswith('/')
        and '$(' in command
        and _command_substitutions_are_absolute(command)
    )
    if not command or _has_unsafe_shell_token(command, allow_command_substitution=allow_macos_command_substitution):
        return None
    if re.search(r'\bPART\b', command) and '[PART]' in content:
        return None
    unquoted_semicolon_command = re.sub(r"'[^']*'|\"[^\"]*\"", '', command)
    if ';' in unquoted_semicolon_command and not re.fullmatch(r'[^;]*(?:\\;[^;]*)*', unquoted_semicolon_command):
        return None
    if command.startswith('xmllint ') and re.search(r'\bnot\s*\[', command):
        return None

    grep_sample_candidate = _grep_sample_line_candidate(rule, stig_id, command, command_end)
    if grep_sample_candidate:
        return grep_sample_candidate

    literal_sample_candidate = _literal_command_output_candidate(rule, stig_id, command, command_end)
    if literal_sample_candidate:
        return literal_sample_candidate

    expected_match = re.search(r'Expected\s+result:\s*(?P<body>.*?)(?:\n\s*If\b|\Z)', content, re.IGNORECASE | re.DOTALL)
    if expected_match:
        expected_lines = [line.strip() for line in expected_match.group('body').splitlines() if line.strip()]
        expected_lines = [line for line in expected_lines if not line.startswith(('$', '#', '>'))]
        expected_result_is_required = re.search(r'output\s+does\s+not\s+match\s+the\s+expected\s+result', content, re.IGNORECASE)
        xpath_empty_result_is_required = expected_lines == ['XPath set is empty'] and re.search(
            r'If\s+any\s+connectors\s+are\s+returned,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        if len(expected_lines) == 1 and (expected_result_is_required or xpath_empty_result_is_required):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux' if _linux_platform(stig_id) else 'windows' if _windows_platform(stig_id) else 'generic',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'equals', 'value': expected_lines[0]},
                'description': rule.get('title', ''),
            }

    if 'fips-mode-setup --check' in command and re.search(r'^\s*FIPS mode is enabled\.\s*$', content, re.MULTILINE):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'contains', 'substring': 'FIPS mode is enabled.'},
            'description': rule.get('title', ''),
        }

    if command == 'ufw status' and re.search(r'^\s*Status:\s+active\s*$', content, re.IGNORECASE | re.MULTILINE) and re.search(
        r'If\s+[^.\n]*status\s+as\s+["“]inactive["”]\s+or\s+any\s+type\s+of\s+error,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'contains', 'substring': 'Status: active'},
            'description': rule.get('title', ''),
        }

    result_match = re.search(
        r'If\s+the\s+(?:result\s+is\s+not|output\s+is\s+not|command\s+does\s+not\s+return)\s+["“]([^"”\n]+)["”]',
        content,
        re.IGNORECASE,
    )
    if not result_match and _macos_platform(stig_id) and command.startswith('/'):
        result_match = re.search(
            r'If\s+the\s+results\s+are\s+not\s+["“]([^"”\n]+)["”]',
            content,
            re.IGNORECASE,
        )
    if result_match:
        if re.search(r'command\s+does\s+not\s+return', result_match.group(0), re.IGNORECASE):
            tail = content[result_match.end():]
            if re.search(r'\b(?:banner\s+)?text\b[^.\n]*(?:must\s+read|worded\s+exactly)|If\s+the\s+text\s+is\s+not\s+worded\s+exactly', tail, re.IGNORECASE):
                return None
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'windows' if _windows_platform(stig_id) else 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': result_match.group(1).strip()},
            'description': rule.get('title', ''),
        }

    passwd_status_match = re.search(
        r'If\s+the\s+output\s+does\s+not\s+contain\s+["“](?P<status>[A-Z])["”]\s+in\s+the\s+second\s+field',
        content,
        re.IGNORECASE,
    )
    if command == 'passwd -S root' and passwd_status_match:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'contains', 'substring': f"root {passwd_status_match.group('status')}"},
            'description': rule.get('title', ''),
        }

    no_output_for_find = command.startswith('find ') and re.search(
        r'if\s+(?:(?:a|any)\s+(?:["“][^"”]+["”]|[^\n.]+?)\s+(?:(?:file|files|directory|directories)\s+)?(?:is|are)\s+(?:found|returned)|there\s+is\s+output\s+that\s+indicates)[^.]*?this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_explicit_output = re.search(r'if\s+(?:any\s+)?output\s+is\s+produced,?\s+this\s+is\s+a\s+finding|if\s+this\s+produces\s+any\s+output|if\s+the\s+command\s+displays\s+any\s+(?:output|results),?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    no_output_for_command_output = re.search(r'if\s+the\s+command\s+(?:has|produces)\s+any\s+output,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    no_output_for_any_output = re.search(r'if\s+(?:there\s+is\s+output|any\s+output\s+is\s+returned|(?:the\s+)?command\s+returns\s+any\s+output),?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    no_output_for_shadow_blank_password = (
        re.search(r"^awk\s+-F:\s+['\"]!\$2\s+\{print\s+\$1\}\s*['\"]\s+/etc/shadow$", command)
        and re.search(r'if\s+the\s+command\s+returns\s+any\s+results,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    )
    no_output_for_grep_found = '| grep' in command and re.search(
        r'if\s+[^.\n]*(?:interfaces?|files?|packages?|certificates?|results?)\s+(?:are|is)\s+found[^.\n]*this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if no_output_for_find or no_output_for_explicit_output or no_output_for_command_output or no_output_for_any_output or no_output_for_shadow_blank_password or no_output_for_grep_found:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'windows' if _windows_platform(stig_id) else 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    return None


def _file_permission_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    find_exec_stat_match = re.search(
        r'\bfind\s+(?P<path>/[A-Za-z0-9_./:+-]+)\s+-exec\s+stat\s+-c\s+["\'](?P<format>[^"\']+)["\']\s+\{\}\s+\\;',
        content,
    )
    path_match = re.search(r'\bstat\s+(?:-[A-Za-z]+\s+)*(?:["\'][^"\']+["\']\s+)?(/[A-Za-z0-9_./:+-]+)', content)
    if not path_match:
        path_match = re.search(r'\b(?:permissions|mode)[^\n.]+\s+(/[A-Za-z0-9_./:+-]+)', content, re.IGNORECASE)
    if not path_match and not find_exec_stat_match:
        return None
    path = path_match.group(1) if path_match else find_exec_stat_match.group('path')
    owner = None
    group = None
    mode = None
    mode_match = re.search(r'\b(?:mode|permissions?)\s+(?:is|are|of)?\s*(?:not\s+)?["“]?([0-7]{3,4})["”]?', content, re.IGNORECASE)
    if not mode_match:
        mode_match = re.search(r'If\s+the\s+mode\s+is\s+not\s+["“]([0-7]{3,4})["”]', content, re.IGNORECASE)
    if mode_match:
        mode = mode_match.group(1)

    stat_match = re.search(r'\bstat\s+-c\s+["\'](?P<format>[^"\']+)["\']\s+' + re.escape(path), content)
    if stat_match or find_exec_stat_match:
        fields = re.findall(r'%[aAUGn]', (stat_match or find_exec_stat_match).group('format'))
        for sample_line in content.splitlines():
            values = sample_line.strip().split()
            if len(values) != len(fields) or path not in values:
                continue
            for field, value in zip(fields, values):
                if field in ('%a', '%A') and re.fullmatch(r'[0-7]{3,4}', value):
                    mode = mode or value
                elif field == '%U':
                    owner = value
                elif field == '%G':
                    group = value
            break
        if stat_match and fields in (['%U'], ['%G'], ['%a'], ['%A']):
            sample_line = None
            for raw_line in content[stat_match.end():].splitlines():
                stripped = raw_line.strip()
                if not stripped:
                    continue
                if stripped.lower().startswith(('if ', 'note:', '$', '#', '>')):
                    break
                sample_line = stripped
                break
            explicit_finding = re.search(
                rf'If\s+["“]?{re.escape(sample_line or "")}["”]?\s+is\s+not\s+returned\s+as\s+a\s+result,?\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            )
            if sample_line and explicit_finding:
                field = fields[0]
                if field in ('%a', '%A') and re.fullmatch(r'[0-7]{3,4}', sample_line):
                    mode = mode or sample_line
                elif field == '%U' and re.fullmatch(r'[A-Za-z0-9_.-]+', sample_line):
                    owner = sample_line
                elif field == '%G' and re.fullmatch(r'[A-Za-z0-9_.-]+', sample_line):
                    group = sample_line

    if owner is None:
        owner_match = re.search(r'not\s+owned\s+by\s+["“]?([A-Za-z0-9_.-]+)', content, re.IGNORECASE)
        if owner_match:
            owner = owner_match.group(1).strip('"”.,')
    if group is None:
        group_match = re.search(r'not\s+group-owned\s+by\s+["“]?([A-Za-z0-9_.-]+)', content, re.IGNORECASE)
        if group_match:
            group = group_match.group(1).strip('"”.,')

    if owner is None and group is None and mode is None:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'file_permission', 'path': path, 'owner': owner, 'group': group, 'mode': mode},
        'expected': {'type': 'is_true'},
        'description': rule.get('title', ''),
    }


def infer_candidate_check(rule: dict, stig_id: str) -> dict | None:
    """Infer a conservative executable check candidate from DISA prose.

    Candidates are not marked validated; they are scaffolds requiring fixture proof
    before a rule can be promoted from planned to implemented/validated.
    """
    content = rule.get('check_content', '') or ''
    combined_registry_content = '\n'.join(part for part in (content, rule.get('fix_text', '') or '') if part)
    hives = [next(group for group in match if group).strip() for match in re.findall(r'Registry[ \t]+Hive(?::[ \t]*([^\n\r]+)|([A-Z][^\n\r]+))', combined_registry_content, re.IGNORECASE)]
    paths = [next(group for group in match if group).strip().strip('\\/') for match in re.findall(r'Registry[ \t]+Path(?::[ \t]*([^:\n\r][^\n\r]*)|(\\[^\n\r]+))', combined_registry_content, re.IGNORECASE)]
    value_names = [next(group for group in match if group).strip() for match in re.findall(r'Value[ \t]+Name(?::[ \t]*([^\n\r]+)|([A-Za-z0-9_.-][^\n\r]+))', combined_registry_content, re.IGNORECASE)]
    if hives and paths and value_names:
        normalized_hives = {_registry_hive_abbrev(hive) for hive in hives}
        normalized_paths = {re.sub(r'\\+', r'\\', path).rstrip('\\/.') for path in paths}
        normalized_value_names = set(value_names)
        if re.search(r'^\s*Value(?!\s*(?:Name|Type))[^\n\r]*\bor\s+less\b', combined_registry_content, re.IGNORECASE | re.MULTILINE):
            if _windows_platform(stig_id):
                security_policy_candidate = _windows_security_policy_candidate(rule)
                if security_policy_candidate:
                    return security_policy_candidate
            return None
        if re.search(r'^\s*Value(?!\s*(?:Name|Type))[^\n\r]*,\s*(?:0x[0-9a-fA-F]+|[-+]?\d+)', combined_registry_content, re.IGNORECASE | re.MULTILINE):
            return None
        expected_value = _registry_value(combined_registry_content)
        value_matches = re.findall(
            r'^\s*Value(?!\s*(?:Name|Type))(?:\s+data)?\s*:?[ \t]*(0x[0-9a-fA-F]+|[-+]?\d+|\S[^\n\r]*)\s*(?:\(([-+]?\d+)\))?',
            combined_registry_content,
            re.IGNORECASE | re.MULTILINE,
        )
        parsed_values = []
        for raw_value, parenthesized_value in value_matches:
            raw = (parenthesized_value or raw_value).strip()
            try:
                parsed_values.append(int(raw, 16) if raw.lower().startswith('0x') else int(raw))
            except ValueError:
                parsed_values.append(raw)
        if (
            len(normalized_hives) == 1
            and len(normalized_paths) == 1
            and len(normalized_value_names) == 1
            and expected_value is not None
            and (not parsed_values or len(set(parsed_values)) == 1)
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows' if 'windows' in stig_id.lower() or 'win' in stig_id.lower() else 'generic',
                'check': {
                    'type': 'registry',
                    'path': f"{next(iter(normalized_hives))}\\{next(iter(normalized_paths))}",
                    'value_name': next(iter(normalized_value_names)),
                },
                'expected': {'type': 'equals', 'value': expected_value},
                'description': rule.get('title', ''),
            }

    if _windows_platform(stig_id) or any(token in stig_id.lower() for token in ('chrome', 'edge', 'defender', 'office')):
        policy_candidate = _windows_registry_policy_candidate(rule, stig_id)
        if policy_candidate:
            return policy_candidate

        audit_policy_candidate = _windows_audit_policy_candidate(rule)
        if audit_policy_candidate:
            return audit_policy_candidate

        security_policy_candidate = _windows_security_policy_candidate(rule)
        if security_policy_candidate:
            return security_policy_candidate

        feature = re.search(r'Get-WindowsFeature\s*\|\s*Where\s+Name\s+-eq\s+([A-Za-z0-9_.-]+)', content, re.IGNORECASE)
        if not feature:
            feature = re.search(r'Get-WindowsFeature\s+-Name\s+([A-Za-z0-9_.-]+)', content, re.IGNORECASE)
        optional_feature = False
        if not feature:
            feature = re.search(r'Get-WindowsOptionalFeature\s+-Online\s*\|\s*Where\s+FeatureName\s+-eq\s+([A-Za-z0-9_.-]+)', content, re.IGNORECASE)
            optional_feature = bool(feature)
        feature_finding = re.search(r'Installed[^\n.]+is[^\n.]+finding|If[^\n.]+Installed[^\n.]+finding', content, re.IGNORECASE)
        optional_feature_finding = optional_feature and re.search(r'If\s+["“]?State\s*:\s*Enabled["”]?\s+is\s+returned,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        if feature and (feature_finding or optional_feature_finding):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {'type': 'windows_feature', 'name': feature.group(1), 'should_be_installed': False},
                'expected': {'type': 'is_false'},
                'description': rule.get('title', ''),
            }

    gsettings_candidate = _gsettings_candidate(rule, stig_id)
    if gsettings_candidate:
        return gsettings_candidate

    systemctl_get_default_candidate = _systemctl_get_default_candidate(rule, stig_id)
    if systemctl_get_default_candidate:
        return systemctl_get_default_candidate

    command_candidate = _command_output_candidate(rule, stig_id)
    if command_candidate:
        return command_candidate

    if _linux_platform(stig_id):
        for infer in (_sysctl_candidate, _package_candidate, _file_content_candidate, _grep_expected_line_candidate, _sshd_config_candidate, _auditctl_expected_rule_candidate, _service_candidate, _file_permission_candidate):
            candidate = infer(rule)
            if candidate:
                return candidate
    return None


def spec_from_rule(manifest_path: Path, manifest: dict, rule: dict) -> dict:
    classification, collector = classify_rule(rule.get('title', ''))
    spec = {
        'vuln_id': rule.get('vuln_id', ''),
        'rule_id': rule.get('rule_id', ''),
        'stig_id': manifest.get('stig_id', manifest.get('benchmark', 'unknown')),
        'title': rule.get('title', ''),
        'severity': rule.get('severity', ''),
        'classification': classification,
        'implementation_status': 'planned',
        'source_coverage_manifest': str(manifest_path),
        'source_benchmark': manifest.get('benchmark', ''),
        'source_version': manifest.get('version', ''),
        'collector_type': collector,
        'collector_commands': [],
        'normalizer': 'planned',
        'evaluator': 'planned',
        'expected_values': {},
        'evidence_fields': ['rule_id', 'vuln_id', 'status', 'evidence', 'source_artifact'],
        'na_conditions': [],
        'remediation': 'planned',
        'fixtures': [],
        'external_acceptance_refs': [],
        'tracking_issue': rule.get('tracking_issue', '') or f"TODO-{rule.get('vuln_id', rule.get('rule_id', 'UNKNOWN'))}",
    }
    if rule.get('check_content'):
        spec['check_content_excerpt'] = rule.get('check_content', '')[:4000]
    if rule.get('fix_text'):
        spec['fix_text_excerpt'] = rule.get('fix_text', '')[:4000]
    candidate = infer_candidate_check(rule, spec['stig_id'])
    if candidate:
        spec['candidate_check'] = candidate
        spec['normalizer'] = candidate['check']['type']
        spec['evaluator'] = 'candidate_template'
        spec['expected_values'] = candidate['expected']
    return spec


def _artifact_rule_map(manifest: dict, repo_root: Path, cache: dict[Path, dict]) -> dict:
    merged = {}
    refs = []
    for key in ('generated_from', 'benchmark_path'):
        if manifest.get(key):
            refs.append(manifest[key])
    refs.extend(manifest.get('generated_from_refs', []))
    refs.extend(manifest.get('validated_by', []))
    for raw_ref in refs:
        ref = str(raw_ref)
        if not ref.lower().endswith(('.zip', '.xml', '.xccdf')):
            continue
        path = Path(ref)
        if not path.is_absolute():
            path = repo_root / path
        if not path.exists():
            continue
        if path not in cache:
            try:
                inv = extract_xccdf_inventory.extract(path)
                cache[path] = {rule.get('vuln_id') or rule.get('rule_id'): rule for rule in inv.get('rules', [])}
            except Exception:
                cache[path] = {}
        merged.update(cache[path])
    return merged


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n')


def generate_specs(coverage_root: Path, implementation_root: Path, repo_root: Path | None = None) -> int:
    repo_root = repo_root or Path.cwd()
    artifact_cache: dict[Path, dict] = {}
    count = 0
    for manifest_path in sorted(coverage_root.rglob('*.json')):
        manifest = json.loads(manifest_path.read_text())
        artifact_rules = _artifact_rule_map(manifest, repo_root, artifact_cache)
        stig_slug = slug(manifest.get('stig_id') or manifest.get('benchmark') or manifest_path.parent.name)
        for rule in manifest.get('rules', []):
            if rule.get('classification') != 'unsupported':
                continue
            enriched = dict(rule)
            enriched.update({k: v for k, v in artifact_rules.get(rule.get('vuln_id') or rule.get('rule_id'), {}).items() if v})
            vuln = enriched.get('vuln_id') or enriched.get('rule_id') or 'unknown'
            out = implementation_root / stig_slug / f'{slug(vuln)}.json'
            write_json(out, spec_from_rule(manifest_path, manifest, enriched))
            count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--coverage-root', default='content/coverage/disa-authoritative')
    parser.add_argument('--implementation-root', default='content/rule-implementations')
    parser.add_argument('--repo-root', default='.')
    args = parser.parse_args(argv)
    count = generate_specs(Path(args.coverage_root), Path(args.implementation_root), Path(args.repo_root))
    print(f'Generated {count} planned rule implementation specs')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
