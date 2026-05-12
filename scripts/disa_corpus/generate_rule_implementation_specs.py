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



def _registry_dword_allowed_values(check_content: str) -> list[int] | None:
    match = re.search(
        r'^\s*Value(?!\s*(?:Name|Type))(?:\s+data)?\s*:?[ \t]*(0x[0-9a-fA-F]+.*)$',
        check_content,
        re.IGNORECASE | re.MULTILINE,
    )
    if not match:
        return None
    line = match.group(1).strip()
    if ',' not in line:
        return None
    if re.search(r'\b(?:or\s+less|or\s+greater|between|minimum|maximum|not\s+0|not\s+"0")\b', line, re.IGNORECASE):
        return None
    parenthesized_values = re.findall(r'\(([-+]?\d+)\)', line)
    if parenthesized_values:
        parts_without_parentheses = [re.sub(r'\([^)]*\)', '', part).strip() for part in line.split(',')]
        if len(parts_without_parentheses) != len(parenthesized_values):
            return None
        if any(not re.fullmatch(r'0x[0-9a-fA-F]+', part) for part in parts_without_parentheses):
            return None
        values = [int(value) for value in parenthesized_values]
    else:
        raw_values = [part.strip() for part in line.split(',')]
        if not raw_values or not all(re.fullmatch(r'0x[0-9a-fA-F]+|[-+]?\d+', value) for value in raw_values):
            return None
        values = [int(value, 16) if value.lower().startswith('0x') else int(value) for value in raw_values]
    unique_values = sorted(set(values))
    return unique_values if len(unique_values) > 1 else None


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


def _powershell_registry_absent_command(path: str, value_name: str) -> str:
    ps_path = _normalize_registry_path(path).replace('HKLM\\', 'HKLM:\\').replace('HKCU\\', 'HKCU:\\')
    return f"powershell -NoProfile -Command \"$p='{ps_path}'; if (-not (Get-ItemProperty -Path $p -Name '{value_name}' -ErrorAction SilentlyContinue)) {{ 'Absent' }}\""


def _windows_defender_registry_absent_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if 'defender' not in stig_id.lower() or vuln_id not in {'V-213428', 'V-213429', 'V-213430'}:
        return None
    path_match = re.search(
        r'Windows\s+Registry\s+Editor\s+to\s+navigate\s+to\s+the\s+following\s+key:\s*\n\s*((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\n\r]+)',
        content,
        re.IGNORECASE,
    )
    absent_match = re.search(
        r'Criteria:\s*If\s+the\s+value\s+["“]([A-Za-z0-9_.-]+)["”]\s+does\s+not\s+exist,\s+this\s+is\s+not\s+a\s+finding\.',
        content,
        re.IGNORECASE,
    )
    if not path_match or not absent_match:
        return None
    if not re.search(r'(?:Disabled|Not\s+Configured)', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': _powershell_registry_absent_command(path_match.group(1), absent_match.group(1)),
        },
        'expected': {'type': 'equals', 'value': 'Absent'},
        'description': rule.get('title', ''),
    }


def _windows_defender_registry_criteria_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if 'defender' not in stig_id.lower():
        return None
    path_match = re.search(
        r'Windows\s+Registry\s+Editor\s+to\s+navigate\s+to\s+the\s+following\s+key:\s*\n\s*((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\n\r]+)',
        content,
        re.IGNORECASE,
    )
    if not path_match:
        return None
    if vuln_id in {'V-213452', 'V-213453'}:
        signature_due_match = re.search(
            r'Criteria:\s*If\s+the\s+value\s+["“](A[Vv]SignatureDue|ASSignatureDue)["”]\s+is\s+REG_DWORD\s*=\s*7,\s+this\s+is\s+not\s+a\s+finding\.\s*\n\s*A\s+value\s+of\s+1\s*-\s*6\s+is\s+also\s+acceptable\s+and\s+not\s+a\s+finding\.\s*\n\s*A\s+value\s+of\s+0\s+is\s+a\s+finding\.\s*\n\s*A\s+value\s+(?:of\s+8\s+or\s+more|higher\s+than\s+7)\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        if signature_due_match and re.search(r'(?:["“]?7["”]?\s+or\s+less[^.]+excluding\s+["“]?0|["“]?7["”]?\s+or\s+less.*?Do\s+not\s+select\s+a\s+value\s+of\s+0)', content + '\n' + fix_text, re.IGNORECASE | re.DOTALL):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {
                    'type': 'registry',
                    'path': _normalize_registry_path(path_match.group(1)),
                    'value_name': signature_due_match.group(1),
                },
                'expected': {'type': 'matches', 'pattern': '^(?:1|2|3|4|5|6|7)$'},
                'description': rule.get('title', ''),
            }
    if vuln_id == 'V-213434':
        maps_match = re.search(
            r'Criteria:\s*If\s+the\s+value\s+["“](SpynetReporting)["”]\s+is\s+REG_DWORD\s*=\s*1,\s+or\s+REG_DWORD\s*=\s*2,\s+this\s+is\s+not\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        if maps_match and re.search(r'Advanced\s+MAPS', content + '\n' + fix_text, re.IGNORECASE):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {
                    'type': 'registry',
                    'path': _normalize_registry_path(path_match.group(1)),
                    'value_name': maps_match.group(1),
                },
                'expected': {'type': 'matches', 'pattern': '^(?:1|2)$'},
                'description': rule.get('title', ''),
            }
    allowed_regsz_match = re.search(
        r'Criteria:\s*If\s+the\s+value\s+["“]([A-Za-z0-9_.-]+)["”]\s+is\s+REG_SZ\s*=\s*([0-9]+)\s*\(or\s+([0-9]+)\),\s+this\s+is\s+not\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if allowed_regsz_match and re.search(
        rf'enter\s+["“]{re.escape(allowed_regsz_match.group(1))}["”]\s+in\s+the\s+["“]Value\s+name["”]\s+field\s+and\s+enter\s+["“]{re.escape(allowed_regsz_match.group(2))}["”]\s+in\s+the\s+["“]Value["”]\s+field',
        fix_text,
        re.IGNORECASE,
    ):
        allowed_values = sorted({int(allowed_regsz_match.group(2)), int(allowed_regsz_match.group(3))})
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': _normalize_registry_path(path_match.group(1)),
                'value_name': allowed_regsz_match.group(1),
            },
            'expected': {'type': 'matches', 'pattern': f"^(?:{'|'.join(str(value) for value in allowed_values)})$"},
            'description': rule.get('title', ''),
        }
    weekday_scan_match = re.search(
        r'Criteria:\s*If\s+the\s+value\s+["“]([A-Za-z0-9_.-]+)["”]\s+is\s+REG_DWORD\s*=\s*0x8,\s+this\s+is\s+a\s+finding\.\s*\n\s*Values\s+of\s+0x0\s+through\s+0x7\s+are\s+acceptable\s+and\s+not\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if weekday_scan_match and re.search(r'select\s+anything\s+other\s+than\s+["“]Never["”]', fix_text, re.IGNORECASE):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': _normalize_registry_path(path_match.group(1)),
                'value_name': weekday_scan_match.group(1),
            },
            'expected': {'type': 'matches', 'pattern': '^(?:0|1|2|3|4|5|6|7)$'},
            'description': rule.get('title', ''),
        }
    return None


def _windows_run_as_different_user_context_menu_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-220801', 'V-253359'}:
        return None
    if not _windows_platform(stig_id):
        return None
    if 'Run as different user must be removed from context menus' not in (rule.get('title', '') or ''):
        return None
    required_paths = [
        '\\SOFTWARE\\Classes\\batfile\\shell\\runasuser',
        '\\SOFTWARE\\Classes\\cmdfile\\shell\\runasuser',
        '\\SOFTWARE\\Classes\\exefile\\shell\\runasuser',
        '\\SOFTWARE\\Classes\\mscfile\\shell\\runasuser',
    ]
    if not all(path in content for path in required_paths):
        return None
    if len(re.findall(r'Value\s+Name:\s*SuppressionPolicy\b', content, re.IGNORECASE)) < 1:
        return None
    if len(re.findall(r'(?:Value\s+)?Type:\s*REG_DWORD\b', content, re.IGNORECASE)) < 1:
        return None
    if len(re.findall(r'Value:\s*0x00001000\s*\(4096\)', content, re.IGNORECASE)) < 1:
        return None
    command = (
        'powershell -NoProfile -Command '
        '"$paths=@(\'HKLM:\\SOFTWARE\\Classes\\batfile\\shell\\runasuser\','
        '\'HKLM:\\SOFTWARE\\Classes\\cmdfile\\shell\\runasuser\','
        '\'HKLM:\\SOFTWARE\\Classes\\exefile\\shell\\runasuser\','
        '\'HKLM:\\SOFTWARE\\Classes\\mscfile\\shell\\runasuser\'); '
        'if (($paths | Where-Object { (Get-ItemProperty -Path $_ -Name SuppressionPolicy -ErrorAction SilentlyContinue).SuppressionPolicy -eq 4096 }).Count -eq 4) { \'Compliant\' }"'
    )
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _windows_registry_policy_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''

    if 'edge' in stig_id.lower():
        edge_download_restrictions = re.search(
            r'Windows\s+Registry\s+Editor\s+to\s+navigate\s+to\s+the\s+following\s+key:\s*\n\s*(HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge)\b',
            content,
            re.IGNORECASE,
        )
        if (
            rule.get('vuln_id') == 'V-235752'
            and edge_download_restrictions
            and re.search(r'Allow\s+download\s+restrictions', content, re.IGNORECASE)
            and re.search(r'If\s+the\s+value\s+for\s+["“]DownloadRestrictions["”]\s+is\s+set\s+to\s+["“]REG_DWORD\s*=\s*0["”],?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
            and all(option in fix_text for option in ('BlockDangerousDownloads', 'Block potentially dangerous or unwanted downloads', 'BlockAllDownloads', 'BlockMaliciousDownloads'))
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {
                    'type': 'registry',
                    'path': _normalize_registry_path(edge_download_restrictions.group(1)),
                    'value_name': 'DownloadRestrictions',
                },
                'expected': {'type': 'matches', 'pattern': '^(?:1|2|3|4)$'},
                'description': rule.get('title', ''),
            }

    if 'chrome' in stig_id.lower():
        chrome_download_restrictions = re.search(
            r'Navigate\s+to\s+["“]?(HKLM\\Software\\Policies\\Google\\Chrome)\\?["”]?\.?',
            content,
            re.IGNORECASE,
        )
        if (
            chrome_download_restrictions
            and re.search(r'If\s+(?:the\s+)?["“]DownloadRestrictions["”]\s+value\s+name\s+does\s+not\s+exist\s+or\s+its\s+value\s+data\s+is\s+set\s+to\s+["“]?0["”]?,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
            and re.search(r'Policy\s+Name:\s+Allow\s+download\s+restrictions', fix_text, re.IGNORECASE)
            and re.search(r'Policy\s+State:\s+1,\s*2,\s*or\s*4\b', fix_text, re.IGNORECASE)
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {
                    'type': 'registry',
                    'path': _normalize_registry_path(chrome_download_restrictions.group(1)),
                    'value_name': 'DownloadRestrictions',
                },
                'expected': {'type': 'matches', 'pattern': '^(?:1|2|4)$'},
                'description': rule.get('title', ''),
            }
        chrome_terminal_value_path = re.search(
            r'Navigate\s+to\s+["“]?(HKLM\\Software\\Policies\\Google\\Chrome)\\(DefaultCookiesSetting)["”]?\.?',
            content,
            re.IGNORECASE,
        )
        if (
            chrome_terminal_value_path
            and re.search(r'policy\s+["“]DefaultCookiesSetting["”]\s+is\s+not\s+shown\s+or\s+is\s+not\s+set\s+to\s+["“]4["”],?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
            and re.search(r'If\s+this\s+key\s+does\s+not\s+exist,\s+or\s+is\s+not\s+set\s+to\s+["“]4["”],?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
            and re.search(r'Policy\s+Name:\s+Default\s+cookies\s+setting', fix_text, re.IGNORECASE)
            and re.search(r'Policy\s+Value:\s+Keep\s+cookies\s+for\s+the\s+duration\s+of\s+the\s+session', fix_text, re.IGNORECASE)
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {
                    'type': 'registry',
                    'path': _normalize_registry_path(chrome_terminal_value_path.group(1)),
                    'value_name': chrome_terminal_value_path.group(2),
                },
                'expected': {'type': 'equals', 'value': 4},
                'description': rule.get('title', ''),
            }
    path_match = re.search(r'Navigate\s+to\s+["“]?((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\n\r"”]+)', content, re.IGNORECASE)
    value_match = None
    expected_value = None
    if path_match:
        value_match = re.search(r'If\s+the\s+["“]([^"”]+)["”]\s+(?:value\s+name|key)\s+does\s+not\s+exist[^\n\r.]*?(?:value\s+data\s+)?is\s+not\s+set\s+to', content, re.IGNORECASE)
        if not value_match:
            value_match = re.search(r'If\s+([A-Za-z0-9_.-]+)\s+is\s+not\s+displayed[^\n\r.]*?or\s+it\s+is\s+not\s+set\s+to', content, re.IGNORECASE)
        expected_value = _parse_expected_registry_data(content)
        allowed_dword_value_match = re.search(
            r'If\s+the\s+value\s+for\s+["“]?([A-Za-z0-9_.-]+)["”]?\s+is\s+not\s+set\s+to\s+["“]?REG_DWORD\s*=\s*(\d+)["”]?\s+or\s+["“]?REG_DWORD\s*=\s*(\d+)["”]?\s*,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        if allowed_dword_value_match:
            allowed_values = sorted({int(allowed_dword_value_match.group(2)), int(allowed_dword_value_match.group(3))})
            if len(allowed_values) > 1:
                return {
                    'vuln_id': rule.get('vuln_id', ''),
                    'platform': 'windows' if any(token in stig_id.lower() for token in ('windows', 'chrome', 'edge', 'defender', 'office')) else 'generic',
                    'check': {
                        'type': 'registry',
                        'path': _normalize_registry_path(path_match.group(1)),
                        'value_name': allowed_dword_value_match.group(1).strip(),
                    },
                    'expected': {'type': 'matches', 'pattern': f"^(?:{'|'.join(str(value) for value in allowed_values)})$"},
                    'description': rule.get('title', ''),
                }
        if (expected_value is None or not value_match) and 'chrome' in stig_id.lower():
            chrome_key_value = re.search(
                r'If\s+the\s+key\s+["“]([A-Za-z0-9_.-]+)["”]\s+does\s+not\s+exist\s+or\s+is\s+not\s+set\s+to\s+["“]?(\d+)["”]?,\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            )
            if chrome_key_value and re.search(
                rf'If\s+the\s+policy\s+["“]{re.escape(chrome_key_value.group(1))}["”]\s+is\s+not\s+shown\s+or\s+is\s+not\s+set\s+to\s+["“]?{re.escape(chrome_key_value.group(2))}["”]?,\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            ):
                value_match = chrome_key_value
                expected_value = int(chrome_key_value.group(2))
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
        if path_match:
            allowed_dword_value_match = re.search(
                r'If\s+the\s+value\s+for\s+["“]?([A-Za-z0-9_.-]+)["”]?\s+is\s+not\s+set\s+to\s+["“]?REG_DWORD\s*=\s*(\d+)["”]?\s+or\s+["“]?REG_DWORD\s*=\s*(\d+)["”]?\s*,?\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            )
            if allowed_dword_value_match:
                allowed_values = sorted({int(allowed_dword_value_match.group(2)), int(allowed_dword_value_match.group(3))})
                if len(allowed_values) > 1:
                    return {
                        'vuln_id': rule.get('vuln_id', ''),
                        'platform': 'windows' if any(token in stig_id.lower() for token in ('windows', 'chrome', 'edge', 'defender', 'office')) else 'generic',
                        'check': {
                            'type': 'registry',
                            'path': _normalize_registry_path(path_match.group(1)),
                            'value_name': allowed_dword_value_match.group(1).strip(),
                        },
                        'expected': {'type': 'matches', 'pattern': f"^(?:{'|'.join(str(value) for value in allowed_values)})$"},
                        'description': rule.get('title', ''),
                    }
            office_also_acceptable_dword = re.search(
                r'If\s+the\s+value\s+(?:for\s+)?["“]?([A-Za-z0-9_.-]+)["”]?\s+is\s+REG_DWORD\s*=\s*(\d+)\s*,?\s+this\s+is\s+not\s+a\s+finding\.\s+A\s+value\s+of\s+REG_DWORD\s*=\s*(\d+)(?P<tail>[^.]*?)\s+is\s+also\s+acceptable\.',
                content,
                re.IGNORECASE,
            )
            if office_also_acceptable_dword and 'office' in stig_id.lower():
                values = {
                    int(office_also_acceptable_dword.group(2)),
                    int(office_also_acceptable_dword.group(3)),
                }
                values.update(int(value) for value in re.findall(r'\bor\s+REG_DWORD\s*=\s*(\d+)', office_also_acceptable_dword.group('tail'), re.IGNORECASE))
                allowed_values = sorted(values)
                if len(allowed_values) > 1:
                    return {
                        'vuln_id': rule.get('vuln_id', ''),
                        'platform': 'windows',
                        'check': {
                            'type': 'registry',
                            'path': _normalize_registry_path(path_match.group(1)),
                            'value_name': office_also_acceptable_dword.group(1).strip(),
                        },
                        'expected': {'type': 'matches', 'pattern': f"^(?:{'|'.join(str(value) for value in allowed_values)})$"},
                        'description': rule.get('title', ''),
                    }
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
            if not value_match:
                value_match = re.search(
                    r'(?:Criteria:\s*)?If\s+the\s+value\s+["“]([^"”]+)["”]\s+is\s+["“]REG_(DWORD|SZ)\s*=\s*([^"”\n\r]+)["”]\s*,?\s+this\s+is\s+not\s+a\s+finding\.',
                    content,
                    re.IGNORECASE,
                )
            if not value_match:
                value_match = re.search(
                    r'(?:Criteria:\s*)?If\s+the\s+value\s+for\s+(allow\s+user\s+locations)\s+is\s+set\s+to\s+REG_(DWORD)\s*=\s*([^,\.\n\r()]+)\s*,?\s+this\s+is\s+not\s+a\s+finding\.',
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


def _firefox_policy_boolean_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'firefox' not in stig_id.lower():
        return None
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-251564', 'V-251566', 'V-251578', 'V-251580'}:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    check_match = re.search(
        r'If\s+["“]([A-Za-z0-9_.-]+)["”]\s+is\s+not\s+displayed\s+under\s+Policy\s+Name\s+or\s+the\s+Policy\s+Value\s+is\s+not\s+["“](true|false)["”],\s+this\s+is\s+a\s+finding\.',
        content,
        re.IGNORECASE,
    )
    if not check_match or 'about:policies' not in content:
        return None
    policy_name = check_match.group(1)
    expected = check_match.group(2).lower()
    linux_policy_match = re.search(
        r'Linux\s+["“]policies\.json["”]\s+file:.*?["“]' + re.escape(policy_name) + r'["”]\s*:\s*(true|false)\b',
        fix_text,
        re.IGNORECASE | re.DOTALL,
    )
    if not linux_policy_match or linux_policy_match.group(1).lower() != expected:
        return None
    command = (
        'python3 -c "import json, pathlib; '
        "p=pathlib.Path('/usr/lib/firefox/distribution/policies.json'); "
        "policies=json.loads(p.read_text()).get('policies', {}) if p.exists() else {}; "
        f"print(str(policies.get('{policy_name}')).lower())\""
    )
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': expected},
        'description': rule.get('title', ''),
    }


def _linux_platform(stig_id: str) -> bool:
    lower = stig_id.lower()
    return any(token in lower for token in ('rhel', 'red_hat', 'linux', 'oracle_linux', 'ol_', 'ubuntu', 'sles', 'suse'))


def _windows_platform(stig_id: str) -> bool:
    lower = stig_id.lower()
    return 'windows' in lower or 'ms_windows' in lower


def _ubuntu_rsyslog_remote_access_methods_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-238324', 'V-260589', 'V-270681'}:
        return None
    if 'ubuntu' not in stig_id.lower():
        return None
    title = rule.get('title', '') or ''
    if 'must monitor remote access methods' not in title:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = f'{content}\n{fix_text}'
    if not re.search(r'grep\s+-[A-Za-z]*E[A-Za-z]*\s+', content, re.IGNORECASE):
        return None
    if not all(token in content for token in ('authpriv', 'daemon')):
        return None
    if not re.search(r'/etc/rsyslog(?:\.\*|\.d/)', content, re.IGNORECASE):
        return None
    if not all(token in combined for token in ('authpriv.*', 'daemon.*')):
        return None
    if not re.search(r'not\s+configured\s+to\s+be\s+logged\s+in\s+at\s+least\s+one\s+of\s+the\s+config\s+files', content, re.IGNORECASE):
        return None
    command = "sh -c 'grep -Ehr \"^(auth\\.\\*,authpriv\\.\\*|auth,authpriv\\.\\*|daemon\\.\\*)[[:space:]]+\" /etc/rsyslog.* /etc/rsyslog.d/* 2>/dev/null | awk '\"'\"'BEGIN{auth=0;daemon=0} /^[[:space:]]*#/ {next} /^(auth\\.\\*,authpriv\\.\\*|auth,authpriv\\.\\*)[[:space:]]+/ {auth=1} /^daemon\\.\\*[[:space:]]+/ {daemon=1} END{if(auth && daemon) print \"configured\"}'\"'\"''"
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'configured'},
        'description': title,
    }


def _windows_legal_notice_caption_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    if not re.search(r'Value\s+Name:\s*LegalNoticeCaption\b', content, re.IGNORECASE):
        return None
    legacy_title_above = re.search(r'Value\s*:\s*See\s+message\s+title\s+above\b', content, re.IGNORECASE)
    if not (
        re.search(r'Automated\s+tools\s+may\s+only\s+search\s+for\s+the\s+titles\s+defined\s+above', content, re.IGNORECASE)
        or legacy_title_above
    ):
        return None
    dod_title_match = re.search(r'"(DoD|DOD)\s+Notice\s+and\s+Consent\s+Banner"', content)
    defense_warning_title = 'US Department of Defense Warning Statement'
    if not dod_title_match or f'"{defense_warning_title}"' not in content:
        return None
    allowed_titles = [f'{dod_title_match.group(1)} Notice and Consent Banner', defense_warning_title]
    hives = [next(group for group in match if group).strip() for match in re.findall(r'Registry[ \t]+Hive(?::[ \t]*([^\n\r]+)|([A-Z][^\n\r]+))', content, re.IGNORECASE)]
    paths = [next(group for group in match if group).strip().strip('\\/') for match in re.findall(r'Registry[ \t]+Path(?::[ \t]*([^:\n\r][^\n\r]*)|(\\[^\n\r]+))', content, re.IGNORECASE)]
    if len(hives) != 1 or len(paths) != 1:
        return None
    normalized_path = re.sub(r'\\+', r'\\', paths[0]).rstrip('\\/')
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'registry',
            'path': f"{_registry_hive_abbrev(hives[0])}\\{normalized_path}",
            'value_name': 'LegalNoticeCaption',
        },
        'expected': {'type': 'matches', 'pattern': f"^(?:{'|'.join(re.escape(title) for title in allowed_titles)})$"},
        'description': rule.get('title', ''),
    }


def _windows_legal_notice_text_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    if not re.search(r'Value\s+Name:\s*LegalNoticeText\b', content, re.IGNORECASE):
        return None
    if not re.search(r'Value\s*:\s*See\s+message\s+text\s+below', content, re.IGNORECASE):
        return None
    if not re.search(r'required\s+legal\s+notice|message\s+text\s+for\s+users\s+attempting\s+to\s+log\s+on', rule.get('title', '') + '\n' + rule.get('fix_text', ''), re.IGNORECASE):
        return None
    hives = [next(group for group in match if group).strip() for match in re.findall(r'Registry[ \t]+Hive(?::[ \t]*([^\n\r]+)|([A-Z][^\n\r]+))', content, re.IGNORECASE)]
    paths = [next(group for group in match if group).strip().strip('\\/') for match in re.findall(r'Registry[ \t]+Path(?::[ \t]*([^:\n\r][^\n\r]*)|(\\[^\n\r]+))', content, re.IGNORECASE)]
    if len(hives) != 1 or len(paths) != 1:
        return None
    text_match = re.search(
        r'(You\s+are\s+accessing\s+a\s+U\.S\.\s+Government\s+\(USG\)\s+Information\s+System\s+\(IS\).*?)\s*$',
        content,
        re.IGNORECASE | re.DOTALL,
    )
    if not text_match:
        return None
    expected_text = text_match.group(1).strip()
    if len(expected_text) < 200 or 'See User Agreement for details.' not in expected_text:
        return None
    normalized_path = re.sub(r'\\+', r'\\', paths[0]).rstrip('\\/')
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'registry',
            'path': f"{_registry_hive_abbrev(hives[0])}\\{normalized_path}",
            'value_name': 'LegalNoticeText',
        },
        'expected': {'type': 'equals', 'value': expected_text},
        'description': rule.get('title', ''),
    }


def _kubernetes_validating_admission_webhook_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'kubernetes' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    if rule.get('vuln_id') != 'V-242436':
        return None
    if 'ValidatingAdmissionWebhook' not in content or 'enable-admission-plugins' not in content:
        return None
    if not re.search(r'If\s+a\s+line\s+is\s+not\s+returned\s+that\s+includes\s+enable-admission-plugins\s+and\s+ValidatingAdmissionWebhook,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {
            'type': 'command_output',
            'command': 'grep -i ValidatingAdmissionWebhook /etc/kubernetes/manifests/*',
        },
        'expected': {'type': 'contains', 'substring': 'enable-admission-plugins'},
        'description': rule.get('title', ''),
    }


def _kubernetes_manifest_grep_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'kubernetes' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if re.search(r'\b(?:PPSM|Ports,\s+Protocols|organization|documentation|interview|namespace|podname|<[^>]+>|latest|skew\s+policy)\b', content + '\n' + fix_text, re.IGNORECASE):
        return None
    if '/etc/kubernetes/manifests' not in content:
        return None
    command_match = re.search(
        r'Run\s+the\s+command:\s*(?:\n|\s)+(?P<command>grep\s+-[iI]\s+(?P<flag>[A-Za-z0-9_-]+)\s+\*)\s*(?:\n|\s)+If\s+(?P<finding>[^.]+?this\s+is\s+a\s+finding)',
        content,
        re.IGNORECASE | re.DOTALL,
    )
    if not command_match:
        return None
    flag = command_match.group('flag')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', flag):
        return None
    finding = command_match.group('finding')
    command = f'grep -i {flag} /etc/kubernetes/manifests/*'
    if re.search(r'\bset\s+to\s+["“]false["”]|or\s+set\s+to\s+["“]false["”]', finding, re.IGNORECASE):
        fix_value = re.search(rf'Set\s+the\s+value\s+of\s+["“]--?{re.escape(flag)}["”]?\s+to\s+["“](true)["”]', fix_text, re.IGNORECASE)
        if not fix_value:
            return None
        expected = {'type': 'contains', 'substring': fix_value.group(1).lower()}
    elif re.search(r'\bset\s+to\s+["“]true["”]|or\s+(?:it\s+is\s+)?set\s+to\s+["“]True["”]', finding, re.IGNORECASE):
        fix_value = re.search(rf'(?:Set\s+(?:the\s+argument\s+)?["“]--?{re.escape(flag)}(?:\s+value)?["”]?|Set\s+the\s+value\s+of\s+["“]--?{re.escape(flag)}["”]?)\s+to\s+["“](false)["”]', fix_text, re.IGNORECASE)
        if not fix_value:
            return None
        expected = {'type': 'contains', 'substring': fix_value.group(1).lower()}
    elif re.search(r'\b(?:not\s+set|not\s+configured|contains\s+no\s+value)\b', finding, re.IGNORECASE) and not re.search(r'\bdoes\s+not\s+contain\b', finding, re.IGNORECASE):
        expected = {'type': 'not_equals', 'value': ''}
    elif re.search(r'\bis\s+set\b', finding, re.IGNORECASE) and re.search(rf'\bRemove\s+the\s+setting\s+["“]--?{re.escape(flag)}["”]', fix_text, re.IGNORECASE):
        expected = {'type': 'equals', 'value': ''}
    else:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': expected,
        'description': rule.get('title', ''),
    }


def _windows_hardened_unc_paths_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    policy_text = '\n'.join(part for part in (content, fix_text) if part)
    required_value = 'RequireMutualAuthentication=1, RequireIntegrity=1'
    if not re.search(r'NetworkProvider\\\\HardenedPaths|HardenedPaths', policy_text, re.IGNORECASE):
        return None
    if '\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths' not in policy_text:
        return None
    if required_value not in policy_text:
        return None
    if '\\\\*\\NETLOGON' not in policy_text:
        return None
    if '\\\\*\\SYSVOL' not in policy_text:
        return None
    expected = '\\\\*\\NETLOGON=RequireMutualAuthentication=1, RequireIntegrity=1\n\\\\*\\SYSVOL=RequireMutualAuthentication=1, RequireIntegrity=1'
    command = (
        'powershell -NoProfile -Command "'
        "$p='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths'; "
        "'\\\\*\\NETLOGON=' + (Get-ItemPropertyValue -Path $p -Name '\\\\*\\NETLOGON'); "
        "'\\\\*\\SYSVOL=' + (Get-ItemPropertyValue -Path $p -Name '\\\\*\\SYSVOL')"
        '"'
    )
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'contains', 'substring': expected},
        'description': rule.get('title', ''),
    }


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


def _positive_integer_range_pattern(maximum: int) -> str:
    if maximum < 1:
        raise ValueError('maximum must be positive')
    alternatives = [str(value) for value in range(1, maximum + 1)]
    return f"^(?:{'|'.join(alternatives)})$"


def _windows_directory_service_max_conn_idle_time_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-254400', 'V-278147'}:
        return None
    if not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'\b(?:ntdsutil|dsquery)\b', content, re.IGNORECASE):
        return None
    if not re.search(r'\bMaxConnIdleTime\b', content, re.IGNORECASE):
        return None
    if not re.search(
        r'MaxConnIdleTime\s+is\s+greater\s+than\s+["“]?300["”]?[^.]*or\s+is\s+not\s+specified,\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE | re.DOTALL,
    ):
        return None
    if not re.search(r'Set\s+MaxConnIdleTime\s+to\s+300\b', fix_text, re.IGNORECASE):
        return None
    command = "powershell -NoProfile -Command \"$root=[ADSI]'LDAP://RootDSE'; $cfg=$root.configurationNamingContext; $p=[ADSI]('LDAP://CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,'+$cfg); $v=@($p.Properties['LDAPAdminLimits']) | Where-Object { $_ -match '^MaxConnIdleTime=(\\d+)$' } | Select-Object -First 1; if ($v -match '^MaxConnIdleTime=(\\d+)$' -and [int]$Matches[1] -le 300) { 'Compliant' }\""
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _vcenter_lookup_optional_xml_value_candidate(rule: dict, stig_id: str) -> dict | None:
    stig_lower = stig_id.lower()
    if 'vsphere' not in stig_lower or 'lookup' not in stig_lower:
        return None
    vuln_id = rule.get('vuln_id', '')
    mappings = {
        'V-259058': {
            'name': 'debug',
            'value': '0',
            'path': '/usr/lib/vmware-lookupsvc/conf/web.xml',
            'command': "sh -c \"xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=\\\".*\\\"//g' | xmllint --xpath 'string(//param-name[text()=\\\"debug\\\"]/parent::init-param/param-value)' - 2>/dev/null | awk 'NF{print \\\"debug=\\\" $0}'\"",
        },
        'V-259059': {
            'name': 'listings',
            'value': 'false',
            'path': '/usr/lib/vmware-lookupsvc/conf/web.xml',
            'command': "sh -c \"xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=\\\".*\\\"//g' | xmllint --xpath 'string(//param-name[text()=\\\"listings\\\"]/parent::init-param/param-value)' - 2>/dev/null | awk 'NF{print \\\"listings=\\\" $0}'\"",
        },
        'V-259062': {
            'name': 'xpoweredBy',
            'value': 'false',
            'path': '/usr/lib/vmware-lookupsvc/conf/server.xml',
            'command': "sh -c \"xmllint --xpath 'string(//Connector/@xpoweredBy)' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null | awk 'NF{print \\\"xpoweredBy=\\\" $0}'\"",
        },
    }
    cfg = mappings.get(vuln_id)
    if not cfg:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    name = re.escape(cfg['name'])
    value = re.escape(cfg['value'])
    if 'xmllint' not in content or cfg['path'] not in content:
        return None
    if not re.search(
        rf'If\s+the\s+["“]{name}["”]\s+parameter\s+is\s+specified\s+and\s+is\s+not\s+["“]{value}["”],\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return None
    if not re.search(
        rf'If\s+the\s+["“]{name}["”]\s+parameter\s+does\s+not\s+exist,\s+this\s+is\s+not\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return None
    if cfg['path'] not in fix_text or not re.search(r'(?:param-value|remove\s+the\s+(?:entire\s+block|"xpoweredBy"\s+attribute))', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'generic',
        'check': {'type': 'command_output', 'command': cfg['command']},
        'expected': {'type': 'matches', 'pattern': rf'^(?:|{re.escape(cfg["name"] + "=" + cfg["value"])})$'},
        'description': rule.get('title', ''),
    }


def _windows_security_policy_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    policy_text = '\n'.join(part for part in (content, fix_text, title) if part)
    has_secedit_context = bool(re.search(r'\bsecedit\b', content, re.IGNORECASE))

    if 'Account Policies >> Kerberos Policy' in policy_text:
        kerberos_option = re.search(
            r'If\s+(?:the\s+)?"([^"]+)"\s+is\s+not\s+set\s+to\s+"(Enabled|Disabled)"\s*,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        if kerberos_option:
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {'type': 'security_policy', 'section': 'Kerberos Policy', 'key': kerberos_option.group(1).strip()},
                'expected': {'type': 'equals', 'value': kerberos_option.group(2).strip()},
                'description': rule.get('title', ''),
            }
        kerberos_less_or_equal = re.search(
            r'Account\s+Policies\s*>>\s*Kerberos\s+Policy\s*>>\s*"?([^"\n]+?)"?\s+to\s+a\s+maximum\s+of\s+"(\d+)"\s+[^.\n]*\bor\s+less\s*\.\s*(?:\n|$)',
            policy_text,
            re.IGNORECASE,
        )
        if kerberos_less_or_equal:
            if re.search(r'\bbut\s+not\s+"?0"?|not\s+"?0"?', kerberos_less_or_equal.group(0), re.IGNORECASE):
                return {
                    'vuln_id': rule.get('vuln_id', ''),
                    'platform': 'windows',
                    'check': {'type': 'security_policy', 'section': 'Kerberos Policy', 'key': kerberos_less_or_equal.group(1).strip()},
                    'expected': {'type': 'matches', 'pattern': _positive_integer_range_pattern(int(kerberos_less_or_equal.group(2)))},
                    'description': rule.get('title', ''),
                }
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {'type': 'security_policy', 'section': 'Kerberos Policy', 'key': kerberos_less_or_equal.group(1).strip()},
                'expected': {'type': 'less_or_equal', 'value': int(kerberos_less_or_equal.group(2))},
                'description': rule.get('title', ''),
            }
        kerberos_nonzero_upper_bound = re.search(
            r'If\s+the\s+value\s+for\s+"([^"]+)"\s+is\s+"0"\s+or\s+greater\s+than\s+"(\d+)"\s+[^.\n]*,\s+this\s+is\s+a\s+finding',
            policy_text,
            re.IGNORECASE,
        )
        if not kerberos_nonzero_upper_bound:
            kerberos_nonzero_upper_bound = re.search(
                r'If\s+the\s+value\s+for\s+"([^"]+)"\s+is\s+greater\s+than\s+"(\d+)"\s+[^.\n]*\s+or\s+is\s+set\s+to\s+"0",\s+this\s+is\s+a\s+finding',
                policy_text,
                re.IGNORECASE,
            )
        if kerberos_nonzero_upper_bound and re.search(
            rf'Kerberos\s+Policy\s*>>\s*{re.escape(kerberos_nonzero_upper_bound.group(1).strip())}\s+to\s+a\s+maximum\s+of\s+"{re.escape(kerberos_nonzero_upper_bound.group(2))}"[^.\n]*\b(?:but\s+not|not)\s+"0"',
            policy_text,
            re.IGNORECASE,
        ):
            maximum = int(kerberos_nonzero_upper_bound.group(2))
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'windows',
                'check': {'type': 'security_policy', 'section': 'Kerberos Policy', 'key': kerberos_nonzero_upper_bound.group(1).strip()},
                'expected': {'type': 'matches', 'pattern': _positive_integer_range_pattern(maximum)},
                'description': rule.get('title', ''),
            }

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
            if not rename_option:
                rename_option = re.search(
                    r'Configure\s+the\s+policy\s+value\s+for\s+Computer\s+Configuration\s*>>\s*Windows\s+Settings\s*>>\s*Security\s+Settings\s*>>\s*Local\s+Policies\s*>>\s*Security\s+Options\s*>>\s*(?P<key>Accounts:\s+Rename\s+(?P<account>administrator|guest)\s+account)\s+to\s+a\s+name\s+other\s+than\s+"(?P<value>Administrator|Guest)"\s*\.\s*(?:\n|$)',
                    policy_text,
                    re.IGNORECASE,
                )
                if rename_option and (
                    rename_option.group('account').lower() != rename_option.group('value').lower()
                    or not re.search(rf'\bbuilt-in\s+{rename_option.group("account")}\s+account\s+must\s+be\s+renamed\b', title, re.IGNORECASE)
                ):
                    rename_option = None
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
            exact_string_option = re.search(
                r'Configure\s+the\s+policy\s+value\s+for\s+Computer\s+Configuration\s*>>\s*Windows\s+Settings\s*>>\s*Security\s+Settings\s*>>\s*Local\s+Policies\s*>>\s*Security\s+Options\s*>>\s*"?([^"\n]+?)"?\s+to\s+"([^"\n]+)"\s*\.\s*(?:\n|$)',
                policy_text,
                re.IGNORECASE,
            )
            if exact_string_option:
                exact_value = exact_string_option.group(2).strip()
                unsafe_string_context = re.search(
                    r'\b(?:also\s+acceptable|acceptable|at\s+a\s+minimum|organization-defined|equivalent|all\s+options\s+selected|with\s+only\s+the\s+following\s+selected)\b',
                    policy_text,
                    re.IGNORECASE,
                )
                if exact_value not in {'Enabled', 'Disabled'} and not unsafe_string_context:
                    return {
                        'vuln_id': rule.get('vuln_id', ''),
                        'platform': 'windows',
                        'check': {'type': 'security_policy', 'section': 'Security Options', 'key': exact_string_option.group(1).strip()},
                        'expected': {'type': 'equals', 'value': exact_value},
                        'description': rule.get('title', ''),
                    }
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
            r'If\s+any\s+(?:groups\s+or\s+accounts|accounts\s+or\s+groups)\s+other\s+than\s+the\s+following\s+are\s+granted\s+the\s+"([^"]+)"\s+(?:user\s+)?right,\s+this\s+is\s+a\s+finding[:.]\s*\n\s*-?\s*Administrators\.?\s*(?:\n|\Z)',
            content,
            re.IGNORECASE,
        )
        administrators_only_fix = re.search(
            r'User\s+Rights\s+Assignment\s*>>\s*"?([^"\n]+?)"?\s+to\s+(?:only\s+include|include\s+only)\s+the\s+following\s+(?:groups\s+or\s+accounts|accounts\s+or\s+groups):\s*\n\s*-?\s*Administrators\.?\s*(?:\n|\Z)',
            fix_text,
            re.IGNORECASE,
        )
        administrators_only_right_keys = {
            'back up files and directories': 'SeBackupPrivilege',
            'allow log on locally': 'SeInteractiveLogonRight',
            'allow log on through remote desktop services': 'SeRemoteInteractiveLogonRight',
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

        fixed_service_allowlist_match = re.search(
            r'If\s+any\s+(?:groups\s+or\s+accounts|accounts\s+or\s+groups)\s+other\s+than\s+the\s+following\s+are\s+granted\s+the\s+"([^"]+)"\s+user\s+right,\s+this\s+is\s+a\s+finding:\s*\n(?P<body>.*?)(?:\n\s*\n|\Z)',
            content,
            re.IGNORECASE | re.DOTALL,
        )
        fixed_service_allowlist_fix = re.search(
            r'User\s+Rights\s+Assignment\s*>>\s*"?([^"\n]+?)"?\s+to\s+only\s+include\s+the\s+following\s+(?:groups\s+or\s+accounts|accounts\s+or\s+groups):\s*\n(?P<body>.*?)(?:\n\s*\n|\Z)',
            fix_text,
            re.IGNORECASE | re.DOTALL,
        )
        fixed_service_right_keys = {
            'change the system time': 'SeSystemtimePrivilege',
            'create global objects': 'SeCreateGlobalPrivilege',
            'impersonate a client after authentication': 'SeImpersonatePrivilege',
        }
        fixed_service_principal_sids = {
            'administrators': '*S-1-5-32-544',
            'local service': '*S-1-5-19',
            'network service': '*S-1-5-20',
            'service': '*S-1-5-6',
        }
        fixed_service_expected_principals = {
            'change the system time': ['administrators', 'local service'],
            'create global objects': ['administrators', 'local service', 'network service', 'service'],
            'impersonate a client after authentication': ['administrators', 'local service', 'network service', 'service'],
        }
        if fixed_service_allowlist_match and fixed_service_allowlist_fix and not re.search(r'\b(application|documented|ISSO|organization-defined|site-defined)\b', policy_text, re.IGNORECASE):
            check_display_name = fixed_service_allowlist_match.group(1).strip().strip('"')
            fix_display_name = fixed_service_allowlist_fix.group(1).strip().strip('"')
            check_principals = [line.strip(' -\t.').lower() for line in fixed_service_allowlist_match.group('body').splitlines() if line.strip()]
            fix_principals = [line.strip(' -\t.').lower() for line in fixed_service_allowlist_fix.group('body').splitlines() if line.strip()]
            expected_principals = fixed_service_expected_principals.get(check_display_name.lower())
            if expected_principals and check_display_name.lower() == fix_display_name.lower() and sorted(check_principals) == sorted(expected_principals) and sorted(fix_principals) == sorted(expected_principals):
                key = fixed_service_right_keys.get(check_display_name.lower())
                if key:
                    expected_value = ','.join(fixed_service_principal_sids[principal] for principal in expected_principals)
                    return {
                        'vuln_id': rule.get('vuln_id', ''),
                        'platform': 'windows',
                        'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': key},
                        'expected': {'type': 'equals', 'value': expected_value},
                        'description': rule.get('title', ''),
                    }

        exact_allowlist_match = re.search(
            r'If\s+any\s+(?:groups\s+or\s+accounts|accounts\s+or\s+groups)\s+other\s+than\s+the\s+following\s+are\s+granted\s+the\s+"([^"]+)"\s+(?:user\s+)?right,\s+this\s+is\s+a\s+finding[:.]\s*(?:\n[ \t]*)*(?P<body>(?:\n[ \t]*(?:[-*]\s*)?[A-Za-z][^\n]+)+)',
            content,
            re.IGNORECASE,
        )
        exact_allowlist_fix = re.search(
            r'User\s+Rights\s+Assignment\s*>>\s*"?([^"\n]+?)"?\s+to\s+(?:only\s+include|include\s+only)\s+the\s+following\s+(?:groups\s+or\s+accounts|accounts\s+or\s+groups):\s*(?:\n[ \t]*)*(?P<body>(?:\n[ \t]*(?:[-*]\s*)?[A-Za-z][^\n]+)+)',
            fix_text,
            re.IGNORECASE,
        )
        exact_allowlist_right_keys = {
            'access this computer from the network': 'SeNetworkLogonRight',
            'allow log on locally': 'SeInteractiveLogonRight',
            'allow log on through remote desktop services': 'SeRemoteInteractiveLogonRight',
            'change the system time': 'SeSystemtimePrivilege',
            'deny access to this computer from the network': 'SeDenyNetworkLogonRight',
            'deny log on as a batch job': 'SeDenyBatchLogonRight',
            'deny log on locally': 'SeDenyInteractiveLogonRight',
            'deny log on through remote desktop services': 'SeDenyRemoteInteractiveLogonRight',
            'impersonate a client after authentication': 'SeImpersonatePrivilege',
        }
        exact_allowlist_principal_sids = {
            'administrators': '*S-1-5-32-544',
            'authenticated users': '*S-1-5-11',
            'enterprise domain controllers': '*S-1-5-9',
            'guests': '*S-1-5-32-546',
            'local service': '*S-1-5-19',
            'network service': '*S-1-5-20',
            'nt service\\autotimesvc is added in v1909 cumulative update': 'NT SERVICE\\autotimesvc',
            'remote desktop users': '*S-1-5-32-555',
            'restricted services\\printspoolerservice': 'RESTRICTED SERVICES\\PrintSpoolerService',
            'service': '*S-1-5-6',
            'local account': '*S-1-5-113',
            'local account and member of administrators group': '*S-1-5-114',
        }
        if exact_allowlist_match and exact_allowlist_fix and not re.search(r'\b(application|documented|ISSO|organization-defined|site-defined|except|exception)\b', policy_text, re.IGNORECASE):
            check_display_name = exact_allowlist_match.group(1).strip().strip('"')
            fix_display_name = exact_allowlist_fix.group(1).strip().strip('"')
            check_principals = [line.strip(' -*\t.').lower() for line in exact_allowlist_match.group('body').splitlines() if line.strip()]
            fix_principals = [line.strip(' -*\t.').lower() for line in exact_allowlist_fix.group('body').splitlines() if line.strip()]
            if check_display_name.lower() == fix_display_name.lower() and check_principals == fix_principals:
                key = exact_allowlist_right_keys.get(check_display_name.lower())
                if key and check_principals and all(principal in exact_allowlist_principal_sids for principal in check_principals):
                    expected_value = ','.join(exact_allowlist_principal_sids[principal] for principal in check_principals)
                    return {
                        'vuln_id': rule.get('vuln_id', ''),
                        'platform': 'windows',
                        'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': key},
                        'expected': {'type': 'equals', 'value': expected_value},
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
            r'^\s*((?:kernel|net|fs|vm|user)\.[A-Za-z0-9_.-]+)\s*=\s*([^\s#]+)\s*$',
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


def _linux_interactive_shadow_sha512_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    supported_vulns = {'V-258231', 'V-271628', 'V-248534', 'V-234887'}
    if vuln_id not in supported_vulns or not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'cut\s+-d:\s+-f2\s+/etc/shadow', content, re.IGNORECASE):
        return None
    if not re.search(r'Password\s+hashes\s+["“]!\s*["”]\s+or\s+["“]\*["”].*not\s+evaluated', content, re.IGNORECASE | re.DOTALL):
        return None
    if not re.search(r'interactive\s+user\s+password\s+hash\s+does\s+not\s+begin\s+with\s+["“]\$6\$?["”]', content, re.IGNORECASE):
        return None
    if not (
        re.search(r'Lock\s+all\s+interactive\s+user\s+accounts\s+not\s+using\s+SHA-?512', fix_text, re.IGNORECASE)
        or re.search(r'ENCRYPT_METHOD\s+SHA512', fix_text, re.IGNORECASE)
    ):
        return None
    command = r"awk -F: 'NR==FNR{shell[$1]=$7; uid[$1]=$3; next} uid[$1]>=1000 && shell[$1] !~ /(nologin|false)$/ && $2 !~ /^[!*]/ && $2 !~ /^\$6\$/ {print $1}' /etc/passwd /etc/shadow"
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _linux_shadow_password_lifetime_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    combined = '\n'.join(part for part in (title, content, fix_text) if part)
    if '/etc/shadow' not in content:
        return None
    if not re.search(r'not\s+associated\s+with\s+a\s+system\s+account', content, re.IGNORECASE):
        return None

    minimum_match = re.search(r"(?:sudo\s+)?awk\s+-F:\s+'\$4\s*<\s*(\d+)\s*\{print\s+\$1\s+\"\s+\"\s+\$4\}'\s+/etc/shadow", content, re.IGNORECASE)
    if minimum_match and re.search(r'\bchage\s+-m\s+' + re.escape(minimum_match.group(1)) + r'\b', fix_text, re.IGNORECASE):
        threshold = int(minimum_match.group(1))
        if threshold != 1 or not re.search(r'minimum\s+password\s+lifetime|minimum\s+time\s+period\s+between\s+password\s+changes|24\s+hours/1\s+day', combined, re.IGNORECASE):
            return None
        command = '''awk -F: 'NR==FNR{uid[$1]=$3; shell[$1]=$7; next} ($1 in uid) && uid[$1]>=1000 && shell[$1] !~ /(nologin|false)$/ && $4 < 1 {print $1 " " $4}' /etc/passwd /etc/shadow'''
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }

    maximum_over_match = re.search(r"(?:sudo\s+)?awk\s+-F:\s+'\$5\s*>\s*(\d+)\s*\{print\s+\$1\s+\"\s+\"\s+\$5\}'\s+/etc/shadow", content, re.IGNORECASE)
    maximum_nonpositive_match = re.search(r"(?:sudo\s+)?awk\s+-F:\s+'\$5\s*<=\s*0\s*\{print\s+\$1\s+\"\s+\"\s+\$5\}'\s+/etc/shadow", content, re.IGNORECASE)
    if maximum_over_match and maximum_nonpositive_match and re.search(r'\bchage\s+-M\s+' + re.escape(maximum_over_match.group(1)) + r'\b', fix_text, re.IGNORECASE):
        threshold = int(maximum_over_match.group(1))
        if threshold != 60 or not re.search(r'maximum\s+password\s+lifetime|maximum\s+time\s+period\s+for\s+existing\s+passwords|60-day', combined, re.IGNORECASE):
            return None
        command = '''awk -F: 'NR==FNR{uid[$1]=$3; shell[$1]=$7; next} ($1 in uid) && uid[$1]>=1000 && shell[$1] !~ /(nologin|false)$/ && ($5 > 60 || $5 <= 0) {print $1 " " $5}' /etc/passwd /etc/shadow'''
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    return None


def _linux_sssd_certmap_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    combined = content + '\n' + (rule.get('fix_text', '') or '')
    if 'sssd.conf' not in combined or '[certmap/' not in combined:
        return None
    if 'maprule = (userCertificate;binary={cert!bin})' not in combined:
        return None
    if not re.search(r'certmap\s+section\s+does\s+not\s+exist[^.]*this\s+is\s+a\s+finding|no\s+evidence\s+of\s+certificate\s+mapping[^.]*this\s+is\s+a\s+finding', content, re.IGNORECASE | re.DOTALL):
        return None
    command = 'cat /etc/sssd/sssd.conf 2>/dev/null'
    if re.search(r'find\s+/etc/sssd/sssd\.conf\s+/etc/sssd/conf\.d/\s+-type\s+f\s+-exec\s+cat\s+\{\}\s+\\;', content):
        command = 'find /etc/sssd/sssd.conf /etc/sssd/conf.d/ -type f -exec cat {} \\; 2>/dev/null'
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'contains', 'substring': 'maprule = (userCertificate;binary={cert!bin})'},
        'description': rule.get('title', ''),
    }


def _sles_mfa_required_packages_candidate(rule: dict, stig_id: str) -> dict | None:
    packages = ['pam_pkcs11', 'mozilla-nss', 'mozilla-nss-tools', 'pcsc-ccid', 'pcsc-lite', 'pcsc-tools', 'opensc', 'coolkey']
    if rule.get('vuln_id', '') != 'V-234854' or stig_id != 'SLES_15_STIG':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    for package in packages:
        if not re.search(rf'\bzypper\s+info\s+{re.escape(package)}\s*\|\s*grep\s+-?i\s+installed\b', content, re.IGNORECASE):
            return None
        if not re.search(rf'\bzypper\s+install\s+{re.escape(package)}\b', fix_text, re.IGNORECASE):
            return None
    if not re.search(r'If\s+any\s+of\s+the\s+packages\s+required\s+for\s+multifactor\s+authentication\s+are\s+not\s+installed,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    command = 'missing=0; for pkg in pam_pkcs11 mozilla-nss mozilla-nss-tools pcsc-ccid pcsc-lite pcsc-tools opensc coolkey; do rpm -q "$pkg" >/dev/null 2>&1 || { echo "$pkg"; missing=1; }; done; exit 0'
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _package_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    title = rule.get('title', '') or ''
    ftp_glob_match = re.search(r'\b(?P<command>(?:sudo\s+)?(?:dnf|yum)\s+list\s+installed\s+\*ftpd\*)', content, re.IGNORECASE)
    ftp_pipeline_match = re.search(r'\b(?P<command>(?:sudo\s+)?(?:dnf|yum)\s+list\s+installed\s*\|\s*grep\s+ftpd)\b', content, re.IGNORECASE)
    ftp_match = ftp_glob_match or ftp_pipeline_match
    if (
        ftp_match
        and re.search(r'\bFile\s+Transfer\s+Protocol\s*\(FTP\)\s+server\s+package\s+must\s+not\s+be\s+installed\b', title, re.IGNORECASE)
        and re.search(r'If\s+an\s+FTP\s+server\s+is\s+installed\s+and\s+is\s+not\s+documented\s+with\s+the\s+Information\s+System\s+Security\s+Officer\s+\(ISSO\)\s+as\s+an\s+operational\s+requirement,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': _normalize_command(ftp_match.group('command'))},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    ssh_glob_install_match = re.search(
        r'\byum\s+list\s+installed\s+\\?\*ssh\\?\*',
        content,
        re.IGNORECASE,
    )
    ssh_fix_match = re.search(
        r'\byum\s+install\s+(openssh-server)(?:\.[A-Za-z0-9_]+)?\b',
        rule.get('fix_text', '') or '',
        re.IGNORECASE,
    )
    if (
        ssh_glob_install_match
        and ssh_fix_match
        and re.search(r'\bnetworked\s+systems\s+have\s+SSH\s+installed\b', title, re.IGNORECASE)
        and re.search(r'If\s+the\s+["“]SSH\s+server["”]\s+package\s+is\s+not\s+installed,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*openssh-server(?:\.[A-Za-z0-9_]+)?\b', content, re.IGNORECASE | re.MULTILINE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'package', 'name': ssh_fix_match.group(1).lower(), 'should_be_installed': True},
            'expected': {'type': 'is_true'},
            'description': rule.get('title', ''),
        }
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
    elif cat_pipe_grep and re.search(rf'if\s+["“]?{re.escape(pattern)}["”]?\s+does\s+not\s+equal\s+[^.]+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        for line in content[cat_pipe_grep.end():].splitlines():
            sample = line.strip()
            if not sample or sample.startswith('$'):
                continue
            if sample.lower().startswith(('if ', 'note:', 'ask ', 'verify ', 'check ')):
                break
            if re.search(rf'\b{re.escape(pattern)}\b', sample, re.IGNORECASE):
                pattern = sample
                expected = {'type': 'contains'}
                break
    if expected is None:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'file_content', 'path': path, 'pattern': pattern, 'is_regex': False},
        'expected': expected,
        'description': rule.get('title', ''),
    }


def _dconf_media_automount_literal_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    title = rule.get('title', '') or ''
    if not re.search(r'disable\s+the\s+graphical\s+user\s+interface\s+automounter', title, re.IGNORECASE):
        return None
    if not re.search(r'output\s+does\s+not\s+match\s+the\s+example', content, re.IGNORECASE):
        return None
    first = re.search(
        r'^\s*#\s*(?P<command>cat\s+(?P<path>/etc/dconf/db/local\.d/00-No-Automount))\s*$',
        content,
        re.MULTILINE,
    )
    second = re.search(
        r'^\s*#\s*(?P<command>cat\s+(?P<path>/etc/dconf/db/local\.d/locks/00-No-Automount))\s*$',
        content,
        re.MULTILINE,
    )
    if not first or not second:
        return None
    required_lines = [
        '[org/gnome/desktop/media-handling]',
        'automount=false',
        'automount-open=false',
        'autorun-never=true',
        '/org/gnome/desktop/media-handling/automount',
        '/org/gnome/desktop/media-handling/automount-open',
        '/org/gnome/desktop/media-handling/autorun-never',
    ]
    if not all(re.search(rf'^\s*{re.escape(line)}\s*$', content, re.MULTILINE) for line in required_lines):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {
            'type': 'command_output',
            'command': f"{_normalize_command(first.group('command'))} && {_normalize_command(second.group('command'))}",
        },
        'expected': {'type': 'contains', 'substring': '\n'.join(required_lines)},
        'description': rule.get('title', ''),
    }


def _firewalld_target_drop_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    title = rule.get('title', '') or ''
    if not re.search(r'firewall\s+employs?\s+a\s+deny-all,\s+allow-by-exception\s+policy', title, re.IGNORECASE):
        return None
    if not re.search(r'runtime\s+and\s+permanent\s+targets?\s+are\s+set\s+to\s+a\s+different\s+option\s+other\s+than\s+["“]DROP["”]', content, re.IGNORECASE):
        return None
    runtime = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?(?P<command>firewall-cmd\s+--info-zone=(?P<zone>[A-Za-z0-9_.-]+)\s*\|\s*grep\s+target)\s*$',
        content,
        re.IGNORECASE | re.MULTILINE,
    )
    permanent = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?(?P<command>firewall-cmd\s+--permanent\s+--info-zone=(?P<zone>[A-Za-z0-9_.-]+)\s*\|\s*grep\s+target)\s*$',
        content,
        re.IGNORECASE | re.MULTILINE,
    )
    if not runtime or not permanent or runtime.group('zone') != permanent.group('zone'):
        return None
    expected_lines: list[str] = []
    for match in (runtime, permanent):
        expected = None
        for raw_line in content[match.end():].splitlines():
            stripped = raw_line.strip()
            if not stripped:
                if expected:
                    break
                continue
            if stripped.startswith(('$', '#', '>')) or stripped.lower().startswith(('if ', 'note:', 'verify ', 'configure ')):
                break
            if stripped == 'target: DROP':
                expected = stripped
                break
        if expected != 'target: DROP':
            return None
        expected_lines.append(expected)
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': f"{_normalize_command(runtime.group('command'))} && {_normalize_command(permanent.group('command'))}"},
        'expected': {'type': 'contains', 'substring': '\n'.join(expected_lines)},
        'description': rule.get('title', ''),
    }


def _sshd_multi_directive_egrep_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    command_match = re.search(
        r"^\s*[$#>]\s*(?P<command>egrep\s+-r\s+'\(Permit\(\.\*\?\)\(Passwords\|Environment\)\)'\s+/etc/ssh/sshd_config)\s*$",
        content,
        re.MULTILINE,
    )
    if not command_match:
        command_match = re.search(
            r"^\s*[$#>]\s*(?P<command>(?:sudo\s+)?/usr/sbin/sshd\s+-dd\s+2>&1\s*\|[^\n\r]+?xargs\s+(?:sudo\s+)?grep\s+-iEH\s+'[^']*permit[^']*passwords\|environment[^']*')\s*$",
            content,
            re.MULTILINE | re.IGNORECASE,
        )
    if not command_match:
        return None
    expected_lines = []
    for raw_line in content[command_match.end():].splitlines():
        stripped = raw_line.strip()
        if not stripped:
            if expected_lines:
                break
            continue
        if stripped.lower().startswith(('if ', 'note:', '$', '#', '>')):
            break
        expected_lines.append(stripped)
    if expected_lines != ['PermitEmptyPasswords no', 'PermitUserEnvironment no']:
        return None
    legacy_finding = re.search(
        r'If\s+the\s+["“]PermitEmptyPasswords["”]\s+or\s+["“]PermitUserEnvironment["”]\s+keywords\s+are\s+set\s+to\s+a\s+value\s+other\s+than\s+["“]no["”],\s+are\s+commented\s+out,\s+are\s+both\s+missing,\s+or\s+conflicting\s+results\s+are\s+returned,\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    sles_finding = re.search(
        r'If\s+["“]PermitEmptyPasswords["”]\s+or\s+["“]PermitUserEnvironment["”]\s+keywords\s+are\s+not\s+set\s+to\s+["“]no["”],\s+are\s+missing\s+completely,\s+or\s+are\s+commented\s+out,\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if not (legacy_finding or sles_finding):
        return None
    command = _normalize_command(command_match.group('command'))
    command = command.replace('/usr/sbin/sshd', 'sshd').replace('xargs sudo grep', 'xargs grep')
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'contains', 'substring': '\n'.join(expected_lines)},
        'description': rule.get('title', ''),
    }


def _vcenter_lookup_service_grep_property_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    if 'lookup' not in stig_id.lower() or 'vmw_vsphere' not in stig_id.lower():
        return None
    if 'xmllint' in content.lower():
        return None
    absent_is_not_finding = re.search(r'does\s+not\s+exist,?\s+this\s+is\s+not\s+a\s+finding', content, re.IGNORECASE)
    grep_matches = list(re.finditer(
        r'^\s*#\s*(?P<command>grep\s+(?P<token>[A-Za-z0-9_.-]+)\s+(?P<path>/usr/lib/vmware-lookupsvc/conf/catalina\.properties))\s*$',
        content,
        re.MULTILINE,
    ))
    if len(grep_matches) != 1:
        return None
    token = grep_matches[0].group('token')
    expected_line = None
    for line in content[grep_matches[0].end():].splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower() in ('example result:', 'expected output:'):
            continue
        if stripped.lower().startswith(('if ', 'note:', '$', '#', '>')):
            break
        if token in stripped and '=' in stripped:
            expected_line = stripped
            break
    if not expected_line:
        return None
    key, expected_value = expected_line.split('=', 1)
    if key != token and token not in key:
        return None
    if absent_is_not_finding:
        absent_or_mismatch_finding = re.search(
            rf'If\s+(?:the\s+)?["“]{re.escape(key)}["”]\s+(?:setting\s+)?(?:is\s+)?not\s+set\s+to\s+["“]{re.escape(expected_value)}["”],?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        if not absent_or_mismatch_finding:
            return None
        command = f"sh -c \"grep '^{key}=' {grep_matches[0].group('path')} || true\""
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'matches', 'pattern': rf'^(?:|{re.escape(expected_line)})$'},
            'description': rule.get('title', ''),
        }
    finding = re.search(
        rf'If\s+there\s+are\s+no\s+results,?\s+or\s+if\s+the\s+["“]{re.escape(key)}["”]\s+is\s+not\s+set\s+to\s+["“]{re.escape(expected_value)}["”],?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if not finding:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {'type': 'file_content', 'path': grep_matches[0].group('path'), 'pattern': expected_line, 'is_regex': False},
        'expected': {'type': 'contains'},
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
    expected_match = re.search(rf'^\s*({re.escape(keyword)}\s+[^\n\r]+?)\s*$', content, re.IGNORECASE | re.MULTILINE)
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
    auditctl_token = r'(?:auditctl|audtctl)'
    if not re.search(rf'\b{auditctl_token}\s+-l\s*\|\s*e?grep\b', content, re.IGNORECASE):
        return None
    single_audit_rule_required = re.search(r'does\s+not\s+return\s+an?\s+audit\s+rule\s+for\b', content, re.IGNORECASE)
    if not re.search(r'does\s+not\s+return\s+(?:a\s+line|lines?)\b|does\s+not\s+return\s+(?:a\s+line|lines?)\s+that\s+match(?:es)?\s+the\s+example|do\s+not\s+return\s+output\s+that\s+match(?:es)?\s+the\s+examples?|does\s+not\s+return\s+audit\s+rules?\s+for|does\s+not\s+return\s+any\s+output|no\s+line\s+is\s+returned|line\s+is\s+commented\s+out|audit\s+rules?\s+are\s+not\s+defined|both\s+the\s+"b32"\s+and\s+"b64"\s+audit\s+rules(?:\s+for\s+"[^"]+"\s+files)?\s+are\s+not\s+defined|does\s+not\s+return\s+all\s+lines', content, re.IGNORECASE) and not single_audit_rule_required:
        return None
    command_match = re.search(rf'[$#>]\s*(?:sudo\s+)?{auditctl_token}\s+-l\s*\|\s*e?grep\b[^\n\r]*', content, re.IGNORECASE)
    if not command_match:
        return None

    if re.search(r'arbitrary\s+identifier|string\s+(?:after|following)\s+(?:it|"-k")\s+does\s+not\s+need\s+to\s+match|string\s+following\s+"-k"\s+does\s+not\s+need\s+to\s+match', content, re.IGNORECASE):
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


def _tomcat_systemd_boolean_property_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    if 'tomcat' not in stig_id.lower():
        return None
    command_match = re.search(
        r'^\s*(?:[$#>]\s*)?(?:sudo\s+)?grep\s+-i\s+(?P<token>[A-Za-z0-9_.-]+)\s+/etc/systemd/system/tomcat\.service\s*$',
        content,
        re.IGNORECASE | re.MULTILINE,
    )
    if not command_match:
        return None
    finding_match = re.search(
        r'If\s+there\s+are\s+no\s+results,\s+or\s+if\s+the\s+(?P<property>org\.apache\.catalina(?:\.[A-Za-z0-9_]+)+)\s+is\s+not\s*=\s*["“](?P<value>true|false)["”],?\s+this\s+is\s+a\s+finding\.',
        content,
        re.IGNORECASE,
    )
    if not finding_match:
        return None
    property_name = finding_match.group('property')
    expected_value = finding_match.group('value').lower()
    grep_token = command_match.group('token').lower()
    if grep_token not in property_name.lower():
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': f'grep -i {command_match.group("token")} /etc/systemd/system/tomcat.service',
        },
        'expected': {'type': 'contains', 'substring': f'{property_name}={expected_value}'},
        'description': rule.get('title', ''),
    }


def _tomcat_auditctl_expected_rule_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    if 'tomcat' not in stig_id.lower():
        return None
    command_match = re.search(
        r'(?:^|\n)\s*(?:[$#>]\s*)?(?:sudo\s+)?auditctl\s+-l\s*\|\s*grep\s+(?P<path>\$CATALINA_(?:HOME|BASE)/(?:bin|lib|conf))\s*(?:\n|$)',
        content,
        re.IGNORECASE,
    )
    if not command_match:
        return None
    finding_match = re.search(
        r'If\s+the\s+results\s+do\s+not\s+include\s+"(?P<expected>-w\s+\$CATALINA_(?:HOME|BASE)/(?:bin|lib|conf)\s+-p\s+wa\s+-k\s+tomcat)"\s+or\s+if\s+there\s+are\s+no\s+results,\s+this\s+is\s+a\s+finding\.',
        content,
        re.IGNORECASE,
    )
    if not finding_match:
        return None
    expected = ' '.join(finding_match.group('expected').split())
    command_path_tail = re.sub(r'^\$CATALINA_(?:HOME|BASE)/', '', command_match.group('path'))
    expected_path_match = re.match(r'-w\s+\$CATALINA_(?:HOME|BASE)/(?P<tail>\S+)\s+', expected)
    if not expected_path_match or expected_path_match.group('tail') != command_path_tail:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': 'auditctl -l'},
        'expected': {'type': 'contains', 'substring': expected},
        'description': rule.get('title', ''),
    }


def _audit_rules_file_expected_rule_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    if not re.search(r'\bcat\s+/etc/audit/rules\.d/\*\s*\|\s*grep\b', content, re.IGNORECASE):
        return None
    if not re.search(r'does\s+not\s+return\s+a\s+line\b|line\s+is\s+commented\s+out', content, re.IGNORECASE):
        return None
    command_match = re.search(r'[$#>]\s*(?:sudo\s+)?(cat\s+/etc/audit/rules\.d/\*\s*\|\s*grep\s+[^\n\r]+)', content, re.IGNORECASE)
    if not command_match:
        return None
    command = ' '.join(command_match.group(1).strip().split())
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
    if len(expected_lines) != 1:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'contains', 'substring': expected_lines[0]},
        'description': rule.get('title', ''),
    }


def _sles_firewalld_status_enabled_active_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    title = rule.get('title', '') or ''
    lower = f"{title}\n{content}".lower()
    if 'suse' not in lower and 'sles' not in lower:
        return None
    if not re.search(r'\bsystemctl\s+status\s+firewalld\.service\b', content):
        return None
    if not re.search(r'if\s+the\s+service\s+is\s+not\s+enabled,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'if\s+the\s+service\s+is\s+not\s+active,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    loaded = re.search(r'^\s*Loaded:\s+loaded \([^\n;]+/firewalld\.service; enabled;[^\n]+\)', content, re.MULTILINE)
    active = re.search(r'^\s*Active:\s+active \(running\)(?:\s|$)[^\n]*', content, re.MULTILINE)
    if not loaded or not active:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': 'systemctl status firewalld.service'},
        'expected': {'type': 'contains', 'substring': f"{loaded.group(0).strip()}\n   Active: active (running)"},
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
    masked_status = command == 'status' and re.search(r'loaded:\s+masked\b', lower) and (
        re.search(r'(?:loaded\s+and\s+)?not\s+masked', lower)
        or re.search(r'loaded:\s+value\s+is\s+not\s+set\s+to\s+["“]masked["”]', lower)
    )
    masked_show = command == 'show' and 'loadstate=masked' in lower and 'unitfilestate=masked' in lower and re.search(r'(?:loaded\s+or\s+active,?\s+and\s+is\s+)?not\s+masked', lower)
    command_end = match.end()
    if command == 'status':
        line_end = content.find('\n', match.end())
        if line_end != -1 and re.search(r'\|\s*grep\b[^\n]*(?:active:|Active:|\bactive\b)', content[match.end():line_end], re.IGNORECASE):
            command_end = line_end
    sample_lines, _finding_text = _authoritative_sample_block_after_command(content, command_end)
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
            and (
                re.search(rf'If\s+["“]?{re.escape(raw_name)}["”]?\s+is\s+["“]?inactive["”]?', content, re.IGNORECASE)
                or re.search(r'If\s+the\s+(?:above\s+)?command\s+returns\s+(?:the\s+)?status\s+as\s+["“]inactive["”]', content, re.IGNORECASE)
            )
        ):
            expected_status = 'running'
        elif (
            any(re.match(r'Active:\s+active\b', line, re.IGNORECASE) for line in sample_lines)
            and re.search(r'if\s+something\s+other\s+than\s+["“]Active:\s+active["”]\s+is\s+returned,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        ):
            expected_status = 'running'
        elif re.search(r'(?:does\s+not\s+show\s+a\s+status\s+of|is\s+not)\s+["“]?(?:active|enabled)["”]?\s+and\s+["“]?running["”]?', lower) or re.search(r'is\s+not\s+enabled\s+and\s+(?:active|running)', lower):
            expected_status = 'running'
        else:
            return None
    elif command == 'is-active' and (
        re.search(rf'systemctl\s+is-active\s+{re.escape(raw_name)}\s*\n\s*active\b', content, re.IGNORECASE)
        or re.search(r'If\s+the\s+(?:above\s+)?command\s+returns\s+["“]inactive["”]\s+or\s+any\s+kind\s+of\s+error,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    ) and (re.search(r'(?:is|service\s+is)\s+not\s+["“]?active["”]?', lower) or re.search(r'["“]?active["”]?\s+is\s+not\s+returned', lower) or re.search(r'returns\s+["“]?inactive["”]?', lower) or re.search(r'is\s+not\s+["“]?enabled["”]?\s+and\s+["“]?active["”]?', lower)):
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
    substitutions = []
    idx = 0
    while idx < len(command):
        start = command.find('$(', idx)
        if start == -1:
            break
        depth = 1
        quote = None
        pos = start + 2
        while pos < len(command) and depth:
            char = command[pos]
            if quote:
                if char == quote:
                    quote = None
            elif char in ('\'', '"'):
                quote = char
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            pos += 1
        if depth:
            return False
        substitutions.append(command[start + 2:pos - 1])
        idx = pos
    if not substitutions:
        return False
    for substitution in substitutions:
        unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", '', substitution)
        if any(token in unquoted for token in ('`', '$(', '&&', '<<', ';')):
            return False
        for segment in substitution.split('|'):
            stripped = segment.strip()
            if re.match(r'^/[A-Za-z0-9_./:+-]+\b', stripped):
                continue
            if re.match(r'^security\s+-q\s+authorizationdb\s+read\b', stripped):
                continue
            return False
    return True


def _has_unsafe_shell_token(command: str, *, allow_command_substitution: bool = False) -> bool:
    unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", '', command)
    tokens = ('`', '&&', '<<') if allow_command_substitution else ('`', '$(', '&&', '<<')
    return any(token in unquoted for token in tokens)


def _uint32_positive_le_pattern(maximum: int) -> str | None:
    if maximum <= 0 or maximum > 999:
        return None
    if maximum < 10:
        return rf'^uint32 [1-{maximum}]$'
    if maximum < 100:
        tens = maximum // 10
        ones = maximum % 10
        parts = ['[1-9]']
        if tens > 1:
            parts.append(f'[1-{tens - 1}][0-9]')
        parts.append(f'{tens}[0-{ones}]')
        alternation = '|'.join(parts)
        return rf'^uint32 (?:{alternation})$'
    hundreds = maximum // 100
    remainder = maximum % 100
    parts = ['[1-9]', '[1-9][0-9]']
    if hundreds > 1:
        parts.append(f'[1-{hundreds - 1}][0-9]{{2}}')
    if remainder == 99:
        parts.append(f'{hundreds}[0-9]{{2}}')
    elif remainder == 0:
        parts.append(f'{hundreds}00')
    elif remainder < 10:
        parts.append(f'{hundreds}0[0-{remainder}]')
    else:
        tens = remainder // 10
        ones = remainder % 10
        if tens > 0:
            parts.append(f'{hundreds}[0-{tens - 1}][0-9]')
        parts.append(f'{hundreds}{tens}[0-{ones}]')
    alternation = '|'.join(parts)
    return rf'^uint32 (?:{alternation})$'


def _gnome_login_banner_text_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if 'Standard Mandatory DoD Notice and Consent Banner' not in content and 'Standard Mandatory DOD Notice and Consent Banner' not in content:
        return None
    if not re.search(r'banner\s+does\s+not\s+match\s+the\s+Standard\s+Mandatory\s+DoD\s+Notice\s+and\s+Consent\s+Banner\s+exactly', content, re.IGNORECASE):
        return None
    command_match = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?(?P<command>(?:gsettings\s+get\s+org\.gnome\.login-screen\s+banner-message-text|grep\s+banner-message-text\s+/etc/dconf/db/local\.d/\*))\s*$',
        content,
        re.MULTILINE,
    )
    if not command_match:
        return None
    banner_match = re.search(
        r'banner-message-text\s*=\s*\n\s*[\'“](?P<banner>You\s+are\s+accessing\s+a\s+U\.S\.\s+Government\s+\(USG\)\s+Information\s+System\s+\(IS\)\s+that\s+is\s+provided\s+for\s+USG-authorized\s+use\s+only\.[\s\S]+?See\s+User\s+Agreement\s+for\s+details\.\s?)[\'”]',
        content,
        re.IGNORECASE,
    )
    if not banner_match:
        banner_match = re.search(
            r'banner-message-text\s*=\s*\n\s*[\'“](?P<banner>You\s+are\s+accessing\s+a\s+U\.S\.\s+Government\s+\(USG\)\s+Information\s+System\s+\(IS\)\s+that\s+is\s+provided\s+for\s+USG-authorized\s+use\s+only\.[^\'”\n]+)[\'”]',
            content,
            re.IGNORECASE,
        )
    if not banner_match:
        return None
    banner = banner_match.group('banner')
    if f"banner-message-text='{banner}'" not in fix_text:
        return None
    command = _normalize_command(command_match.group('command'))
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'contains', 'substring': banner},
        'description': rule.get('title', ''),
    }


def _gsettings_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    login_banner_candidate = _gnome_login_banner_text_candidate(rule, stig_id)
    if login_banner_candidate:
        return login_banner_candidate
    content = rule.get('check_content', '') or ''
    picture_uri_command = re.search(
        r'^\s*\$\s*(?P<command>(?:sudo\s+)?gsettings\s+get\s+org\.gnome\.desktop\.screensaver\s+picture-uri)\s*$',
        content,
        re.MULTILINE,
    )
    picture_uri_lock = re.search(
        r'^\s*\$\s*(?P<command>grep\s+picture-uri\s+/etc/dconf/db/local\.d/locks/\*)\s*$',
        content,
        re.MULTILINE,
    )
    if (
        picture_uri_command
        and picture_uri_lock
        and re.search(r'output\s+should\s+be\s+["“]\'\'["”]', content, re.IGNORECASE)
        and re.search(r'output\s+should\s+be\s+["“]/org/gnome/desktop/screensaver/picture-uri["”]', content, re.IGNORECASE)
        and re.search(r'If\s+it\s+is\s+not\s+set\s+or\s+configured\s+properly,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*picture-uri=\'\'\s*$', rule.get('fix_text', '') or '', re.MULTILINE)
        and re.search(r'^\s*/org/gnome/desktop/screensaver/picture-uri\s*$', rule.get('fix_text', '') or '', re.MULTILINE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': f"{_normalize_command(picture_uri_command.group('command'))} && {_normalize_command(picture_uri_lock.group('command'))}",
            },
            'expected': {'type': 'contains', 'substring': "''\n/org/gnome/desktop/screensaver/picture-uri"},
            'description': rule.get('title', ''),
        }
    command_matches = list(re.finditer(
        r'^\s*\**\s*[$#>]\s*(?P<command>(?:sudo\s+)?gsettings\s+(?:get|writable)\s+[A-Za-z0-9_.-]+\s+[A-Za-z0-9_.-]+)\s*$',
        content,
        re.MULTILINE,
    ))
    if len(command_matches) == 2:
        commands = [_normalize_command(match.group('command')) for match in command_matches]
        expected_lines = []
        for match in command_matches:
            expected_line_for_command = None
            for line in content[match.end():].splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.lower().startswith(('if ', 'note:', '$', '#', '>')):
                    break
                expected_line_for_command = stripped
                break
            expected_lines.append(expected_line_for_command)
        if (
            commands == [
                'gsettings get org.gnome.settings-daemon.plugins.media-keys logout',
                'gsettings writable org.gnome.settings-daemon.plugins.media-keys logout',
            ]
            and expected_lines == ["''", 'false']
            and re.search(r'If\s+the\s+logout\s+value\s+is\s+not\s+\[\'\'\]\s+and\s+the\s+writable\s+status\s+is\s+not\s+false,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux',
                'check': {'type': 'command_output', 'command': ' && '.join(commands)},
                'expected': {'type': 'equals', 'value': '\n'.join(expected_lines)},
                'description': rule.get('title', ''),
            }
    if len(command_matches) == 3:
        commands = [_normalize_command(match.group('command')) for match in command_matches]
        expected_lines = []
        for match in command_matches:
            expected_line_for_command = None
            for line in content[match.end():].splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.lower().startswith(('if ', 'note:', '$', '#', '>')):
                    break
                expected_line_for_command = stripped
                break
            expected_lines.append(expected_line_for_command)
        idle_delay = re.fullmatch(r'uint32\s+([1-9][0-9]{0,2})', expected_lines[2] or '')
        if (
            commands == [
                'gsettings get org.gnome.desktop.screensaver lock-enabled',
                'gsettings get org.gnome.desktop.screensaver lock-delay',
                'gsettings get org.gnome.desktop.session idle-delay',
            ]
            and expected_lines[0] == 'true'
            and expected_lines[1] == 'uint32 0'
            and idle_delay
            and re.search(r'If\s+["“]lock-enabled["”]\s+is\s+not\s+set\s+to\s+["“]true["”]', content, re.IGNORECASE)
            and re.search(r'If\s+["“]lock-delay["”]\s+is\s+set\s+to\s+a\s+value\s+greater\s+than\s+["“]0["”]', content, re.IGNORECASE)
            and re.search(r'["“]idle-delay["”]\s+is\s+set\s+to\s+a\s+value\s+greater\s+than\s+["“]' + re.escape(idle_delay.group(1)) + r'["”]', content, re.IGNORECASE)
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux',
                'check': {'type': 'command_output', 'command': ' && '.join(commands)},
                'expected': {'type': 'equals', 'value': '\n'.join(expected_lines)},
                'description': rule.get('title', ''),
            }
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
        uint32_match = re.fullmatch(r'uint32\s+([1-9][0-9]{0,2})', expected_line or '')
        if uint32_match:
            maximum = int(uint32_match.group(1))
            pattern = _uint32_positive_le_pattern(maximum)
            if pattern and (
                re.search(
                    rf'If\s+["“]?[A-Za-z0-9_.-]+["”]?\s+is\s+set\s+to\s+["“]?0["”]?\s+or\s+a\s+value\s+greater\s+than\s+["“]?{maximum}["”]?',
                    content,
                    re.IGNORECASE,
                )
                or re.search(
                    rf'If\s+the\s+["“]?uint32["”]?\s+setting\s+is\s+(?:missing,\s+or\s+is\s+)?not\s+set\s+to\s+["“]?{maximum}["”]?\s+or\s+less(?:,\s+or\s+is\s+missing)?',
                    content,
                    re.IGNORECASE,
                )
            ):
                return {
                    'vuln_id': rule.get('vuln_id', ''),
                    'platform': 'linux',
                    'check': {'type': 'command_output', 'command': command},
                    'expected': {'type': 'matches', 'pattern': pattern},
                    'description': rule.get('title', ''),
                }
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


def _fstab_mount_option_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    title = rule.get('title', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = '\n'.join(part for part in (title, fix_text) if part)
    if re.search(
        r'user\s+home\s+directories|removable\s+media|Network\s+File\s+System|\bNFS\b|imported\s+via|separate\s+file\s+system',
        combined,
        re.IGNORECASE,
    ):
        return None
    title_match = re.search(
        r'\bmust\s+mount\s+(?P<path>/[A-Za-z0-9_./:+-]+)\s+with\s+the\s+["“]?(?P<option>nodev|nosuid|noexec)["”]?\s+option\b',
        title,
        re.IGNORECASE,
    )
    if not title_match or not re.search(r'/etc/fstab', fix_text, re.IGNORECASE):
        return None
    mount_path = title_match.group('path')
    required_option = title_match.group('option').lower()
    if not re.search(
        rf'\bso\s+that\s+{re.escape(mount_path)}\s+is\s+mounted\s+with\s+the\s+["“]{re.escape(required_option)}["”]\s+option\b',
        fix_text,
        re.IGNORECASE,
    ):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': f'findmnt {mount_path}'},
        'expected': {'type': 'contains', 'substring': required_option},
        'description': rule.get('title', ''),
    }


def _dconf_needs_update_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    command_match = re.search(
        r'^\s*[$#>]\s*(?P<command>function\s+dconf_needs_update\s+\{\s+for\s+db\s+in\s+\$\(find\s+/etc/dconf/db\s+-maxdepth\s+1\s+-type\s+f\);\s+do\s+db_mtime=\$\(stat\s+-c\s+%Y\s+"\$db"\);\s+keyfile_mtime=\$\(stat\s+-c\s+%Y\s+"\$db"\.d/\*\s+\|\s+sort\s+-n\s+\|\s+tail\s+-1\);\s+if\s+\[\s+-n\s+"\$db_mtime"\s+\]\s+&&\s+\[\s+-n\s+"\$keyfile_mtime"\s+\]\s+&&\s+\[\s+"\$db_mtime"\s+-lt\s+"\$keyfile_mtime"\s+\];\s+then\s+echo\s+"\$db\s+needs\s+update";\s+return\s+1;\s+fi;\s+done;\s+\};\s+dconf_needs_update)\s*$',
        content,
        re.MULTILINE,
    )
    if not command_match:
        return None
    if not re.search(
        r'If\s+the\s+command\s+has\s+any\s+output,\s+then\s+a\s+dconf\s+database\s+needs\s+to\s+be\s+updated,\s+and\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': _normalize_command(command_match.group('command'))},
        'expected': {'type': 'equals', 'value': ''},
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
    finding_key_pattern = re.escape(key)
    if key.endswith('s'):
        finding_key_pattern = rf'{finding_key_pattern}|{re.escape(key[:-1])}'
    explicit_value_required = re.search(
        rf'If\s+the\s+["“](?:{finding_key_pattern})["”]\s+setting\s+is\s+not\s+set\s+to\s+["“]{re.escape(expected_value)}["”]',
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
        update_crypto_expected_messages = {
            'update-crypto-policies --is-applied': 'The configured policy is applied',
            'update-crypto-policies --check': 'The configured policy matches the generated policy',
        }
        if (
            command in update_crypto_expected_messages
            and sample_line == update_crypto_expected_messages[command]
            and re.search(
                r'If\s+the\s+returned\s+message\s+does\s+not\s+match\s+the\s+above,?\s+(?:but\s+instead\s+matches\s+the\s+following,?\s+)?this\s+is\s+a\s+finding',
                finding_text,
                re.IGNORECASE,
            )
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux' if _linux_platform(stig_id) else 'generic',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'equals', 'value': sample_line},
                'description': rule.get('title', ''),
            }
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


def _macos_osascript_true_heredoc_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _macos_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    if not re.search(r'If\s+the\s+result\s+is\s+not\s+["“]true["”],?\s+this\s+is\s+a\s+finding\.', content, re.IGNORECASE):
        return None
    block_match = re.search(
        r'(?P<command>^/usr/bin/osascript\s+-l\s+JavaScript\s+<<\s+EOS\n(?:(?!^EOS\s*$).+\n)+^EOS\s*$)',
        content,
        re.MULTILINE,
    )
    if not block_match:
        return None
    command = block_match.group('command').strip()
    body = command.split('\n', 1)[1].rsplit('\n', 1)[0]
    if 'function run()' not in body:
        return None
    if 'return("true")' not in body or 'return("false")' not in body:
        return None
    unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", '', body)
    if any(token in unquoted for token in ('`', '$(', '>>')):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'macos',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'true'},
        'description': rule.get('title', ''),
    }


def _macos_result_variable_shell_block_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _macos_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    if not re.search(r'If\s+the\s+result\s+is\s+not\s+["“]1["”],?\s+this\s+is\s+a\s+finding\.', content, re.IGNORECASE):
        return None
    block_match = re.search(
        r'(?P<command>authDBs=\([^\n]+\)\nresult=["“]1["”]\nfor\s+section\s+in\s+\$\{authDBs\[@\]\};\s+do\n(?:(?!\n\s*done\n\s*echo\s+\$result\b).+\n)+\s*done\n\s*echo\s+\$result)',
        content,
        re.DOTALL,
    )
    if not block_match:
        return None
    command = block_match.group('command').strip()
    unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", '', command)
    if any(token in unquoted for token in ('`', '&&', '<<', '>', '>>')):
        return None
    if 'result="0"' not in command and 'result=“0”' not in command:
        return None
    allowed_line = re.compile(
        r'^(?:authDBs=\([^\n]+\)|\s*result=["“][01]["”]|for\s+section\s+in\s+\$\{authDBs\[@\]\};\s+do|\s*if\s+\[\[\s+\$\([^\n]+\)\s+!=\s+["“][^"”]+["”]\s+\]\];\s+then|\s*fi|done|\s*echo\s+\$result)$'
    )
    if not all(allowed_line.fullmatch(line) for line in command.splitlines()):
        return None
    if not _command_substitutions_are_absolute(command):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'macos',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': '1'},
        'description': rule.get('title', ''),
    }


def _macos_sshd_fips_count_shell_block_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _macos_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    if not re.search(r'\blimit\s+SSHD\s+to\s+FIPS-compliant\s+connections\b', rule.get('title', ''), re.IGNORECASE):
        return None
    if not re.search(r'If\s+the\s+result\s+is\s+not\s+["“]7["”],?\s+this\s+is\s+a\s+finding\.', content, re.IGNORECASE):
        return None
    block_match = re.search(
        r'(?P<command>fips_sshd_config=\((?P<items>[^\n]+)\)\ntotal=0\nfor\s+config\s+in\s+\$fips_sshd_config;\s+do\n\s*total=\$\(expr\s+\$\(/usr/sbin/sshd\s+-G\s+\|\s+/usr/bin/grep\s+-i\s+-c\s+"\$config"\)\s+\+\s+\$total\)\ndone\n\s*echo\s+\$total)',
        content,
        re.DOTALL,
    )
    if not block_match:
        return None
    items = re.findall(r'"([^"]+)"', block_match.group('items'))
    expected_prefixes = {
        'Ciphers ',
        'HostbasedAcceptedAlgorithms ',
        'HostKeyAlgorithms ',
        'KexAlgorithms ',
        'MACs ',
        'PubkeyAcceptedAlgorithms ',
        'CASignatureAlgorithms ',
    }
    if len(items) != 7 or {item.split(' ', 1)[0] + ' ' for item in items if ' ' in item} != expected_prefixes:
        return None
    if any('...' in item or any(token in item for token in (';', '`', '$(', '&&', '<<', '>', '|')) for item in items):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'macos',
        'check': {'type': 'command_output', 'command': block_match.group('command').strip()},
        'expected': {'type': 'equals', 'value': '7'},
        'description': rule.get('title', ''),
    }


def _macos_pass_fail_shell_block_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _macos_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    if not re.search(r'If\s+the\s+result\s+is\s+not\s+["“]pass["”],?\s+this\s+is\s+a\s+finding\.', content, re.IGNORECASE):
        return None
    password_hint_command = 'HINT=$(/usr/bin/dscl . -list /Users hint | /usr/bin/awk \'{ print $2 }\')\nif [ -z "$HINT" ]; then echo "PASS"\nelse echo "FAIL"\nfi'
    if (
        re.search(r'\bremove\s+password\s+hints\b', rule.get('title', ''), re.IGNORECASE)
        and re.search(r'HINT=\$\(/usr/bin/dscl\s+\.\s+-list\s+/Users\s+hint\s+\|\s+/usr/bin/awk\s+\'\{\s*print\s+\$2\s*\}\'\)', content)
        and re.search(r'if\s+\[\s+-z\s+"\$HINT"\s+\];\s+then\s+echo\s+"PASS"\s+else\s+echo\s+"FAIL"\s+fi', content, re.IGNORECASE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'macos',
            'check': {'type': 'command_output', 'command': password_hint_command},
            'expected': {'type': 'equals', 'value': 'PASS'},
            'description': rule.get('title', ''),
        }
    block_match = re.search(
        r'(?P<command>(?:[A-Z][A-Z0-9_]*=\$\([^\n]+\)\n)+if\s+\[\[.*?\]\];\s+then\n\s*echo\s+["“]pass["”]\nelse\n\s*echo\s+["“]fail["”]\nfi)',
        content,
        re.DOTALL,
    )
    if not block_match:
        return None
    command = block_match.group('command').strip()
    unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", '', command)
    if any(token in unquoted for token in ('`', '<<', '>', '>>')):
        return None
    allowed_line = re.compile(
        r'^(?:[A-Z][A-Z0-9_]*=\$\([^\n]+\)|if\s+\[\[.*\]\];\s+then|\s*echo\s+"(?:pass|fail)"|else|fi)$'
    )
    lines = command.splitlines()
    if not lines or not all(allowed_line.fullmatch(line) for line in lines):
        return None
    for assignment in [line for line in lines if '$(' in line]:
        if not _command_substitutions_are_absolute(assignment):
            return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'macos',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'pass'},
        'description': rule.get('title', ''),
    }


def _esxi_active_directory_authentication_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'esxi' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    command_match = re.search(r'(?m)^\s*(?:PS>\s*)?Get-VMHost\s*\|\s*Get-VMHostAuthentication\s*$', content)
    if not command_match:
        return None
    if not re.search(r'Directory\s+Services\s+Type[^.\n]+set\s+to\s+["“]Active\s+Directory["”]', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+the\s+Directory\s+Services\s+Type\s+is\s+not\s+set\s+to\s+["“]Active\s+Directory["”]\s*,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': 'Get-VMHost | Get-VMHostAuthentication',
        },
        'expected': {'type': 'contains', 'substring': 'Active Directory'},
        'description': rule.get('title', ''),
    }


def _esxi_syslog_persistent_log_output_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'esxi' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    if not re.search(r'(?m)^\s*\$esxcli\s*=\s*Get-EsxCli\s+-v2\s*$', content):
        return None
    if not re.search(
        r'(?m)^\s*\$esxcli\.system\.syslog\.config\.get\.Invoke\(\)\s*\|\s*Select\s+LocalLogOutput\s*,\s*LocalLogOutputIsPersistent\s*$',
        content,
        re.IGNORECASE,
    ):
        return None
    if not re.search(
        r'If\s+the\s+["“]LocalLogOutputIsPersistent["”]\s+value\s+is\s+not\s+true,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': '$esxcli = Get-EsxCli -v2; $esxcli.system.syslog.config.get.Invoke() | Select-Object -ExpandProperty LocalLogOutputIsPersistent',
        },
        'expected': {'type': 'equals', 'value': 'true'},
        'description': rule.get('title', ''),
    }


def _esxi_disabled_vmhost_service_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'esxi' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    command_match = re.search(
        r'(?m)^\s*(?:PS>\s*)?Get-VMHost\s*\|\s*Get-VMHostService\s*\|\s*Where\s*\{\s*\$?_\.Label\s+-eq\s+["“](?P<label>[^"”]+)["”]\s*\}\s*$',
        content,
        re.IGNORECASE,
    )
    if not command_match:
        return None
    label = command_match.group('label').strip()
    if not label or any(char in label for char in ('`', '$', '|', ';', '\\')):
        return None
    quoted_label = re.escape(label)
    if not re.search(
        rf'If\s+the\s+(?:["“]{quoted_label}["”]|{quoted_label})\s+service\s+does\s+not\s+have\s+a\s+["“]Policy["”]\s+of\s+["“]off["”]\s+or\s+is\s+running,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return None
    if not re.search(rf'Where\s*\{{\s*\$?_\.Label\s+-eq\s+["“]{quoted_label}["”]\s*\}}\s*\|\s*Set-VMHostService\s+-Policy\s+Off\b', fix_text, re.IGNORECASE):
        return None
    if not re.search(rf'Where\s*\{{\s*\$?_\.Label\s+-eq\s+["“]{quoted_label}["”]\s*\}}\s*\|\s*Stop-VMHostService\b', fix_text, re.IGNORECASE):
        return None
    command = (
        f'Get-VMHost | Get-VMHostService | Where-Object {{$_.Label -eq "{label}"}} | '
        'ForEach-Object { "$($_.Policy)`n$($_.Running)" }'
    )
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'off\nFalse'},
        'description': rule.get('title', ''),
    }


def _esxi_advanced_setting_exact_value_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'esxi' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    command_match = re.search(r'(?m)^\s*(?:PS>\s*)?Get-VMHost\s*\|\s*Get-AdvancedSetting\s+-Name\s+([A-Za-z0-9_.-]+)\s*$', content)
    if not command_match:
        return None
    setting_name = command_match.group(1)
    quoted_name = re.escape(setting_name)
    finding_match = re.search(
        rf'If\s+(?:the\s+)?"{quoted_name}"\s+(?:setting\s+)?(?:is\s+set\s+to\s+a\s+value\s+other\s+than|is\s+not\s+set\s+to)\s+"([^"]+)"(?:\s+or\s+the\s+setting\s+does\s+not\s+exist)?\s*,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    expected_type = 'equals'
    if not finding_match:
        finding_match = re.search(
            rf'If\s+(?:the\s+)?"{quoted_name}"\s+(?:key\s+)?is\s+set\s+to\s+"([^"]+)"\s*,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        expected_type = 'not_equals'
    if not finding_match:
        return None
    expected_value = finding_match.group(1).strip()
    if not expected_value or re.search(r'\b(?:or|and)\b', expected_value, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': f'Get-VMHost | Get-AdvancedSetting -Name {setting_name} | Select-Object -ExpandProperty Value',
        },
        'expected': {'type': expected_type, 'value': expected_value},
        'description': rule.get('title', ''),
    }


def _windows_certificate_store_thumbprint_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    command_matches = list(re.finditer(
        r'^\s*(?P<command>Get-ChildItem\s+-Path\s+Cert:Localmachine\\(?:root|disallowed)\b[^\n\r]+\|\s*FL\s+[^\n\r]*Thumbprint[^\n\r]*)\s*$',
        content,
        re.IGNORECASE | re.MULTILINE,
    ))
    if len(command_matches) != 1:
        return None
    finding_match = re.search(
        r'If\s+the\s+following\s+certificate\s+["“]Subject["”][^\n.]*["“]Thumbprint["”]\s+information\s+is\s+not\s+displayed,?\s+this\s+is\s+a\s+finding[:.]?\s*(?P<body>.*?)(?:\n\s*Alternately\b|\n\s*or\s*\n|\Z)',
        content,
        re.IGNORECASE | re.DOTALL,
    )
    if not finding_match:
        return None
    block_lines = []
    for raw_line in finding_match.group('body').splitlines():
        stripped = raw_line.strip()
        if not stripped:
            if block_lines and block_lines[-1] != '':
                block_lines.append('')
            continue
        if re.match(r'^(?:Subject|Issuer|Thumbprint|NotAfter)\s*:', stripped, re.IGNORECASE):
            block_lines.append(stripped)
            continue
        return None
    while block_lines and block_lines[-1] == '':
        block_lines.pop()
    expected_substring = '\n'.join(block_lines)
    if 'Subject:' not in expected_substring or 'Thumbprint' not in expected_substring:
        return None
    thumbprints = re.findall(r'Thumbprint\s*:\s*([A-Fa-f0-9]{40})', expected_substring)
    if not thumbprints:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': _normalize_command(command_matches[0].group('command'))},
        'expected': {'type': 'contains', 'substring': expected_substring},
        'description': rule.get('title', ''),
    }
def _windows_account_password_required_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-254257', 'V-278004'}:
        return None
    if not _windows_platform(stig_id):
        return None
    if 'accounts must require passwords' not in (rule.get('title', '') or '').lower():
        return None
    required_phrases = (
        'Get-Aduser -Filter * -Properties Passwordnotrequired',
        'Passwordnotrequired" is "True" or blank for any enabled user account, this is a finding',
        'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True"',
        'PasswordRequired" status of "False", this is a finding',
    )
    if not all(phrase.lower() in content.lower() for phrase in required_phrases):
        return None
    command = (
        'powershell -NoProfile -Command "'
        'if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { '
        'Get-ADUser -Filter * -Properties PasswordNotRequired,Enabled | '
        'Where-Object { $_.Enabled -eq $true -and $_.PasswordNotRequired -eq $true -and $_.Name -notin @(\'DefaultAccount\',\'Guest\') } | '
        'Select-Object -ExpandProperty Name '
        '} else { '
        'Get-CimInstance -Class Win32_UserAccount -Filter \'PasswordRequired=False and LocalAccount=True\' | '
        'Where-Object { $_.Disabled -ne $true -and $_.Name -notin @(\'DefaultAccount\',\'Guest\') } | '
        'Select-Object -ExpandProperty Name '
        '}"'
    )
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _windows_krbtgt_password_age_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    if not _windows_platform(stig_id):
        return None
    if rule.get('vuln_id') not in {'V-205877', 'V-254427', 'V-278176'}:
        return None
    if not re.search(r'\bkrbtgt\b', title + '\n' + content + '\n' + fix_text, re.IGNORECASE):
        return None
    if not re.search(r'Get-ADUser\s+krbtgt\s+-Property\s+PasswordLastSet', content, re.IGNORECASE):
        return None
    if not re.search(r'PasswordLastSet[^.\n]+more\s+than\s+180\s+days\s+old[^.\n]+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'Reset\s+the\s+password\s+for\s+the\s+krbtgt\s+account[^.\n]+(?:least|every)\s+180\s+days', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': 'powershell -NoProfile -Command "if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { $d=(Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet; if (((Get-Date)-$d).TotalDays -gt 180) { \'PasswordLastSetOlderThan180Days\' } }"',
        },
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _windows_ad_smartcard_no_listed_users_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    command_match = re.search(
        r'["“](?P<command>Get-ADUser\s+-Filter\s+\{\(Enabled\s+-eq\s+\$True\)\s+-and\s+\(SmartcardLogonRequired\s+-eq\s+\$False\)\}\s*\|\s*FT\s+Name)["”]',
        content,
        re.IGNORECASE,
    )
    if not command_match:
        return None
    if not re.search(
        r'If\s+any\s+user\s+accounts,?\s+including\s+administrators,?\s+are\s+listed,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': re.sub(r'\s+', ' ', command_match.group('command')).strip()},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _ssh_host_key_mode_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    key_kind = None
    key_glob = None
    if re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?ls\s+-[alL]*l[alL]*\s+/etc/ssh/(?:ssh_host\*key|\*_key)\s*$',
        content,
        re.MULTILINE,
    ) or re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?find\s+/\s+-name\s+["\']\*ssh_host\*key["\']\s*\|\s*xargs\s+ls\s+-lL\s*$',
        content,
        re.MULTILINE,
    ) or re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?find\s+/etc/ssh\s+-name\s+["\']ssh_host\*key["\']\s+-exec\s+stat\s+-c\s+["\']%a\s+%n["\']\s+\{\}\s+\\;\s*$',
        content,
        re.MULTILINE,
    ):
        key_kind = 'private'
        key_glob = 'ssh_host*key'
    elif re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?(?:find\s+/etc/ssh\s+-name\s+(?:["\']ssh_host\*key\.pub["\']|["\']\*\.pub["\'])\s+-exec\s+(?:stat\s+-c\s+["\']%a\s+%n["\']|ls\s+-lL)\s+\{\}\s+\\;|ls\s+-l\s+/etc/ssh/\*\.pub)\s*$',
        content,
        re.MULTILINE,
    ):
        key_kind = 'public'
        key_glob = 'ssh_host*key.pub'
    if not key_kind or not key_glob:
        return None
    mode_match = re.search(
        rf'SSH(?:\s+daemon)?\s+{key_kind}\s+host\s+key\s+files\s+have\s+(?:a\s+)?mode\s+(?:of\s+)?["“](?P<mode>0?[0-7]{{3}})["”]\s+or\s+less\s+permissive',
        content,
        re.IGNORECASE,
    )
    if not mode_match or not re.search(
        rf'If\s+any\s+(?:(?:{key_kind}\s+host\s+key|["“]?key\.pub["”]?)\s+)?file\s+has\s+a\s+mode\s+more\s+permissive\s+than\s+["“]0?[0-7]{{3}}["”],?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return None
    mode = int(mode_match.group('mode'), 8)
    prohibited_bits = 0o777 & ~mode
    if prohibited_bits == 0:
        return None
    follow_links = bool(
        re.search(
            r'^\s*[$#>]\s*(?:sudo\s+)?ls\s+-[alL]*L[alL]*\s+/etc/ssh/(?:ssh_host\*key|\*_key)\s*$',
            content,
            re.MULTILINE,
        )
    )
    find_prefix = 'find -L /etc/ssh' if follow_links else 'find /etc/ssh'
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {
            'type': 'command_output',
            'command': f'{find_prefix} -maxdepth 1 -type f -name \'{key_glob}\' -perm /{prohibited_bits:o} -exec stat -c "%n %a" {{}} \\;',
        },
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _ssh_private_host_key_mode_candidate(rule: dict, stig_id: str) -> dict | None:
    return _ssh_host_key_mode_candidate(rule, stig_id)


def _kubernetes_pki_mode_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'kubernetes' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    command_match = re.search(
        r'^\s*(?:[$#>]\s*)?(?:sudo\s+)?find\s+(?P<path>/etc/kubernetes/pki(?:/\*)?)\s+-name\s+["\'](?P<glob>\*\.(?:key|crt))["\']\s*\|\s*xargs\s+stat\s+-c\s+["\']%n\s+%a["\']\s*$',
        content,
        re.MULTILINE | re.IGNORECASE,
    )
    mode_match = re.search(
        r'If\s+any\s+of\s+the\s+files\s+have\s+permissions\s+more\s+permissive\s+than\s+["“](?P<mode>[0-7]{3})["”],?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if not command_match or not mode_match:
        return None
    mode = int(mode_match.group('mode'), 8)
    prohibited_bits = 0o777 & ~mode
    if prohibited_bits == 0:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': f'find /etc/kubernetes/pki -name "{command_match.group("glob")}" -perm /{prohibited_bits:o} -exec stat -c "%n %a" {{}} \\;',
        },
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _kubernetes_authoritative_file_compliance_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'kubernetes' not in stig_id.lower():
        return None
    vuln_id = rule.get('vuln_id', '')
    content = rule.get('check_content', '') or ''
    title = rule.get('title', '') or ''
    owner_finding = re.search(r'If\s+(?:the\s+command\s+returns\s+)?any\s+(?:non\s+)?root:root\s+file\s+permissions,?\s+this\s+is\s+a\s+finding|If\s+any\s+[^.]*file\s+is\s+not\s+owned\s+by\s+root:root,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    mode_644_finding = re.search(r'permissions\s+(?:more\s+permissive|less\s+restrictive)\s+than\s+["“]644["”],?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    if vuln_id == 'V-242447' and 'stat -c %a <location from --kubeconfig>' in content and mode_644_finding:
        command = "sh -c 'path=$(ps -ef | sed -n \"s/.*--kubeconfig[= ]\\([^ ]*\\).*/\\1/p\" | head -n 1); [ -z \"$path\" ] || find \"$path\" -perm /133 -exec stat -c \"%a %n\" {} \\;'"
    elif vuln_id == 'V-242448' and 'stat -c' in content and '<location from --kubeconfig>' in content and owner_finding:
        command = "sh -c 'path=$(ps -ef | sed -n \"s/.*--kubeconfig[= ]\\([^ ]*\\).*/\\1/p\" | head -n 1); [ -z \"$path\" ] || stat -c \"%U:%G %n\" \"$path\" 2>/dev/null | grep -v \"^root:root \"'"
    elif vuln_id == 'V-242449' and 'grep -i clientCAFile <path_to_config_file>' in content and mode_644_finding:
        command = "sh -c 'cfg=$(ps -ef | sed -n \"s/.*--config[= ]\\([^ ]*\\).*/\\1/p\" | head -n 1); ca=$(grep -i \"clientCAFile\" \"$cfg\" 2>/dev/null | sed -n \"s/.*clientCAFile:[ ]*\\([^ ]*\\).*/\\1/p\" | head -n 1); [ -z \"$ca\" ] || find \"$ca\" -perm /133 -exec stat -c \"%a %n\" {} \\;'"
    elif vuln_id == 'V-242450' and 'grep -i clientCAFile <path_to_config_file>' in content and owner_finding:
        command = "sh -c 'cfg=$(ps -ef | sed -n \"s/.*--config[= ]\\([^ ]*\\).*/\\1/p\" | head -n 1); ca=$(grep -i \"clientCAFile\" \"$cfg\" 2>/dev/null | sed -n \"s/.*clientCAFile:[ ]*\\([^ ]*\\).*/\\1/p\" | head -n 1); [ -z \"$ca\" ] || stat -c \"%U:%G %n\" \"$ca\" 2>/dev/null | grep -v \"^root:root \"'"
    elif vuln_id == 'V-242451' and '/etc/kubernetes/pki' in content and owner_finding:
        command = "sh -c 'find /etc/kubernetes/pki -mindepth 1 -exec stat -c \"%U:%G %n\" {} \\; 2>/dev/null | grep -v \"^root:root \"'"
    elif vuln_id == 'V-242454' and '/etc/systemd/system/kubelet.service.d/10-kubeadm.conf' in content and owner_finding:
        command = "sh -c 'stat -c \"%U:%G\" /etc/systemd/system/kubelet.service.d/10-kubeadm.conf 2>/dev/null | grep -v root:root'"
    elif vuln_id == 'V-242455' and '/etc/systemd/system/kubelet.service.d/10-kubeadm.conf' in content and mode_644_finding:
        command = "sh -c 'find /etc/systemd/system/kubelet.service.d/10-kubeadm.conf -perm /133 -exec stat -c \"%a %n\" {} \\; 2>/dev/null'"
    elif vuln_id == 'V-242405' and '/etc/kubernetes/manifest' in content and 'owned by root:root' in content:
        command = "sh -c 'find /etc/kubernetes/manifests -maxdepth 1 -type f -exec stat -c \"%U:%G %n\" {} \\; 2>/dev/null | grep -v \"^root:root \"'"
    elif vuln_id == 'V-242408' and '/etc/kubernetes/manifest' in content and 'permissions "644" or more restrictive' in content:
        command = "sh -c 'find /etc/kubernetes/manifests -maxdepth 1 -type f -perm /133 -exec stat -c \"%a %n\" {} \\; 2>/dev/null'"
    else:
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': title,
    }


def _kubernetes_fixed_file_mode_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'kubernetes' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    command_matches = list(re.finditer(
        r'^\s*(?:[$#>]\s*)?stat\s+-c\s+%a\s+(?P<path>/(?:etc/kubernetes|var/lib/kubelet)/[A-Za-z0-9_.@/-]+)\s*$',
        content,
        re.MULTILINE,
    ))
    if not command_matches:
        return None
    mode_match = re.search(
        r'If\s+any\s+of\s+the\s+files\s+are\s+have\s+permissions\s+more\s+permissive\s+than\s+["“](?P<mode>[0-7]{3})["”],?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if not mode_match:
        return None
    paths = [match.group('path') for match in command_matches]
    if len(paths) != len(set(paths)):
        return None
    prohibited_bits = 0o777 & ~int(mode_match.group('mode'), 8)
    if prohibited_bits == 0:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': f'find {" ".join(paths)} -perm /{prohibited_bits:o} -exec stat -c "%a %n" {{}} \\;',
        },
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _interactive_home_directory_mode_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    passwd_home_dirs = r"\$\(awk\s+-F:\s+['\"]\(\$3>=1000\)&&\(\$7\s+!~\s+/nologin/\)\{print\s+\$6\}['\"]\s+/etc/passwd\)"
    has_stat_command = re.search(
        rf"stat\s+-L\s+-c\s+['\"]%a\s+%n['\"]\s+{passwd_home_dirs}\s+2>/dev/null",
        content,
        re.IGNORECASE,
    )
    has_ls_command = re.search(
        rf"ls\s+-ld\s+{passwd_home_dirs}",
        content,
        re.IGNORECASE,
    )
    if not has_stat_command and not has_ls_command:
        return None
    mode_match = re.search(
        r'home\s+directories\s+referenced\s+in\s+["“]/etc/passwd["”]\s+do\s+not\s+have\s+a\s+mode\s+of\s+["“](?P<mode>0?[0-7]{3})["”]\s+or\s+less\s+permissive,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if not mode_match:
        return None
    mode = int(mode_match.group('mode'), 8)
    prohibited_bits = 0o777 & ~mode
    if prohibited_bits == 0:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {
            'type': 'command_output',
            'command': f"find $(awk -F: '($3>=1000)&&($7 !~ /nologin/){{print $6}}' /etc/passwd) -maxdepth 0 -type d -perm /{prohibited_bits:03o} -exec stat -c \"%a %n\" {{}} \\; 2>/dev/null",
        },
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _command_output_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    interactive_home_mode_candidate = _interactive_home_directory_mode_candidate(rule, stig_id)
    if interactive_home_mode_candidate:
        return interactive_home_mode_candidate
    kubernetes_authoritative_file_candidate = _kubernetes_authoritative_file_compliance_candidate(rule, stig_id)
    if kubernetes_authoritative_file_candidate:
        return kubernetes_authoritative_file_candidate
    kubernetes_fixed_file_mode_candidate = _kubernetes_fixed_file_mode_candidate(rule, stig_id)
    if kubernetes_fixed_file_mode_candidate:
        return kubernetes_fixed_file_mode_candidate
    kubernetes_pki_mode_candidate = _kubernetes_pki_mode_candidate(rule, stig_id)
    if kubernetes_pki_mode_candidate:
        return kubernetes_pki_mode_candidate
    ssh_private_host_key_mode_candidate = _ssh_private_host_key_mode_candidate(rule, stig_id)
    if ssh_private_host_key_mode_candidate:
        return ssh_private_host_key_mode_candidate
    local_init_files_mode = (
        _linux_platform(stig_id)
        and re.search(r'local\s+initialization\s+files?.*mode\s+(?:of\s+)?["“]?0?740["”]?\s+or\s+less\s+permissive', rule.get('title', '') or '', re.IGNORECASE)
        and re.search(r'If\s+any\s+local\s+initialization\s+files?\s+have\s+a\s+mode\s+more\s+permissive\s+than\s+["“]?0?740["”]?,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'chmod\s+0?740\s+[^\n]*(?:INIT_FILE|\.\[\^\.\]\*|\.<?)', fix_text, re.IGNORECASE)
    )
    if local_init_files_mode:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': '''awk -F: '($3>=1000)&&($7 !~ /(nologin|false)$/){print $6}' /etc/passwd | while IFS= read -r home; do [ -d "$home" ] && find "$home" -maxdepth 1 -type f -name ".*" ! -name "." ! -name ".." -perm /037 -print; done''',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    sshd_x11_forwarding_no_literal = (
        _linux_platform(stig_id)
        and re.search(r'^\s*[$#>]\s*(?:sudo\s+)?grep\s+-ir\s+x11forwarding\s+/etc/ssh/sshd_config\*\s*\|\s*grep\s+-v\s+["“]\^#["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'^\s*X11Forwarding\s+no\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(
            r'If\s+the\s+["“]X11Forwarding["”]\s+keyword\s+is\s+set\s+to\s+["“]yes["”][^.]*?,\s+is\s+missing,\s+or\s+multiple\s+conflicting\s+results\s+are\s+returned,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    if sshd_x11_forwarding_no_literal:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v "^#"'},
            'expected': {'type': 'equals', 'value': 'X11Forwarding no'},
            'description': rule.get('title', ''),
        }
    ubuntu_sshd_macs_literal = (
        _linux_platform(stig_id)
        and 'ubuntu' in stig_id.lower()
        and re.search(r'^\s*[$#>]\s*(?:sudo\s+)?grep\s+-irs\s+macs\s+/etc/ssh/sshd_config\*\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(
            r'^\s*MACs\s+hmac-sha2-512-etm@openssh\.com,hmac-sha2-256-etm@openssh\.com,hmac-sha2-512,hmac-sha2-256\s*$',
            content,
            re.MULTILINE | re.IGNORECASE,
        )
        and re.search(
            r'If\s+any\s+algorithms\s+other\s+than\s+["“]hmac-sha2-512-etm@openssh\.com,hmac-sha2-256-etm@openssh\.com,hmac-sha2-512,hmac-sha2-256["”]\s+are\s+listed,\s+the\s+returned\s+line\s+is\s+commented\s+out,\s+or\s+if\s+conflicting\s+results\s+are\s+returned,\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    if ubuntu_sshd_macs_literal:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'grep -irs macs /etc/ssh/sshd_config*'},
            'expected': {'type': 'equals', 'value': 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256'},
            'description': rule.get('title', ''),
        }
    vlock_binary_literal = (
        _linux_platform(stig_id)
        and re.search(r'\bVerify\s+[^.\n]*\bhas\s+the\s+["“]vlock["”]\s+package\s+installed\b', content, re.IGNORECASE)
        and re.search(r'^\s*[$#>]\s*(?:sudo\s+)?grep\s+vlock\s+/usr/bin/\*\s*$', content, re.MULTILINE)
        and re.search(r'^\s*Binary\s+file\s+/usr/bin/vlock\s+matches\s*$', content, re.MULTILINE)
        and re.search(r'If\s+["“]vlock["”]\s+is\s+not\s+installed,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    )
    if vlock_binary_literal:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'grep vlock /usr/bin/*'},
            'expected': {'type': 'contains', 'substring': 'Binary file /usr/bin/vlock matches'},
            'description': rule.get('title', ''),
        }
    pam_pwquality_retry_upper_bound = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?(?P<command>cat\s+(?P<path>/etc/pam\.d/(?:system-auth|password-auth))\s*\|\s*grep\s+pam_pwquality)\s*$',
        content,
        re.MULTILINE | re.IGNORECASE,
    )
    if (
        _linux_platform(stig_id)
        and pam_pwquality_retry_upper_bound
        and re.search(r'^\s*password\s+requisite\s+pam_pwquality\.so\s+retry=3\s*$', content, re.MULTILINE)
        and re.search(r'If\s+the\s+value\s+of\s+["“]retry["”]\s+is\s+set\s+to\s+["“]0["”]\s+or\s+greater\s+than\s+["“]3["”],\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': _normalize_command(pam_pwquality_retry_upper_bound.group('command'))},
            'expected': {'type': 'matches', 'pattern': r'^password\s+requisite\s+pam_pwquality\.so\b.*\bretry=[1-3]\b.*$'},
            'description': rule.get('title', ''),
        }
    snmp_default_community_strings = (
        _linux_platform(stig_id)
        and re.search(r'^\s*[$#>]\s*grep\s+public\s+/etc/snmp/snmpd\.conf\s*$', content, re.MULTILINE)
        and re.search(r'^\s*[$#>]\s*grep\s+private\s+/etc/snmp/snmpd\.conf\s*$', content, re.MULTILINE)
        and re.search(
            r'If\s+either\s+of\s+these\s+commands\s+returns\s+any\s+output,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    if snmp_default_community_strings:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "grep -E 'public|private' /etc/snmp/snmpd.conf"},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    postgresql_pgaudit_shared_preload_libraries = (
        'postgresql' in stig_id.lower()
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+shared_preload_libraries["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(
            r'If\s+(?:pgaudit\s+is\s+not\s+present\s+in\s+the\s+result\s+from\s+the\s+query|the\s+output\s+does\s+not\s+contain\s+["“]?pgaudit["”]?),?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    if postgresql_pgaudit_shared_preload_libraries:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -c "SHOW shared_preload_libraries"'},
            'expected': {'type': 'contains', 'substring': 'pgaudit'},
            'description': rule.get('title', ''),
        }
    pgaudit_log_commands = re.findall(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+pgaudit\.log["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
    postgresql_pgaudit_log_literal = re.search(
        r'If\s+pgaudit\.log\s+does\s+not\s+contain,?\s+["“]([^"”]+)["”],?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if (
        'postgresql' in stig_id.lower()
        and len(pgaudit_log_commands) == 1
        and postgresql_pgaudit_log_literal
        and re.search(rf'pgaudit\.log\s*=\s*[\'"“]{re.escape(postgresql_pgaudit_log_literal.group(1))}[\'"”]', fix_text, re.IGNORECASE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -c "SHOW pgaudit.log"'},
            'expected': {'type': 'contains', 'substring': postgresql_pgaudit_log_literal.group(1).strip()},
            'description': rule.get('title', ''),
        }
    yum_repo_gpgcheck_all_returned_lines = (
        _linux_platform(stig_id)
        and re.search(r'^\s*[$#>]\s*grep\s+gpgcheck\s+/etc/yum\.repos\.d/\*\.repo\s*\|\s*more\s*$', content, re.MULTILINE)
        and re.search(r'^\s*gpgcheck\s*=\s*1\s*$', content, re.IGNORECASE | re.MULTILINE)
        and re.search(
            r'If\s+["“]gpgcheck["”]\s+is\s+not\s+set\s+to\s+["“]1["”]\s+for\s+all\s+returned\s+lines,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    if yum_repo_gpgcheck_all_returned_lines:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "grep gpgcheck /etc/yum.repos.d/*.repo | grep -v -E '^gpgcheck\\s*=\\s*1$'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    apt_allowunauthenticated_true = (
        _linux_platform(stig_id)
        and re.search(r'^\s*[$#>]\s*grep\s+AllowUnauthenticated\s+/etc/apt/apt\.conf\.d/\*\s*$', content, re.MULTILINE)
        and re.search(
            r'Check\s+that\s+the\s+["“]AllowUnauthenticated["”]\s+variable\s+is\s+not\s+set\s+at\s+all\s+or\s+is\s+set\s+to\s+["“]false["”]',
            content,
            re.IGNORECASE,
        )
        and re.search(
            r'If\s+any\s+of\s+the\s+files\s+returned\s+from\s+the\s+command\s+with\s+["“]AllowUnauthenticated["”]\s+are\s+set\s+to\s+["“]true["”],?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    if apt_allowunauthenticated_true:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "grep AllowUnauthenticated /etc/apt/apt.conf.d/* | grep -i 'true'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    timedatectl_timezone_utc_or_gmt = (
        _linux_platform(stig_id)
        and re.search(r'^\s*[$#>]\s*timedatectl\s+status\s*\|\s*grep\s+-i\s+["“]time\s+zone["”]\s*$', content, re.MULTILINE)
        and re.search(
            r'If\s+["“]Timezone["”]\s+is\s+not\s+set\s+to\s+UTC\s+or\s+GMT,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    if timedatectl_timezone_utc_or_gmt:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'timedatectl status | grep -i "time zone" | grep -E "UTC|GMT"'},
            'expected': {'type': 'not_equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    networkmanager_dns_allowed_value = (
        _linux_platform(stig_id)
        and re.search(r'(?:oracle_linux_9|rhel_9)', stig_id, re.IGNORECASE)
        and re.search(r'^\s*[$#>]\s*NetworkManager\s+--print-config\s*$', content, re.MULTILINE)
        and re.search(r'^\s*dns\s*=\s*none\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(
            r'If\s+the\s+DNS\s+key\s+under\s+main\s+does\s+not\s+exist\s+or\s+is\s+not\s+set\s+to\s+["“]none["”]\s+or\s+["“]default["”],\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    if networkmanager_dns_allowed_value:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'NetworkManager --print-config | grep -E "^dns=(none|default)$"'},
            'expected': {'type': 'matches', 'pattern': r'^dns=(?:default|none)$'},
            'description': rule.get('title', ''),
        }
    nmcli_wireless_disabled = (
        _linux_platform(stig_id)
        and re.search(r'^\s*[$#>]\s*(?:sudo\s+)?nmcli\s+device(?:\s+status)?\s*$', content, re.MULTILINE)
        and re.search(r'\bwireless\s+interfaces?\s+(?:(?:to\s+be\s+)?configured|with the following command)\b', content, re.IGNORECASE)
        and re.search(
            r'If\s+a\s+wireless\s+interface\s+is\s+configured\s+and\s+(?:has\s+not\s+been\s+documented\s+and\s+approved\s+by\s+the|its\s+use\s+on\s+the\s+system\s+is\s+not\s+documented\s+with\s+the)\s+[^.]+,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    if nmcli_wireless_disabled:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "nmcli -t -f TYPE device status | grep -Fx 'wifi'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    sysfs_wireless_disabled = (
        _linux_platform(stig_id)
        and re.search(
            r'^\s*[$#>]\s*(?:sudo\s+)?ls\s+-L\s+-d\s+/sys/class/net/\*/wireless\s*\|\s*xargs\s+dirname\s*\|\s*xargs\s+basename\s*$',
            content,
            re.MULTILINE,
        )
        and re.search(r'\bno\s+wireless\s+interfaces?\s+configured\b', content, re.IGNORECASE)
        and re.search(
            r'If\s+a\s+wireless\s+interface\s+is\s+configured\s+and\s+has\s+not\s+been\s+documented\s+and\s+approved\s+by\s+the\s+[^.]+,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    if sysfs_wireless_disabled:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': 'ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename'},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    duplicate_uid_zero_match = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?(?P<command>awk\s+-F:\s+["\']\$3\s*==\s*0\s*\{print\s+\$1\}\s*["\']\s+/etc/passwd)\s*$',
        content,
        re.MULTILINE,
    )
    if duplicate_uid_zero_match and re.search(
        r'If\s+any\s+accounts\s+other\s+than\s+["“]?root["”]?\s+have\s+a\s+UID\s+of\s+["“]?0["”]?,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'generic',
            'check': {'type': 'command_output', 'command': _normalize_command(duplicate_uid_zero_match.group('command'))},
            'expected': {'type': 'equals', 'value': 'root'},
            'description': rule.get('title', ''),
        }
    cron_group_root_match = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?stat\s+-c\s+["\']%G\s+%n["\']\s+/etc/cron\*\s*$',
        content,
        re.MULTILINE,
    )
    if cron_group_root_match and re.search(
        r'If\s+any\s+crontab\s+is\s+not\s+group\s+owned\s+by\s+root,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'generic',
            'check': {
                'type': 'command_output',
                'command': 'find /etc/cron* ! -group root -exec stat -c "%G %n" {} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    cron_directory_mode_match = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?find\s+/etc/cron\*\s+-type\s+d\s*\|\s*xargs\s+stat\s+-c\s+["\']%a\s+%n["\']\s*$',
        content,
        re.MULTILINE,
    )
    cron_directory_mode_finding = re.search(
        r'If\s+any\s+cron\s+configuration\s+directory\s+is\s+more\s+permissive\s+than\s+["“]?(?P<mode>0?[0-7]{3})["”]?,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if cron_directory_mode_match and cron_directory_mode_finding:
        mode = int(cron_directory_mode_finding.group('mode'), 8)
        prohibited_bits = 0o777 & ~mode
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'generic',
            'check': {
                'type': 'command_output',
                'command': f'find /etc/cron* -type d -perm /{prohibited_bits:03o} -exec stat -c "%a %n" {{}} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    audit_configuration_ls_match = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?ls\s+-al\s+/etc/audit/\s+/etc/audit/rules\.d/\s*$',
        content,
        re.MULTILINE,
    )
    audit_configuration_paths = '/etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf'
    if audit_configuration_ls_match:
        if re.search(
            r'If\s+(?:the\s+)?["“]?/etc/audit/audit\.rules["”]?,\s+["“]?/etc/audit/rules\.d/\*["”]?,\s+or\s+["“]?/etc/audit/auditd\.conf["”]?\s+files?\s+(?:is|are)\s+owned\s+by\s+a\s+user\s+other\s+than\s+["“]root["”],?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux' if _linux_platform(stig_id) else 'generic',
                'check': {
                    'type': 'command_output',
                    'command': f'find {audit_configuration_paths} -type f ! -user root -exec stat -c "%U %n" {{}} \\;',
                },
                'expected': {'type': 'equals', 'value': ''},
                'description': rule.get('title', ''),
            }
        if re.search(
            r'If\s+(?:the\s+)?["“]?/etc/audit/audit\.rules["”]?,\s+["“]?/etc/audit/rules\.d/\*["”]?,\s+or\s+["“]?/etc/audit/auditd\.conf["”]?\s+files?\s+(?:is|are)\s+owned\s+by\s+a\s+group\s+other\s+than\s+["“]root["”],?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux' if _linux_platform(stig_id) else 'generic',
                'check': {
                    'type': 'command_output',
                    'command': f'find {audit_configuration_paths} -type f ! -group root -exec stat -c "%G %n" {{}} \\;',
                },
                'expected': {'type': 'equals', 'value': ''},
                'description': rule.get('title', ''),
            }
        audit_configuration_mode_finding = re.search(
            r'If\s+(?:the\s+)?["“]?/etc/audit/audit\.rules?["”]?,\s+["“]?/etc/audit/rules\.d/\*["”]?,\s+or\s+["“]?/etc/audit/auditd\.conf["”]?\s+files?\s+have\s+a\s+mode\s+more\s+permissive\s+than\s+["“]?(?P<mode>0?[0-7]{3})["”]?,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        if audit_configuration_mode_finding:
            mode = int(audit_configuration_mode_finding.group('mode'), 8)
            prohibited_bits = 0o777 & ~mode
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux' if _linux_platform(stig_id) else 'generic',
                'check': {
                    'type': 'command_output',
                    'command': f'find {audit_configuration_paths} -type f -perm /{prohibited_bits:04o} -exec stat -c "%a %n" {{}} \\;',
                },
                'expected': {'type': 'equals', 'value': ''},
                'description': rule.get('title', ''),
            }

    audit_rules_mode_match = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?find\s+/etc/audit/rules\.d/\s+/etc/audit/audit\.rules\s+/etc/audit/auditd\.conf\s+-type\s+f\s+-exec\s+stat\s+-c\s+["\']%a\s+%n["\']\s+\{\}\s+\\;\s*$',
        content,
        re.MULTILINE,
    )
    audit_rules_mode_prose = re.search(
        r'files\s+in\s+directory\s+["“]/etc/audit/rules\.d/["”]\s+and\s+["“]/etc/audit/auditd\.conf["”]\s+file\s+have\s+a\s+mode\s+of\s+["“]?(?P<mode>0?[0-7]{3})["”]?\s+or\s+less\s+permissive',
        content,
        re.IGNORECASE,
    )
    if audit_rules_mode_match and audit_rules_mode_prose:
        mode = int(audit_rules_mode_prose.group('mode'), 8)
        prohibited_bits = 0o777 & ~mode
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'generic',
            'check': {
                'type': 'command_output',
                'command': f'find /etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf -type f -perm /{prohibited_bits:04o} -exec stat -c "%a %n" {{}} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    audit_log_mode_matches = re.findall(
        r'^\s*[$#>]\s*(?:sudo\s+)?find\s+/var/log/audit/\s+-type\s+f\s+-exec\s+stat\s+-c\s+["\']%a\s+%n["\']\s+\{\}\s+\\;\s*$',
        content,
        re.MULTILINE,
    )
    audit_log_mode_finding = re.search(
        r'If\s+the\s+audit\s+logs\s+have\s+a\s+mode\s+more\s+permissive\s+than\s+["“]?(?P<mode>0?[0-7]{3})["”]?,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if audit_log_mode_matches and audit_log_mode_finding:
        mode = int(audit_log_mode_finding.group('mode'), 8)
        prohibited_bits = 0o7777 & ~mode
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'generic',
            'check': {
                'type': 'command_output',
                'command': f'find /var/log/audit/ -type f -perm /{prohibited_bits:o} -exec stat -c "%a %n" {{}} \\;',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    macos_osascript_true_candidate = _macos_osascript_true_heredoc_candidate(rule, stig_id)
    if macos_osascript_true_candidate:
        return macos_osascript_true_candidate
    macos_result_variable_candidate = _macos_result_variable_shell_block_candidate(rule, stig_id)
    if macos_result_variable_candidate:
        return macos_result_variable_candidate
    macos_sshd_fips_count_candidate = _macos_sshd_fips_count_shell_block_candidate(rule, stig_id)
    if macos_sshd_fips_count_candidate:
        return macos_sshd_fips_count_candidate
    macos_pass_fail_candidate = _macos_pass_fail_shell_block_candidate(rule, stig_id)
    if macos_pass_fail_candidate:
        return macos_pass_fail_candidate
    dconf_needs_update_candidate = _dconf_needs_update_candidate(rule, stig_id)
    if dconf_needs_update_candidate:
        return dconf_needs_update_candidate
    dconf_candidate = _dconf_grep_candidate(rule, stig_id)
    if dconf_candidate:
        return dconf_candidate
    findmnt_candidate = _findmnt_option_candidate(rule, stig_id)
    if findmnt_candidate:
        return findmnt_candidate
    fstab_mount_candidate = _fstab_mount_option_candidate(rule, stig_id)
    if fstab_mount_candidate:
        return fstab_mount_candidate
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
    kubernetes_ownership_matches = list(re.finditer(
        r'^\s*(?P<command>stat\s+-c\s+%U:%G\s+/[A-Za-z0-9_./:+-]+\*?\s*\|\s*grep\s+-v\s+(?P<owner_group>[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+))\s*$',
        content,
        re.MULTILINE,
    ))
    if kubernetes_ownership_matches:
        owner_groups = {match.group('owner_group') for match in kubernetes_ownership_matches}
        if len(owner_groups) == 1:
            owner_group = next(iter(owner_groups))
            if re.search(
                rf'If\s+the\s+command\s+returns\s+any\s+non\s+{re.escape(owner_group)}\s+file\s+permissions,?\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            ):
                if len(kubernetes_ownership_matches) == 1:
                    command = _normalize_command(kubernetes_ownership_matches[0].group('command'))
                else:
                    paths = []
                    for match in kubernetes_ownership_matches:
                        path_match = re.search(r'stat\s+-c\s+%U:%G\s+(?P<path>/[A-Za-z0-9_./:+-]+\*?)\s*\|', match.group('command'))
                        if not path_match:
                            paths = []
                            break
                        paths.append(path_match.group('path'))
                    if not paths:
                        command = ''
                    else:
                        command = f"stat -c %U:%G {' '.join(paths)} | grep -v {owner_group}"
                if command:
                    return {
                        'vuln_id': rule.get('vuln_id', ''),
                        'platform': 'linux' if _linux_platform(stig_id) else 'windows' if _windows_platform(stig_id) else 'generic',
                        'check': {'type': 'command_output', 'command': command},
                        'expected': {'type': 'equals', 'value': ''},
                        'description': rule.get('title', ''),
                    }
    sshd_config_find_stat_match = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?find\s+/etc/ssh/sshd_config\s+/etc/ssh/sshd_config\.d\s+-exec\s+stat\s+-c\s+["\']%(?P<field>[UG])\s+%n["\']\s+\{\}\s+\\;\s*$',
        content,
        re.MULTILINE,
    )
    if sshd_config_find_stat_match:
        field = sshd_config_find_stat_match.group('field')
        if field == 'U':
            finding = re.search(
                r'If\s+the\s+["“]/etc/ssh/sshd_config["”]\s+file\s+or\s+["“]/etc/ssh/sshd_config\.d["”]\s+or\s+any\s+files\s+in\s+the\s+["“]sshd_config\.d["”]\s+directory\s+do\s+not\s+have\s+an?\s+owner\s+of\s+["“](?P<principal>[A-Za-z0-9_.-]+)["”],?\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            )
            predicate = '-user'
        else:
            finding = re.search(
                r'If\s+the\s+["“]/etc/ssh/sshd_config["”]\s+file\s+or\s+["“]/etc/ssh/sshd_config\.d["”]\s+or\s+any\s+files\s+in\s+the\s+["“]?sshd_config\.d["”]?\s+directory\s+do\s+not\s+have\s+a\s+group\s+owner\s+of\s+["“](?P<principal>[A-Za-z0-9_.-]+)["”],?\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            )
            predicate = '-group'
        if finding:
            principal = finding.group('principal')
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux' if _linux_platform(stig_id) else 'generic',
                'check': {
                    'type': 'command_output',
                    'command': f'find /etc/ssh/sshd_config /etc/ssh/sshd_config.d ! {predicate} {principal} -exec stat -c "%{field} %n" {{}} \\;',
                },
                'expected': {'type': 'equals', 'value': ''},
                'description': rule.get('title', ''),
            }
    journal_find_mode_match = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?find\s+/run/log/journal\s+/var/log/journal\s+-type\s+(?P<kind>[df])\s+-exec\s+stat\s+-c\s+["\']%n\s+%a["\']\s+\{\}\s+\\;\s*$',
        content,
        re.MULTILINE,
    )
    if journal_find_mode_match:
        finding = re.search(
            r'If\s+any\s+output\s+returned\s+has\s+a\s+permission\s+(?:set\s+)?greater\s+than\s+["“]?(?P<mode>[0-7]{3,4})["”]?,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        if finding:
            mode = int(finding.group('mode'), 8)
            prohibited_bits = 0o7777 & ~mode
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux' if _linux_platform(stig_id) else 'generic',
                'check': {
                    'type': 'command_output',
                    'command': f'find /run/log/journal /var/log/journal -type {journal_find_mode_match.group("kind")} -perm /{prohibited_bits:o} -exec stat -c "%n %a" {{}} \\;',
                },
                'expected': {'type': 'equals', 'value': ''},
                'description': rule.get('title', ''),
            }
    journal_find_stat_match = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?find\s+/run/log/journal\s+/var/log/journal\s+-type\s+(?P<kind>[df])\s+-exec\s+stat\s+-c\s+["\']%n\s+%(?P<field>[UG])["\']\s+\{\}\s+\\;\s*$',
        content,
        re.MULTILINE,
    )
    if journal_find_stat_match:
        field = journal_find_stat_match.group('field')
        if field == 'U':
            finding = re.search(
                r'If\s+any\s+output\s+returned\s+is\s+not\s+owned\s+by\s+["“](?P<principal>[A-Za-z0-9_.-]+)["”],?\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            )
            predicate = '-user'
        else:
            finding = re.search(
                r'If\s+any\s+output\s+returned\s+is\s+not\s+group-owned\s+by\s+["“](?P<principal>[A-Za-z0-9_.-]+)["”],?\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            )
            predicate = '-group'
        if finding:
            principal = finding.group('principal')
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux' if _linux_platform(stig_id) else 'generic',
                'check': {
                    'type': 'command_output',
                    'command': f'find /run/log/journal /var/log/journal -type {journal_find_stat_match.group("kind")} ! {predicate} {principal} -exec stat -c "%n %{field}" {{}} \\;',
                },
                'expected': {'type': 'equals', 'value': ''},
                'description': rule.get('title', ''),
            }
    tomcat_find_owner_match = re.search(
        r'^\s*(?:sudo\s+)?(?P<command>find\s+\$(?:CATALINA_HOME|CATALINA_BASE)(?:/[A-Za-z0-9_.-]+/?)*\s+-follow\s+-maxdepth\s+0\s+\\\(\s*!\s+-user\s+(?P<owner>[A-Za-z0-9_.-]+)\s+-o\s*!\s+-group\s+(?P<group>[A-Za-z0-9_.-]+)\s+\\\)\s+-ls)\s*$',
        content,
        re.MULTILINE,
    )
    kubelet_hostname_override_match = re.search(
        r'^\s*ps\s+-ef\s+\|\s+grep\s+kubelet\s*$',
        content,
        re.MULTILINE,
    )
    if (
        kubelet_hostname_override_match
        and 'kubernetes' in stig_id.lower()
        and re.search(r'\bdeny\s+hostname\s+override\b', rule.get('title', ''), re.IGNORECASE)
        and re.search(r'If\s+the\s+option\s+["“]--hostname-override["”]\s+is\s+present,?\s+this\s+is\s+a\s+finding\.', content, re.IGNORECASE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': "ps -ef | grep '[k]ubelet' | grep -- '--hostname-override'"},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    if tomcat_find_owner_match:
        owner = tomcat_find_owner_match.group('owner')
        group = tomcat_find_owner_match.group('group')
        folder_pattern = re.escape(tomcat_find_owner_match.group('command').split()[1].rstrip('/'))
        if re.search(r'If\s+no\s+folders\s+are\s+displayed,?\s+this\s+is\s+not\s+a\s+finding', content, re.IGNORECASE) and re.search(
            rf'If\s+results\s+indicate\s+the\s+{folder_pattern}/?\s+folder\s+ownership\s+and\s+group\s+membership\s+is\s+not\s+set\s+to\s+{re.escape(owner)}:{re.escape(group)},?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'generic',
                'check': {'type': 'command_output', 'command': re.sub(r'\s+', ' ', _normalize_command(tomcat_find_owner_match.group('command')))},
                'expected': {'type': 'equals', 'value': ''},
                'description': rule.get('title', ''),
            }

    tomcat_find_permission_match = re.search(
        r'^\s*(?:sudo\s+)?(?P<command>find\s+\$(?:CATALINA_HOME|CATALINA_BASE)(?:/[A-Za-z0-9_.-]+/?)*\s+-follow\s+-maxdepth\s+0\s+-type\s+d\s+\\\(\s+\\?!\s+-perm\s+(?P<mode>[0-7]{3,4})\s+\\\)\s+-ls)\s*$',
        content,
        re.MULTILINE,
    )
    if tomcat_find_permission_match:
        mode = tomcat_find_permission_match.group('mode')
        folder_pattern = re.escape(tomcat_find_permission_match.group('command').split()[1].rstrip('/'))
        if re.search(r'If\s+no\s+folders\s+are\s+displayed,?\s+this\s+is\s+not\s+a\s+finding', content, re.IGNORECASE) and re.search(
            rf'If\s+results\s+indicate\s+the\s+{folder_pattern}/?\s+folder\s+permissions\s+are\s+not\s+set\s+to\s+{re.escape(mode)},?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'generic',
                'check': {'type': 'command_output', 'command': re.sub(r'\s+', ' ', _normalize_command(tomcat_find_permission_match.group('command')))},
                'expected': {'type': 'equals', 'value': ''},
                'description': rule.get('title', ''),
            }

    command_matches = list(re.finditer(r'^\s*[$#>]\s*(?P<command>(?:sudo\s+)?(?:/[A-Za-z0-9_./:+-]+|[A-Za-z0-9_.:+-]+)\b[^\n\r]*)$', content, re.MULTILINE))
    rpm_xorg_server_matches = [
        match for match in command_matches
        if re.fullmatch(r'(?:sudo\s+)?rpm\s+-qa\s+\|\s+grep\s+xorg\s+\|\s+grep\s+server', match.group('command').strip())
    ]
    if (
        len(command_matches) == 1
        and len(rpm_xorg_server_matches) == 1
        and _linux_platform(stig_id)
        and re.search(r'\b(?:graphical\s+display\s+manager|display\s+server)\b', rule.get('title', '') or '', re.IGNORECASE)
        and re.search(
            r'\b(?:must\s+not\s+(?:have\s+\S+\s+)?be\s+installed|not\s+installed|display\s+server\s+installed,\s+it\s+is\s+authorized)\b',
            content,
            re.IGNORECASE,
        )
        and re.search(r'If\s+the\s+use\s+of\s+(?:a\s+graphical\s+user\s+interface|(?:(?:a|the)\s+)?display\s+server)\s+[^.\n]*not\s+documented\s+with\s+the\s+(?:Information\s+System\s+Security\s+Officer\s+\()?ISSO\)?[^.\n]*this\s+is\s+a\s+finding', content, re.IGNORECASE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': _normalize_command(rpm_xorg_server_matches[0].group('command'))},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
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
        macos_audit_flag_command = re.search(
            r'^\s*(?P<command>/usr/bin/awk\s+-F["\']?:["\']?\s+["\']?/\^flags/\s+\{\s*print\s+\$NF\s*\}["\']?\s+/etc/security/audit_control\s+\|\s+/usr/bin/tr\s+["\'],["\']\s+["\']\\n["\']\s+\|\s+/usr/bin/grep\s+-Ec\s+["\'](?P<flag>[A-Za-z0-9_-]+)["\'])\s*$',
            content,
            re.MULTILINE,
        )
        if not command and macos_audit_flag_command and _macos_platform(stig_id) and re.search(
            rf'If\s+["“]{re.escape(macos_audit_flag_command.group("flag"))}["”]\s+is\s+not\s+listed\s+in\s+the\s+output,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        ):
            command = _normalize_command(macos_audit_flag_command.group('command'))
            command_end = macos_audit_flag_command.end()
        macos_audit_log_folder_mode_command = re.search(
            r"^\s*(?P<command>/usr/bin/stat\s+-f\s+%A\s+\$\(/usr/bin/grep\s+'\^dir'\s+/etc/security/audit_control\s+\|\s+/usr/bin/awk\s+-F:\s+'\{print\s+\$2\}'\))\s*$",
            content,
            re.MULTILINE,
        )
        if not command and macos_audit_log_folder_mode_command and _macos_platform(stig_id) and re.search(
            r'If\s+the\s+result\s+is\s+not\s+a\s+mode\s+of\s+700\s+or\s+less\s+permissive,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        ):
            command = _normalize_command(macos_audit_log_folder_mode_command.group('command'))
            command_end = macos_audit_log_folder_mode_command.end()
    pwck_home_directory_match = re.search(r'^\s*[$#>]\s*(?:sudo\s+)?(?P<command>pwck\s+-r)\s*$', content, re.MULTILINE)
    if pwck_home_directory_match and (
        re.search(
            r'If\s+any\s+home\s+directories\s+referenced\s+in\s+["“]/etc/passwd["”]\s+are\s+returned\s+as\s+not\s+defined,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        or re.search(
            r'If\s+pwck\s+reports\s+["“]no\s+group["”]\s+for\s+any\s+interactive\s+user,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        or re.search(
            r'If\s+GIDs\s+referenced\s+in\s+["“]/etc/passwd["”]\s+file\s+are\s+returned\s+as\s+not\s+defined\s+in\s+["“]/etc/group["”]\s+file,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        or re.search(
            r'If\s+users\s+home\s+director(?:y|ies)\s+does\s+not\s+exist,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        or re.search(
            r'If\s+any\s+interactive\s+users\s+do\s+not\s+have\s+a\s+home\s+directory\s+assigned,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    ):
        command = _normalize_command(pwck_home_directory_match.group('command'))
        command_end = pwck_home_directory_match.end()

    allow_macos_command_substitution = bool(
        command
        and _macos_platform(stig_id)
        and command.startswith('/')
        and '$(' in command
        and _command_substitutions_are_absolute(command)
    )
    if not command or _has_unsafe_shell_token(command, allow_command_substitution=allow_macos_command_substitution):
        return None
    if command in {'dnf repolist', 'yum repolist'} and re.search(
        r'If\s+any\s+repositories\s+containing\s+the\s+word\s+["“]epel["”]\s+in\s+the\s+name\s+exist,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'generic',
            'check': {'type': 'command_output', 'command': f'{command} | grep -i epel'},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    if (
        _linux_platform(stig_id)
        and command == 'grep banner-message-enable /etc/dconf/db/gdm.d/*'
        and re.search(r'^\s*banner-message-enable\s*=\s*true\s*$', content, re.MULTILINE)
        and re.search(
            r'If\s+["“]banner-message-enable["”]\s+is\s+set\s+to\s+["“]false["”]\s+or\s+is\s+missing\s+completely,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'contains', 'substring': 'banner-message-enable=true'},
            'description': rule.get('title', ''),
        }
    if re.search(r'\bPART\b', command) and '[PART]' in content:
        return None
    crypto_policy_krb5_symlink = (
        _linux_platform(stig_id)
        and command == 'file /etc/crypto-policies/back-ends/krb5.config'
        and (
            re.search(
                r'If\s+command\s+output\s+shows\s+the\s+following\s+line,\s+Kerberos\s+is\s+configured\s+to\s+use\s+the\s+systemwide\s+crypto\s+policy:',
                content,
                re.IGNORECASE,
            )
            or re.search(
                r'Verify\s+that\s+[^.\n]*\bconfigures\s+Kerberos\s+to\s+use\s+the\s+systemwide\s+crypto\s+policy\s+with\s+the\s+following\s+command:',
                content,
                re.IGNORECASE,
            )
        )
        and re.search(
            r'If\s+the\s+symlink\s+does\s+not\s+exist\s+or\s+points\s+to\s+a\s+different\s+target,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    if crypto_policy_krb5_symlink:
        expected_line = '/etc/crypto-policies/back-ends/krb5.config: symbolic link to /usr/share/crypto-policies/FIPS/krb5.txt'
        expected_line_pattern = re.escape(expected_line).replace(r'\ ', r'\s+')
        if re.search(rf'^\s*{expected_line_pattern}\s*$', content, re.MULTILINE):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'contains', 'substring': expected_line},
                'description': rule.get('title', ''),
            }
    macos_audit_log_folder_mode = re.fullmatch(
        r"/usr/bin/stat\s+-f\s+%A\s+\$\(/usr/bin/grep\s+'\^dir'\s+/etc/security/audit_control\s+\|\s+/usr/bin/awk\s+-F:\s+'\{print\s+\$2\}'\)",
        command,
    )
    if macos_audit_log_folder_mode and _macos_platform(stig_id) and re.search(
        r'If\s+the\s+result\s+is\s+not\s+a\s+mode\s+of\s+700\s+or\s+less\s+permissive,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'macos',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'matches', 'pattern': r'^[0-7]00$'},
            'description': rule.get('title', ''),
        }
    macos_audit_flag_count = re.fullmatch(
        r'/usr/bin/awk\s+-F["\']?:["\']?\s+["\']?/\^flags/\s+\{\s*print\s+\$NF\s*\}["\']?\s+/etc/security/audit_control\s+\|\s+/usr/bin/tr\s+["\'],["\']\s+["\']\\n["\']\s+\|\s+/usr/bin/grep\s+-Ec\s+["\'](?P<flag>[A-Za-z0-9_-]+)["\']',
        command,
    )
    if macos_audit_flag_count and _macos_platform(stig_id) and re.search(
        rf'If\s+["“]{re.escape(macos_audit_flag_count.group("flag"))}["”]\s+is\s+not\s+listed\s+in\s+the\s+output,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'macos',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': '1'},
            'description': rule.get('title', ''),
        }
    systemctl_active_socket = (
        _linux_platform(stig_id)
        and re.fullmatch(r'systemctl\s+is-active\s+[A-Za-z0-9_.@-]+\.socket', command)
        and re.search(rf'{re.escape(command)}\s*\n\s*active\b', content, re.IGNORECASE)
        and re.search(r'If\s+[^.\n]*\bsocket\s+is\s+not\s+["“]?active["”]?,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    )
    if systemctl_active_socket:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'active'},
            'description': rule.get('title', ''),
        }
    systemctl_masked_socket = (
        _linux_platform(stig_id)
        and re.fullmatch(r'systemctl\s+status\s+[A-Za-z0-9_.@-]+\.socket', command)
        and re.search(r'^\s*Loaded:\s+masked\b', content, re.IGNORECASE | re.MULTILINE)
        and re.search(r'If\s+[^.\n]*\.socket["”]?\s+is\s+loaded\s+and\s+not\s+masked\b', content, re.IGNORECASE)
    )
    if systemctl_masked_socket:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'contains', 'substring': 'Loaded: masked'},
            'description': rule.get('title', ''),
        }
    unquoted_semicolon_command = re.sub(r"'[^']*'|\"[^\"]*\"", '', command)
    if ';' in unquoted_semicolon_command and not re.fullmatch(r'[^;]*(?:\\;[^;]*)*', unquoted_semicolon_command):
        return None
    if command.startswith('xmllint ') and re.search(r'\bnot\s*\[', command):
        return None

    if (
        _linux_platform(stig_id)
        and re.fullmatch(r'grep\s+(?:-i\s+)?sha_crypt\s+/etc/login\.defs', command, re.IGNORECASE)
        and re.search(r'"SHA_CRYPT_MIN_ROUNDS"\s+or\s+"SHA_CRYPT_MAX_ROUNDS"\s+is\s+less\s+than\s+"100000",?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'SHA_CRYPT_MIN_ROUNDS\s+100000', fix_text, re.IGNORECASE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': command},
            'expected': {
                'type': 'matches',
                'pattern': r'(?ims)^(?!.*^\s*SHA_CRYPT_(?:MIN|MAX)_ROUNDS\s+(?:[0-9]{1,5})\b).*^\s*SHA_CRYPT_(?:MIN|MAX)_ROUNDS\s+(?:[1-9][0-9]{5,})\b.*$',
            },
            'description': rule.get('title', ''),
        }

    if (
        stig_id == 'Tomcat_Application_Server_9_STIG'
        and command == 'grep -i shutdown $CATALINA_BASE/conf/server.xml'
        and re.search(r'^\s*<Server\s+port=["“]-1["”]\s+shutdown=["“]SHUTDOWN["”]>\s*$', content, re.MULTILINE)
        and re.search(
            r'If\s+Server\s+port\s+not\s*=\s*["“]-1["”]\s+shutdown=["“]SHUTDOWN["”],?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'contains', 'substring': '<Server port="-1" shutdown="SHUTDOWN">'},
            'description': rule.get('title', ''),
        }

    grep_sample_candidate = _grep_sample_line_candidate(rule, stig_id, command, command_end)
    if grep_sample_candidate:
        return grep_sample_candidate

    literal_sample_candidate = _literal_command_output_candidate(rule, stig_id, command, command_end)
    if literal_sample_candidate:
        return literal_sample_candidate

    example_xml_attribute_match = re.search(r'Example\s+result:\s*(?P<body>.*?)(?:\n\s*If\b|\Z)', content, re.IGNORECASE | re.DOTALL)
    if command.startswith('xmllint ') and example_xml_attribute_match:
        example_lines = [line.strip() for line in example_xml_attribute_match.group('body').splitlines() if line.strip()]
        if len(example_lines) == 1 and re.fullmatch(r'<[A-Za-z][^\n<>]*/?>', example_lines[0]):
            attribute_requirement = re.search(
                r'If\s+the\s+["“][^"”]+["”]\s+element\s+is\s+not\s+defined\s+or\s+["“](?P<attribute>[A-Za-z][A-Za-z0-9_.:-]*)["”]\s+is\s+not\s+set\s+to\s+["“](?P<value>[^"”\n]+)["”],?\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            )
            if attribute_requirement:
                required_fragment = f'{attribute_requirement.group("attribute")}="{attribute_requirement.group("value")}"'
                if required_fragment in example_lines[0]:
                    return {
                        'vuln_id': rule.get('vuln_id', ''),
                        'platform': 'linux' if _linux_platform(stig_id) else 'windows' if _windows_platform(stig_id) else 'generic',
                        'check': {'type': 'command_output', 'command': command},
                        'expected': {'type': 'contains', 'substring': required_fragment},
                        'description': rule.get('title', ''),
                    }

    expected_match = re.search(r'Expected\s+result:\s*(?P<body>.*?)(?:\n\s*If\b|\Z)', content, re.IGNORECASE | re.DOTALL)
    if expected_match:
        expected_lines = [line.strip() for line in expected_match.group('body').splitlines() if line.strip()]
        expected_lines = [line for line in expected_lines if not line.startswith(('$', '#', '>'))]
        expected_result_is_required = re.search(r'output\s+(?:of\s+the\s+command\s+)?does\s+not\s+match\s+the\s+expected\s+result', content, re.IGNORECASE)
        xpath_empty_result_is_required = expected_lines == ['XPath set is empty'] and re.search(
            r'If\s+any\s+connectors\s+are\s+returned,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        xml_attribute_result_is_required = False
        if len(expected_lines) == 1:
            xml_attribute_match = re.fullmatch(r'([A-Za-z][A-Za-z0-9_.:-]*)="([^"\n]+)"', expected_lines[0])
            if xml_attribute_match:
                attribute, value = xml_attribute_match.groups()
                xml_attribute_result_is_required = bool(re.search(
                    rf'If\s+["“]{re.escape(attribute)}["”]\s+does\s+not\s+equal\s+["“]{re.escape(value)}["”],?\s+this\s+is\s+a\s+finding',
                    content,
                    re.IGNORECASE,
                ))
        if len(expected_lines) == 1 and (expected_result_is_required or xpath_empty_result_is_required or xml_attribute_result_is_required):
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

    if command == 'cat /proc/sys/crypto/fips_enabled' and re.search(
        r'(?:fips_enabled\s+is\s+not\s+["“]1["”]|value\s+returned\s+is\s+["“]0["”])[^.]*this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': '1'},
            'description': rule.get('title', ''),
        }

    if command == 'opensc-tool --get-conf-entry app:default:card_drivers cac' and re.search(
        r'^[ \t]*cac[ \t]*$',
        content,
        re.IGNORECASE | re.MULTILINE,
    ) and re.search(
        r'If\s+["“]cac["”]\s+is\s+not\s+listed\s+as\s+a\s+card\s+driver,?\s+or\s+no\s+line\s+is\s+returned\s+for\s+["“]card_drivers["”],?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'cac'},
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

    dmesg_active_match = re.search(
        r'If\s+["“]dmesg["”]\s+does\s+not\s+show\s+["“](?P<phrase>[^"”\n]+)["”]\s+active,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if command.startswith('dmesg ') and dmesg_active_match:
        expected_substring = f"{dmesg_active_match.group('phrase').strip()}: active"
        if re.search(rf'^.*{re.escape(expected_substring)}\s*$', content, re.IGNORECASE | re.MULTILINE):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux' if _linux_platform(stig_id) else 'generic',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'contains', 'substring': expected_substring},
                'description': rule.get('title', ''),
            }

    getsebool_match = re.fullmatch(r'getsebool\s+(?P<boolean>[A-Za-z0-9_]+)', command)
    if getsebool_match:
        boolean_name = getsebool_match.group('boolean')
        sample_match = re.search(rf'^\s*{re.escape(boolean_name)}\s+-->\s+(?P<value>on|off)\s*$', content, re.IGNORECASE | re.MULTILINE)
        if sample_match and re.search(
            rf'If\s+the\s+["“]{re.escape(boolean_name)}["”]\s+boolean\s+is\s+not\s+["“]{re.escape(sample_match.group("value"))}["”][^.\n]*this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        ):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'linux' if _linux_platform(stig_id) else 'generic',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'equals', 'value': f'{boolean_name} --> {sample_match.group("value").lower()}'},
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
        r'if\s+(?:(?:an?|any)\s+(?:["“][^"”]+["”]|[^\n.]+?)\s+(?:(?:file|files|directory|directories)\s+)?(?:is|are)\s+(?:found|returned)|there\s+is\s+output\s+that\s+indicates)[^.]*?this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_find_not_owner = command.startswith('find ') and re.search(
        r'!\s+-(?:user|group)\s+\S+[^\n]*\s+-exec\s+stat\s+-c\s+["\'][^"\']*[UG][^"\']*["\']',
        command,
        re.IGNORECASE,
    ) and re.search(
        r'If\s+any\s+(?:system-?wide\s+)?(?:shared\s+library\s+)?director(?:y|ies)\s+is\s+not\s+(?:owned|group-owned)\s+by\s+["“]?[A-Za-z0-9_.-]+["”]?,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_explicit_output = re.search(r'if\s+(?:any\s+)?output\s+is\s+produced,?\s+this\s+is\s+a\s+finding|if\s+this\s+produces\s+any\s+output|if\s+the\s+command\s+displays\s+any\s+(?:output|results),?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    no_output_for_command_output = re.search(r'if\s+the\s+command\s+(?:has|produces)\s+any\s+output,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    no_output_for_keytab_listing = re.fullmatch(r'ls\s+-al\s+/etc/\*\.keytab', command) and re.search(
        r'If\s+this\s+command\s+produces\s+any\s+(?:["“]keytab["”]\s+)?file\(s\),?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_any_output = re.search(r'if\s+(?:there\s+is\s+output|any\s+output\s+is\s+returned|(?:the\s+)?command\s+returns\s+any\s+output),?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    no_output_for_audit_backlog_limit_grep_v = re.fullmatch(
        r"grubby\s+--info=ALL\s+\|\s+grep\s+args\s+\|\s+grep\s+-v\s+'audit_backlog_limit=8192'",
        command,
    ) and re.search(
        r'If\s+the\s+command\s+returns\s+any\s+outputs,\s+and\s+audit_backlog_limit\s+is\s+less\s+than\s+["“]8192["”],?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_rpm_va_any_output = re.fullmatch(r"rpm\s+-Va\s+--noconfig\s+\|\s+grep\s+'\^\.\.5'", command) and re.search(
        r'If\s+there\s+is\s+any\s+output\s+from\s+the\s+command\s+for\s+system\s+files\s+or\s+binaries,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_shadow_blank_password = (
        re.search(r"^awk\s+-F:\s+['\"]!\$2\s+\{print\s+\$1\}\s*['\"]\s+/etc/shadow$", command)
        and re.search(r'if\s+the\s+command\s+returns\s+any\s+results,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    )
    no_output_for_grep_found = '| grep' in command and re.search(
        r'if\s+[^.\n]*(?:interfaces?|files?|packages?|certificates?|results?)\s+(?:are|is)\s+found[^.\n]*this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_grep_occurrences_return = re.search(r'\b(?:e?grep|grep)\b', command) and re.search(
        r'if\s+any\s+occurrences\s+of\s+["“][^"”\n]+["”]\s+(?:return|are\s+returned)\s+from\s+the\s+command(?:\s+and\s+have\s+not\s+been\s+documented\s+with\s+the\s+information\s+system\s+security\s+officer\s+\(ISSO\)\s+as\s+an\s+organizationally\s+defined\s+administrative\s+group\s+using\s+multifactor\s+authentication\s+\(MFA\))?,?\s+this\s+is\s+a\s+finding|if\s+any\s+occurrences\s+of\s+["“][^"”\n]+["”]\s+are\s+returned,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_find_unassigned_owner_group = re.search(r'\bfind\b[^\n]*(?:-nouser|-nogroup)\b', command) and re.search(
        r'If\s+any\s+files?\s+on\s+the\s+system\s+do\s+not\s+have\s+an\s+assigned\s+(?:owner|group),?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_duplicate_gid = re.fullmatch(r'cut\s+-d\s+:\s+-f\s+3\s+/etc/group\s*\|\s*uniq\s+-d', command) and re.search(
        r'If\s+the\s+system\s+has\s+duplicate\s+GIDs,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_duplicate_uid = re.fullmatch(
        r"awk\s+-F\s+['\"]?:['\"]?\s+['\"]list\[\$3\]\+\+\{print\s+\$1,\s*\$3\}\s*['\"]\s+/etc/passwd",
        command,
    ) and re.search(
        r'If\s+output\s+is\s+produced,?\s+and\s+the\s+accounts\s+listed\s+are\s+interactive\s+user\s+accounts,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_public_directory_sticky_bit = re.fullmatch(
        r'find\s+/\s+-type\s+d\s+\\\(\s+-perm\s+-0002\s+-a\s+!\s+-perm\s+-1000\s+\\\)\s+-print\s+2>/dev/null',
        command,
    ) and re.search(
        r'If\s+any\s+of\s+the\s+returned\s+director(?:y|ies)\s+are\s+world-writable\s+and\s+do\s+not\s+have\s+the\s+sticky\s+bit\s+set,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    no_output_for_pwck_home_directories = command == 'pwck -r' and (
        re.search(
            r'If\s+any\s+home\s+directories\s+referenced\s+in\s+["“]/etc/passwd["”]\s+are\s+returned\s+as\s+not\s+defined,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        or re.search(
            r'If\s+users\s+home\s+director(?:y|ies)\s+does\s+not\s+exist,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        or re.search(
            r'If\s+any\s+interactive\s+users\s+do\s+not\s+have\s+a\s+home\s+directory\s+assigned,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    no_output_for_pwck_gid_defined = command == 'pwck -r' and (
        re.search(
            r'If\s+pwck\s+reports\s+["“]no\s+group["”]\s+for\s+any\s+interactive\s+user,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
        or re.search(
            r'If\s+GIDs\s+referenced\s+in\s+["“]/etc/passwd["”]\s+file\s+are\s+returned\s+as\s+not\s+defined\s+in\s+["“]/etc/group["”]\s+file,?\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        )
    )
    no_output_for_pwck_quiet_duplicate_gid = command == 'pwck -qr' and re.search(
        r'If\s+the\s+system\s+has\s+any\s+interactive\s+users\s+with\s+duplicate\s+GIDs,?\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if no_output_for_find or no_output_for_find_not_owner or no_output_for_explicit_output or no_output_for_command_output or no_output_for_keytab_listing or no_output_for_any_output or no_output_for_audit_backlog_limit_grep_v or no_output_for_rpm_va_any_output or no_output_for_shadow_blank_password or no_output_for_grep_found or no_output_for_grep_occurrences_return or no_output_for_find_unassigned_owner_group or no_output_for_duplicate_gid or no_output_for_duplicate_uid or no_output_for_public_directory_sticky_bit or no_output_for_pwck_home_directories or no_output_for_pwck_gid_defined or no_output_for_pwck_quiet_duplicate_gid:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux' if _linux_platform(stig_id) else 'windows' if _windows_platform(stig_id) else 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    return None


def _aide_audit_tool_selection_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    command_match = re.search(
        r'^\s*[$#>]\s*(?P<command>egrep\s+["\']\(\\/sbin\\/\(audit\|au\)\)["\']\s+/etc/aide/aide\.conf)\s*$',
        content,
        re.MULTILINE,
    )
    if not command_match:
        return None
    expected_lines = []
    for line in content[command_match.end():].splitlines():
        stripped = line.strip()
        if not stripped:
            if expected_lines:
                break
            continue
        if stripped.lower().startswith(('if ', 'note:', '$', '#', '>')):
            break
        if not re.fullmatch(r'/sbin/(?:auditctl|auditd|ausearch|aureport|autrace|audispd|augenrules)\s+p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512', stripped):
            return None
        expected_lines.append(stripped)
    if len(expected_lines) not in (6, 7):
        return None
    if not re.search(r'If\s+any\s+of\s+the\s+seven\s+audit\s+tools\s+do\s+not\s+have\s+appropriate\s+selection\s+lines,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': _normalize_command(command_match.group('command'))},
        'expected': {'type': 'contains', 'substring': '\n'.join(expected_lines)},
        'description': rule.get('title', ''),
    }


def _file_permission_candidate(rule: dict) -> dict | None:
    content = rule.get('check_content', '') or ''
    find_exec_stat_match = re.search(
        r'\bfind\s+(?P<path>/[A-Za-z0-9_./:+-]+)\s+-exec\s+stat\s+-c\s+["\'](?P<format>[^"\']+)["\']\s+\{\}\s+\\;',
        content,
    )
    ls_file_match = re.search(
        r'^\s*[$#>]\s*(?:sudo\s+)?ls\s+-(?![A-Za-z]*R)[A-Za-z]*l[A-Za-z]*\s+(?P<path>/[A-Za-z0-9_./:+-]+)\s*$',
        content,
        re.MULTILINE,
    )
    path_match = re.search(r'\bstat\s+(?:-[A-Za-z]+\s+)*(?:["\'][^"\']+["\']\s+)?(/[A-Za-z0-9_./:+-]+)', content)
    if not path_match:
        path_match = re.search(r'\b(?:permissions|mode)[^\n.]+\s+(/[A-Za-z0-9_./:+-]+)', content, re.IGNORECASE)
    if not path_match and not find_exec_stat_match and not ls_file_match:
        return None
    path = path_match.group(1) if path_match else find_exec_stat_match.group('path') if find_exec_stat_match else ls_file_match.group('path')
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
                if field in ('%a', '%A') and re.fullmatch(r'[0-7]{1,4}', value):
                    mode = mode or value.zfill(4)
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

    if ls_file_match:
        for raw_line in content[ls_file_match.end():].splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            if stripped.lower().startswith(('if ', 'note:', '$', '#', '>')):
                break
            values = stripped.split()
            if len(values) >= 5 and values[-1] == path:
                sample_owner = values[2]
                sample_group = values[3]
                owner_finding = re.search(
                    rf'If\s+(?:the\s+)?["“]?{re.escape(path)}["”]?[^.\n]*does\s+not\s+have\s+an?\s+owner\s+of\s+["“]?{re.escape(sample_owner)}["”]?',
                    content,
                    re.IGNORECASE,
                )
                group_finding = re.search(
                    rf'If\s+(?:the\s+)?["“]?{re.escape(path)}["”]?[^.\n]*does\s+not\s+have\s+a\s+group\s+owner\s+of\s+["“]?{re.escape(sample_group)}["”]?',
                    content,
                    re.IGNORECASE,
                )
                if owner_finding:
                    owner = owner or sample_owner
                if group_finding:
                    group = group or sample_group
            break

    if owner is None:
        owner_match = re.search(r'not\s+owned\s+by\s+["“]?([A-Za-z0-9_.-]+)', content, re.IGNORECASE)
        if not owner_match:
            owner_match = re.search(r'has\s+an?\s+owner\s+other\s+than\s+["“]?([A-Za-z0-9_.-]+)', content, re.IGNORECASE)
        if owner_match:
            owner = owner_match.group(1).strip('"”.,')
    if group is None:
        group_match = re.search(r'not\s+group-owned\s+by\s+["“]?([A-Za-z0-9_.-]+)', content, re.IGNORECASE)
        if not group_match:
            group_match = re.search(r'has\s+a\s+group\s+owner\s+other\s+than\s+["“]?([A-Za-z0-9_.-]+)', content, re.IGNORECASE)
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


def _windows_registry_absent_or_dword_value_candidate(rule: dict, stig_id: str) -> dict | None:
    if not any(token in stig_id.lower() for token in ('office', 'defender')):
        return None
    content = rule.get('check_content', '') or ''
    path_match = re.search(
        r'Use\s+the\s+Windows\s+Registry\s+Editor\s+to\s+navigate\s+to\s+the\s+following\s+key:\s*\n+\s*((?:HKCU|HKLM)\\[^\n\r]+)',
        content,
        re.IGNORECASE,
    )
    if not path_match:
        return None
    expected_match = re.search(
        r'If\s+the\s+value\s+["“]?([A-Za-z0-9_.-]+)["”]?\s+does\s+not\s+exist,\s+this\s+is\s+not\s+a\s+finding\.\s+If\s+the\s+value\s+is\s+REG_DWORD\s*=\s*(\d+),\s+this\s+is\s+not\s+a\s+finding\.',
        content,
        re.IGNORECASE,
    )
    if not expected_match:
        expected_match = re.search(
            r'If\s+the\s+value\s+["“]?([A-Za-z0-9_.-]+)["”]?\s+is\s+REG_DWORD\s*=\s*(\d+),\s+this\s+is\s+not\s+a\s+finding\.\s*If\s+the\s+value\s+does\s+not\s+exist,\s+this\s+is\s+not\s+a\s+finding\.',
            content,
            re.IGNORECASE,
        )
    if not expected_match:
        expected_match = re.search(
            r'If\s+(?:the\s+)?value\s+for\s+["“]?([A-Za-z0-9_.-]+)["”]?\s+is\s+REG_DWORD\s*=\s*(\d+),\s+this\s+is\s+not\s+a\s+finding\.',
            content,
            re.IGNORECASE,
        )
    if not expected_match:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'registry',
            'path': _normalize_registry_path(path_match.group(1)),
            'value_name': expected_match.group(1),
        },
        'expected': {'type': 'equals', 'value': int(expected_match.group(2))},
        'description': rule.get('title', ''),
    }


def _office_registry_absent_or_dword_value_candidate(rule: dict, stig_id: str) -> dict | None:
    return _windows_registry_absent_or_dword_value_candidate(rule, stig_id)


def _sql_server_sa_login_renamed_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'sql_server' not in stig_id.lower() and 'sql server' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    title = rule.get('title', '') or ''
    if title.strip().lower() != 'the sql server default account [sa] must have its name changed.':
        return None
    if not re.search(r'FROM\s+sys\.sql_logins\s+WHERE\s+\[name\]\s*=\s*\'sa\'\s+OR\s+\[principal_id\]\s*=\s*1', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+the\s+login\s+account\s+name\s+["“]SA["”]\s+or\s+["“]sa["”]\s+appears\s+in\s+the\s+query\s+output,?\s+this\s+is\s+a\s+finding\.', content, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': 'sqlcmd -Q "SET NOCOUNT ON; SELECT name FROM sys.sql_logins WHERE [name] = \'sa\' OR [principal_id] = 1;"',
        },
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _windows_system32_absent_application_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    if not re.search(r'Navigate\s+to\s+the\s+Windows\\System32\s+directory\.', content, re.IGNORECASE):
        return None
    app_match = re.search(
        r'If\s+the\s+["“](telnet|tftp|snmp)["”]\s+application\s+exists,?\s+this\s+is\s+a\s+finding\.',
        content,
        re.IGNORECASE,
    )
    if not app_match:
        return None
    app = app_match.group(1).lower()
    expected_titles = {
        'telnet': 'The Telnet Client must not be installed on the system.',
        'tftp': 'The TFTP Client must not be installed on the system.',
        'snmp': 'Simple Network Management Protocol (SNMP) must not be installed on the system.',
    }
    if rule.get('title', '').strip().lower() != expected_titles[app].lower():
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': f'powershell -NoProfile -Command "Test-Path \\"$env:windir\\System32\\{app}.exe\\""',
        },
        'expected': {'type': 'equals', 'value': 'False'},
        'description': rule.get('title', ''),
    }


def _adobe_dc_repair_installation_disabled_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-213133', 'V-213180'}:
        return None
    combined = '\n'.join(part for part in (rule.get('check_content', '') or '', rule.get('fix_text', '') or '') if part)
    if not re.search(r'Adobe\s+(?:Acrobat\s+Pro|Reader)\s+DC', rule.get('title', '') + '\n' + stig_id, re.IGNORECASE):
        return None
    if not re.search(r'Value\s+Name:\s*DisableMaintenance\b', combined, re.IGNORECASE):
        return None
    if not re.search(r'Type:\s*REG_DWORD\b', combined, re.IGNORECASE):
        return None
    if not re.search(r'Value:\s*1\b', combined, re.IGNORECASE):
        return None
    if not re.search(r'DisableMaintenance[^\n.]+not\s+set\s+to\s+["“]?1["”]?[^\n.]+finding', combined, re.IGNORECASE):
        return None
    normalized = combined.lower().replace('\\\\', '\\')
    if vuln_id == 'V-213133':
        product_paths = [
            'Software\\Adobe\\Adobe Acrobat\\DC\\Installer',
            'SOFTWARE\\Wow6432Node\\Adobe\\Adobe Acrobat\\DC\\Installer',
        ]
    else:
        product_paths = [
            'Software\\Adobe\\Acrobat Reader\\DC\\Installer',
            'SOFTWARE\\Wow6432Node\\Adobe\\Acrobat Reader\\DC\\Installer',
        ]
    if any(path.lower() not in normalized for path in product_paths):
        return None
    ps_paths = ','.join(f"'HKLM:\\{path}'" for path in product_paths)
    command = (
        'powershell -NoProfile -Command '
        f'"$paths=@({ps_paths}); $ok=$true; foreach ($p in $paths) '
        "{ $v=(Get-ItemProperty -Path $p -Name 'DisableMaintenance' -ErrorAction SilentlyContinue).DisableMaintenance; "
        "if ($v -ne 1) { $ok=$false } }; if ($ok) { 'Compliant' }"
        '"'
    )
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _windows_ftp_anonymous_authentication_disabled_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    title = rule.get('title', '') or ''
    if vuln_id not in {'V-205853', 'V-254279', 'V-278027'}:
        return None
    if 'FTP servers must be configured to prevent anonymous logons' not in title:
        return None
    if not re.search(r'If\s+FTP\s+is\s+not\s+installed\s+on\s+the\s+system,\s+this\s+is\s+(?:NA|not\s+applicable)', content, re.IGNORECASE):
        return None
    if not re.search(r'FTP\s+Authentication', content, re.IGNORECASE):
        return None
    if not re.search(r'Anonymous\s+Authentication["”]?\s+status\s+is\s+["“]?Enabled["”]?,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'Select\s+["“]Anonymous\s+Authentication["”].*?Select\s+["“]Disabled["”]', fix_text, re.IGNORECASE | re.DOTALL):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': "powershell -NoProfile -Command \"Import-Module WebAdministration -ErrorAction SilentlyContinue; $value=(Get-WebConfigurationProperty -PSPath 'IIS:\\' -Filter '/system.ftpServer/security/authentication/anonymousAuthentication' -Name enabled -ErrorAction SilentlyContinue).Value; if ($value -eq $false) { 'Disabled' }\"",
        },
        'expected': {'type': 'equals', 'value': 'Disabled'},
        'description': title,
    }


def _windows_services_msc_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = content + '\n' + fix_text
    vuln_id = rule.get('vuln_id', '')
    title = rule.get('title', '') or ''
    if 'Services.msc' not in combined:
        return None
    if vuln_id == 'V-253289':
        if not re.search(r'Locate\s+the\s+["“]Secondary\s+Logon["”]\s+service', content, re.IGNORECASE):
            return None
        if not re.search(r'Startup\s+Type["”]?\s+is\s+not\s+["“]Disabled["”]\s+or\s+the\s+["“]Status["”]\s+is\s+["“]Running["”]', content, re.IGNORECASE):
            return None
        if not re.search(r'Configure\s+the\s+["“]Secondary\s+Logon["”]\s+service\s+["“]Startup\s+Type["”]\s+to\s+["“]Disabled["”]', fix_text, re.IGNORECASE):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$svc=Get-CimInstance Win32_Service -Filter \\\"Name='seclogon'\\\" -ErrorAction SilentlyContinue; if ($svc -and $svc.StartMode -eq 'Disabled' -and $svc.State -ne 'Running') { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': title,
        }
    if vuln_id == 'V-253277':
        if not re.search(r'Verify\s+Simple\s+TCP/IP\s+Services\s+has\s+not\s+been\s+installed', content, re.IGNORECASE):
            return None
        if not re.search(r'If\s+["“]Simple\s+TCP/IP\s+Services["”]\s+is\s+listed,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        if not re.search(r'Uninstall\s+["“]Simple\s+TCP/?IP\s+Services\b', fix_text, re.IGNORECASE):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"if (-not (Get-Service -Name 'SimpTcp' -ErrorAction SilentlyContinue)) { 'Absent' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Absent'},
            'description': title,
        }
    return None


def infer_candidate_check(rule: dict, stig_id: str) -> dict | None:
    """Infer a conservative executable check candidate from DISA prose.

    Candidates are not marked validated; they are scaffolds requiring fixture proof
    before a rule can be promoted from planned to implemented/validated.
    """
    content = rule.get('check_content', '') or ''
    kubernetes_admission_candidate = _kubernetes_validating_admission_webhook_candidate(rule, stig_id)
    if kubernetes_admission_candidate:
        return kubernetes_admission_candidate
    kubernetes_manifest_grep_candidate = _kubernetes_manifest_grep_candidate(rule, stig_id)
    if kubernetes_manifest_grep_candidate:
        return kubernetes_manifest_grep_candidate
    windows_legal_notice_caption_candidate = _windows_legal_notice_caption_candidate(rule, stig_id)
    if windows_legal_notice_caption_candidate:
        return windows_legal_notice_caption_candidate
    windows_legal_notice_text_candidate = _windows_legal_notice_text_candidate(rule, stig_id)
    if windows_legal_notice_text_candidate:
        return windows_legal_notice_text_candidate
    windows_run_as_different_user_candidate = _windows_run_as_different_user_context_menu_candidate(rule, stig_id)
    if windows_run_as_different_user_candidate:
        return windows_run_as_different_user_candidate
    vcenter_lookup_optional_xml_value_candidate = _vcenter_lookup_optional_xml_value_candidate(rule, stig_id)
    if vcenter_lookup_optional_xml_value_candidate:
        return vcenter_lookup_optional_xml_value_candidate
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
        allowed_dword_values = _registry_dword_allowed_values(combined_registry_content)
        if allowed_dword_values:
            if (
                len(normalized_hives) == 1
                and len(normalized_paths) == 1
                and len(normalized_value_names) == 1
                and re.search(r'^\s*(?:Value\s+Type|Type)\s*:?\s*REG_DWORD\s*$', combined_registry_content, re.IGNORECASE | re.MULTILINE)
            ):
                return {
                    'vuln_id': rule.get('vuln_id', ''),
                    'platform': 'windows' if 'windows' in stig_id.lower() or 'win' in stig_id.lower() else 'generic',
                    'check': {
                        'type': 'registry',
                        'path': f"{next(iter(normalized_hives))}\\{next(iter(normalized_paths))}",
                        'value_name': next(iter(normalized_value_names)),
                    },
                    'expected': {'type': 'matches', 'pattern': f"^(?:{'|'.join(str(value) for value in allowed_dword_values)})$"},
                    'description': rule.get('title', ''),
                }
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

    if _windows_platform(stig_id) or any(token in stig_id.lower() for token in ('chrome', 'edge', 'defender', 'office', 'adobe', 'acrobat')):
        hardened_unc_candidate = _windows_hardened_unc_paths_candidate(rule, stig_id)
        if hardened_unc_candidate:
            return hardened_unc_candidate

        defender_registry_absent_candidate = _windows_defender_registry_absent_candidate(rule, stig_id)
        if defender_registry_absent_candidate:
            return defender_registry_absent_candidate

        defender_registry_criteria_candidate = _windows_defender_registry_criteria_candidate(rule, stig_id)
        if defender_registry_criteria_candidate:
            return defender_registry_criteria_candidate

        policy_candidate = _windows_registry_policy_candidate(rule, stig_id)
        if policy_candidate:
            return policy_candidate

        ftp_anonymous_authentication_candidate = _windows_ftp_anonymous_authentication_disabled_candidate(rule, stig_id)
        if ftp_anonymous_authentication_candidate:
            return ftp_anonymous_authentication_candidate

        services_msc_candidate = _windows_services_msc_candidate(rule, stig_id)
        if services_msc_candidate:
            return services_msc_candidate

        office_absent_or_dword_candidate = _office_registry_absent_or_dword_value_candidate(rule, stig_id)
        if office_absent_or_dword_candidate:
            return office_absent_or_dword_candidate

        adobe_repair_installation_candidate = _adobe_dc_repair_installation_disabled_candidate(rule, stig_id)
        if adobe_repair_installation_candidate:
            return adobe_repair_installation_candidate

        audit_policy_candidate = _windows_audit_policy_candidate(rule)
        if audit_policy_candidate:
            return audit_policy_candidate

        security_policy_candidate = _windows_security_policy_candidate(rule)
        if security_policy_candidate:
            return security_policy_candidate

        directory_service_max_conn_idle_time_candidate = _windows_directory_service_max_conn_idle_time_candidate(rule, stig_id)
        if directory_service_max_conn_idle_time_candidate:
            return directory_service_max_conn_idle_time_candidate

        certificate_candidate = _windows_certificate_store_thumbprint_candidate(rule, stig_id)
        if certificate_candidate:
            return certificate_candidate

        account_password_required_candidate = _windows_account_password_required_candidate(rule, stig_id)
        if account_password_required_candidate:
            return account_password_required_candidate

        krbtgt_password_age_candidate = _windows_krbtgt_password_age_candidate(rule, stig_id)
        if krbtgt_password_age_candidate:
            return krbtgt_password_age_candidate

        system32_absent_app_candidate = _windows_system32_absent_application_candidate(rule, stig_id)
        if system32_absent_app_candidate:
            return system32_absent_app_candidate

        ad_smartcard_candidate = _windows_ad_smartcard_no_listed_users_candidate(rule, stig_id)
        if ad_smartcard_candidate:
            return ad_smartcard_candidate

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

    ubuntu_rsyslog_candidate = _ubuntu_rsyslog_remote_access_methods_candidate(rule, stig_id)
    if ubuntu_rsyslog_candidate:
        return ubuntu_rsyslog_candidate

    gsettings_candidate = _gsettings_candidate(rule, stig_id)
    if gsettings_candidate:
        return gsettings_candidate

    systemctl_get_default_candidate = _systemctl_get_default_candidate(rule, stig_id)
    if systemctl_get_default_candidate:
        return systemctl_get_default_candidate

    esxi_active_directory_authentication_candidate = _esxi_active_directory_authentication_candidate(rule, stig_id)
    if esxi_active_directory_authentication_candidate:
        return esxi_active_directory_authentication_candidate

    esxi_syslog_persistent_log_output_candidate = _esxi_syslog_persistent_log_output_candidate(rule, stig_id)
    if esxi_syslog_persistent_log_output_candidate:
        return esxi_syslog_persistent_log_output_candidate

    esxi_disabled_service_candidate = _esxi_disabled_vmhost_service_candidate(rule, stig_id)
    if esxi_disabled_service_candidate:
        return esxi_disabled_service_candidate

    esxi_advanced_setting_candidate = _esxi_advanced_setting_exact_value_candidate(rule, stig_id)
    if esxi_advanced_setting_candidate:
        return esxi_advanced_setting_candidate

    vcenter_lookup_service_grep_property_candidate = _vcenter_lookup_service_grep_property_candidate(rule, stig_id)
    if vcenter_lookup_service_grep_property_candidate:
        return vcenter_lookup_service_grep_property_candidate

    firefox_policy_boolean_candidate = _firefox_policy_boolean_candidate(rule, stig_id)
    if firefox_policy_boolean_candidate:
        return firefox_policy_boolean_candidate

    tomcat_systemd_boolean_property_candidate = _tomcat_systemd_boolean_property_candidate(rule, stig_id)
    if tomcat_systemd_boolean_property_candidate:
        return tomcat_systemd_boolean_property_candidate

    linux_shadow_password_lifetime_candidate = _linux_shadow_password_lifetime_candidate(rule, stig_id)
    if linux_shadow_password_lifetime_candidate:
        return linux_shadow_password_lifetime_candidate

    command_candidate = _command_output_candidate(rule, stig_id)
    if command_candidate:
        return command_candidate

    sql_server_sa_candidate = _sql_server_sa_login_renamed_candidate(rule, stig_id)
    if sql_server_sa_candidate:
        return sql_server_sa_candidate

    tomcat_auditctl_candidate = _tomcat_auditctl_expected_rule_candidate(rule, stig_id)
    if tomcat_auditctl_candidate:
        return tomcat_auditctl_candidate

    if _linux_platform(stig_id):
        for infer_with_stig in (_linux_interactive_shadow_sha512_candidate, _linux_shadow_password_lifetime_candidate, _linux_sssd_certmap_candidate, _sles_mfa_required_packages_candidate):
            candidate = infer_with_stig(rule, stig_id)
            if candidate:
                return candidate
        for infer in (_sysctl_candidate, _package_candidate, _file_content_candidate, _dconf_media_automount_literal_candidate, _sles_firewalld_status_enabled_active_candidate, _firewalld_target_drop_candidate, _sshd_multi_directive_egrep_candidate, _grep_expected_line_candidate, _sshd_config_candidate, _auditctl_expected_rule_candidate, _audit_rules_file_expected_rule_candidate, _service_candidate, _aide_audit_tool_selection_candidate, _file_permission_candidate):
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
            for k, v in artifact_rules.get(rule.get('vuln_id') or rule.get('rule_id'), {}).items():
                if not v:
                    continue
                if k in {'vuln_id', 'rule_id'} and enriched.get(k):
                    continue
                enriched[k] = v
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
