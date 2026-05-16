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
    value_data_match = re.search(r'\bValue\s+Data\s*:\s*(\S[^\n\r]*)$', check_content, re.IGNORECASE | re.MULTILINE)
    if value_data_match:
        return value_data_match.group(1).strip()

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


def _powershell_registry_key_absent_command(path: str) -> str:
    ps_path = _normalize_registry_path(path).replace('HKLM\\', 'HKLM:\\').replace('HKCU\\', 'HKCU:\\')
    return f"powershell -NoProfile -Command \"if (-not (Test-Path -LiteralPath '{ps_path}')) {{ 'Absent' }}\""


def _office_disabled_policy_registry_key_absent_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'office' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'policy\s+value\s+for\s+.*?\s+is\s+set\s+to\s+["“]Disabled["”]', content, re.IGNORECASE | re.DOTALL):
        return None
    if not re.search(r'Set\s+the\s+policy\s+value\s+for\s+.*?\s+to\s+["“]Disabled["”]', fix_text, re.IGNORECASE | re.DOTALL):
        return None
    path_match = re.search(
        r'Windows\s+Registry\s+Editor\s+to\s+navigate\s+to\s+the\s+following\s+key:\s*((?:HKLM|HKCU)\\[^\n\r]+)',
        content,
        re.IGNORECASE,
    )
    if not path_match or not re.search(r'If\s+the\s+registry\s+key\s+exists,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    path = path_match.group(1).strip()
    if not re.search(r'\\software\\policies\\microsoft\\office\\16\.0\\', path, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': _powershell_registry_key_absent_command(path)},
        'expected': {'type': 'equals', 'value': 'Absent'},
        'description': rule.get('title', ''),
    }


def _oracle_linux_8_nx_bit_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if stig_id != 'Oracle_Linux_8_STIG' or rule.get('vuln_id') != 'V-248589':
        return None
    if not re.search(r'NX\s*\(no-execution\)\s+bit\s+flag\s+is\s+set', content, re.IGNORECASE):
        return None
    if not re.search(r'NX\s*\(Execute\s+Disable\)\s+protection:\s+active', content, re.IGNORECASE):
        return None
    if not re.search(r'/proc/cpuinfo\s*\|\s*grep\s+-i\s+flags', content, re.IGNORECASE):
        return None
    if not re.search(r'Enable\s+the\s+NX\s+bit\s+execute\s+protection\s+in\s+the\s+system\s+BIOS', fix_text, re.IGNORECASE):
        return None
    command = (
        "sh -c \"if dmesg 2>/dev/null | grep -Fq 'NX (Execute Disable) protection: active' || "
        "grep -Eiq '(^|[[:space:]])nx([[:space:]]|$)' /proc/cpuinfo; then printf Compliant; fi\""
    )
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


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


def _apache_windows_httpd_conf_directive_candidate(rule: dict, stig_id: str) -> dict | None:
    if stig_id != 'Apache_Server_2-4_Windows_Server_STIG':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    title = rule.get('title', '') or ''
    directive_specs = {
        'V-214327': ('SSLVerifyClient', 'require', 'required'),
        'V-214340': ('TraceEnable', 'Off', 'required'),
        'V-214355': ('SSLCompression', 'off', 'absent_or_value'),
    }
    if vuln_id in {'V-214311', 'V-214323', 'V-214326', 'V-214339', 'V-214351'}:
        combined = content + '\n' + fix_text
        if vuln_id != 'V-214351' and 'httpd.conf' not in combined:
            return None
        commands = {
            'V-214311': "powershell -NoProfile -Command \"$p=Join-Path $env:ProgramFiles 'Apache24\\conf\\httpd.conf'; $line=Select-String -Path $p -Pattern '^\\s*LogFormat\\s+\\\"(?=.*%a)(?=.*%A)(?=.*%h)(?=.*%H)(?=.*%l)(?=.*%m)(?=.*%s)(?=.*%t)(?=.*%u)(?=.*%U)(?=.*%\\{Referer\\}i).*\\\"\\s+combined\\s*(?:#.*)?$' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($line) { 'Compliant' }\"",
            'V-214323': "powershell -NoProfile -Command \"$p=Join-Path $env:ProgramFiles 'Apache24\\conf\\httpd.conf'; $bad=Select-String -Path $p -Pattern '^\\s*(?:Action|AddHandler)\\b.*\\.(?:exe|dll|com|bat|csh)\\b' -ErrorAction SilentlyContinue; if (-not $bad) { 'Compliant' }\"",
            'V-214326': "powershell -NoProfile -Command \"$p=Join-Path $env:ProgramFiles 'Apache24\\conf\\httpd.conf'; $listen=Select-String -Path $p -Pattern '^\\s*Listen\\s+([^#\\s]+)\\s*(?:#.*)?$' -ErrorAction SilentlyContinue; if ($listen -and -not ($listen | Where-Object { $_.Matches[0].Groups[1].Value -notmatch '^(?!0\\.0\\.0\\.0:|\\[::ffff:0\\.0\\.0\\.0\\]:)(?:\\d{1,3}\\.){3}\\d{1,3}:\\d+$' })) { 'Compliant' }\"",
            'V-214339': "powershell -NoProfile -Command \"$p=Join-Path $env:ProgramFiles 'Apache24\\conf\\httpd.conf'; $line=Select-String -Path $p -Pattern '^\\s*ErrorDocument\\s+\\d{3}\\s+\\S+' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($line) { 'Compliant' }\"",
            'V-214351': "powershell -NoProfile -Command \"$m=& httpd -M 2>$null; $p=Join-Path $env:ProgramFiles 'Apache24\\conf\\httpd.conf'; $line=Select-String -Path $p -Pattern '^\\s*LogFormat\\s+\\\"[^\\\"]*%t[^\\\"]*\\\"' -ErrorAction SilentlyContinue | Select-Object -First 1; if (($m -match 'log_config_module') -and $line) { 'Compliant' }\"",
        }
        guards = {
            'V-214311': (
                r'LogFormat\s+["“]%a\s+%A\s+%h\s+%H\s+%l\s+%m\s+%s\s+%t\s+%u\s+%U\s+\\?["“]%\{Referer\}i',
                r'configured\s+to\s+capture\s+the\s+required\s+audit\s+events',
            ),
            'V-214323': (
                r'Action["”]?\s+or\s+["“]?AddHandler',
                r'\.exe,\s*\.dll,\s*\.com,\s*\.bat,\s*or\s*\.csh',
            ),
            'V-214326': (
                r'Listen',
                r'specify\s+both\s+an\s+IP\s+address\s+and\s+port\s+number',
                r'0\.0\.0\.0:80|\[::ffff:0\.0\.0\.0\]:80',
            ),
            'V-214339': (
                r'ErrorDocument',
                r'directive\s+is\s+not\s+being\s+used,\s+this\s+is\s+a\s+finding',
            ),
            'V-214351': (
                r'httpd\s+-M',
                r'log_config_module',
                r'LogFormat',
                r'%t',
            ),
        }
        if all(re.search(pattern, combined, re.IGNORECASE) for pattern in guards[vuln_id]):
            return {
                'vuln_id': vuln_id,
                'platform': 'windows',
                'check': {'type': 'command_output', 'command': commands[vuln_id]},
                'expected': {'type': 'equals', 'value': 'Compliant'},
                'description': title,
            }
        return None

    if vuln_id == 'V-214309':
        combined = content + '\n' + fix_text
        if 'CustomLog' not in combined or 'httpd.conf' not in combined:
            return None
        if not re.search(r'If\s+the\s+["“]?CustomLog["”]?\s+directive\s+is\s+missing\s+or\s+does\s+not\s+look\s+like\s+the\s+following,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        if not re.search(r'^\s*CustomLog\s+["“]Logs/access_log["”]\s+common\s*$', content, re.IGNORECASE | re.MULTILINE):
            return None
        pattern = r'^\s*CustomLog\s+"Logs/access_log"\s+common\s*(?:#.*)?$'
        command = (
            'powershell -NoProfile -Command '
            '"$p=Join-Path $env:ProgramFiles \'Apache24\\conf\\httpd.conf\'; '
            f"$line=Select-String -Path $p -Pattern '{pattern}' -ErrorAction SilentlyContinue | Select-Object -First 1; "
            "if ($line) { 'Compliant' }\""
        )
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': title,
        }

    if vuln_id == 'V-214335':
        combined = content + '\n' + fix_text
        required_lines = ('SSLRandomSeed startup builtin', 'SSLRandomSeed connect builtin')
        if not all(line in combined for line in required_lines):
            return None
        if not re.search(r'If\s+the\s+["“]?SSLRandomSeed["”]?\s+directive\s+is\s+missing\s+or\s+does\s+not\s+look\s+like\s+the\s+following,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        if not re.search(r'Set\s+the\s+["“]?SSLRandomSeed["”]?\s+directives\s+to\s+the\s+following', fix_text, re.IGNORECASE):
            return None
        command = (
            'powershell -NoProfile -Command '
            '"$p=Join-Path $env:ProgramFiles \'Apache24\\conf\\extra\\httpd-ssl.conf\'; '
            "$startup=Select-String -Path $p -Pattern '^\\s*SSLRandomSeed\\s+startup\\s+builtin\\s*(?:#.*)?$' -ErrorAction SilentlyContinue | Select-Object -First 1; "
            "$connect=Select-String -Path $p -Pattern '^\\s*SSLRandomSeed\\s+connect\\s+builtin\\s*(?:#.*)?$' -ErrorAction SilentlyContinue | Select-Object -First 1; "
            "if ($startup -and $connect) { 'Compliant' }\""
        )
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': title,
        }

    if vuln_id == 'V-214359':
        if not re.search(r'\bhttpd\s+-v\b', content, re.IGNORECASE):
            return None
        if not re.search(r'If\s+the\s+version\s+of\s+Apache\s+is\s+not\s+at\s+the\s+following\s+version\s+or\s+higher,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        if not re.search(r'^\s*Apache\s+2\.4\s+\(February\s+2012\)\s*$', content, re.IGNORECASE | re.MULTILINE):
            return None
        command = (
            'powershell -NoProfile -Command '
            '"$v=& httpd -v 2>$null | Select-String -Pattern \'Apache/(?<major>\\d+)\\.(?<minor>\\d+)\' | Select-Object -First 1; '
            "$major=[int]$v.Matches[0].Groups['major'].Value; $minor=[int]$v.Matches[0].Groups['minor'].Value; "
            "if ($major -gt 2 -or ($major -eq 2 -and $minor -ge 4)) { 'Compliant' }\""
        )
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': title,
        }

    if vuln_id in {'V-214306', 'V-214338', 'V-214341'}:
        numeric_specs = {
            'V-214306': {
                'directive': 'MaxKeepAliveRequests',
                'threshold': 100,
                'operator': 'ge',
                'config_path': 'Apache24\\conf\\extra\\httpd-default',
                'check_pattern': r'Verify\s+the\s+value\s+is\s+["“]?100["”]?\s+or\s+greater',
                'finding_pattern': r'If\s+the\s+["“]?MaxKeepAliveRequests["”]?\s+directive\s+is\s+not\s+["“]?100["”]?\s+or\s+greater,\s+this\s+is\s+a\s+finding',
                'fix_pattern': r'Set\s+the\s+["“]?MaxKeepAliveRequests["”]?\s+directive\s+to\s+a\s+value\s+of\s+["“]?100["”]?\s+or\s+greater',
                'ps_operator': '-ge',
            },
            'V-214338': {
                'directive': 'Timeout',
                'threshold': 60,
                'operator': 'le',
                'config_path': 'Apache24\\conf\\httpd.conf',
                'check_pattern': r'Verify\s+the\s+["“]?Timeout["”]?\s+directive\s+is\s+specified\s+in\s+the\s+["“]?httpd\.conf["”]?\s+file\s+to\s+have\s+a\s+value\s+of\s+["“]?60["”]?\s+seconds\s+or\s+less',
                'finding_pattern': r'If\s+the\s+["“]?Timeout["”]?\s+directive\s+is\s+not\s+configured\s+or\s+set\s+for\s+more\s+than\s+["“]?60["”]?\s+seconds,\s+this\s+is\s+a\s+finding',
                'fix_pattern': r'Add\s+or\s+modify\s+the\s+["“]?Timeout["”]?\s+directive\s+in\s+the\s+Apache\s+configuration\s+to\s+have\s+a\s+value\s+of\s+["“]?60["”]?\s+seconds\s+or\s+less',
                'ps_operator': '-le',
            },
            'V-214341': {
                'directive': 'SessionMaxAge',
                'threshold': 600,
                'operator': 'le',
                'config_path': 'Apache24\\conf\\httpd.conf',
                'check_pattern': r'Verify\s+the\s+value\s+of\s+["“]?SessionMaxAge["”]?\s+is\s+set\s+to\s+["“]?600["”]?\s+or\s+less',
                'finding_pattern': r'If\s+the\s+["“]?SessionMaxAge["”]?\s+does\s+not\s+exist\s+or\s+is\s+set\s+to\s+more\s+than\s+["“]?600["”]?,\s+this\s+is\s+a\s+finding',
                'fix_pattern': r'Set\s+the\s+["“]?SessionMaxAge["”]?\s+directive\s+to\s+a\s+value\s+of\s+["“]?600["”]?\s+or\s+less',
                'ps_operator': '-le',
            },
        }
        cfg = numeric_specs[vuln_id]
        combined = content + '\n' + fix_text
        directive = cfg['directive']
        if directive not in combined:
            return None
        if not re.search(cfg['check_pattern'], content, re.IGNORECASE):
            return None
        if not re.search(cfg['finding_pattern'], content, re.IGNORECASE):
            return None
        if not re.search(cfg['fix_pattern'], fix_text, re.IGNORECASE):
            return None
        pattern = rf'^\s*{re.escape(directive)}\s+(\d+)\s*(?:#.*)?$'
        command = (
            'powershell -NoProfile -Command '
            f'"$p=Join-Path $env:ProgramFiles \'{cfg["config_path"]}\'; '
            f"$line=Select-String -Path $p -Pattern '{pattern}' -ErrorAction SilentlyContinue | Select-Object -First 1; "
            f"if ($line -and [int]$line.Matches[0].Groups[1].Value {cfg['ps_operator']} {cfg['threshold']}) {{ 'Compliant' }}\""
        )
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': title,
        }

    if vuln_id == 'V-214320':
        combined = content + '\n' + fix_text
        if 'ProxyRequests' not in combined:
            return None
        if not re.search(r'If\s+the\s+ProxyRequests\s+directive\s+is\s+set\s+to\s+["“]?On["”]?,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        if not re.search(r'Set\s+the\s+directive\s+to\s+a\s+value\s+of\s+["“]?off["”]?', fix_text, re.IGNORECASE):
            return None
        command = (
            'powershell -NoProfile -Command '
            '"$p=Join-Path $env:ProgramFiles \'Apache24\\conf\\httpd.conf\'; '
            "$lines=Select-String -Path $p -Pattern '^\\s*ProxyRequests\\s+On\\s*(?:#.*)?$' -ErrorAction SilentlyContinue; "
            "if (-not $lines) { 'Compliant' }\""
        )
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': title,
        }

    spec = directive_specs.get(vuln_id)
    if not spec:
        return None
    directive, value, mode = spec
    combined = content + '\n' + fix_text
    if directive not in combined:
        return None
    if mode == 'required':
        if not re.search(rf'If\s+[^.]*{re.escape(directive)}[^.]*not\s+set\s+to\s+["“]?{re.escape(value)}["”]?', content, re.IGNORECASE):
            return None
        pattern = rf'^\s*{re.escape(directive)}\s+{re.escape(value)}\s*(?:#.*)?$'
    else:
        if not re.search(rf'If\s+the\s+["“]{re.escape(directive)}["”]\s+directive\s+does\s+not\s+exist,\s+this\s+is\s+a\s+not\s+a\s+finding', content, re.IGNORECASE):
            return None
        finding_patterns = (
            rf'If\s+the\s+["“]{re.escape(directive)}["”]\s+directive\s+is\s+set\s+to\s+["“]?on["”]?,\s+this\s+is\s+a\s+finding',
            rf'If\s+the\s+["“]{re.escape(directive)}["”]\s+directive\s+exists\s+and\s+is\s+not\s+set\s+to\s+["“]?{re.escape(value)}["”]?,\s+this\s+is\s+a\s+finding',
        )
        if not any(re.search(pattern, content, re.IGNORECASE) for pattern in finding_patterns):
            return None
        pattern = rf'^(?:\s*|\s*{re.escape(directive)}\s+{re.escape(value)}\s*(?:#.*)?)$'
    command = (
        'powershell -NoProfile -Command '
        f'"$p=Join-Path $env:ProgramFiles \'Apache24\\conf\\httpd.conf\'; '
        f"$line=Select-String -Path $p -Pattern '{pattern}' -ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($line) { 'Compliant' }\""
    )
    if mode == 'absent_or_value':
        command = (
            'powershell -NoProfile -Command '
            f'"$p=Join-Path $env:ProgramFiles \'Apache24\\conf\\httpd.conf\'; '
            f"$lines=Select-String -Path $p -Pattern '^\\s*{re.escape(directive)}\\b' -ErrorAction SilentlyContinue; "
            f"if ((-not $lines) -or ($lines | Where-Object {{ $_.Line -match '^\\s*{re.escape(directive)}\\s+{re.escape(value)}\\s*(?:#.*)?$' }})) {{ 'Compliant' }}\""
        )
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': title,
    }


def _apache_windows_module_candidate(rule: dict, stig_id: str) -> dict | None:
    if stig_id != 'Apache_Server_2-4_Windows_Server_STIG':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if vuln_id == 'V-214333' and 'httpd -M' not in content:
        combined = content + '\n' + fix_text
        if 'mod_unique_id' not in combined:
            return None
        if not re.search(r'If\s+it\s+does\s+not\s+exist,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        command = (
            'powershell -NoProfile -Command '
            '"$p=Join-Path $env:ProgramFiles \'Apache24\\conf\\httpd.conf\'; '
            "$line=Select-String -Path $p -Pattern '^\\s*LoadModule\\s+unique_id_module\\b.*mod_unique_id' -ErrorAction SilentlyContinue | Select-Object -First 1; "
            "if ($line) { 'Compliant' }\""
        )
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': rule.get('title', ''),
        }
    if 'httpd -M' not in content:
        return None
    module_sets = {
        'V-214307': ('required', ('session_module', 'usertrack_module')),
        'V-214308': ('required', ('ssl_module',)),
        'V-214310': ('required', ('log_config_module',)),
        'V-214325': ('forbidden', ('dav_module', 'dav_fs_module', 'dav_lock_module')),
        'V-214333': ('required', ('unique_id_module',)),
    }
    module_spec = module_sets.get(vuln_id)
    if not module_spec:
        return None
    mode, modules = module_spec
    combined = content + '\n' + fix_text
    if not all(module in combined for module in modules):
        return None
    if mode == 'required' and not re.search(r'(?:not\s+enabled|not\s+listed|does\s+not\s+exist|must\s+be\s+loaded|is\s+loaded)', content, re.IGNORECASE):
        return None
    if mode == 'forbidden' and not re.search(r'If\s+any\s+of\s+the\s+following\s+modules\s+are\s+present,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    operator = '-match' if mode == 'required' else '-notmatch'
    checks = ' -and '.join(f"($m {operator} '{module}')" for module in modules)
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': f"powershell -NoProfile -Command \"$m=& httpd -M 2>$null; if ({checks}) {{ 'Compliant' }}\"",
        },
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _windows_firmware_state_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    title = rule.get('title', '') or ''
    content = rule.get('check_content', '') or ''
    if vuln_id in {'V-253256', 'V-205856', 'V-278031'}:
        if not (
            re.search(r'Run\s+["“]System\s+Information["”]', content, re.IGNORECASE)
            and re.search(r'["“]BIOS\s+Mode["”]\s+does\s+not\s+display\s+["“]UEFI["”]', content, re.IGNORECASE)
            and re.search(r'UEFI\s+mode,\s+not\s+Legacy\s+BIOS', content + '\n' + title, re.IGNORECASE)
        ):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$info=Get-ComputerInfo -Property BiosFirmwareType -ErrorAction SilentlyContinue; if ($info.BiosFirmwareType -eq 'Uefi') { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': title,
        }
    if vuln_id == 'V-253257':
        if not (
            re.search(r'Run\s+["“]System\s+Information["”]', content, re.IGNORECASE)
            and re.search(r'["“]Secure\s+Boot\s+State["”]\s+does\s+not\s+display\s+["“]On["”]', content, re.IGNORECASE)
            and re.search(r'Secure\s+Boot', content + '\n' + title, re.IGNORECASE)
        ):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$secure=$false; try { $secure=Confirm-SecureBootUEFI -ErrorAction Stop } catch { $secure=$false }; if ($secure) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': title,
        }
    if vuln_id in {'V-253255', 'V-205848', 'V-277993'}:
        if not (
            re.search(r'Run\s+["“]tpm\.msc["”]', content, re.IGNORECASE)
            and re.search(r'(?:TPM\s+enabled\s+and\s+ready\s+for\s+use|has\s+a\s+TPM\s+and\s+it\s+is\s+ready\s+for\s+use)', content + '\n' + title, re.IGNORECASE)
            and re.search(r'TPM\s+is\s+ready\s+for\s+use|TPM\s+is\s+on\s+and\s+ownership\s+has\s+been\s+taken', content, re.IGNORECASE)
        ):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {
                'type': 'command_output',
                'command': "powershell -NoProfile -Command \"$tpm=Get-Tpm -ErrorAction SilentlyContinue; if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) { 'Compliant' }\"",
            },
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': title,
        }
    return None


def _windows_host_firewall_enabled_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    title = rule.get('title', '') or ''
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = '\n'.join(part for part in (title, content, fix_text) if part)
    if not re.search(r'\bhost-based\s+firewall\s+(?:is\s+)?installed\s+and\s+enabled\b', combined, re.IGNORECASE):
        return None
    if not re.search(r'If\s+a\s+host-based\s+firewall\s+is\s+not\s+installed\s+and\s+enabled\s+on\s+the\s+system,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'Install\s+and\s+enable\s+a\s+host-based\s+firewall', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': "powershell -NoProfile -Command \"$profiles=Get-NetFirewallProfile -ErrorAction SilentlyContinue; if ($profiles -and -not ($profiles | Where-Object { -not $_.Enabled })) { 'Compliant' }\"",
        },
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': title,
    }


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


def _office_all_installed_programs_feature_control_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if 'office' not in stig_id.lower():
        return None
    supported_vulns = {
        'V-223296', 'V-223297', 'V-223298', 'V-223299', 'V-223300', 'V-223301',
        'V-223302', 'V-223303', 'V-223304', 'V-223305', 'V-223306', 'V-223307',
        'V-223308',
    }
    if vuln_id not in supported_vulns:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = f'{content}\n{fix_text}'
    path_match = re.search(
        r'Windows\s+Registry\s+Editor\s+to\s+navigate\s+to\s+the\s+following\s+key:\s*((?:HKLM|HKEY_LOCAL_MACHINE)\\software\\microsoft\\internet\s+explorer\\main\\featurecontrol\\feature_[a-z0-9_]+)',
        content,
        re.IGNORECASE | re.DOTALL,
    )
    if not path_match:
        return None
    if not re.search(r'If\s+the\s+value\s+for\s+(?:all\s+installed\s+Office\s+Programs|all\s+installed\s+programs|each\s+installed\s+Office\s+Program)\s+is\s+(?:set\s+to\s+is\s+)?REG_DWORD\s*=\s*1\s*,?\s+this\s+is\s+not\s+a\s+finding', content, re.IGNORECASE):
        return None
    explicit_all_programs_fix = re.search(
        r'Set\s+the\s+policy\s+value\s+for\s+Computer\s+Configuration\s+>>\s+Administrative\s+Templates\s+>>\s+Microsoft\s+Office\s+2016\s+\(Machine\)\s+>>\s+Security\s+Settings\s+>>\s+IE\s+Security\s+>>\s+Mime\s+Sniffing\s+Safety\s+Feature\s+to\s+["“]Enabled["”]\s+for\s+all\s+installed\s+Office\s+programs',
        fix_text,
        re.IGNORECASE,
    )
    if not re.search(r'select\s+the\s+check\s+boxes?\s+for\s+all\s+installed\s+Office\s+programs', combined, re.IGNORECASE) and not (vuln_id == 'V-223301' and explicit_all_programs_fix):
        return None
    registry_path = _normalize_registry_path(path_match.group(1))
    ps_path = registry_path.replace('HKLM\\', 'HKLM:\\')
    office_apps = (
        'excel.exe', 'groove.exe', 'lync.exe', 'msaccess.exe', 'mspub.exe',
        'onenote.exe', 'outlook.exe', 'powerpnt.exe', 'visio.exe', 'winproj.exe',
        'winword.exe',
    )
    app_list = ','.join(f"'{app}'" for app in office_apps)
    command = (
        'powershell -NoProfile -Command '
        f'"$apps=@({app_list}); '
        '$roots=@($env:ProgramFiles,${env:ProgramFiles(x86)}) | Where-Object { $_ }; '
        "$installed=$apps | Where-Object { $app=$_; $roots | Where-Object { "
        "Test-Path (Join-Path $_ ('Microsoft Office\\root\\Office16\\' + $app)) -or "
        "Test-Path (Join-Path $_ ('Microsoft Office\\Office16\\' + $app)) } }; "
        f"$key='{ps_path.upper()}'; "
        "$bad=$installed | Where-Object { $props=Get-ItemProperty -Path $key -Name $_ -ErrorAction SilentlyContinue; "
        "$props.PSObject.Properties[$_].Value -ne 1 }; "
        "if (($installed | Measure-Object).Count -gt 0 -and -not $bad) { 'Compliant' }\""
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
            office_single_dword_all_programs = re.search(
                r'If\s+the\s+value\s+([A-Za-z0-9_.-]+)\s+is\s+REG_DWORD\s*=\s*(\d+)\s+for\s+all\s+installed\s+Office\s+programs,\s+this\s+is\s+not\s+a\s+finding\.',
                content,
                re.IGNORECASE,
            )
            if (
                office_single_dword_all_programs
                and 'office' in stig_id.lower()
                and rule.get('vuln_id') in {'V-223287'}
                and re.search(r'Disable\s+UI\s+extending\s+from\s+documents\s+and\s+templates', content + '\n' + fix_text, re.IGNORECASE)
            ):
                return {
                    'vuln_id': rule.get('vuln_id', ''),
                    'platform': 'windows',
                    'check': {
                        'type': 'registry',
                        'path': _normalize_registry_path(path_match.group(1)),
                        'value_name': office_single_dword_all_programs.group(1).strip(),
                    },
                    'expected': {'type': 'equals', 'value': int(office_single_dword_all_programs.group(2))},
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


def _firefox_nested_policy_command(parent_name: str, checks: list[tuple[str, str]]) -> str:
    checks_literal = repr(checks)
    return (
        'python3 -c "import json, pathlib; '
        "p=pathlib.Path('/usr/lib/firefox/distribution/policies.json'); "
        "policies=json.loads(p.read_text()).get('policies', {}) if p.exists() else {}; "
        f"parent=policies.get('{parent_name}') or {{}}; checks={checks_literal}; "
        "print('configured' if all(str(parent.get(k)).lower()==v for k,v in checks) else '')\""
    )


def _firefox_preferences_value_status_command(child_name: str, value: str) -> str:
    return (
        'python3 -c "import json, pathlib; '
        "p=pathlib.Path('/usr/lib/firefox/distribution/policies.json'); "
        "policies=json.loads(p.read_text()).get('policies', {}) if p.exists() else {}; "
        "prefs=policies.get('Preferences') or {}; "
        f"entry=prefs.get('{child_name}') or {{}}; "
        f"print('configured' if str(entry.get('Value')).lower()=='{value}' and str(entry.get('Status')).lower()=='locked' else '')\""
    )


def _firefox_policy_has_linux_nested_values(fix_text: str, parent_name: str, checks: list[tuple[str, str]]) -> bool:
    for key, expected in checks:
        if not re.search(
            r'Linux\s+["“]policies\.json["”]\s+file:.*?["“]'
            + re.escape(parent_name)
            + r'["”]\s*:\s*\{.*?["“]'
            + re.escape(key)
            + r'["”]\s*:\s*'
            + re.escape(expected)
            + r'\b',
            fix_text,
            re.IGNORECASE | re.DOTALL,
        ):
            return False
    return True


def _firefox_policy_boolean_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'firefox' not in stig_id.lower():
        return None
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-251564', 'V-251565', 'V-251566', 'V-251567', 'V-251568', 'V-251569', 'V-251570', 'V-251571', 'V-251572', 'V-251573', 'V-251577', 'V-251578', 'V-251580', 'V-251581', 'V-252881', 'V-252908', 'V-252909'}:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    firefox_specific = {
        'V-251569': ('Preferences', [('browser.contentblocking.category', 'strict', 'locked')]),
        'V-251570': ('Preferences', [('extensions.htmlaboutaddons.recommendations.enabled', 'false', 'locked')]),
    }
    if vuln_id in firefox_specific:
        _parent_name, checks = firefox_specific[vuln_id]
        child_name, value, status = checks[0]
        combined = f'{content}\n{fix_text}'
        if not all(token in combined for token in ('Preferences', child_name, value, status)):
            return None
        if not re.search(
            r'Linux\s+["“]policies\.json["”]\s+file:.*?["“]Preferences["”]\s*:\s*\{.*?["“]'
            + re.escape(child_name)
            + r'["”]\s*:\s*\{.*?["“]Value["”]\s*:\s*["“]?'
            + re.escape(value)
            + r'["”]?\s*,\s*["“]Status["”]\s*:\s*["“]locked["”]',
            fix_text,
            re.IGNORECASE | re.DOTALL,
        ):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': _firefox_preferences_value_status_command(child_name, value)},
            'expected': {'type': 'equals', 'value': 'configured'},
            'description': rule.get('title', ''),
        }
    firefox_multi_bool = {
        'V-251573': ('FirefoxHome', [('Search', 'false'), ('TopSites', 'false'), ('SponsoredTopSites', 'false'), ('Pocket', 'false'), ('SponsoredPocket', 'false'), ('Highlights', 'false'), ('Snippets', 'false'), ('Locked', 'true')]),
        'V-251581': ('EncryptedMediaExtensions', [('Enabled', 'false'), ('Locked', 'true')]),
        'V-252881': ('SanitizeOnShutdown', [('Cache', 'false'), ('Cookies', 'false'), ('Downloads', 'false'), ('FormData', 'false'), ('History', 'false'), ('Sessions', 'false'), ('SiteSettings', 'false'), ('OfflineApps', 'false'), ('Locked', 'true')]),
    }
    if vuln_id in firefox_multi_bool:
        parent_name, checks = firefox_multi_bool[vuln_id]
        combined = f'{content}\n{fix_text}'
        if not all(token in combined for token in (parent_name, *(key for key, _expected in checks))):
            return None
        if not _firefox_policy_has_linux_nested_values(fix_text, parent_name, checks):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': _firefox_nested_policy_command(parent_name, checks)},
            'expected': {'type': 'equals', 'value': 'configured'},
            'description': rule.get('title', ''),
        }
    if vuln_id == 'V-251565':
        if not re.search(
            r'If\s+["“]Permissions["”]\s+is\s+not\s+displayed\s+under\s+Policy\s+Name\s+or\s+the\s+Policy\s+Value\s+is\s+not\s+["“]Autoplay["”]\s+with\s+a\s+value\s+of\s+["“]Default["”]\s+and\s+["“]Block-audio-video["”],\s+this\s+is\s+a\s+finding\.',
            content,
            re.IGNORECASE,
        ):
            return None
        if not re.search(
            r'Linux\s+["“]policies\.json["”]\s+file:.*?["“]Permissions["”]\s*:\s*\{.*?["“]Autoplay["”]\s*:\s*\{.*?["“]Default["”]\s*:\s*["“]block-audio-video["”]',
            fix_text,
            re.IGNORECASE | re.DOTALL,
        ):
            return None
        command = (
            'python3 -c "import json, pathlib; '
            "p=pathlib.Path('/usr/lib/firefox/distribution/policies.json'); "
            "policies=json.loads(p.read_text()).get('policies', {}) if p.exists() else {}; "
            "permissions=policies.get('Permissions') or {}; "
            "autoplay=permissions.get('Autoplay') or {}; "
            "print(str(autoplay.get('Default')).lower())\""
        )
        return {
            'vuln_id': vuln_id,
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'block-audio-video'},
            'description': rule.get('title', ''),
        }
    nested_bool_match = re.search(
        r'If\s+["“]([A-Za-z0-9_.-]+)["”]\s+is\s+not\s+displayed\s+under\s+Policy\s+Name\s+or\s+the\s+Policy\s+Value\s+(?:is\s+not|does\s+not\s+have)\s+["“]([A-Za-z0-9_.-]+)["”]\s+(?:with\s+a\s+value\s+of|set\s+to)\s+["“]?(true|false)["”]?',
        content,
        re.IGNORECASE,
    )
    if nested_bool_match:
        policy_name = nested_bool_match.group(1)
        child_name = nested_bool_match.group(2)
        expected = nested_bool_match.group(3).lower()
        if not re.search(
            r'Linux\s+["“]policies\.json["”]\s+file:.*?["“]'
            + re.escape(policy_name)
            + r'["”]\s*:\s*\{.*?["“]'
            + re.escape(child_name)
            + r'["”]\s*:\s*'
            + expected
            + r'\b',
            fix_text,
            re.IGNORECASE | re.DOTALL,
        ):
            return None
        command = (
            'python3 -c "import json, pathlib; '
            "p=pathlib.Path('/usr/lib/firefox/distribution/policies.json'); "
            "policies=json.loads(p.read_text()).get('policies', {}) if p.exists() else {}; "
            f"parent=policies.get('{policy_name}') or {{}}; "
            f"print(str(parent.get('{child_name}')).lower())\""
        )
        return {
            'vuln_id': vuln_id,
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': expected},
            'description': rule.get('title', ''),
        }
    flat_has_value_match = re.search(
        r'If\s+["“]([A-Za-z0-9_.-]+)["”]\s+is\s+not\s+displayed\s+under\s+Policy\s+Name\s+or\s+the\s+Policy\s+Value\s+does\s+not\s+have\s+a\s+value\s+of\s+["“]?(true|false)["”]?',
        content,
        re.IGNORECASE,
    )
    if flat_has_value_match:
        policy_name = flat_has_value_match.group(1)
        expected = flat_has_value_match.group(2).lower()
        if not re.search(
            r'Linux\s+["“]policies\.json["”]\s+file:.*?["“]'
            + re.escape(policy_name)
            + r'["”]\s*:\s*'
            + expected
            + r'\b',
            fix_text,
            re.IGNORECASE | re.DOTALL,
        ):
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


def _sles_gdm_banner_file_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id != 'V-234807' or not _linux_platform(stig_id) or 'sles' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if '/etc/gdm/banner' not in content or '/etc/gdm/banner' not in fix_text:
        return None
    if not re.search(r'file\s+does\s+not\s+contain\s+the\s+following\s+text,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'more\s+/etc/gdm/banner', content, re.IGNORECASE):
        return None
    banner_match = re.search(
        r'file\s+does\s+not\s+contain\s+the\s+following\s+text,?\s+this\s+is\s+a\s+finding\.\s*[\r\n]+\s*["“](.+?)["”]\s*(?:\nFIX:|\Z)',
        content,
        re.IGNORECASE | re.DOTALL,
    )
    if not banner_match:
        return None
    banner = banner_match.group(1).strip()
    if 'You are accessing a U.S. Government (USG) Information System' not in banner:
        return None
    if len(banner) < 100:
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'file_content', 'path': '/etc/gdm/banner', 'pattern': banner},
        'expected': {'type': 'contains'},
        'description': rule.get('title', ''),
    }


def _linux_world_writable_directory_owner_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-204487', 'V-228563', 'V-230319', 'V-248636', 'V-248637', 'V-257928'}:
        return None
    if not re.search(r'world[-\s]writable\s+directories', content, re.IGNORECASE):
        return None
    if not re.search(r'Run\s+it\s+once\s+for\s+each\s+local\s+partition\s+\[PART\]', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+there\s+is\s+output,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None

    if re.search(r'find\s+(?:\[PART\]|PART)\s+-xdev\s+-type\s+d\s+-perm\s+-0002\s+-gid\s+\+999\s+-print', content, re.IGNORECASE):
        predicate = '-gid +999'
    elif re.search(r'find\s+(?:\[PART\]|PART)\s+-xdev\s+-type\s+d\s+-perm\s+-0002\s+-uid\s+\+(?:0|999)\s+-print', content, re.IGNORECASE):
        uid_match = re.search(r'-uid\s+\+(0|999)\s+-print', content, re.IGNORECASE)
        if not uid_match:
            return None
        predicate = f'-uid +{uid_match.group(1)}'
    else:
        return None

    command = f"sh -c 'findmnt -rn -t xfs,ext2,ext3,ext4,btrfs -o TARGET | while IFS= read -r p; do find \"$p\" -xdev -type d -perm -0002 {predicate} -print; done'"
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _windows_platform(stig_id: str) -> bool:
    lower = stig_id.lower()
    return 'windows' in lower or 'ms_windows' in lower


def _windows_domain_controller_pki_certificate_exists_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id) or rule.get('vuln_id') != 'V-254412':
        return None
    content = rule.get('check_content', '') or ''
    combined = f"{rule.get('title', '')}\n{content}"
    if not re.search(r'domain\s+controllers?\s+must\s+have\s+a\s+pki\s+server\s+certificate', combined, re.IGNORECASE):
        return None
    if not all(phrase in content for phrase in ('Certificates (Local Computer)', 'Personal', 'If no certificate for the domain controller exists')):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': "powershell -NoProfile -Command \"if (Get-ChildItem -Path Cert:\\LocalMachine\\My -ErrorAction SilentlyContinue | Select-Object -First 1) { 'Present' }\"",
        },
        'expected': {'type': 'equals', 'value': 'Present'},
        'description': rule.get('title', ''),
    }


def _windows_11_enterprise_64bit_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '') or ''
    if vuln_id != 'V-253254' or not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = f"{content}\n{fix_text}"
    if not re.search(r'Windows\s+11\s+Enterprise(?:\s+Edition)?\s+64-bit\s+version', combined, re.IGNORECASE):
        return None
    if content.strip() and not (
        re.search(r'If\s+["“]Edition["”]\s+is\s+not\s+["“]Windows\s+11\s+Enterprise["”],?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'If\s+["“]System\s+type["”]\s+is\s+not\s+["“]64-bit\s+operating\s+system', content, re.IGNORECASE)
    ):
        return None
    if not re.search(r'Use\s+Windows\s+11\s+Enterprise\s+64-bit\s+version\s+for\s+domain-joined\s+systems', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': "powershell -NoProfile -Command \"$os=Get-CimInstance Win32_OperatingSystem; if ($os.Caption -eq 'Microsoft Windows 11 Enterprise' -and $os.OSArchitecture -like '64-bit*') { 'Compliant' }\""},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _cisco_nxos_static_config_command_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'cisco' not in stig_id.lower() or 'nx' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    absent_commands = {
        'V-221078': {
            'command': 'show running-config | section ^callhome | include "^ enable$"',
            'content': r'call\s+home\s+service\s+is\s+enabled.*?If\s+the\s+call\s+home\s+feature\s+is\s+configured\s+to\s+call\s+home\s+to\s+the\s+vendor,\s+this\s+is\s+a\s+finding\.',
            'fix': r'no\s+enable',
        },
        'V-221083': {
            'command': 'show running-config | include "^ ip directed-broadcast$"',
            'content': r'IP\s+directed\s+broadcast\s+command\s+must\s+not\s+be\s+found\s+on\s+any\s+interface.*?If\s+IP\s+directed\s+broadcast\s+is\s+not\s+disabled\s+on\s+all\s+interfaces,\s+this\s+is\s+a\s+finding\.',
            'fix': r'no\s+ip\s+directed-broadcast',
        },
        'V-221084': {
            'command': 'show running-config | include "^ ip unreachables$"',
            'content': r'ip\s+unreachables\s+command\s+must\s+not\s+be\s+found\s+on\s+any\s+interface.*?If\s+ICMP\s+unreachable\s+notifications\s+are\s+sent\s+from\s+any\s+external\s+interfaces,\s+this\s+is\s+a\s+finding\.',
            'fix': r'no\s+ip\s+unreachables',
        },
        'V-221101': {
            'command': 'show running-config | include "^ disable-connected-check$"',
            'content': r'disable-connected-check.*?If\s+the\s+switch\s+is\s+configured\s+to\s+disable\s+checking\s+whether\s+a\s+single-hop\s+eBGP\s+peer\s+is\s+directly\s+connected,\s+this\s+is\s+a\s+finding\.',
            'fix': r'no\s+disable-connected-check',
        },
        'V-221108': {
            'command': 'show running-config | section "^router bgp" | include "^ no enforce-first-as$"',
            'content': r'command\s+no\s+enforce-first-as\s+is\s+not\s+configured.*?If\s+the\s+switch\s+is\s+not\s+configured\s+to\s+reject\s+updates\s+from\s+peers\s+that\s+do\s+not\s+list\s+their\s+AS\s+number\s+as\s+the\s+first\s+AS\s+in\s+the\s+AS_PATH\s+attribute,\s+this\s+is\s+a\s+finding\.',
            'fix': r'\benforce-first-as\b',
        },
    }
    if vuln_id in absent_commands:
        spec = absent_commands[vuln_id]
        if not re.search(spec['content'], content, re.IGNORECASE | re.DOTALL):
            return None
        if not re.search(spec['fix'], fix_text, re.IGNORECASE):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'network',
            'check': {'type': 'command_output', 'command': spec['command']},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    if vuln_id == 'V-221116':
        if not re.search(r'Review\s+the\s+switch\s+configuration\s+to\s+verify\s+that\s+TTL\s+propagation\s+is\s+disabled.*?no\s+mpls\s+ip\s+propagate-ttl.*?If\s+the\s+MPLS\s+switch\s+is\s+not\s+configured\s+to\s+disable\s+TTL\s+propagation,\s+this\s+is\s+a\s+finding\.', content, re.IGNORECASE | re.DOTALL):
            return None
        if not re.search(r'no\s+mpls\s+ip\s+propagate-ttl', fix_text, re.IGNORECASE):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'network',
            'check': {'type': 'command_output', 'command': 'show running-config | include "^no mpls ip propagate-ttl$"'},
            'expected': {'type': 'contains', 'substring': 'no mpls ip propagate-ttl'},
            'description': rule.get('title', ''),
        }
    if vuln_id == 'V-237757':
        if not re.search(r'Review\s+the\s+switch\s+configuration\s+to\s+ensure\s+FEC0::/10\s+IPv6\s+addresses\s+are\s+not\s+defined', content, re.IGNORECASE):
            return None
        if not re.search(r'If\s+IPv6\s+Site\s+Local\s+Unicast\s+addresses\s+are\s+defined,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        if not re.search(r'Configure\s+the\s+switch\s+using\s+only\s+authorized\s+IPv6\s+addresses', fix_text, re.IGNORECASE):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'network',
            'check': {'type': 'command_output', 'command': 'show running-config | include "[Ff][Ee][Cc][0-9AaBbCcDdEeFf]*:"'},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    return None


def _cisco_nxos_no_ip_source_route_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-221095', 'V-221128'} or 'cisco' not in stig_id.lower() or 'nx' not in stig_id.lower():
        return None
    combined = '\n'.join(part for part in (content, fix_text) if part)
    if not re.search(r'no\s+ip\s+source-route', combined, re.IGNORECASE):
        return None
    if not re.search(r'source\s+rout(?:e|ing)\s+is\s+disabled|drop\s+all\s+packets\s+with\s+IP\s+option\s+source\s+routing', combined, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'network',
        'check': {'type': 'command_output', 'command': 'show running-config | include ^no ip source-route$'},
        'expected': {'type': 'equals', 'value': 'no ip source-route'},
        'description': rule.get('title', ''),
    }


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


def _aide_selection_line_token_command(token: str) -> str:
    escaped_token = token.replace("'", "'\\''")
    return (
        "awk -v token='" + escaped_token + "' '\n"
        "function trim(s){gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",s); return s}\n"
        "/^[[:space:]]*(#|$)/{next}\n"
        "$1 !~ /^\\// && $0 ~ /^[[:space:]]*[A-Za-z][A-Za-z0-9_]*[[:space:]]*=/ {name=$1; sub(/[[:space:]]*=.*/,\"\",name); expr=$0; sub(/^[^=]*=/,\"\",expr); rules[name]=trim(expr); next}\n"
        "$1 ~ /^\\// {expr=$NF; gsub(/[[:space:]]*#.*/,\"\",expr); resolved=(expr in rules)?rules[expr]:expr; if (resolved !~ \"(^|[+[:space:]])\" token \"($|[+[:space:]])\") print $0}\n"
        "' /etc/aide.conf 2>/dev/null"
    )


def _linux_aide_selection_line_token_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    token_by_vuln = {
        'V-204498': 'acl',
        'V-204499': 'xattrs',
        'V-230551': 'xattrs',
        'V-234986': 'acl',
        'V-234987': 'xattrs',
        'V-248896': 'xattrs',
    }
    token = token_by_vuln.get(vuln_id)
    if not token or not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'\baide\.conf\b', content, re.IGNORECASE):
        return None
    if not re.search(r'all\s+uncommented\s+(?:file\s+and\s+directory\s+)?selection\s+lists|all\s+uncommented\s+selection\s+lines', content + '\n' + fix_text, re.IGNORECASE):
        return None
    if not re.search(rf'\b{re.escape(token)}\b', content + '\n' + fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': _aide_selection_line_token_command(token)},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _ubuntu_aide_filesystem_integrity_check_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-260583', 'V-270650'}:
        return None
    if 'ubuntu' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = f'{content}\n{fix_text}'
    if not re.search(r'aide\s+-c\s+/etc/aide/aide\.conf\s+--check', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+AIDE\s+is\s+being\s+used\s+(?:to\s+perform\s+file\s+integrity\s+checks|for\s+system\s+file\s+integrity\s+checking)\s+(?:but|and)\s+the\s+command\s+fails,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'Initialize\s+AIDE|aideinit|AIDE\s+initialized\s+database', combined, re.IGNORECASE):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': 'aide -c /etc/aide/aide.conf --check >/dev/null 2>&1 && echo configured'},
        'expected': {'type': 'equals', 'value': 'configured'},
        'description': rule.get('title', ''),
    }


def _sles_aide_cron_mail_notification_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'sles' not in stig_id.lower() or rule.get('vuln_id', '') != 'V-234864':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = content + '\n' + fix_text
    if not re.search(r'grep\s+-i\s+["“]?aide["”]?\s+/etc/cron\.\*/aide', content, re.IGNORECASE):
        return None
    if not re.search(r'/usr/bin/aide\s+--check\s*\|\s*/bin/mail', combined, re.IGNORECASE):
        return None
    if not re.search(r'cron\s+job\s+is\s+not\s+configured\s+to\s+execute\s+a\s+binary\s+to\s+send\s+an\s+email\s+\(such\s+as\s+["“]/bin/mail["”]\)', content, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {
            'type': 'command_output',
            'command': 'sh -c \'grep -I -h -i "aide" /etc/cron.*/aide 2>/dev/null | grep -E "/usr/bin/aide[[:space:]]+--check.*\\|[[:space:]]*/bin/mail" >/dev/null || printf Missing\'',
        },
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _ubuntu_aide_default_cron_script_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-238236', 'V-260585', 'V-270651'}:
        return None
    if 'ubuntu' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    title = rule.get('title', '') or ''
    if 'aide' not in content.lower() or 'this is a finding' not in content.lower():
        return None
    if vuln_id in {'V-238236', 'V-260585'}:
        expected_hash = {
            'V-238236': '32958374f18871e3f7dda27a58d721f471843e26',
            'V-260585': 'b71bb2cafaedf15ec3ac2f566f209d3260a37af0',
        }[vuln_id]
        if expected_hash not in content:
            return None
        if not re.search(r'sha1sum\s+/etc/cron\.\{daily,monthly\}/aide\s+2>/dev/null', content):
            return None
        if not re.search(r'no\s+AIDE\s+script\s+file\s+in\s+the\s+cron\s+directories', content, re.IGNORECASE):
            return None
        command = (
            f"expected='{expected_hash}'; found=0; for f in /etc/cron.daily/aide /etc/cron.monthly/aide; "
            "do [ -f \"$f\" ] || continue; found=1; actual=$(sha1sum \"$f\" | awk '{print $1}'); "
            "[ \"$actual\" = \"$expected\" ] || printf '%s %s\\n' \"$f\" \"$actual\"; done; "
            "[ \"$found\" -eq 1 ] || printf 'missing aide cron script\\n'"
        )
        return {
            'vuln_id': vuln_id,
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': title,
        }
    expected_sha256 = 'f3bbea2552f2c5b475627850d8a5fba1659df6466986d5a18948d9821ecbe491'
    if expected_sha256 not in content:
        return None
    if 'SCRIPT="/usr/share/aide/bin/dailyaidecheck"' not in content:
        return None
    if not re.search(r'sha256sum\s+/etc/aide/aide\.conf', content):
        return None
    command = (
        "conf_hash=$(sha256sum /etc/aide/aide.conf 2>/dev/null | awk '{print $1}'); "
        f"[ \"$conf_hash\" = \"{expected_sha256}\" ] || printf 'aide.conf %s\\n' \"${{conf_hash:-missing}}\"; "
        "grep -R -- 'SCRIPT=\"/usr/share/aide/bin/dailyaidecheck\"' /etc/cron.daily/dailyaidecheck /etc/cron* /etc/crontab >/dev/null 2>&1 || printf 'missing dailyaidecheck cron script\\n'"
    )
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
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


def _kubernetes_kubelet_config_value_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'kubernetes' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    known_values = {
        'V-242420': ('client-ca-file', 'clientCAFile', {'type': 'not_equals', 'value': ''}),
        'V-242424': ('tls-private-key-file', 'tlsPrivateKeyFile', {'type': 'not_equals', 'value': ''}),
        'V-242425': ('tls-cert-file', 'tlsCertFile', {'type': 'not_equals', 'value': ''}),
        'V-242434': ('protect-kernel-defaults', 'protectKernelDefaults', {'type': 'equals', 'value': 'true'}),
    }
    if vuln_id not in known_values:
        return None
    cli_flag, config_key, expected = known_values[vuln_id]
    if f'--{cli_flag}' not in content:
        return None
    if f'grep -i {config_key} <path_to_config_file>' not in content:
        return None
    if not re.search(r'Note\s+the\s+path\s+to\s+the\s+config\s+file\s+\(identified\s+by\s+--config\)', content, re.IGNORECASE):
        return None
    if not re.search(rf'Remove\s+the\s+["“]--{re.escape(cli_flag)}["”]\s+option\s+if\s+present', fix_text, re.IGNORECASE):
        return None
    if expected['type'] == 'equals':
        if not re.search(rf'Set\s+["“]{re.escape(config_key)}["”]\s+to\s+["“]{re.escape(str(expected["value"]))}["”]', fix_text, re.IGNORECASE):
            return None
        if not re.search(rf'If\s+the\s+setting\s+["“]{re.escape(config_key)}["”]\s+is\s+not\s+set\s+or\s+is\s+set\s+to\s+false,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
    else:
        if not re.search(rf'If\s+the\s+setting\s+["“]{re.escape(config_key)}["”]\s+is\s+not\s+set\s+or\s+contains\s+no\s+value,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
    command = (
        f"sh -c \"if ps -ef | grep '[k]ubelet' | grep -q -- '--{cli_flag}'; "
        f"then exit 0; fi; cfg=\\$(ps -ef | grep '[k]ubelet' | tr ' ' '\\n' | sed -n 's/^--config=//p' | head -n1); "
        f"test -n \\\"\\$cfg\\\" && sed -n 's/^[[:space:]]*{config_key}:[[:space:]]*//p' \\\"\\$cfg\\\" | head -n1\""
    )
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': expected,
        'description': rule.get('title', ''),
    }


def _kubernetes_api_server_cipher_suites_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'kubernetes' not in stig_id.lower() or rule.get('vuln_id') != 'V-242418':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    approved_suites = (
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,'
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,'
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,'
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
    )
    combined = content + '\n' + fix_text
    if not re.search(r'Kubernetes\s+API\s+Server\s+manifest\s+file\s+in\s+the\s+/etc/kubernetes/manifests\s+directory', combined, re.IGNORECASE):
        return None
    if not re.search(r'Set\s+the\s+value\s+of\s+["“]--tls-cipher-suites["”]\s+to', fix_text, re.IGNORECASE):
        return None
    if approved_suites not in combined:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {
            'type': 'command_output',
            'command': "grep -h -- '--tls-cipher-suites' /etc/kubernetes/manifests/kube-apiserver.yaml /etc/kubernetes/manifests/* 2>/dev/null | head -n1",
        },
        'expected': {'type': 'contains', 'substring': approved_suites},
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


def _ol9_crypto_policy_not_overridden_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if rule.get('vuln_id') != 'V-271479':
        return None
    if 'oracle_linux_9' not in stig_id.lower() and 'ol_9' not in stig_id.lower():
        return None
    if not re.search(r'update-crypto-policies\s+--check\s+&&\s+echo\s+PASS', content):
        return None
    if not re.search(r'If\s+the\s+last\s+line\s+is\s+not\s+["“]PASS["”],\s+this\s+is\s+a\s+finding\.', content, re.IGNORECASE):
        return None
    if '/etc/crypto-policies/back-ends/' not in content or '/usr/share/crypto-policies/FIPS' not in content:
        return None
    if not re.search(r'paths\s+do\s+not\s+point\s+to\s+the\s+respective\s+files\s+under\s+/usr/share/crypto-policies/FIPS\s+path,\s+this\s+is\s+a\s+finding\.', content, re.IGNORECASE):
        return None
    if not re.search(r'dnf\s+-y\s+reinstall\s+crypto-policies', fix_text) or not re.search(r'update-crypto-policies\s+--set\s+FIPS', fix_text):
        return None
    command = 'sh -c \'update-crypto-policies --check >/dev/null && test -z "$(find /etc/crypto-policies/back-ends -maxdepth 1 -type l ! -lname "/usr/share/crypto-policies/FIPS/*" -print -quit)" && echo PASS\''
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'PASS'},
        'description': rule.get('title', ''),
    }


def _vcenter_lookup_core_setting_candidate(rule: dict, stig_id: str) -> dict | None:
    stig_lower = stig_id.lower()
    if 'vsphere' not in stig_lower or 'lookup' not in stig_lower:
        return None
    vuln_id = rule.get('vuln_id', '')
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''

    if vuln_id == 'V-259039':
        path = '/etc/vmware/vmware-vmon/svcCfgfiles/lookupsvc.json'
        expected_line = '"StreamRedirectFile": "%VMWARE_LOG_DIR%/vmware/lookupsvc/lookupsvc_stream.log",'
        if (
            f'grep StreamRedirectFile {path}' in content
            and expected_line in content
            and expected_line in fix_text
            and re.search(r'If\s+no\s+log\s+file\s+is\s+specified\s+for\s+the\s+["“]StreamRedirectFile["”]\s+setting,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        ):
            return {
                'vuln_id': vuln_id,
                'platform': 'generic',
                'check': {'type': 'file_content', 'path': path, 'pattern': expected_line, 'is_regex': False},
                'expected': {'type': 'contains'},
                'description': title,
            }

    if vuln_id == 'V-259040':
        path = '/usr/lib/vmware-lookupsvc/conf/server.xml'
        valve = 'org.apache.catalina.valves.AccessLogValve'
        required_elements = ('%h', '%{X-Forwarded-For}i', '%l', '%t', '%u', '%r', '%s', '%b')
        if (
            path in content
            and valve in content
            and all(element in content or element.replace('%r', '&quot;%r&quot;') in content for element in required_elements)
            and re.search(r'If\s+the\s+log\s+pattern\s+does\s+not\s+contain\s+the\s+required\s+elements\s+in\s+any\s+order,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
            and path in fix_text
            and 'AccessLogValve' in fix_text
            and 'pattern=' in fix_text
        ):
            command = "sh -c \"pattern=$(xmllint --xpath 'string(/Server/Service/Engine/Host/Valve[@className=\\\"org.apache.catalina.valves.AccessLogValve\\\"]/@pattern)' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null); for token in '%h' '%{X-Forwarded-For}i' '%l' '%t' '%u' '%r' '%s' '%b'; do case \\\"$pattern\\\" in *\\\"$token\\\"*) ;; *) exit 0;; esac; done; printf PASS\""
            return {
                'vuln_id': vuln_id,
                'platform': 'generic',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'equals', 'value': 'PASS'},
                'description': title,
            }

    if vuln_id == 'V-259050':
        path = '/etc/vmware-syslog/vmware-services-lookupsvc.conf'
        required_tokens = (
            'File="/var/log/vmware/lookupsvc/tomcat/catalina.*.log"',
            'Tag="lookupsvc-tc-catalina"',
            'File="/var/log/vmware/lookupsvc/tomcat/localhost.*.log"',
            'Tag="lookupsvc-tc-localhost"',
            'File="/var/log/vmware/lookupsvc/lookupsvc_stream.log.std*"',
            'Tag="lookupsvc-std"',
        )
        if (
            path in content
            and all(token in content for token in required_tokens)
            and re.search(r'If\s+the\s+output\s+does\s+not\s+match\s+the\s+expected\s+result,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
            and path in fix_text
            and all(token in fix_text for token in required_tokens)
        ):
            command = "sh -c \"f=/etc/vmware-syslog/vmware-services-lookupsvc.conf; for token in 'File=\\\"/var/log/vmware/lookupsvc/tomcat/catalina.*.log\\\"' 'Tag=\\\"lookupsvc-tc-catalina\\\"' 'File=\\\"/var/log/vmware/lookupsvc/tomcat/localhost.*.log\\\"' 'Tag=\\\"lookupsvc-tc-localhost\\\"' 'File=\\\"/var/log/vmware/lookupsvc/tomcat/localhost_access.log\\\"' 'Tag=\\\"lookupsvc-localhost_access\\\"' 'File=\\\"/var/log/vmware/lookupsvc/lookupsvc-init.log\\\"' 'Tag=\\\"lookupsvc-init\\\"' 'File=\\\"/var/log/vmware/lookupsvc/lookupsvc-prestart.log\\\"' 'Tag=\\\"lookupsvc-prestart\\\"' 'File=\\\"/var/log/vmware/lookupsvc/lookupsvc-health.log\\\"' 'Tag=\\\"lookupsvc-health\\\"' 'File=\\\"/var/log/vmware/lookupsvc/lookupserver-default.log\\\"' 'Tag=\\\"lookupsvc-lookupserver-default\\\"' 'File=\\\"/var/log/vmware/lookupsvc/lookupsvc_stream.log.std*\\\"' 'Tag=\\\"lookupsvc-std\\\"' 'File=\\\"/var/log/vmware/lookupsvc/vmware-lookupsvc-gc.log.*.current\\\"' 'Tag=\\\"lookupsvc-gc\\\"'; do grep -Fqx \\\"      $token\\\" $f || exit 0; done; printf PASS\""
            return {
                'vuln_id': vuln_id,
                'platform': 'generic',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'equals', 'value': 'PASS'},
                'description': title,
            }

    if vuln_id == 'V-259049':
        path = '/usr/lib/vmware-lookupsvc/conf/web.xml'
        if (
            path in content
            and 'session-timeout' in content
            and 'session-timeout' in fix_text
            and re.search(r'not\s+["“]30["”]\s+or\s+less,\s+or\s+is\s+missing,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
            and re.search(r'<session-timeout>\s*30\s*</session-timeout>', fix_text, re.IGNORECASE)
        ):
            command = "sh -c \"timeout=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=\\\".*\\\"//g' | xmllint --xpath 'string(/web-app/session-config/session-timeout)' - 2>/dev/null); case $timeout in ''|*[!0-9]*) exit 0;; *) [ $timeout -le 30 ] && printf PASS;; esac\""
            return {
                'vuln_id': vuln_id,
                'platform': 'generic',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'equals', 'value': 'PASS'},
                'description': title,
            }

    if vuln_id == 'V-259057':
        server_path = '/usr/lib/vmware-lookupsvc/conf/server.xml'
        catalina_path = '/usr/lib/vmware-lookupsvc/conf/catalina.properties'
        if (
            server_path in content
            and catalina_path in content
            and 'port="${base.shutdown.port}"' in content
            and 'base.shutdown.port=-1' in content
            and 'port="${base.shutdown.port}"' in fix_text
            and 'base.shutdown.port=-1' in fix_text
            and re.search(r'If\s+["“]port["”]\s+does\s+not\s+equal\s+["“]\$\{base\.shutdown\.port\}["”],\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
            and re.search(r'If\s+["“]base\.shutdown\.port["”]\s+does\s+not\s+equal\s+["“]-1["”],\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        ):
            command = "sh -c \"server_port=$(xmllint --xpath 'string(/Server/@port)' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null); shutdown_port=$(grep '^base.shutdown.port=' /usr/lib/vmware-lookupsvc/conf/catalina.properties 2>/dev/null | tail -n 1 | cut -d= -f2-); [ \\\"$server_port\\\" = '${base.shutdown.port}' ] && [ \\\"$shutdown_port\\\" = '-1' ] && printf PASS\""
            return {
                'vuln_id': vuln_id,
                'platform': 'generic',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'equals', 'value': 'PASS'},
                'description': title,
            }

    if vuln_id == 'V-259047':
        path = '/usr/lib/vmware-lookupsvc/conf/server.xml'
        if (
            path in content
            and 'URIEncoding' in content
            and 'URIEncoding="UTF-8"' in fix_text
            and re.search(r'If\s+any\s+connectors\s+are\s+returned,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        ):
            command = "xmllint --xpath \"count(//Connector[@URIEncoding != 'UTF-8' or not(@URIEncoding)])\" /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null"
            return {
                'vuln_id': vuln_id,
                'platform': 'generic',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'equals', 'value': '0'},
                'description': title,
            }

    if vuln_id == 'V-259056':
        path = '/usr/lib/vmware-lookupsvc/conf/web.xml'
        if (
            path in content
            and 'DefaultServlet' in content
            and re.search(r'["“]?readOnly["”]?\s+param-value.*?set\s+to\s+["“]?false["”]?,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE | re.DOTALL)
            and re.search(r'["“]?readOnly["”]?\s+param-value\s+does\s+not\s+exist,\s+this\s+is\s+not\s+a\s+finding', content, re.IGNORECASE)
            and re.search(r'<param-value>\s*false\s*</param-value>', fix_text, re.IGNORECASE)
        ):
            command = "xmllint --xpath \"count(//servlet[servlet-class='org.apache.catalina.servlets.DefaultServlet']//init-param[translate(param-name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='readonly' and translate(param-value, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='false'])\" /usr/lib/vmware-lookupsvc/conf/web.xml 2>/dev/null"
            return {
                'vuln_id': vuln_id,
                'platform': 'generic',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'equals', 'value': '0'},
                'description': title,
            }

    if vuln_id == 'V-259054':
        path = '/usr/lib/vmware-lookupsvc/conf/web.xml'
        required_tokens = (
            'setCharacterEncodingFilter',
            'org.apache.catalina.filters.SetCharacterEncodingFilter',
            '<async-supported>true</async-supported>',
            '<param-name>encoding</param-name>',
            '<param-value>UTF-8</param-value>',
            '<param-name>ignore</param-name>',
            '<param-value>true</param-value>',
            '<url-pattern>/*</url-pattern>',
        )
        if (
            path in content
            and all(token in content for token in required_tokens)
            and 'setCharacterEncodingFilter' in fix_text
            and re.search(r'If\s+the\s+output\s+(?:is\s+)?does\s+not\s+match\s+the\s+expected\s+result,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        ):
            command = "sh -c \"f=/usr/lib/vmware-lookupsvc/conf/web.xml; xmllint --xpath \\\"count(//filter-mapping[filter-name='setCharacterEncodingFilter' and url-pattern='/*'])\\\" $f 2>/dev/null | grep -qx 1 || exit 1; xmllint --xpath \\\"count(//filter[filter-name='setCharacterEncodingFilter' and filter-class='org.apache.catalina.filters.SetCharacterEncodingFilter' and async-supported='true' and init-param[param-name='encoding' and param-value='UTF-8'] and init-param[param-name='ignore' and param-value='true']])\\\" $f 2>/dev/null | grep -qx 1 && printf PASS\""
            return {
                'vuln_id': vuln_id,
                'platform': 'generic',
                'check': {'type': 'command_output', 'command': command},
                'expected': {'type': 'equals', 'value': 'PASS'},
                'description': title,
            }

    return None


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


def _vcenter_lookup_removed_webapp_directory_candidate(rule: dict, stig_id: str) -> dict | None:
    stig_lower = stig_id.lower()
    if 'vsphere' not in stig_lower or 'lookup' not in stig_lower:
        return None
    mappings = {
        'V-259063': '/var/opt/apache-tomcat/webapps/examples',
        'V-259064': '/var/opt/apache-tomcat/webapps/ROOT',
        'V-259065': '/var/opt/apache-tomcat/webapps/docs',
        'V-259069': '/var/opt/apache-tomcat/webapps/manager',
        'V-259070': '/var/opt/apache-tomcat/webapps/host-manager',
    }
    path = mappings.get(rule.get('vuln_id', ''))
    if not path:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    basename = path.rsplit('/', 1)[-1]
    if not re.search(rf'^\s*#\s*ls\s+-l\s+{re.escape(path)}\s*$', content, re.MULTILINE):
        return None
    if not re.search(rf'If\s+the\s+["“]?{re.escape(basename)}["”]?\s+(?:folder|web\s+application)\s+(?:exists\s+or\s+contains\s+any\s+content|contains\s+any\s+content),\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(rf'^\s*#\s*rm\s+-rf\s+{re.escape(path)}(?:/\*)?\s*$', fix_text, re.MULTILINE):
        return None
    command = f"sh -c '[ ! -e {path} ] || [ -z \"$(ls -A {path} 2>/dev/null)\" ] && printf Compliant'"
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _vcenter_lookup_security_listener_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'vsphere' not in stig_id.lower() or 'lookup' not in stig_id.lower():
        return None
    if rule.get('vuln_id') != 'V-259042':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    listener = 'org.apache.catalina.security.SecurityListener'
    path = '/usr/lib/vmware-lookupsvc/conf/server.xml'
    if path not in content or listener not in content or 'xmllint' not in content:
        return None
    if not re.search(rf'If\s+the\s+["“]{re.escape(listener)}["”]\s+listener\s+is\s+not\s+present,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'configured\s+with\s+a\s+["“]minimumUmask["”]\s+and\s+is\s+not\s+["“]0007["”],\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if path not in fix_text or listener not in fix_text:
        return None
    command = "sh -c \"xmllint --xpath '/Server/Listener[@className=\\\"org.apache.catalina.security.SecurityListener\\\"]' /usr/lib/vmware-lookupsvc/conf/server.xml >/dev/null 2>&1 || exit 0; umask=$(xmllint --xpath 'string(/Server/Listener[@className=\\\"org.apache.catalina.security.SecurityListener\\\"]/@minimumUmask)' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null); { [ -z \\\"$umask\\\" ] || [ \\\"$umask\\\" = 0007 ]; } && printf PASS\""
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'PASS'},
        'description': rule.get('title', ''),
    }


def _ol8_mitigations_not_off_candidate(rule: dict, stig_id: str) -> dict | None:
    if rule.get('vuln_id') != 'V-248593' or 'oracle_linux_8' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if 'grubby --info=/boot/vmlinuz-$(uname -r) | grep mitigations' not in content:
        return None
    if not re.search(r'If\s+the\s+["“]mitigations["”]\s+parameter\s+is\s+set\s+to\s+["“]off["”]\s+\(mitigations=off\),\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if 'remove-args=mitigations=off' not in fix_text:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': "sh -c \"grubby --info=/boot/vmlinuz-$(uname -r) 2>/dev/null | grep -o 'mitigations=off' || true\""},
        'expected': {'type': 'equals', 'value': ''},
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
            rf'Kerberos\s+Policy\s*>>\s*"?{re.escape(kerberos_nonzero_upper_bound.group(1).strip())}"?\s+to\s+a\s+maximum\s+of\s+"{re.escape(kerberos_nonzero_upper_bound.group(2))}"[^.\n]*\b(?:but\s+not|not)\s+"0"',
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
        domain_member_deny_service_match = re.search(
            r'If\s+the\s+following\s+accounts\s+or\s+groups\s+are\s+not\s+defined\s+for\s+the\s+"Deny\s+log\s+on\s+as\s+a\s+service"\s+user\s+right\s+on\s+domain-joined\s+systems,\s+this\s+is\s+a\s+finding:\s*(?P<body>.*?)(?:\n\s*\n|\Z)',
            content,
            re.IGNORECASE | re.DOTALL,
        )
        domain_member_deny_service_fix = re.search(
            r'User\s+Rights\s+Assignment\s*>>\s*"?Deny\s+log\s+on\s+as\s+a\s+service"?\s+to\s+include\s+the\s+following:\s*\n\s*Domain\s+systems:\s*(?P<body>.*?)(?:\n\s*\n|\Z)',
            fix_text,
            re.IGNORECASE | re.DOTALL,
        )
        if domain_member_deny_service_match and domain_member_deny_service_fix:
            check_body = domain_member_deny_service_match.group('body')
            fix_body = domain_member_deny_service_fix.group('body')
            required_groups = ('Enterprise Admins Group', 'Domain Admins Group')
            has_required_check_groups = all(group in check_body for group in required_groups)
            has_required_fix_groups = all(group in fix_body for group in required_groups)
            has_nondomain_blank_check = re.search(
                r'If\s+any\s+accounts\s+or\s+groups\s+are\s+defined\s+for\s+the\s+"Deny\s+log\s+on\s+as\s+a\s+service"\s+user\s+right\s+on\s+nondomain-joined\s+systems,\s+this\s+is\s+a\s+finding',
                content,
                re.IGNORECASE,
            )
            has_required_sid_suffixes = re.search(r'S-1-5-root\s+domain-519\s+\(Enterprise\s+Admins\)', content, re.IGNORECASE) and re.search(r'S-1-5-domain-512\s+\(Domain\s+Admins\)', content, re.IGNORECASE)
            if has_required_check_groups and has_required_fix_groups and has_nondomain_blank_check and has_required_sid_suffixes:
                command = "powershell -NoProfile -Command \"$cfg=Join-Path $env:TEMP ('automatestig-'+[guid]::NewGuid()+'.inf'); secedit /export /areas USER_RIGHTS /cfg $cfg | Out-Null; $line=(Get-Content $cfg -ErrorAction SilentlyContinue | Where-Object { $_ -like 'SeDenyServiceLogonRight*' } | Select-Object -First 1); Remove-Item $cfg -ErrorAction SilentlyContinue; $values=@(); if ($line -match '=(.*)$') { $values=@($Matches[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }; $domain=(Get-CimInstance Win32_ComputerSystem).PartOfDomain; if ($domain) { $suffixes=@($values | ForEach-Object { if ($_ -match 'S-1-5-.+-(512|519)$') { $Matches[1] } }); if (($values.Count -eq 2) -and (($suffixes | Sort-Object -Unique).Count -eq 2)) { 'Compliant' } } else { if ($values.Count -eq 0) { 'Compliant' } }\""
                return {
                    'vuln_id': rule.get('vuln_id', ''),
                    'platform': 'windows',
                    'check': {'type': 'command_output', 'command': command},
                    'expected': {'type': 'equals', 'value': 'Compliant'},
                    'description': rule.get('title', ''),
                }

        blank_user_right_match = re.search(
            r'Configure\s+the\s+policy\s+value\s+for\s+Computer\s+Configuration\s*>>\s*Windows\s+Settings\s*>>\s*Security\s+Settings\s*>>\s*Local\s+Policies\s*>>\s*User\s+Rights\s+Assignment\s*>>\s*"?([^"\n]+?)"?\s+to\s+(?:(?:be\s+defined\s+but\s+containing|include)\s+no\s+entries|include\s+no\s+accounts\s+or\s+groups)\s+\(blank\)\s*\.\s*(?:\n|$)',
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
            r'If\s+any\s+(?:groups\s+or\s+accounts|accounts\s+or\s+groups)\s+other\s+than\s+the\s+following\s+are\s+granted\s+the\s+"([^"]+)"\s+(?:user\s+)?right,\s+this\s+is\s+a\s+finding[:.]\s*(?P<body>.*?)(?:\n\s*\n|\s+For\s+server\s+core\b|\Z)',
            content,
            re.IGNORECASE | re.DOTALL,
        )
        exact_allowlist_fix = re.search(
            r'User\s+Rights\s+Assignment\s*>>\s*"?([^"\n]+?)"?\s+to\s+(?:only\s+include|include\s+only)\s+the\s+following\s+(?:groups\s+or\s+accounts|accounts\s+or\s+groups):\s*(?P<body>.*?)(?:\n\s*\n|\s+For\s+server\s+core\b|\Z)',
            fix_text,
            re.IGNORECASE | re.DOTALL,
        )
        exact_allowlist_right_keys = {
            'access this computer from the network': 'SeNetworkLogonRight',
            'add workstations to domain': 'SeMachineAccountPrivilege',
            'allow log on locally': 'SeInteractiveLogonRight',
            'allow log on through remote desktop services': 'SeRemoteInteractiveLogonRight',
            'back up files and directories': 'SeBackupPrivilege',
            'change the system time': 'SeSystemtimePrivilege',
            'create a pagefile': 'SeCreatePagefilePrivilege',
            'create global objects': 'SeCreateGlobalPrivilege',
            'create symbolic links': 'SeCreateSymbolicLinkPrivilege',
            'debug programs': 'SeDebugPrivilege',
            'deny access to this computer from the network': 'SeDenyNetworkLogonRight',
            'deny log on as a batch job': 'SeDenyBatchLogonRight',
            'deny log on locally': 'SeDenyInteractiveLogonRight',
            'deny log on through remote desktop services': 'SeDenyRemoteInteractiveLogonRight',
            'enable computer and user accounts to be trusted for delegation': 'SeEnableDelegationPrivilege',
            'force shutdown from a remote system': 'SeRemoteShutdownPrivilege',
            'generate security audits': 'SeAuditPrivilege',
            'impersonate a client after authentication': 'SeImpersonatePrivilege',
            'increase scheduling priority': 'SeIncreaseBasePriorityPrivilege',
            'load and unload device drivers': 'SeLoadDriverPrivilege',
            'manage auditing and security log': 'SeSecurityPrivilege',
            'modify firmware environment values': 'SeSystemEnvironmentPrivilege',
            'perform volume maintenance tasks': 'SeManageVolumePrivilege',
            'profile single process': 'SeProfileSingleProcessPrivilege',
            'restore files and directories': 'SeRestorePrivilege',
            'take ownership of files or other objects': 'SeTakeOwnershipPrivilege',
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
            'users': '*S-1-5-32-545',
            'service': '*S-1-5-6',
            'local account': '*S-1-5-113',
            'local account and member of administrators group': '*S-1-5-114',
        }
        def _allowlist_principals(body: str) -> list[str]:
            bullet_principals = re.findall(
                r'(?:^|\s)[-*]\s*([A-Za-z][A-Za-z \\]+?)(?=\s+[-*]\s+|\s{2,}(?:For|If|Review|Run|Secedit)\b|\n|$)',
                body,
                re.IGNORECASE,
            )
            raw_lines = [line.rstrip() for line in body.splitlines() if line.strip()]
            bullet_lines = [line for line in raw_lines if re.match(r'^\s*[-*]\s+', line)]
            candidate_lines = bullet_principals or bullet_lines or raw_lines
            principals = []
            for line in candidate_lines:
                principal = line.strip(' -*\t.').lower()
                principal = re.sub(r'\s+group$', '', principal, flags=re.IGNORECASE)
                if principal not in exact_allowlist_principal_sids:
                    break
                principals.append(principal)
            return principals

        if exact_allowlist_match and exact_allowlist_fix and not re.search(r'\b(application|documented|ISSO|organization-defined|site-defined|except|exception)\b', policy_text, re.IGNORECASE):
            check_display_name = exact_allowlist_match.group(1).strip().strip('"')
            fix_display_name = exact_allowlist_fix.group(1).strip().strip('"')

            check_principals = _allowlist_principals(exact_allowlist_match.group('body'))
            fix_principals = _allowlist_principals(exact_allowlist_fix.group('body'))
            if check_display_name.lower() == fix_display_name.lower() and check_principals == fix_principals:
                key = exact_allowlist_right_keys.get(check_display_name.lower())
                if key and check_principals:
                    expected_value = ','.join(exact_allowlist_principal_sids[principal] for principal in check_principals)
                    return {
                        'vuln_id': rule.get('vuln_id', ''),
                        'platform': 'windows',
                        'check': {'type': 'security_policy', 'section': 'Privilege Rights', 'key': key},
                        'expected': {'type': 'equals', 'value': expected_value},
                        'description': rule.get('title', ''),
                    }

        fix_only_allowlist = re.search(
            r'Configure\s+the\s+policy\s+value\s+for\s+Computer\s+Configuration\s*>>\s*Windows\s+Settings\s*>>\s*Security\s+Settings\s*>>\s*Local\s+Policies\s*>>\s*User\s+Rights\s+Assignment\s*>>\s*"?([^"\n]+?)"?\s+to\s+(?:only\s+include|include\s+only)\s+the\s+following\s+(?:groups\s+or\s+accounts|accounts\s+or\s+groups):\s*(?P<body>.*?)(?:\n\s*\n|\Z)',
            fix_text,
            re.IGNORECASE | re.DOTALL,
        )
        if (
            fix_only_allowlist
            and not content.strip()
            and not re.search(r'\b(application|documented|ISSO|organization-defined|site-defined|except|exception|Domain\s+Systems\s+Only|All\s+Systems|Note:)\b', fix_text, re.IGNORECASE)
        ):
            display_name = fix_only_allowlist.group(1).strip().strip('"')
            key = exact_allowlist_right_keys.get(display_name.lower())
            principals = _allowlist_principals(fix_only_allowlist.group('body'))
            if key and principals:
                expected_value = ','.join(exact_allowlist_principal_sids[principal] for principal in principals)
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


def _linux_sudoers_default_include_directory_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    if rule.get('vuln_id', '') not in {'V-251711', 'V-251703', 'V-252655'}:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'grep\s+include\s+/etc/sudoers', content, re.IGNORECASE):
        return None
    if not re.search(r'grep\s+-E?r\s+include\s+/etc/sudoers\.d', content, re.IGNORECASE):
        return None
    if '#includedir /etc/sudoers.d' not in content or '#includedir /etc/sudoers.d' not in fix_text:
        return None
    if not re.search(r'If\s+the\s+results\s+are\s+not\s+["“]/etc/sudoers\.d["”]\s+or\s+additional\s+files\s+or\s+directories\s+are\s+specified,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+results\s+are\s+returned,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    command = r'''awk '/^[[:space:]]*#?(include|includedir)[[:space:]]+/ { if ($0 !~ /^[[:space:]]*#includedir[[:space:]]+[/]etc[/]sudoers[.]d[[:space:]]*$/) print FILENAME ":" $0 }' /etc/sudoers 2>/dev/null; grep -R -n -E '^[[:space:]]*#?(include|includedir)[[:space:]]+' /etc/sudoers.d 2>/dev/null'''
    return {
        'vuln_id': rule.get('vuln_id', ''),
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

    minimum_match = re.search(r"(?:sudo\s+)?awk\s+-F:\s+'\$4\s*<\s*(\d+)\s*\{\s*(?:print\s+\$1\s+(?:\"\s+\"|\":\")\s+\$4|printf\s+\"%s\s+%d\\n\",\s*\$1,\s*\$4)\s*\}'\s+/etc/shadow", content, re.IGNORECASE)
    if minimum_match and re.search(r'\b(?:chage\s+-m|passwd\s+-n)\s+' + re.escape(minimum_match.group(1)) + r'\b', fix_text, re.IGNORECASE):
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

    shadow_print_separator = r'(?:\"\s+\"|\":\"|\"\"\s+\"\")'
    maximum_over_match = re.search(r"(?:sudo\s+)?awk\s+-F:\s+'\$5\s*>\s*(\d+)(?:\s*\|\|\s*\$5\s*==\s*\"\")?\s*\{\s*(?:print\s+\$1\s+" + shadow_print_separator + r"\s+\$5|printf\s+\"%s\s+%d\\n\",\s*\$1,\s*\$5)\s*\}'\s+/etc/shadow", content, re.IGNORECASE)
    maximum_nonpositive_match = re.search(r"(?:sudo\s+)?awk\s+-F:\s+'\$5\s*<=\s*0\s*\{\s*(?:print\s+\$1\s+" + shadow_print_separator + r"\s+\$5|printf\s+\"%s\s+%d\\n\",\s*\$1,\s*\$5)\s*\}'\s+/etc/shadow", content, re.IGNORECASE)
    maximum_blank_in_over_match = bool(maximum_over_match and re.search(r"\$5\s*==\s*\"\"", maximum_over_match.group(0)))
    if maximum_over_match and (maximum_nonpositive_match or maximum_blank_in_over_match) and re.search(r'\b(?:chage\s+-M|passwd\s+-x)\s+' + re.escape(maximum_over_match.group(1)) + r'\b', fix_text, re.IGNORECASE):
        threshold = int(maximum_over_match.group(1))
        if threshold != 60 or not re.search(r'maximum\s+password\s+lifetime|maximum\s+time\s+period\s+for\s+existing\s+passwords|maximum\s+user\s+password\s+age|maximum\s+lifetime|60-day', combined, re.IGNORECASE):
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


def _sles_bios_grub_password_pbkdf2_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'sles' not in stig_id.lower() and 'suse' not in stig_id.lower():
        return None
    if rule.get('vuln_id', '') != 'V-234819':
        return None
    content = rule.get('check_content', '') or ''
    combined = content + '\n' + (rule.get('fix_text', '') or '')
    if '/boot/grub2/grub.cfg' not in combined:
        return None
    if 'password_pbkdf2 root grub.pbkdf2' not in combined:
        return None
    if not re.search(r'root\s+password\s+entry\s+does\s+not\s+begin\s+with\s+["“]password_pbkdf2["”],?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    command = "awk '/^password_pbkdf2[[:space:]]+root[[:space:]]+grub\\.pbkdf2/{print \"Compliant\"; exit}' /boot/grub2/grub.cfg 2>/dev/null"
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _linux_sudoers_no_nopasswd_or_no_authenticate_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    combined = content + '\n' + (rule.get('fix_text', '') or '')
    if rule.get('vuln_id', '') != 'V-234853':
        return None
    if not re.search(r'/etc/sudoers', combined, re.IGNORECASE):
        return None
    if not re.search(r'NOPASSWD', combined, re.IGNORECASE) or not re.search(r'!authenticate', combined, re.IGNORECASE):
        return None
    if not re.search(r'uncommented\s+lines\s+containing\s+["“]!authenticate["”],?\s+or\s+["“]NOPASSWD["”]\s+are\s+returned[^.]*this\s+is\s+a\s+finding', content, re.IGNORECASE | re.DOTALL):
        return None
    command = "sh -c \"grep -Ehi '^[[:space:]]*[^#].*(NOPASSWD|!authenticate)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null\""
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _sles_ctrl_alt_del_burst_action_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'sles' not in stig_id.lower() and 'suse' not in stig_id.lower():
        return None
    if rule.get('vuln_id', '') != 'V-234990':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'\bsystemd-analyze\s+cat-config\s+systemd/system\.conf\b', content, re.IGNORECASE):
        return None
    if not re.search(r'CtrlAltDelBurstAction=none', content) or not re.search(r'CtrlAltDelBurstAction=none', fix_text):
        return None
    if not re.search(r'setting\s+is\s+not\s+configured\s+in\s+a\s+drop\s+in\s+file,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    command = r'''systemd-analyze cat-config systemd/system.conf 2>/dev/null | awk '/^# \/etc\/systemd\/system\.conf\.d\//{drop=1; next} drop && /^CtrlAltDelBurstAction=none$/{print "Compliant"; exit}' '''.strip()
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _linux_sssd_certmap_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    combined = content + '\n' + (rule.get('fix_text', '') or '')
    if 'sssd.conf' not in combined or '[certmap/' not in combined:
        return None
    if 'maprule = (userCertificate;binary={cert!bin})' not in combined:
        return None
    if not re.search(r'(?:the\s+)?["“]?certmap["”]?\s+section\s+does\s+not\s+exist[^.]*this\s+is\s+a\s+finding|no\s+evidence\s+of\s+certificate\s+mapping[^.]*this\s+is\s+a\s+finding', content, re.IGNORECASE | re.DOTALL):
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


def _linux_removable_media_mount_option_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    supported_vulns = {
        'V-204481',
        'V-230303', 'V-230304', 'V-230305',
        'V-234999',
        'V-248621', 'V-248622', 'V-248623',
        'V-257857', 'V-257858', 'V-257859',
        'V-271644', 'V-271645', 'V-271646',
    }
    if rule.get('vuln_id', '') not in supported_vulns:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    option_match = re.search(
        r'file\s+systems?(?:\s+that\s+are)?\s+used\s+for\s+removable\s+media\s+are\s+mounted\s+with\s+the\s+["“](nodev|noexec|nosuid)["”]\s+option',
        content,
        re.IGNORECASE,
    )
    if not option_match:
        return None
    required_option = option_match.group(1).lower()
    if not re.search(r'\b(?:sudo\s+)?more\s+/etc/fstab\b', content, re.IGNORECASE):
        return None
    if not re.search(
        r'file\s+system\s+found\s+in\s+["“]/etc/fstab["”]\s+refers\s+to\s+removable\s+media\s+and\s+it\s+does\s+not\s+have\s+the\s+["“]'
        + re.escape(required_option)
        + r'["”]\s+option\s+set,\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    ):
        return None
    if not re.search(
        r'/etc/fstab.*use\s+the\s+["“]'
        + re.escape(required_option)
        + r'["”]\s+option\s+on\s+file\s+systems\s+that\s+are\s+associated\s+with\s+removable\s+media',
        fix_text,
        re.IGNORECASE | re.DOTALL,
    ):
        return None
    command = (
        "awk '!/^[[:space:]]*#/ && NF >= 4 && "
        "($3 ~ /^(vfat|exfat|iso9660|udf|ntfs|msdos)$/ || $2 ~ \"^/(media|mnt)/\") "
        "{ ok=0; n=split($4, opts, \",\"); for (i=1; i<=n; i++) if (opts[i] == \""
        + required_option
        + "\") ok=1; if (!ok) print }' /etc/fstab"
    )
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': title,
    }



def _linux_nfs_imported_mount_option_candidate(rule: dict, stig_id: str) -> dict | None:
    if rule.get('vuln_id', '') != 'V-204482' or not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    if not re.search(r'file\s+systems\s+that\s+are\s+being\s+NFS\s+imported\s+are\s+configured\s+with\s+the\s+["“]nosuid["”]\s+option', content, re.IGNORECASE):
        return None
    if not re.search(r'file\s+system\s+found\s+in\s+["“]/etc/fstab["”]\s+refers\s+to\s+NFS\s+and\s+it\s+does\s+not\s+have\s+the\s+["“]nosuid["”]\s+option\s+set,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'/etc/fstab.*use\s+the\s+["“]nosuid["”]\s+option\s+on\s+file\s+systems\s+that\s+are\s+being\s+imported\s+via\s+NFS', fix_text, re.IGNORECASE):
        return None
    command = "awk '$3 ~ /^(nfs|nfs4)$/ { ok=0; n=split($4, opts, \",\"); for (i=1; i<=n; i++) if (opts[i] == \"nosuid\") ok=1; if (!ok) print }' /etc/fstab"
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': title,
    }


def _linux_fixed_mount_option_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    title = rule.get('title', '') or ''
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = '\n'.join(part for part in (title, content, fix_text) if part)
    match = re.search(r'\bmust\s+mount\s+(?P<path>/[A-Za-z0-9_./-]+)\s+with\s+the\s+["“]?(?P<option>nodev|nosuid|noexec)["”]?\s+option\b', title, re.IGNORECASE)
    if not match:
        return None
    mount_path = match.group('path')
    required_option = match.group('option').lower()
    if re.search(r'(?:removable\s+media|NFS|Network\s+File\s+System|user\s+home\s+directories)', combined, re.IGNORECASE):
        return None
    if not re.search(r'/etc/fstab', combined, re.IGNORECASE):
        return None
    if not re.search(re.escape(mount_path), fix_text + '\n' + content):
        return None
    if not re.search(r'\b' + re.escape(required_option) + r'\b', fix_text + '\n' + content, re.IGNORECASE):
        return None
    command = f"findmnt -nkT '{mount_path}' | awk 'NR==1{{print $4}}' | grep -Eq '(^|,){required_option}(,|$)' && printf 'Compliant'"
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': title,
    }


def _linux_interactive_home_mount_option_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    option_match = re.search(
        r'file\s+systems\s+(?:that\s+contain|containing)\s+user\s+home\s+directories\s+are\s+mounted\s+with\s+the\s+["“](noexec|nosuid)["”]\s+option',
        content,
        re.IGNORECASE,
    )
    if not option_match:
        return None
    required_option = option_match.group(1).lower()
    if not re.search(r'awk\s+-F:\s+.*?\$3\s*>=\s*1000.*?/etc/passwd', content, re.IGNORECASE | re.DOTALL):
        return None
    root_exception = re.search(r'user\s+home\s+directories\s+are\s+mounted\s+under\s+["“]/["”].*?automatically\s+a\s+finding.*?' + re.escape(required_option) + r'.*?cannot\s+be\s+used\s+on\s+the\s+["“]/["”]', content, re.IGNORECASE | re.DOTALL)
    fstab_finding = re.search(r'file\s+system\s+found\s+in\s+["“]/etc/fstab["”]\s+refers\s+to\s+the\s+user\s+home\s+director(?:y|ies).*?does\s+not\s+have\s+the\s+["“]' + re.escape(required_option) + r'["”]\s+option\s+set,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE | re.DOTALL)
    ol8_home_fstab_finding = (
        rule.get('vuln_id', '') in {'V-248616', 'V-248620'}
        and stig_id == 'Oracle_Linux_8_STIG'
        and re.search(r'Check\s+the\s+file\s+systems\s+that\s+are\s+mounted\s+at\s+boot\s+time.*?/etc/fstab', content, re.IGNORECASE | re.DOTALL)
        and fstab_finding
    )
    if not (root_exception and fstab_finding) and not ol8_home_fstab_finding:
        return None
    if not re.search(r'/etc/fstab', fix_text, re.IGNORECASE) or not re.search(r'file\s+systems\s+that\s+contain\s+user\s+home\s+directories', title + '\n' + fix_text, re.IGNORECASE):
        return None
    command = f"awk -F: '($3>=1000)&&($7 !~ /nologin/){{print $6}}' /etc/passwd | while IFS= read -r home; do [ -z \"$home\" ] && continue; mount=$(findmnt -nkT \"$home\" | awk 'NR==1{{print $1 \" \" $4}}'); [ -z \"$mount\" ] && continue; target=${{mount%% *}}; opts=${{mount#* }}; if [ \"$target\" = \"/\" ] || ! printf '%s' \"$opts\" | grep -Eq '(^|,){required_option}(,|$)'; then printf '%s\\n' \"$home $target $opts\"; fi; done"
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _sles_interactive_home_nosuid_candidate(rule: dict, stig_id: str) -> dict | None:
    if rule.get('vuln_id', '') != 'V-234998' or stig_id != 'SLES_15_STIG':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    if not re.search(r"awk\s+-F:\s+'\(\$3>=1000\)\s*&&\s*\(\$7\s*!~\s*/nologin/\)\{print\s+\$6\}'\s+/etc/passwd", content):
        return None
    if not re.search(r'findmnt\s+-nkT\s+\$X', content):
        return None
    if not re.search(r'If\s+a\s+file\s+system\s+containing\s+user\s+home\s+directories\s+is\s+not\s+mounted\s+with\s+the\s+FSTYPE\s+OPTION\s+nosuid,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'user\s+home\s+directories\s+are\s+mounted\s+under\s+["“]/["”].*?not\s+a\s+finding.*?nosuid.*?cannot\s+be\s+used\s+on\s+the\s+["“]/["”]', content, re.IGNORECASE | re.DOTALL):
        return None
    if not re.search(r'/etc/fstab', fix_text) or not re.search(r'\bnosuid\b', fix_text):
        return None
    command = 'awk -F: \'($3>=1000)&&($7 !~ /nologin/){print $6}\' /etc/passwd | while IFS= read -r home; do [ "$home" = "/" ] && continue; findmnt -nkT "$home"; done | awk \'$1 != "/" && $4 !~ /(^|,)nosuid(,|$)/ {print}\''
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': title,
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
    if (
        rule.get('vuln_id', '') == 'V-234860'
        and re.search(r'\bSUSE\s+operating\s+systems\s+must\s+have\s+and\s+implement\s+SSH\b', title, re.IGNORECASE)
        and re.search(r'\bzypper\s+info\s+openssh\s*\|\s*grep\s+-i\s+installed\b', content, re.IGNORECASE)
        and re.search(r'If\s+the\s+OpenSSH\s+package\s+is\s+not\s+installed,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'\bsystemctl\s+status\s+sshd\.service\s*\|\s*grep\s+-i\s+["“]active:', content, re.IGNORECASE)
        and re.search(r'If\s+OpenSSH\s+service\s+is\s+not\s+active,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'\bzypper\s+in\s+openssh\b', rule.get('fix_text', '') or '', re.IGNORECASE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "sh -c 'rpm -q openssh >/dev/null 2>&1 && systemctl is-active --quiet sshd.service && echo Compliant'"},
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': rule.get('title', ''),
        }
    nfs_dpkg_absent_match = re.search(
        r'(?P<command>(?:sudo\s+)?dpkg\s+-l\s*\|\s*grep\s+-E\s+["\']nfs-common\s*\|\s*nfs-kernel-server["\'])',
        content,
        re.IGNORECASE,
    )
    if (
        rule.get('vuln_id', '') in {'V-279937', 'V-279938'}
        and nfs_dpkg_absent_match
        and re.search(r'\bmust\s+not\s+have\s+the\s+nfs-kernel-server\s+package\s+installed\b', title, re.IGNORECASE)
        and re.search(r'If\s+the\s+nfs-common\s+or\s+nfs-kernel-server\s+packages\s+are\s+installed,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'apt\s+purge\s+--yes\s+nfs-common\s+nfs-kernel-server', rule.get('fix_text', '') or '', re.IGNORECASE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': _normalize_command(nfs_dpkg_absent_match.group('command'))},
            'expected': {'type': 'equals', 'value': ''},
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


def _linux_audit_configuration_file_modes_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    if vuln_id != 'V-238249':
        return None
    title = rule.get('title', '') or ''
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    policy_text = '\n'.join(part for part in (content, fix_text) if part)
    required_paths = ('/etc/audit/audit.rules', '/etc/audit/rules.d/*', '/etc/audit/auditd.conf')
    if not all(path in policy_text for path in required_paths):
        return None
    if not re.search(r'audit\s+configuration\s+files\s+are\s+not\s+write-accessible', title, re.IGNORECASE):
        return None
    has_finding = re.search(r'mode\s+more\s+permissive\s+than\s+["“]0640["”].*?this\s+is\s+a\s+finding', content, re.IGNORECASE | re.DOTALL)
    has_fix = re.search(r'chmod\s+-R\s+0640\s+/etc/audit/audit\*\.\{rules,conf\}\s+/etc/audit/rules\.d/\*', fix_text, re.IGNORECASE)
    if not (has_finding and has_fix):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {
            'type': 'command_output',
            'command': 'find /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d -type f -perm /0137 -print 2>/dev/null',
        },
        'expected': {'type': 'equals', 'value': ''},
        'description': title,
    }


def _linux_faillock_conf_exact_setting_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    canonical_vuln = re.search(r'V-\d+', vuln_id)
    if not canonical_vuln:
        return None
    allowed_vulns = {
        'V-230333', 'V-230335', 'V-230337', 'V-230341', 'V-230343', 'V-230345',
        'V-258054', 'V-258055', 'V-258056', 'V-258057', 'V-258060', 'V-258070',
    }
    if canonical_vuln.group(0) not in allowed_vulns:
        return None
    title = rule.get('title', '') or ''
    if 'faillock' not in (rule.get('check_content', '') + '\n' + rule.get('fix_text', '')).lower():
        return None
    if not re.search(r'unsuccessful\s+logon|account\s+lock', title, re.IGNORECASE):
        return None
    fix_text = rule.get('fix_text', '') or ''
    match = re.search(
        r'/etc/security/faillock\.conf["”]?\s+file\s+to\s+match\s+the\s+following\s+line:\s*(?P<line>[^\n\r]+(?:\s*=\s*[^\n\r]+)?)',
        fix_text,
        re.IGNORECASE,
    )
    if not match:
        return None
    line = match.group('line').strip().strip('"“”')
    allowed_lines = {
        'deny': '3',
        'fail_interval': '900',
        'unlock_time': '0',
        'dir': '/var/log/faillock',
    }
    bare_flags = {'even_deny_root', 'audit', 'silent'}
    assignment = re.fullmatch(r'(?P<key>deny|fail_interval|unlock_time|dir)\s*=\s*(?P<value>\S+)', line)
    if assignment:
        key = assignment.group('key')
        value = assignment.group('value')
        if allowed_lines.get(key) != value:
            return None
        regex = rf'^[[:space:]]*{re.escape(key)}[[:space:]]*=[[:space:]]*{re.escape(value)}[[:space:]]*$'
    elif line in bare_flags:
        regex = rf'^[[:space:]]*{re.escape(line)}[[:space:]]*$'
    else:
        return None
    command = f"awk 'BEGIN{{ok=0}} /^[[:space:]]*#/ {{next}} /{regex}/ {{ok=1}} END{{if(ok) print \"Compliant\"}}' /etc/security/faillock.conf"
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': title,
    }


def _linux_login_defs_fix_line_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    if not re.search(r'V-\d+', vuln_id):
        return None
    combined = '\n'.join(part for part in (rule.get('title', '') or '', rule.get('check_content', '') or '', rule.get('fix_text', '') or '') if part)
    if re.search(r'\b(?:organization-defined|documented\s+requirement|operational\s+requirement|site\s+policy|ask\s+the\s+(?:system\s+)?administrator)\b', combined, re.IGNORECASE):
        return None
    content = rule.get('check_content', '') or ''
    if content.strip():
        return None
    fix_text = rule.get('fix_text', '') or ''
    if '/etc/login.defs' not in fix_text:
        return None
    line_match = None
    allowed = {
        'CREATE_HOME': ('exact_ci', 'yes'),
        'ENCRYPT_METHOD': ('exact_ci', 'SHA512'),
        'PASS_MIN_DAYS': ('minimum_int', '1'),
        'SHA_CRYPT_MIN_ROUNDS': ('minimum_int', '100000'),
        'SHA_CRYPT_MAX_ROUNDS': ('minimum_int', '100000'),
    }
    for match in re.finditer(r'^\s*(?P<key>[A-Z][A-Z0-9_]+)\s+(?P<value>[A-Za-z0-9_./-]+)\s*$', fix_text, re.MULTILINE):
        key = match.group('key')
        value = match.group('value')
        if key in allowed and allowed[key][1].lower() == value.lower():
            line_match = (key, value, allowed[key][0])
            break
    if not line_match:
        return None
    key, value, mode = line_match
    if mode == 'minimum_int':
        command = f"awk 'BEGIN{{ok=0}} /^[[:space:]]*#/ {{next}} toupper($1)==\"{key}\" && $2 ~ /^[0-9]+$/ && $2+0 >= {value} {{ok=1}} END{{if(ok) print \"Compliant\"}}' /etc/login.defs"
    else:
        command = f"awk 'BEGIN{{ok=0}} /^[[:space:]]*#/ {{next}} toupper($1)==\"{key}\" && toupper($2)==\"{value.upper()}\" {{ok=1}} END{{if(ok) print \"Compliant\"}}' /etc/login.defs"
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _linux_passwd_home_directory_assigned_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    if not re.fullmatch(r'V-\d+', vuln_id):
        return None
    title = rule.get('title', '') or ''
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'home\s+directory\s+assigned\s+in\s+the\s+/etc/passwd\s+file', title, re.IGNORECASE):
        return None
    if not re.search(r"awk\s+-F:\s+['\"]\(\$3>=1000\).*?\{print\s+\$1,\s*\$3,\s*\$6\}['\"]\s+/etc/passwd", content, re.IGNORECASE | re.DOTALL):
        return None
    if not re.search(r'If\s+users?\s+home\s+director(?:y|ies)\s+is\s+not\s+defined,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'Create\s+and\s+assign\s+home\s+directories\s+to\s+all\s+local\s+interactive\s+users', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {
            'type': 'command_output',
            'command': "awk -F: '($3>=1000)&&($7 !~ /nologin/)&&($6==\"\"){print $1}' /etc/passwd",
        },
        'expected': {'type': 'equals', 'value': ''},
        'description': title,
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
    if not re.search(r'firewall\s+(?:must\s+)?employs?\s+a\s+deny-all,\s+allow-by-exception\s+policy', title, re.IGNORECASE):
        return None
    runtime_only_drop = (
        re.search(r'firewall-cmd\s+--get-active-zones', content, re.IGNORECASE)
        and re.search(r'firewall-cmd\s+--info-zone=[A-Za-z0-9_.\[\]-]+\s*\|\s*grep\s+target', content, re.IGNORECASE)
        and re.search(r'target:\s*DROP', content, re.IGNORECASE)
        and re.search(r'If\s+no\s+zones\s+are\s+active[^.]*or\s+if\s+the\s+target\s+is\s+set\s+to\s+a\s+different\s+option\s+other\s+than\s+["“]DROP["”],?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE | re.DOTALL)
    )
    if runtime_only_drop and not re.search(r'firewall-cmd\s+--permanent\s+--info-zone=', content, re.IGNORECASE):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {
                'type': 'command_output',
                'command': 'firewall-cmd --get-active-zones | awk \'NF==1{print $1}\' | while read -r zone; do target=$(firewall-cmd --info-zone="$zone" | awk -F: \'/^[[:space:]]*target:/{gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",$2); print $2}\'); [ "$target" = "DROP" ] || printf \'%s %s\\n\' "$zone" "$target"; done',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
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


def _scap_rhel_sshd_effective_config_from_fix_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'scap_mil.disa.stig_collection_u_rhel_' not in stig_id.lower():
        return None
    vuln_id = rule.get('vuln_id', '')
    vuln_match = re.search(r'V-\d+', vuln_id)
    canonical_vuln = vuln_match.group(0) if vuln_match else vuln_id
    allowed_vulns = {
        'V-230380', 'V-230288', 'V-230382', 'V-230244', 'V-244525', 'V-230330',
        'V-230296', 'V-230556', 'V-257983', 'V-257995', 'V-257982', 'V-258006',
        'V-257985', 'V-257993', 'V-257992', 'V-257984', 'V-258003', 'V-257986',
        'V-258005', 'V-258009', 'V-257981', 'V-258008', 'V-257996', 'V-258004',
        'V-258007', 'V-258011',
    }
    if canonical_vuln not in allowed_vulns:
        return None
    combined = '\n'.join(part for part in (rule.get('title', '') or '', rule.get('check_content', '') or '', rule.get('fix_text', '') or '') if part)
    if re.search(r'\b(?:documented|validated\s+mission|organization-defined|operational\s+requirement|if\s+.*?required)\b', combined, re.IGNORECASE):
        return None
    fix_text = rule.get('fix_text', '') or ''
    if '/etc/ssh/sshd_config' not in fix_text:
        return None
    allowed_keywords = {
        'Banner', 'ClientAliveCountMax', 'ClientAliveInterval', 'GSSAPIAuthentication',
        'HostbasedAuthentication', 'IgnoreRhosts', 'IgnoreUserKnownHosts',
        'KerberosAuthentication', 'LogLevel', 'PermitEmptyPasswords', 'PermitRootLogin',
        'PermitUserEnvironment', 'PrintLastLog', 'PubkeyAuthentication', 'StrictModes',
        'UsePAM', 'X11Forwarding', 'X11UseLocalhost',
    }
    directive_match = None
    for match in re.finditer(r'^\s*([A-Za-z][A-Za-z0-9]+)\s+([^\n\r#]+?)\s*$', fix_text, re.MULTILINE):
        if match.group(1) in allowed_keywords:
            directive_match = match
            break
    if not directive_match:
        return None
    keyword = directive_match.group(1)
    value = ' '.join(directive_match.group(2).strip().split())
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/@:-]*(?:\s+[A-Za-z0-9][A-Za-z0-9._/@:-]*)*', value):
        return None
    expected = f'{keyword.lower()} {value.lower()}'
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': f"sshd -T | grep -i '^{keyword.lower()} '"},
        'expected': {'type': 'contains', 'substring': expected},
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
        r'If\s+there\s+are\s+no\s+results,\s+or\s+if\s+the\s+(?P<property>org\.apache\.catalina(?:\s*\.\s*[A-Za-z0-9_]+)+)\s+is\s+not\s*=\s*["“](?P<value>true|false)["”],?\s+this\s+is\s+a\s+finding\.',
        content,
        re.IGNORECASE,
    )
    if not finding_match:
        return None
    property_name = re.sub(r'\s+', '', finding_match.group('property'))
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


def _tomcat_autodeploy_disabled_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'tomcat' not in stig_id.lower() or rule.get('vuln_id', '') != 'V-222956':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'grep\s+-i\s+-C2\s+autodeploy', content, re.IGNORECASE) or '$CATALINA_BASE/conf/server.xml' not in content:
        return None
    if not re.search(r'If\s+autoDeploy\s*=\s*["“]?true["”]?\s+or\s+if\s+autoDeploy\s+is\s+not\s+set,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'autoDeploy\s*=\s*["“]false["”]', content + '\n' + fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {'type': 'command_output', 'command': 'xmllint --xpath "count(//Host[not(@autoDeploy) or translate(@autoDeploy,\'TRUE\',\'true\')=\'true\'])" $CATALINA_BASE/conf/server.xml 2>/dev/null'},
        'expected': {'type': 'equals', 'value': '0'},
        'description': rule.get('title', ''),
    }


def _tomcat_manager_client_cert_auth_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'tomcat' not in stig_id.lower() or rule.get('vuln_id', '') != 'V-222993':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'grep\s+-i\s+auth-method\s+\$CATALINA_BASE/webapps/manager/WEB-INF/web\.xml', content, re.IGNORECASE):
        return None
    if not re.search(r'<Auth-Method>\s+for\s+the\s+web\s+manager\s+application\s+is\s+not\s+set\s+to\s+CLIENT-CERT,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'CLIENT-CERT', content + '\n' + fix_text, re.IGNORECASE):
        return None
    command = 'sh -c \'p="${CATALINA_BASE:-/opt/tomcat}/webapps/manager/WEB-INF/web.xml"; test ! -e "$p" && printf Compliant && exit 0; v=$(xmllint --xpath "string(translate(//login-config/auth-method, \\\'abcdefghijklmnopqrstuvwxyz\\\', \\\'ABCDEFGHIJKLMNOPQRSTUVWXYZ\\\'))" "$p" 2>/dev/null); [ "$v" = CLIENT-CERT ] && printf Compliant\''
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _tomcat_ldap_realm_ldaps_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'tomcat' not in stig_id.lower() or rule.get('vuln_id', '') != 'V-222965':
        return None
    content = rule.get('check_content', '') or ''
    combined = content + '\n' + (rule.get('fix_text', '') or '')
    if not re.search(r'grep\s+-i\s+-A8\s+JNDIRealm\s+\$CATALINA_BASE/conf/server\.xml', content, re.IGNORECASE):
        return None
    if not re.search(r'JNDIRealm\s+connectionURL\s+setting\s+is\s+not\s+configured\s+to\s+use\s+LDAPS', content, re.IGNORECASE):
        return None
    if not re.search(r'connectionURL\s*=\s*["“]ldaps://', combined, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {
            'type': 'command_output',
            'command': 'sh -c \'grep -i -A8 JNDIRealm "${CATALINA_BASE:-/opt/tomcat}/conf/server.xml" 2>/dev/null || true\'',
        },
        'expected': {'type': 'contains', 'substring': 'ldaps://'},
        'description': rule.get('title', ''),
    }


def _tomcat_jmx_false_property_absent_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'tomcat' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    property_by_vuln = {
        'V-222963': 'com.sun.management.jmxremote.authenticate',
        'V-222964': 'com.sun.management.jmxremote.ssl',
    }
    property_name = property_by_vuln.get(rule.get('vuln_id', ''))
    if not property_name:
        return None
    false_flag = f'-D{property_name}=false'
    true_flag = f'-D{property_name}=true'
    if not re.search(re.escape(property_name) + r'\s*=\s*["“]?false["”]?', content, re.IGNORECASE) or true_flag.lower() not in fix_text.lower():
        return None
    if not re.search(r'jmxremote', content, re.IGNORECASE) or not re.search(r'this\s+is\s+(?:not\s+)?a\s+finding', content, re.IGNORECASE):
        return None
    command = f'sh -c \'grep -i -- "{false_flag}" /etc/systemd/system/tomcat.service 2>/dev/null || ps -ef | grep -i -- "{false_flag}" | grep -v grep || true\''
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _tomcat_error_report_valve_boolean_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'tomcat' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-222975', 'V-222977'}:
        return None
    if not re.search(r'grep\s+-i\s+ErrorReportValve\s+\$CATALINA_BASE/conf/server\.xml', content, re.IGNORECASE):
        return None
    finding_match = re.search(
        r'If\s+the\s+ErrorReportValve\s+element\s+is\s+not\s+defined\s+and\s+(?P<attr>showServerInfo|showReport)\s+set\s+to\s+["“](?P<value>false)["”],\s+this\s+is\s+a\s+finding\.',
        content,
        re.IGNORECASE,
    )
    if not finding_match:
        return None
    attr = finding_match.group('attr')
    expected_value = finding_match.group('value').lower()
    if not re.search(r'ErrorReportValve[^\n<>]*\s+' + re.escape(attr) + r'\s*=\s*["“]' + expected_value + r'["”]', fix_text + '\n' + content, re.IGNORECASE):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': f'xmllint --xpath "string(//Valve[contains(@className,\'ErrorReportValve\')]/@{attr})" $CATALINA_BASE/conf/server.xml 2>/dev/null',
        },
        'expected': {'type': 'equals', 'value': expected_value},
        'description': rule.get('title', ''),
    }


def _tomcat_removed_webapp_directory_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'tomcat' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    webapp_by_vuln = {
        'V-222958': 'examples',
        'V-222960': 'docs',
    }
    webapp = webapp_by_vuln.get(vuln_id)
    if not webapp:
        return None
    path = f'$CATALINA_BASE/webapps/{webapp}'
    if not re.search(r'ls\s+-l\s+' + re.escape(path) + r'\.?\s*(?:\n|$)', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+the\s+' + re.escape(webapp) + r'\s+folder\s+exists\s+or\s+contains\s+any\s+content,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'rm\s+-rf\s+' + re.escape(path), fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': f'sh -c \'test ! -e "{path}" && printf Absent\''},
        'expected': {'type': 'equals', 'value': 'Absent'},
        'description': rule.get('title', ''),
    }


def _tomcat_connector_boolean_absent_or_false_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'tomcat' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    attr_by_vuln = {
        'V-222950': 'allowTrace',
        'V-222957': 'xpoweredBy',
    }
    attr = attr_by_vuln.get(vuln_id)
    if not attr:
        return None
    attr_pattern = re.escape(attr)
    if attr == 'allowTrace':
        attr_pattern = r'allow\s*Trace'
    if not re.search(r'Connector', content, re.IGNORECASE) or not re.search(attr_pattern, content, re.IGNORECASE):
        return None
    true_finding = re.search(
        r'If\s+any\s+connector\s+elements\s+contain\s+' + attr_pattern + r'\s*=\s*["“]?true["”]?,\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    true_statement_finding = attr == 'allowTrace' and re.search(
        r'contains\s+the\s+["“]allow\s*Trace\s*=\s*true["”]\s+statement,\s+this\s+is\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if not (true_finding or true_statement_finding):
        return None
    false_target = re.search(attr_pattern + r'\s*=\s*["“]?false["”]?', fix_text + '\n' + content, re.IGNORECASE)
    if not false_target and attr == 'allowTrace':
        false_target = re.search(r'ensure\s+the\s+["“]?allowTrace["”]?\s+setting\s+is\s+set\s+to\s+false', content, re.IGNORECASE)
    if not false_target:
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'generic',
        'check': {'type': 'command_output', 'command': f'xmllint --xpath "count(//Connector[translate(@{attr},\'TRUE\',\'true\')=\'true\'])" $CATALINA_BASE/conf/server.xml 2>/dev/null'},
        'expected': {'type': 'equals', 'value': '0'},
        'description': rule.get('title', ''),
    }


def _tomcat_lockout_realm_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'tomcat' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-222980', 'V-222981', 'V-222982'}:
        return None
    if not re.search(r'grep\s+-i\s+LockOutRealm\s+\$CATALINA_BASE/conf/server\.xml', content, re.IGNORECASE):
        return None
    if vuln_id == 'V-222980':
        if not re.search(r'If\s+there\s+are\s+no\s+results\s+or\s+if\s+the\s+LockOutRealm\s+is\s+not\s+used', content, re.IGNORECASE):
            return None
        if not re.search(r'className=["“]org\.apache\.catalina\.realm\.LockOutRealm["”]', fix_text, re.IGNORECASE):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': "xmllint --xpath 'name(//Realm[contains(@className,\"LockOutRealm\")])' $CATALINA_BASE/conf/server.xml 2>/dev/null"},
            'expected': {'type': 'equals', 'value': 'Realm'},
            'description': rule.get('title', ''),
        }
    attribute = {'V-222981': ('failureCount', '5'), 'V-222982': ('lockOutTime', '600')}[vuln_id]
    attr_name, expected_value = attribute
    if not re.search(r'LockOutRealm\s+' + re.escape(attr_name) + r'\s+setting\s+is\s+not\s+configured\s+to\s+' + re.escape(expected_value), content, re.IGNORECASE):
        return None
    if not re.search(re.escape(attr_name) + r'=["“]' + re.escape(expected_value) + r'["”]', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'generic',
        'check': {'type': 'command_output', 'command': f"xmllint --xpath 'string(//Realm[contains(@className,\"LockOutRealm\")]/@{attr_name})' $CATALINA_BASE/conf/server.xml 2>/dev/null"},
        'expected': {'type': 'equals', 'value': expected_value},
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


SCAP_FIX_ONLY_SYSTEMCTL_SERVICE_VULNS = {
    'V-230298', 'V-230502', 'V-230312', 'V-230532', 'V-230529', 'V-244542',
    'V-230526', 'V-244548', 'V-244544', 'V-244545', 'V-258142', 'V-257782',
    'V-257783', 'V-257849', 'V-257936', 'V-257815', 'V-258152', 'V-257818',
    'V-257785', 'V-258036', 'V-257786', 'V-257944', 'V-257979', 'V-258090',
}


def _scap_fix_only_systemctl_service_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'scap' not in stig_id.lower() or not _linux_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '') or ''
    vuln_match = re.search(r'V-\d+', vuln_id)
    if not vuln_match or vuln_match.group(0) not in SCAP_FIX_ONLY_SYSTEMCTL_SERVICE_VULNS:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    if content.strip() or not fix_text.strip():
        return None
    service_commands = re.findall(
        r'\bsystemctl\s+(?:--\S+\s+)*(enable|start|disable|stop|mask)\b((?:\s+--\S+)*)(?:\s+([^\s;&|]+))',
        fix_text,
        re.IGNORECASE,
    )
    if not service_commands:
        return None
    names = []
    actions = set()
    for action, options, raw_name in service_commands:
        name = raw_name.strip().strip('"\'')
        if name in {'--now', 'daemon-reload'}:
            continue
        if name.endswith('.socket'):
            return None
        if '.' in name and not name.endswith(('.service', '.target')):
            return None
        names.append(name.removesuffix('.service').removesuffix('.target'))
        actions.add(action.lower())
        if '--now' in options:
            actions.add('start' if action.lower() == 'enable' else 'stop' if action.lower() in {'disable', 'mask'} else action.lower())
    unique_names = sorted(set(names))
    if len(unique_names) != 1:
        return None
    lower_title = title.lower()
    if actions & {'disable', 'stop', 'mask'}:
        if not re.search(r'\b(?:disabled|disable)\b', lower_title):
            return None
        expected_status = 'disabled'
    elif actions & {'enable', 'start'}:
        if not re.search(r'\b(?:active|running|enabled|enable)\b', lower_title):
            return None
        expected_status = 'running'
    else:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'service', 'name': unique_names[0], 'expected_status': expected_status},
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


def _rhel9_audit_backlog_limit_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id != 'V-258173' or 'rhel_9' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'grubby\s+--info=ALL\s*\|\s*grep\s+args\s*\|\s*grep\s+[\'"].*audit_backlog_limit', content):
        return None
    if not re.search(r'audit_backlog_limit\s+is\s+less\s+than\s+["“]8192["”]', content, re.IGNORECASE):
        return None
    if 'grubby --update-kernel=ALL --args=audit_backlog_limit=8192' not in fix_text:
        return None
    command = "grubby --info=ALL | awk '/^args=/{ if ($0 !~ /audit_backlog_limit=/) { print $0; next } while (match($0, /audit_backlog_limit=([0-9]+)/, m)) { if (m[1] + 0 < 8192) print $0; $0=substr($0, RSTART+RLENGTH) } }'"
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _gsettings_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    rhel9_audit_backlog_limit_candidate = _rhel9_audit_backlog_limit_candidate(rule, stig_id)
    if rhel9_audit_backlog_limit_candidate:
        return rhel9_audit_backlog_limit_candidate
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


def _linux_device_file_selinux_label_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    if rule.get('vuln_id') not in {'V-204479', 'V-257932', 'V-271769'}:
        return None
    content = rule.get('check_content', '') or ''
    if not re.search(r'system\s+device\s+files\s+(?:are\s+|to\s+be\s+)?correctly\s+labeled', content, re.IGNORECASE):
        return None
    if not re.search(r'(?:sudo\s+)?find\s+/dev\s+-context\s+\*:device_t:\*\s+\\\(\s+-type\s+c\s+-o\s+-type\s+b\s+\\\)\s+-printf\s+["“\']%p\s+%Z\\n["”\']', content, re.IGNORECASE):
        return None
    if not re.search(r'(?:sudo\s+)?find\s+/dev\s+-context\s+\*:unlabeled_t:\*\s+\\\(\s+-type\s+c\s+-o\s+-type\s+b\s+\\\)\s+-printf\s+["“\']%p\s+%Z\\n["”\']', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+there\s+is\s+(?:any\s+)?output\s+from\s+(?:the\s+)?(?:above|either)(?:\s+of\s+these)?\s+commands?', content, re.IGNORECASE):
        return None
    command = "find /dev -context '*:device_t:*' \\( -type c -o -type b \\) -printf '%p %Z\\n'; find /dev -context '*:unlabeled_t:*' \\( -type c -o -type b \\) -printf '%p %Z\\n'"
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
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


def _nfs_fstab_mount_option_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    title = rule.get('title', '') or ''
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = '\n'.join(part for part in (title, content, fix_text) if part)
    if not re.search(r'\b(?:Network\s+File\s+System|NFS)\b', combined, re.IGNORECASE):
        return None
    if not re.search(r'cat\s+/etc/fstab\s*\|\s*grep\s+nfs', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+no\s+NFS\s+mounts\s+are\s+configured,\s+this\s+requirement\s+is\s+Not\s+Applicable', content, re.IGNORECASE):
        return None

    option_match = re.search(
        r'has\s+the\s+["“](?P<option>nodev|nosuid|noexec)["”]\s+option\s+configured\s+for\s+all\s+NFS\s+mounts',
        content,
        re.IGNORECASE,
    )
    if option_match:
        required_option = option_match.group('option').lower()
        if not re.search(
            rf'NFS\s+and\s+the\s+["“]{re.escape(required_option)}["”]\s+option\s+is\s+missing,\s+this\s+is\s+a\s+finding',
            content,
            re.IGNORECASE,
        ):
            return None
        if not re.search(rf'use\s+the\s+["“]{re.escape(required_option)}["”]\s+option\s+on\s+file\s+systems\s+that\s+are\s+being\s+imported\s+via\s+NFS', fix_text, re.IGNORECASE):
            return None
        command = f"awk '!/^\\s*#/ && $3 ~ /^nfs/ && $4 !~ /(^|,){required_option}(,|$)/ {{print}}' /etc/fstab"
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }

    if re.search(r'\bNetwork\s+File\s+System\s*\(NFS\).*?configured\s+to\s+use\s+RPCSEC_GSS\b', title, re.IGNORECASE):
        if not re.search(r'has\s+the\s+["“]sec["”]\s+option\s+configured\s+for\s+all\s+NFS\s+mounts', content, re.IGNORECASE):
            return None
        if not re.search(r'sec\s+option\s+without\s+the\s+["“]krb5:krb5i:krb5p["”]\s+settings.*?["“]sec["”]\s+option\s+has\s+the\s+["“]sys["”]\s+setting.*?["“]sec["”]\s+option\s+is\s+missing,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE | re.DOTALL):
            return None
        if not re.search(r'Ensure\s+the\s+["“]sec["”]\s+option\s+is\s+defined\s+as\s+["“]krb5p:krb5i:krb5["”]', fix_text, re.IGNORECASE):
            return None
        command = "awk '!/^\\s*#/ && $3 ~ /^nfs/ && ($4 !~ /(^|,)sec=(krb5|krb5i|krb5p)(:krb5|:krb5i|:krb5p)*(,|$)/ || $4 ~ /(^|,)sec=sys(,|$)/) {print}' /etc/fstab"
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    return None


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


def _macos_policy_banner_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _macos_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-259431', 'V-268431'}:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = content + '\n' + fix_text
    if not re.search(r'/Library/Security/PolicyBanner\.rtfd', combined):
        return None
    if not re.search(r'text\s+is\s+not\s+worded\s+exactly\s+this\s+way,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    text_match = re.search(
        r'The\s+banner\s+text\s+of\s+the\s+document\s+must\s+read:\s*[\r\n]+\s*["“](?P<text>You\s+are\s+accessing\s+a\s+U\.S\.\s+Government\s+\(USG\)\s+Information\s+System\s+\(IS\).*?See\s+User\s+Agreement\s+for\s+details\.)["”]',
        content,
        re.IGNORECASE | re.DOTALL,
    )
    if not text_match:
        return None
    expected_text = text_match.group('text').strip().strip('"“”')
    if any(token in expected_text for token in ('`', '$(', '&&', '<<')):
        return None
    command = '/bin/sh -c \'p=/Library/Security/PolicyBanner.rtfd; [ -e "$p" ] && /usr/bin/textutil -convert txt -stdout "$p" 2>/dev/null\''
    if re.search(r'permissions?\s+for\s+["“]PolicyBanner\.rtfd["”]\s+are\s+not\s+["“]644["”]', content, re.IGNORECASE):
        command = '/bin/sh -c \'p=/Library/Security/PolicyBanner.rtfd; [ -e "$p" ] && [ "$(/usr/bin/stat -f %Lp "$p")" = 644 ] && /usr/bin/textutil -convert txt -stdout "$p" 2>/dev/null\''
    return {
        'vuln_id': vuln_id,
        'platform': 'macos',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': expected_text},
        'description': rule.get('title', ''),
    }


def _macos_remote_login_banner_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _macos_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-259429', 'V-268429'}:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = content + '\n' + fix_text
    if not re.search(r'/(?:etc|private/etc)/banner\b', combined):
        return None
    if not re.search(r'^\s*/usr/bin/more\s+/etc/banner\s*$', content, re.MULTILINE):
        return None
    if not (
        re.search(r'text\s+is\s+not\s+worded\s+exactly\s+this\s+way,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        or re.search(r'text\s+in\s+the\s+["“]/etc/banner["”]\s+file\s+does\s+not\s+match\s+the\s+Standard\s+Mandatory\s+DOD\s+Notice\s+and\s+Consent\s+Banner,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    ):
        return None
    text_match = re.search(
        r'The\s+command\s+must\s+return\s+the\s+following\s+text:\s*[\r\n]+\s*["“](?P<text>You\s+are\s+accessing\s+a\s+U\.S\.\s+Government\s+\(USG\)\s+Information\s+System\s+\(IS\).*?See\s+User\s+Agreement\s+for\s+details\.)["”]',
        content,
        re.IGNORECASE | re.DOTALL,
    )
    if not text_match:
        return None
    expected_text = text_match.group('text').strip().strip('"“”')
    if any(token in expected_text for token in ('`', '$(', '&&', '<<')):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'macos',
        'check': {'type': 'command_output', 'command': '/usr/bin/more /etc/banner'},
        'expected': {'type': 'equals', 'value': expected_text},
        'description': rule.get('title', ''),
    }


def _ubuntu_ssh_confirm_banner_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id != 'V-270694' or 'ubuntu' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'Standard\s+Mandatory\s+DOD\s+Notice\s+and\s+Consent\s+Banner', rule.get('title', '') or '', re.IGNORECASE):
        return None
    if '/etc/profile.d/ssh_confirm.sh' not in content or '/etc/profile.d/ssh_confirm.sh' not in fix_text:
        return None
    if not re.search(r'If\s+the\s+output\s+does\s+not\s+match\s+the\s+text\s+above,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if 'Note: The "ssh_confirm.sh" script is provided as a supplemental file to this document.' not in fix_text:
        return None
    script_match = re.search(
        r'^\$\s+less\s+/etc/profile\.d/ssh_confirm\.sh\s*\n(?P<script>#!/bin/bash.*?)(?:\n\s*If\s+the\s+output\s+does\s+not\s+match\s+the\s+text\s+above,\s+this\s+is\s+a\s+finding\.)',
        content,
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    if not script_match:
        return None
    script = script_match.group('script').strip()
    required_fragments = (
        'if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then',
        'read -p',
        'You are accessing a U.S. Government (USG) Information System (IS)',
        'Do you agree? [y/N]',
        '[Nn]* ) exit 1 ;;',
    )
    if not all(fragment in script for fragment in required_fragments):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': 'cat /etc/profile.d/ssh_confirm.sh'},
        'expected': {'type': 'equals', 'value': script},
        'description': rule.get('title', ''),
    }


def _linux_issue_banner_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-248529', 'V-271455'}:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = content + '\n' + fix_text
    if not re.search(r'\bcat\s+/etc/issue\b', content):
        return None
    if '/etc/issue' not in combined:
        return None
    if not re.search(r'banner\s+text\s+does\s+not\s+match\s+the\s+Standard\s+Mandatory\s+DoD\s+Notice\s+and\s+Consent\s+Banner\s+exactly', content, re.IGNORECASE):
        return None
    if not re.search(r'Edit\s+the\s+["“]/etc/issue["”]\s+file', fix_text, re.IGNORECASE):
        return None
    text_match = re.search(
        r'will\s+return\s+the\s+following\s+text:\s*[\r\n]+\s*["“](?P<text>You\s+are\s+accessing\s+a\s+U\.S\.\s+Government\s+\(USG\)\s+Information\s+System\s+\(IS\).*?See\s+User\s+Agreement\s+for\s+details\.)["”]',
        content,
        re.IGNORECASE | re.DOTALL,
    )
    if not text_match:
        return None
    expected_text = text_match.group('text').strip().strip('"“”')
    if any(token in expected_text for token in ('`', '$(', '&&', '<<')):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': 'cat /etc/issue'},
        'expected': {'type': 'equals', 'value': expected_text},
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


def _esxi_auditrecords_enabled_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'esxi' not in stig_id.lower() or rule.get('vuln_id') != 'V-256436':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'(?m)^\s*#?\s*esxcli\s+system\s+auditrecords\s+get\s*$', content):
        return None
    if not re.search(r'(?m)^\s*\$esxcli\.system\.auditrecords\.get\.invoke\(\)\s*\|\s*Format-List\s*$', content, re.IGNORECASE):
        return None
    required_fields = (
        'AuditRecordRemoteTransmissionActive : true',
        'AuditRecordStorageActive : true',
        'AuditRecordStorageCapacity : 100',
    )
    if not all(field in content for field in required_fields):
        return None
    if not re.search(r'If\s+audit\s+record\s+storage\s+is\s+not\s+active\s+and\s+configured,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not all(command in fix_text for command in (
        'esxcli system auditrecords local set --size=100',
        'esxcli system auditrecords local enable',
        'esxcli system auditrecords remote enable',
    )):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': '$esxcli = Get-EsxCli -v2; $esxcli.system.auditrecords.get.invoke() | Select-Object -Property AuditRecordRemoteTransmissionActive,AuditRecordStorageActive,AuditRecordStorageCapacity | ConvertTo-Json -Compress',
        },
        'expected': {'type': 'contains', 'substring': '"AuditRecordRemoteTransmissionActive":true,"AuditRecordStorageActive":true,"AuditRecordStorageCapacity":100'},
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


def _windows_ie11_standalone_browser_disabled_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-256893', 'V-256894'}:
        return None
    title = rule.get('title', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'Internet\s+Explorer\s+must\s+be\s+disabled\s+for\s+Windows\s+(?:10|11)', title, re.IGNORECASE):
        return None
    if not re.search(r'Disable\s+Internet\s+Explorer\s+11\s+as\s+a\s+standalone\s+browser', fix_text, re.IGNORECASE):
        return None
    if not re.search(r'policy\s+value\s+.*\bEnabled\b.*option\s+value\s+set\s+to\s+["“]Never["”]', fix_text, re.IGNORECASE | re.DOTALL):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {
            'type': 'registry',
            'path': r'HKLM\Software\Policies\Microsoft\Internet Explorer\Main',
            'value_name': 'NotifyDisableIEOptions',
        },
        'expected': {'type': 'equals', 'value': 0},
        'description': title,
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

def _windows_unused_accounts_35_days_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-205707', 'V-220711', 'V-253268', 'V-254256', 'V-278003'}:
        return None
    if not _windows_platform(stig_id):
        return None
    title = (rule.get('title', '') or '').lower()
    if not (
        'outdated or unused accounts' in title
        or 'unused accounts must be disabled or removed from the system after 35 days of inactivity' in title
    ):
        return None
    content_lower = content.lower()
    server_domain_content = all(phrase.lower() in content_lower for phrase in (
        'Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00',
        'Member servers and stand-alone or nondomain-joined systems',
        'If any enabled accounts have not been logged on to within the past 35 days, this is a finding',
    )) or all(phrase.lower() in content_lower for phrase in (
        'Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00',
        'Member servers and standalone or nondomain-joined systems',
        'If any enabled accounts have not been logged on to within the past 35 days, this is a finding',
    ))
    client_local_content = all(phrase.lower() in content_lower for phrase in (
        "([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children",
        '$lastLogin = $user.Properties.LastLogin.Value',
        'If any enabled accounts have not been logged on to within the past 35 days, this is a finding',
    ))
    if not (server_domain_content or client_local_content):
        return None
    if not re.search(r'(?:Remove\s+or\s+disable\s+accounts|Disable\s+or\s+delete\s+any\s+active\s+accounts)\s+that\s+have\s+not\s+been\s+used\s+in\s+the\s+last\s+35\s+days', fix_text, re.IGNORECASE):
        return None
    command = (
        'powershell -NoProfile -Command "'
        '$cutoff=(Get-Date).AddDays(-35); '
        'if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { '
        'Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00 | '
        'Where-Object { $_.Enabled -eq $true } | Select-Object -ExpandProperty SamAccountName '
        '} else { '
        'Get-CimInstance Win32_UserAccount -Filter \'LocalAccount=True and Disabled=False\' | '
        'Where-Object { $_.Name -notin @(\'DefaultAccount\',\'Guest\') -and (-not $_.LastUseTime -or ([Management.ManagementDateTimeConverter]::ToDateTime($_.LastUseTime) -lt $cutoff)) } | '
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


def _windows_account_password_expires_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-254258', 'V-278005'}:
        return None
    if not _windows_platform(stig_id):
        return None
    if 'passwords must be configured to expire' not in (rule.get('title', '') or '').lower():
        return None
    required_phrases = (
        'Search-ADAccount -PasswordNeverExpires -UsersOnly',
        'PasswordNeverExpires" status of "True", this is a finding',
        'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True"',
        'PasswordExpires" status of "False", this is a finding',
        'Exclude application accounts, disabled accounts',
    )
    if not all(phrase.lower() in content.lower() for phrase in required_phrases):
        return None
    command = (
        'powershell -NoProfile -Command "'
        'if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { '
        'Search-ADAccount -PasswordNeverExpires -UsersOnly | '
        'Where-Object { $_.Enabled -eq $true -and $_.Name -notin @(\'DefaultAccount\',\'Guest\',\'krbtgt\') } | '
        'Select-Object -ExpandProperty Name '
        '} else { '
        'Get-CimInstance -Class Win32_UserAccount -Filter \'PasswordExpires=False and LocalAccount=True\' | '
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


def _windows_enabled_local_admin_password_age_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-220952', 'V-253476', 'V-277986'}:
        return None
    title = rule.get('title', '') or ''
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    policy_text = f'{title}\n{content}\n{fix_text}'
    if not re.search(r'enabled\s+local\s+Administrator\s+accounts?', policy_text, re.IGNORECASE):
        return None
    required_patterns = (
        r'Get-LocalUser',
        r'PasswordLastSet',
        r'(?:more|greater)\s+than\s+["“]?60["”]?\s+days\s+old[^.\n]+this\s+is\s+a\s+finding',
        r'changed?\s+at\s+least\s+every\s+60\s+days',
    )
    if not all(re.search(pattern, policy_text, re.IGNORECASE) for pattern in required_patterns):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': 'powershell -NoProfile -Command "Get-LocalUser | Where-Object { $_.SID -like \'S-1-5-*-500\' -and $_.Enabled -eq $true -and $_.PasswordLastSet -lt (Get-Date).AddDays(-60) } | Select-Object -ExpandProperty Name"',
        },
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
    elif vuln_id == 'V-242406' and '--config' in content and 'kubelet' in content.lower() and 'owned by root:root' in content:
        command = "sh -c 'cfg=$(ps -ef | sed -n \"s/.*--config[= ]\\([^ ]*\\).*/\\1/p\" | head -n 1); [ -z \"$cfg\" ] && exit 0; path=\"$cfg\"; [ -d \"$cfg\" ] && path=\"$cfg/kubelet\"; stat -c \"%U:%G %n\" \"$path\" 2>/dev/null | grep -v \"^root:root \"'"
    elif vuln_id == 'V-242407' and '--config' in content and 'kubeletconfiguration' in content.lower() and 'permissions of "644" or more restrictive' in content:
        command = "sh -c 'cfg=$(ps -ef | sed -n \"s/.*--config[= ]\\([^ ]*\\).*/\\1/p\" | head -n 1); [ -z \"$cfg\" ] && exit 0; path=\"$cfg\"; [ -d \"$cfg\" ] && path=\"$cfg/kubelet\"; find \"$path\" -perm /133 -exec stat -c \"%a %n\" {} \\; 2>/dev/null'"
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


def _linux_init_files_world_writable_programs_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'local\s+initialization\s+files\s+do\s+not\s+execute\s+world-writable\s+programs', content, re.IGNORECASE):
        return None
    if not re.search(r'find\s+\[PART\]\s+-xdev\s+-type\s+f\s+-perm\s+-0002\s+-print', content, re.IGNORECASE):
        return None
    if not re.search(r'local\s+initialization\s+files?\s+(?:are\s+)?found\s+to\s+reference\s+world-writable\s+files?,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'chmod\s+0?755\s+<file>', fix_text, re.IGNORECASE):
        return None
    command = '''findmnt -rn -t xfs,ext2,ext3,ext4,btrfs | awk '{print $1}' | while IFS= read -r mount; do find "$mount" -xdev -type f -perm -0002 -print 2>/dev/null; done | while IFS= read -r wwfile; do grep -RslF -- "$wwfile" /etc /home 2>/dev/null | while IFS= read -r initfile; do case "$initfile" in */.*|/etc/profile|/etc/bashrc|/etc/zshrc|/etc/csh.cshrc|/etc/csh.login|/etc/profile.d/*) printf '%s -> %s\\n' "$initfile" "$wwfile";; esac; done; done'''
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _interactive_home_contents_mode_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'files\s+and\s+directories\s+contained\s+in\s+a\s+local\s+interactive\s+user\s+home\s+directory', content, re.IGNORECASE):
        return None
    mode_match = re.search(r'mode\s+(?:of\s+)?["“](0?[0-7]{3})["”]\s*\.?\s*(?:\n|.*?or\s+less\s+permissive)', content, re.IGNORECASE | re.DOTALL)
    finding_match = re.search(r'If\s+any\s+files\s+or\s+directories\s+are\s+found\s+with\s+a\s+mode\s+more\s+permissive\s+than\s+["“]?0?750["”]?,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    if not mode_match or not finding_match:
        return None
    if not re.search(r'chmod\s+0?750\s+', fix_text, re.IGNORECASE):
        return None
    mode = int(mode_match.group(1), 8)
    prohibited_bits = 0o777 & ~mode
    if prohibited_bits == 0:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {
            'type': 'command_output',
            'command': f'''awk -F: '($3>=1000)&&($7 !~ /(nologin|false)$/){{print $6}}' /etc/passwd | while IFS= read -r home; do [ -d "$home" ] && find "$home" -xdev ! -name ".*" -perm /{prohibited_bits:03o} -exec stat -c "%a %n" {{}} \\; 2>/dev/null; done''',
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


def _ubuntu_ufw_rate_limit_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-238367', 'V-260517', 'V-270754'}:
        return None
    if 'ubuntu' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'\bss\s+-l46ut\b', content):
        return None
    if not re.search(r'\bufw\s+status\b', content, re.IGNORECASE):
        return None
    has_denied_or_limited_port_prose = re.search(r'If\s+any\s+port\s+with\s+a\s+state\s+of\s+["“]LISTEN["”]\s+that\s+does\s+not\s+have\s+an\s+action\s+of\s+["“]DENY["”],\s+is\s+not\s+marked\s+with\s+the\s+["“]LIMIT["”]\s+action,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    has_limited_port_prose = re.search(r'If\s+any\s+port\s+with\s+a\s+state\s+of\s+["“]LISTEN["”]\s+is\s+not\s+marked\s+with\s+the\s+["“]LIMIT["”]\s+action,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    if not (has_denied_or_limited_port_prose or has_limited_port_prose):
        return None
    has_inactive_status_prose = re.search(r'If\s+the\s+Status\s+is\s+set\s+to\s+(?:["“]inactive["”]\s+or\s+any\s+type\s+of\s+error|anything\s+other\s+than\s+["“]active["”]),?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
    if vuln_id == 'V-270754' and not has_inactive_status_prose:
        return None
    if not re.search(r'\bufw\s+limit\s+(?:\[service\]|<service_name>)', fix_text, re.IGNORECASE):
        return None
    command = "ufw status 2>/dev/null | awk 'BEGIN{status=0} /^Status:[[:space:]]+active[[:space:]]*$/ {status=1} END{exit(status?0:1)}' >/dev/null || { echo ufw-inactive; exit 0; }; ss -H -l46utn | awk '$1 ~ /^(tcp|udp)/ {addr=$5; sub(/.*:/,\"\",addr); if (addr ~ /^[0-9]+$/) print addr}' | sort -nu | while read -r port; do ufw status | awk -v p=\"$port\" 'BEGIN{ok=0} $1 ~ (\"^\" p \"(/|$)\") && ($2==\"LIMIT\" || $2==\"DENY\") {ok=1} END{exit(ok?0:1)}' || echo \"$port\"; done"
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _command_output_candidate(rule: dict, stig_id: str) -> dict | None:
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    ubuntu_ufw_rate_limit_candidate = _ubuntu_ufw_rate_limit_candidate(rule, stig_id)
    if ubuntu_ufw_rate_limit_candidate:
        return ubuntu_ufw_rate_limit_candidate
    linux_init_files_world_writable_candidate = _linux_init_files_world_writable_programs_candidate(rule, stig_id)
    if linux_init_files_world_writable_candidate:
        return linux_init_files_world_writable_candidate
    interactive_home_contents_mode_candidate = _interactive_home_contents_mode_candidate(rule, stig_id)
    if interactive_home_contents_mode_candidate:
        return interactive_home_contents_mode_candidate
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
    if (
        'postgresql' in stig_id.lower()
        and rule.get('vuln_id', '') == 'V-233519'
        and re.search(r'^\s*[$#>]\s*cat\s+\$\{PGDATA\?\}/pg_hba\.conf\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+any\s+entries\s+use\s+the\s+auth_method\s+\(last\s+column\s+in\s+records\)\s+["“]password["”]\s+or\s+["“]md5["”],\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'\b(?:password|md5)\b', fix_text, re.IGNORECASE)
    ):
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "grep -E '^[[:space:]]*host[^#]*[[:space:]](password|md5)([[:space:]]*(#.*)?)?$' ${PGDATA?}/pg_hba.conf"},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }

    postgresql_nonzero_session_settings = {
        'tcp_keepalives_idle',
        'tcp_keepalives_interval',
        'tcp_keepalives_count',
        'statement_timeout',
    }
    if (
        'postgresql' in stig_id.lower()
        and rule.get('vuln_id', '') == 'V-233606'
        and all(re.search(rf'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+{setting}["”]\s*$', content, re.MULTILINE | re.IGNORECASE) for setting in postgresql_nonzero_session_settings)
        and re.search(r'If\s+these\s+settings\s+are\s+not\s+set\s+to\s+something\s+other\s+than\s+zero,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and all(re.search(rf'^\s*{setting}\s*=\s*[1-9][0-9]*\b', fix_text, re.MULTILINE | re.IGNORECASE) for setting in postgresql_nonzero_session_settings)
    ):
        command = "sh -c 'for s in tcp_keepalives_idle tcp_keepalives_interval tcp_keepalives_count statement_timeout; do v=$(psql -tAc \"SHOW $s\" | tr -d \"[:space:]\"); [ \"$v\" = 0 ] && echo \"$s=0\"; done'"
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    postgresql_log_line_prefix_required_tokens = {
        'V-233578': ('%m', '%u', '%d', '%s'),
        'V-233581': ('%m',),
        'V-233582': ('%m', '%u', '%d', '%p', '%r', '%a'),
        'V-233608': ('%m',),
    }.get(rule.get('vuln_id', ''))
    if (
        'postgresql' in stig_id.lower()
        and postgresql_log_line_prefix_required_tokens
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+log_line_prefix["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and all(token in content for token in postgresql_log_line_prefix_required_tokens)
        and re.search(r'If\s+(?:the\s+query\s+result\s+does\s+not\s+contain|log_line_prefix\s+does\s+not\s+contain)', content, re.IGNORECASE)
        and all(token in fix_text for token in postgresql_log_line_prefix_required_tokens)
    ):
        tokens = ' '.join(postgresql_log_line_prefix_required_tokens)
        command = f"sh -c 'out=$(psql -tAc \"SHOW log_line_prefix\"); for token in {tokens}; do printf %s \"$out\" | grep -Fq \"$token\" || echo \"$token\"; done'"
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    postgresql_connection_audit_settings = {
        'V-233569': ('%m', '%u', '%d', '%c'),
        'V-233604': ('%m', '%u', '%d', '%c'),
    }.get(rule.get('vuln_id', ''))
    if (
        'postgresql' in stig_id.lower()
        and postgresql_connection_audit_settings
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+log_connections["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+log_disconnections["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+log_line_prefix["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+either\s+(?:setting\s+)?is\s+off,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'If\s+log_line_prefix\s+does\s+not\s+contain\s+at\s+least\s+%m\s+%u\s+%d\s+%c,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*log_connections\s*=\s*on\s*$', fix_text, re.MULTILINE | re.IGNORECASE)
        and re.search(r'^\s*log_disconnections\s*=\s*on\s*$', fix_text, re.MULTILINE | re.IGNORECASE)
        and all(token in fix_text for token in postgresql_connection_audit_settings)
    ):
        command = "sh -c 'bad=\"\"; for s in log_connections log_disconnections; do v=$(psql -tAc \"SHOW $s\" | tr -d \"[:space:]\"); [ \"$v\" = on ] || bad=\"$bad $s=$v\"; done; lp=$(psql -tAc \"SHOW log_line_prefix\"); for token in %m %u %d %c; do printf %s \"$lp\" | grep -Fq \"$token\" || bad=\"$bad missing:$token\"; done; printf %s \"$bad\"'"
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    postgresql_log_file_mode = (
        'postgresql' in stig_id.lower()
        and rule.get('vuln_id', '') == 'V-233618'
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+log_file_mode["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+permissions\s+are\s+not\s+0600,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*log_file_mode\s*=\s*0600\s*$', fix_text, re.MULTILINE | re.IGNORECASE)
    )
    if postgresql_log_file_mode:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -tAc "SHOW log_file_mode"'},
            'expected': {'type': 'equals', 'value': '0600'},
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
    postgresql_pgaudit_startup = (
        'postgresql' in stig_id.lower()
        and rule.get('vuln_id', '') == 'V-233589'
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+shared_preload_libraries["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+pgaudit\s+is\s+not\s+in\s+the\s+current\s+setting,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+log_destination["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+stderr\s+or\s+syslog\s+are\s+not\s+in\s+the\s+current\s+setting,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'\bpgaudit\b', fix_text, re.IGNORECASE)
    )
    if postgresql_pgaudit_startup:
        command = "sh -c 'bad=\"\"; spl=$(psql -tAc \"SHOW shared_preload_libraries\"); printf %s \"$spl\" | grep -Fq pgaudit || bad=\"$bad missing:pgaudit\"; dest=$(psql -tAc \"SHOW log_destination\"); printf %s \"$dest\" | grep -Eq \"stderr|syslog\" || bad=\"$bad log_destination=$dest\"; printf %s \"$bad\"'"
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    postgresql_nonrepudiation_audit_settings = ('%m', '%a', '%u', '%d', '%r', '%p')
    if (
        'postgresql' in stig_id.lower()
        and rule.get('vuln_id', '') == 'V-233598'
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+log_line_prefix["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+shared_preload_libraries["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+log_line_prefix\s+does\s+not\s+contain\s+at\s+least\s+["“\']?<\s*%m\s+%a\s+%u\s+%d\s+%r\s+%p\s*>["”\']?,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'If\s+shared_preload_libraries\s+does\s+not\s+contain\s+["“]?pgaudit["”]?,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and all(token in fix_text for token in postgresql_nonrepudiation_audit_settings)
        and re.search(r'\bpgaudit\b', fix_text, re.IGNORECASE)
    ):
        tokens = ' '.join(postgresql_nonrepudiation_audit_settings)
        command = f"sh -c 'bad=\"\"; lp=$(psql -tAc \"SHOW log_line_prefix\"); for token in {tokens}; do printf %s \"$lp\" | grep -Fq \"$token\" || bad=\"$bad missing:$token\"; done; spl=$(psql -tAc \"SHOW shared_preload_libraries\"); printf %s \"$spl\" | grep -Fq pgaudit || bad=\"$bad missing:pgaudit\"; printf %s \"$bad\"'"
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    postgresql_client_min_messages_error = (
        'postgresql' in stig_id.lower()
        and re.search(r"\bSELECT\s+current_setting\([\"']client_min_messages[\"']\);", content, re.IGNORECASE)
        and re.search(r'If\s+client_min_messages\s+is\s+not\s+set\s+to\s+error,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*client_min_messages\s*=\s*error\s*$', fix_text, re.MULTILINE | re.IGNORECASE)
    )
    if postgresql_client_min_messages_error:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -tAc "SELECT current_setting(\'client_min_messages\');"'},
            'expected': {'type': 'equals', 'value': 'error'},
            'description': rule.get('title', ''),
        }
    postgresql_client_min_messages_no_log_debug = (
        'postgresql' in stig_id.lower()
        and rule.get('vuln_id', '') == 'V-233533'
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+client_min_messages;?["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+client_min_messages\s+is\s+set\s+to\s+LOG\s+or\s+DEBUG,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*client_min_messages\s*=\s*error\s*$', fix_text, re.MULTILINE | re.IGNORECASE)
    )
    if postgresql_client_min_messages_no_log_debug:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {
                'type': 'command_output',
                'command': 'sh -c \'v=$(psql -tAc "SHOW client_min_messages" | tr -d "[:space:]" | tr "[:upper:]" "[:lower:]"); case "$v" in log|debug) printf %s "$v";; esac\'',
            },
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }
    postgresql_ssl_on = (
        'postgresql' in stig_id.lower()
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+ssl["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+(?:this\s+is\s+not\s+set\s+to\s+on|SSL\s+is\s+(?:off|not\s+enabled)),\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*ssl\s*=\s*on\s*$', fix_text, re.MULTILINE | re.IGNORECASE)
        and not re.search(r'\b(data\s+owner|classified|NSA-approved|strict\s+requirement|organization-defined)\b', '\n'.join((content, fix_text, rule.get('title', '') or '')), re.IGNORECASE)
    )
    if postgresql_ssl_on:
        if re.search(r'If\s+this\s+is\s+not\s+set\s+to\s+on,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return {
                'vuln_id': rule.get('vuln_id', ''),
                'platform': 'generic',
                'check': {'type': 'command_output', 'command': 'psql -c "SHOW ssl"'},
                'expected': {'type': 'contains', 'substring': 'on'},
                'description': rule.get('title', ''),
            }
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -tAc "SHOW ssl"'},
            'expected': {'type': 'equals', 'value': 'on'},
            'description': rule.get('title', ''),
        }

    postgresql_pgaudit_security_objects = (
        'postgresql' in stig_id.lower()
        and rule.get('vuln_id', '') == 'V-233573'
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+shared_preload_libraries["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+the\s+results\s+does\s+not\s+contain\s+pgaudit,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+pgaudit\.log["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+the\s+output\s+does\s+not\s+contain\s+role,\s+read,\s+write,\s+and\s+ddl,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+pgaudit\.log_catalog["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+log_catalog\s+is\s+not\s+on,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'APPENDIX-B\s+for\s+documentation\s+on\s+installing\s+pgaudit', fix_text, re.IGNORECASE)
        and re.search(r'^\s*pgaudit\.log_catalog\s*=\s*[\'"“]?on[\'"”]?\s*$', fix_text, re.MULTILINE | re.IGNORECASE)
        and re.search(r'^\s*pgaudit\.log\s*=\s*[\'"“]?ddl,\s*role,\s*read,\s*write[\'"”]?\s*$', fix_text, re.MULTILINE | re.IGNORECASE)
    )
    if postgresql_pgaudit_security_objects:
        command = "sh -c 'bad=\"\"; spl=$(psql -tAc \"SHOW shared_preload_libraries\"); printf %s \"$spl\" | grep -Fq pgaudit || bad=\"$bad missing:pgaudit\"; pal=$(psql -tAc \"SHOW pgaudit.log\"); for token in ddl role read write; do printf %s \"$pal\" | grep -Fq \"$token\" || bad=\"$bad missing:$token\"; done; plc=$(psql -tAc \"SHOW pgaudit.log_catalog\" | tr -d \"[:space:]\"); [ \"$plc\" = on ] || bad=\"$bad pgaudit.log_catalog=$plc\"; printf %s \"$bad\"'"
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }

    postgresql_openssl_fips_version = (
        'postgresql' in stig_id.lower()
        and rule.get('vuln_id', '') == 'V-233619'
        and re.search(r'^\s*[$#>]\s*openssl\s+version\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+["“]fips["”]\s+is\s+not\s+included\s+in\s+the\s+OpenSSL\s+version,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'FIPS-compliant\s+cryptography', fix_text, re.IGNORECASE)
    )
    if postgresql_openssl_fips_version:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'linux',
            'check': {'type': 'command_output', 'command': "sh -c 'openssl version | tr [:upper:] [:lower:]'"},
            'expected': {'type': 'contains', 'substring': 'fips'},
            'description': rule.get('title', ''),
        }
    postgresql_log_timezone_utc = (
        'postgresql' in stig_id.lower()
        and rule.get('vuln_id', '') == 'V-233532'
        and re.search(r'\bCoordinated\s+Universal\s+Time\s*\(UTC', rule.get('title', '') or '', re.IGNORECASE)
        and re.search(r'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+log_timezone["”]\s*$', content, re.MULTILINE | re.IGNORECASE)
        and re.search(r'If\s+log_timezone\s+is\s+not\s+set\s+to\s+the\s+desired\s+time\s+zone,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
        and re.search(r'^\s*log_timezone\s*=\s*[\'"“]?UTC[\'"”]?\s*$', fix_text, re.MULTILINE | re.IGNORECASE)
    )
    if postgresql_log_timezone_utc:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': 'psql -tAc "SHOW log_timezone"'},
            'expected': {'type': 'equals', 'value': 'UTC'},
            'description': rule.get('title', ''),
        }
    postgresql_show_literal_settings = {
        'V-233531': {
            'setting': 'log_file_mode',
            'expected': '0600',
            'finding': r'If\s+(?:the\s+permissions\s+are\s+not\s+0?600|log_file_mode\s+is\s+not\s+0?600),\s+this\s+is\s+a\s+finding',
            'fix': r'^\s*log_file_mode\s*=\s*0?600\s*$',
        },
        'V-233514': {
            'setting': 'log_file_mode',
            'expected': '0600',
            'finding': r'If\s+(?:the\s+permissions\s+are\s+not\s+0?600|log_file_mode\s+is\s+not\s+0?600),\s+this\s+is\s+a\s+finding',
            'fix': r'^\s*log_file_mode\s*=\s*0?600\s*$',
        },
        'V-233549': {
            'setting': 'log_file_mode',
            'expected': '0600',
            'finding': r'If\s+(?:the\s+permissions\s+are\s+not\s+0?600|log_file_mode\s+is\s+not\s+0?600),\s+this\s+is\s+a\s+finding',
            'fix': r'^\s*log_file_mode\s*=\s*0?600\s*$',
        },
        'V-233558': {
            'setting': 'log_connections',
            'expected': 'on',
            'finding': r'If\s+log_connections\s+is\s+off,\s+this\s+is\s+a\s+finding',
            'fix': r'^\s*log_connections\s*=\s*on\s*$',
        },
        'V-233596': {
            'setting': 'password_encryption',
            'expected': 'scram-sha-256',
            'finding': r'If\s+password_encryption\s+is\s+not\s+["“]scram-sha-256["”],\s+this\s+is\s+a\s+finding',
            'fix': r'^\s*password_encryption\s*=\s*[\'"“]?scram-sha-256[\'"”]?\s*$',
        },
        'V-233610': {
            'setting': 'log_destination',
            'expected': 'syslog',
            'finding': r'If\s+log_destination\s+is\s+not\s+[\'"“]?syslog[\'"”]?,\s+this\s+is\s+a\s+finding',
            'fix': r'^\s*log_destination\s*=\s*[\'"“]?syslog[\'"”]?\s*$',
        },
        'V-233618': {
            'setting': 'log_file_mode',
            'expected': '0600',
            'finding': r'If\s+(?:the\s+permissions\s+are\s+not\s+0?600|log_file_mode\s+is\s+not\s+0?600),\s+this\s+is\s+a\s+finding',
            'fix': r'^\s*log_file_mode\s*=\s*0?600\s*$',
        },
    }
    postgresql_show_literal = postgresql_show_literal_settings.get(rule.get('vuln_id', ''))
    if (
        'postgresql' in stig_id.lower()
        and postgresql_show_literal
        and re.search(
            rf'^\s*[$#>]\s*psql\s+-c\s+["“]SHOW\s+{re.escape(postgresql_show_literal["setting"])}\s*;?["”]\s*$',
            content,
            re.MULTILINE | re.IGNORECASE,
        )
        and re.search(postgresql_show_literal['finding'], content, re.IGNORECASE)
        and re.search(postgresql_show_literal['fix'], fix_text, re.MULTILINE | re.IGNORECASE)
    ):
        setting = postgresql_show_literal['setting']
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'generic',
            'check': {'type': 'command_output', 'command': f'psql -c "SHOW {setting}"'},
            'expected': {'type': 'contains', 'substring': postgresql_show_literal['expected']},
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
    macos_policy_banner_candidate = _macos_policy_banner_candidate(rule, stig_id)
    if macos_policy_banner_candidate:
        return macos_policy_banner_candidate
    macos_remote_login_banner_candidate = _macos_remote_login_banner_candidate(rule, stig_id)
    if macos_remote_login_banner_candidate:
        return macos_remote_login_banner_candidate
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
    nfs_fstab_mount_candidate = _nfs_fstab_mount_option_candidate(rule, stig_id)
    if nfs_fstab_mount_candidate:
        return nfs_fstab_mount_candidate

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
        and re.fullmatch(r'(?:e?grep\s+(?:-i\s+|-E\s+)?(?:"\^SHA_CRYPT_"|sha_crypt)|grep\s+-E\s+"\^SHA_CRYPT_")\s+/etc/login\.defs', command, re.IGNORECASE)
        and (
            re.search(r'"SHA_CRYPT_MIN_ROUNDS"\s+or\s+"SHA_CRYPT_MAX_ROUNDS"\s+is\s+less\s+than\s+"100000",?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE)
            or re.search(r'If\s+only\s+one\s+of\s+"SHA_CRYPT_MIN_ROUNDS"\s+or\s+"SHA_CRYPT_MAX_ROUNDS"\s+is\s+set,\s+and\s+this\s+value\s+is\s+below\s+"100000",\s+this\s+is\s+a\s+finding\.\s*If\s+both\s+"SHA_CRYPT_MIN_ROUNDS"\s+and\s+"SHA_CRYPT_MAX_ROUNDS"\s+are\s+set,\s+and\s+the\s+(?:highest\s+)?value\s+for\s+either\s+is\s+below\s+"100000",\s+this\s+is\s+a\s+finding', content, re.IGNORECASE | re.DOTALL)
        )
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
        r'Use\s+the\s+Windows\s+Registry(?:\s+Editor)?\s+to\s+navigate\s+to\s+the\s+following\s+key:\s*\n+\s*((?:HKCU|HKLM)\\[^\n\r]+)',
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
            r'If\s+(?:the\s+)?value\s+for\s+["“]?([A-Za-z0-9_.-]+)["”]?\s+is\s+(?:set\s+to\s+)?["“]?REG_DWORD\s*=\s*(\d+)["”]?,\s+this\s+is\s+not\s+a\s+finding\.',
            content,
            re.IGNORECASE,
        )
    if expected_match:
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
    exact_reg_sz_match = re.search(
        r'If\s+(?:the\s+)?value\s+["“]?([A-Za-z0-9_.-]+)["”]?\s+is\s+(?:set\s+to\s+)?REG_SZ\s*=\s+["“]([^"”\n]+)["”],\s+this\s+is\s+not\s+a\s+finding\.',
        content,
        re.IGNORECASE,
    )
    if exact_reg_sz_match:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': _normalize_registry_path(path_match.group(1)),
                'value_name': exact_reg_sz_match.group(1),
            },
            'expected': {'type': 'equals', 'value': exact_reg_sz_match.group(2)},
            'description': rule.get('title', ''),
        }
    dword_at_least_match = re.search(
        r'If\s+(?:the\s+)?value\s+for\s+["“]?([A-Za-z0-9_.-]+)["”]?\s+is\s+set\s+to\s+(\d+)\s+or\s+above,\s+this\s+is\s+not\s+a\s+finding\.',
        content,
        re.IGNORECASE,
    )
    if dword_at_least_match and int(dword_at_least_match.group(2)) == 168:
        return {
            'vuln_id': rule.get('vuln_id', ''),
            'platform': 'windows',
            'check': {
                'type': 'registry',
                'path': _normalize_registry_path(path_match.group(1)),
                'value_name': dword_at_least_match.group(1),
            },
            'expected': {'type': 'matches', 'pattern': '^(?:1(?:6[8-9]|[7-9]\\d)|[2-9]\\d{2,}|\\d{4,})$'},
            'description': rule.get('title', ''),
        }
    return None


def _office_registry_absent_or_dword_value_candidate(rule: dict, stig_id: str) -> dict | None:
    return _windows_registry_absent_or_dword_value_candidate(rule, stig_id)


def _powershell_registry_absent_or_dwords_command(path: str, required_values: dict[str, int], absent_value: str | None = None) -> str:
    ps_path = _normalize_registry_path(path).replace('HKLM\\', 'HKLM:\\').replace('HKCU\\', 'HKCU:\\')
    absent_value = absent_value or next(iter(required_values))
    checks = ' -and '.join(
        f"([int]$item.'{name}' -eq {value})" for name, value in required_values.items()
    )
    return (
        f"powershell -NoProfile -Command \"$p='{ps_path}'; "
        f"$item=Get-ItemProperty -Path $p -ErrorAction SilentlyContinue; "
        f"if (-not $item -or -not ($item.PSObject.Properties.Name -contains '{absent_value}')) {{ 'Compliant' }} "
        f"elseif ({checks}) {{ 'Compliant' }}\""
    )


def _office_forms3_absent_or_dword_one_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'office' not in stig_id.lower() or rule.get('vuln_id') != 'V-223295':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    path_match = re.search(
        r'Use\s+the\s+Windows\s+Registry\s+Editor\s+to\s+navigate\s+to\s+the\s+following\s+key:\s*\n+\s*((?:HKCU|HKLM)\\[^\n\r]+)',
        content,
        re.IGNORECASE,
    )
    if not path_match:
        return None
    if not re.search(r'If\s+the\s+value\s+LoadControlsInForms\s+is\s+REG_DWORD\s*=\s*1,\s+this\s+is\s+not\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+the\s+value\s+LoadControlsInForms\s+does\s+not\s+exist,\s+this\s+is\s+not\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'Load\s+Controls\s+in\s+Forms3', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': _powershell_registry_absent_or_dwords_command(path_match.group(1), {'LoadControlsInForms': 1}),
        },
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _office_file_validation_protected_view_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'office' not in stig_id.lower() or rule.get('vuln_id') not in {'V-223342', 'V-223388', 'V-223404'}:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    path_match = re.search(
        r'Use\s+the\s+Windows\s+Registry\s+Editor\s+to\s+navigate\s+to\s+the\s+following\s+key:\s*\n+\s*((?:HKCU|HKLM)\\[^\n\r]+)',
        content,
        re.IGNORECASE,
    )
    if not path_match:
        return None
    if not re.search(r'If\s+the\s+value\s+openinprotectedview\s+does\s+not\s+exist,\s+this\s+is\s+not\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+both\s+the\s+value\s+for\s+openinprotectedview\s+is\s+REG_DWORD\s*=\s*1\s+and\s+the\s+value\s+for\s+DisableEditFromPV\s+is\s+set\s+to\s+REG_DWORD\s*=\s*1,\s+this\s+is\s+not\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'Open\s+in\s+Protected\s+View', fix_text, re.IGNORECASE) or not re.search(r'Allow\s+edit', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': _powershell_registry_absent_or_dwords_command(
                path_match.group(1), {'openinprotectedview': 1, 'DisableEditFromPV': 1}, 'openinprotectedview'
            ),
        },
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _office_exchange_kerberos_authentication_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'office' not in stig_id.lower() or rule.get('vuln_id') != 'V-223346':
        return None
    content = rule.get('check_content', '') or ''
    path_match = re.search(
        r'Use\s+the\s+Windows\s+Registry\s+Editor\s+to\s+navigate\s+to\s+the\s+following\s+key:\s*\n+\s*((?:HKCU|HKLM)\\[^\n\r]+)',
        content,
        re.IGNORECASE,
    )
    expected_match = re.search(
        r'If\s+the\s+value\s+authenticationservice\s+is\s+set\s+to\s+REG_DWORD\s*=\s*16\s+\(decimal\)\s+or\s+10\s+\(hex\),\s+this\s+is\s+not\s+a\s+finding',
        content,
        re.IGNORECASE,
    )
    if not path_match or not expected_match:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'registry',
            'path': _normalize_registry_path(path_match.group(1)),
            'value_name': 'authenticationservice',
        },
        'expected': {'type': 'equals', 'value': 16},
        'description': rule.get('title', ''),
    }


def _oracle_sqlplus_command(select_sql: str) -> str:
    return (
        "sqlplus -s / as sysdba <<'SQL'\n"
        "SET HEADING OFF FEEDBACK OFF PAGESIZE 0 VERIFY OFF ECHO OFF\n"
        f"{select_sql}\n"
        "EXIT\n"
        "SQL"
    )


def _oracle_database_public_empty_result_candidate(rule: dict, stig_id: str) -> dict | None:
    if not re.search(r'oracle[_\s-]+database', stig_id, re.IGNORECASE):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    allowed = {
        'V-270528': {
            'title': 'System Privileges must not be granted to PUBLIC.',
            'content_pattern': r"Select\s+privilege\s+from\s+dba_sys_privs\s+where\s+grantee\s*=\s*'PUBLIC'",
            'finding_pattern': r'If\s+any\s+records\s+are\s+returned,\s+this\s+is\s+a\s+finding\.',
            'fix_pattern': r'revoke\s+\[system\s+privilege\]\s+from\s+PUBLIC',
            'sql': "SELECT privilege FROM dba_sys_privs WHERE grantee = 'PUBLIC';",
        },
        'V-270532': {
            'title': 'Application role permissions must not be assigned to the Oracle PUBLIC role.',
            'content_pattern': r"select\s+granted_role\s+from\s+dba_role_privs\s+where\s+grantee\s*=\s*'PUBLIC'",
            'finding_pattern': r'If\s+any\s+roles\s+are\s+listed,\s+this\s+is\s+a\s+finding\.',
            'fix_pattern': r'Revoke\s+role\s+grants\s+from\s+PUBLIC',
            'sql': "SELECT granted_role FROM dba_role_privs WHERE grantee = 'PUBLIC';",
        },
        'V-270545': {
            'title': 'Oracle Database default accounts must be assigned custom passwords.',
            'content_pattern': r'SELECT\s+\*\s+FROM\s+SYS\.DBA_USERS_WITH_DEFPWD',
            'finding_pattern': r'If\s+any\s+accounts\s+other\s+than\s+XS\$NULL\s+are\s+listed,\s+this\s+is\s+a\s+finding\.',
            'fix_pattern': r'Change\s+passwords\s+for\s+database\s+management\s+system\s+\(DBMS\)\s+accounts\s+to\s+nondefault\s+values',
            'sql': "SELECT username FROM SYS.DBA_USERS_WITH_DEFPWD WHERE username <> 'XS$NULL';",
        },
    }
    expected = allowed.get(vuln_id)
    if not expected:
        return None
    if rule.get('title', '').strip().lower() != expected['title'].lower():
        return None
    if not re.search(expected['content_pattern'], content, re.IGNORECASE):
        return None
    if not re.search(expected['finding_pattern'], content, re.IGNORECASE):
        return None
    if not re.search(expected['fix_pattern'], fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'generic',
        'check': {'type': 'command_output', 'command': _oracle_sqlplus_command(expected['sql'])},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _oracle_database_exact_parameter_candidate(rule: dict, stig_id: str) -> dict | None:
    if not re.search(r'oracle[_\s-]+database', stig_id, re.IGNORECASE):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    allowed = {
        'V-270524': ('remote_os_roles', 'FALSE'),
        'V-270525': ('sql92_security', 'TRUE'),
        'V-270535': ('_trace_files_public', 'FALSE'),
    }
    expected = allowed.get(vuln_id)
    if not expected:
        return None
    parameter, value = expected
    if not re.search(r'(?:^|[^A-Za-z0-9])(?:v_?\$parameter|gv_\$parameter)(?:[^A-Za-z0-9]|$)', content, re.IGNORECASE):
        return None
    if not re.search(rf"['\"]{re.escape(parameter)}['\"]", content, re.IGNORECASE):
        return None
    if not re.search(rf'PARAMETER_VALUE\s+is\s+not\s+{re.escape(value)}|value\s+returned\s+is\s+set\s+to\s+{("FALSE" if value == "TRUE" else "TRUE")}|value\s+returned\s+is\s+{("TRUE" if value == "FALSE" else "FALSE")}', content, re.IGNORECASE):
        return None
    if not re.search(rf'ALTER\s+SYSTEM\s+SET\s+{re.escape(parameter)}\s*=\s*{re.escape(value)}\b|remove\s+the\s+following\s+line:\s*\*\.{re.escape(parameter)}\s*=\s*{("TRUE" if value == "FALSE" else "FALSE")}', fix_text, re.IGNORECASE):
        return None
    command = (
        "sqlplus -s / as sysdba <<'SQL'\n"
        "SET HEADING OFF FEEDBACK OFF PAGESIZE 0 VERIFY OFF ECHO OFF\n"
        f"SELECT value FROM v$parameter WHERE LOWER(name) = '{parameter}';\n"
        "EXIT\n"
        "SQL"
    )
    return {
        'vuln_id': vuln_id,
        'platform': 'generic',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': value},
        'description': rule.get('title', ''),
    }


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


def _sql_server_audit_action_groups_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'sql_server' not in stig_id.lower() and 'sql server' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-271351', 'V-271370', 'V-271375'}:
        return None
    if not re.search(r'sys\.server_audit_specification_details', content, re.IGNORECASE):
        return None
    if not re.search(r'identified\s+groups?\s+.*?not\s+returned.*?this\s+is\s+a\s+finding', content, re.IGNORECASE | re.DOTALL):
        return None
    if not re.search(r'add\s+the\s+required\s+events\s+to\s+the\s+server\s+audit\s+specification', fix_text, re.IGNORECASE):
        return None
    in_match = re.search(r'd\.audit_action_name\s+IN\s*\((.*?)\)', content, re.IGNORECASE | re.DOTALL)
    if not in_match:
        return None
    groups = re.findall(r"'([A-Z0-9_]+_GROUP)'", in_match.group(1))
    if not groups or len(set(groups)) != len(groups):
        return None
    if any(not re.fullmatch(r'[A-Z0-9_]+_GROUP', group) for group in groups):
        return None
    values = ', '.join(f"('{group}')" for group in groups)
    command = (
        'sqlcmd -h -1 -W -Q "SET NOCOUNT ON; '
        f'WITH required(name) AS (SELECT v.name FROM (VALUES {values}) AS v(name)) '
        'SELECT name FROM required EXCEPT SELECT d.audit_action_name '
        'FROM sys.server_audit_specifications s '
        'JOIN sys.server_audits a ON s.audit_guid = a.audit_guid '
        'JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id '
        'WHERE a.is_state_enabled = 1;"'
    )
    return {
        'vuln_id': vuln_id,
        'platform': 'generic',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _sql_server_sa_login_disabled_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'sql_server' not in stig_id.lower() and 'sql server' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    if title.strip().lower() != 'the sql server default account [sa] must be disabled.':
        return None
    if not re.search(r'FROM\s+sys\.sql_logins\s+WHERE\s+principal_id\s*=\s*1', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+the\s+["“]is_disabled["”]\s+column\s+is\s+not\s+set\s+to\s+["“]?1["”]?,?\s+this\s+is\s+a\s+finding\.', content, re.IGNORECASE):
        return None
    if not re.search(r'ALTER\s+LOGIN\s+\[sa\]\s+DISABLE', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': 'sqlcmd -h -1 -W -Q "SET NOCOUNT ON; SELECT CAST(is_disabled AS varchar(1)) FROM sys.sql_logins WHERE principal_id = 1;"',
        },
        'expected': {'type': 'equals', 'value': '1'},
        'description': rule.get('title', ''),
    }


def _sql_server_audit_status_started_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'sql_server' not in stig_id.lower() and 'sql server' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if rule.get('vuln_id', '') != 'V-271273':
        return None
    if not re.search(r'FROM\s+sys\.dm_server_audit_status\s+WHERE\s+status_desc\s*=\s*[\'"“]STARTED[\'"”]', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+no\s+audits\s+are\s+returned,?\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'ALTER\s+SERVER\s+AUDIT\s+\[<Server\s+Audit\s+Name>\]\s+WITH\s+STATE\s*=\s*ON', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': "sqlcmd -h -1 -W -Q \"SET NOCOUNT ON; SELECT name FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED';\"",
        },
        'expected': {'type': 'not_equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _sql_server_common_criteria_enabled_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'sql_server' not in stig_id.lower() and 'sql server' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if rule.get('vuln_id', '') != 'V-271328':
        return None
    if not re.search(r'FROM\s+sys\.configurations\s+WHERE\s+name\s*=\s*[\'"“]common\s+criteria\s+compliance\s+enabled[\'"”]', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+["“]value_in_use["”]\s+is\s+set\s+to\s+["“]1["”]\s+this\s+is\s+not\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+["“]value_in_use["”]\s+is\s+set\s+to\s+["“]0["”]\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r"SP_CONFIGURE\s+[\'\"]common\s+criteria\s+compliance\s+enabled[\'\"]\s*,\s*1", fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': "sqlcmd -h -1 -W -Q \"SET NOCOUNT ON; SELECT CAST(value_in_use AS varchar(1)) FROM sys.configurations WHERE name = 'common criteria compliance enabled';\"",
        },
        'expected': {'type': 'equals', 'value': '1'},
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


def _adobe_reader_dc_block_websites_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id != 'V-213172':
        return None
    title = rule.get('title', '') or ''
    combined = '\n'.join(part for part in (rule.get('check_content', '') or '', rule.get('fix_text', '') or '') if part)
    if 'reader' not in stig_id.lower() and 'reader' not in title.lower():
        return None
    expected_path = r'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms'
    normalized = combined.lower().replace('\\\\', '\\')
    if f'hkey_local_machine\\{expected_path}'.lower() not in normalized and f'\\{expected_path}'.lower() not in normalized:
        return None
    if not re.search(r'Value\s+Name:\s*iURLPerms\b', combined, re.IGNORECASE):
        return None
    if not re.search(r'Type:\s*REG_DWORD\b', combined, re.IGNORECASE):
        return None
    if not re.search(r'Value:\s*1\b', combined, re.IGNORECASE):
        return None
    if not re.search(r'iURLPerms[^\n.]+not\s+set\s+to\s+["“]?1["”]?[^\n.]+finding', combined, re.IGNORECASE):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {
            'type': 'registry',
            'path': f'HKLM\\{expected_path}',
            'value_name': 'iURLPerms',
        },
        'expected': {'type': 'equals', 'value': 1},
        'description': title,
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


def _windows_dep_bcdedit_at_least_optout_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    policy_text = '\n'.join(part for part in (content, fix_text) if part)
    if not re.search(r'Data\s+Execution\s+Prevention\s+\(DEP\)\s+must\s+be\s+configured\s+to\s+at\s+least\s+OptOut', title, re.IGNORECASE):
        return None
    required_patterns = (
        r'BCDEdit\s+/enum\s+\{current\}',
        r'value\s+for\s+["“]nx["”]\s+is\s+not\s+["“]OptOut["”],\s+this\s+is\s+a\s+finding',
        r'more\s+restrictive\s+configuration\s+of\s+["“]AlwaysOn["”]\s+would\s+not\s+be\s+a\s+finding',
        r'BCDEDIT\s+/set\s+\{current\}\s+nx\s+OptOut',
    )
    if not all(re.search(pattern, policy_text, re.IGNORECASE) for pattern in required_patterns):
        return None
    command = 'powershell -NoProfile -Command "(bcdedit /enum `{current`}) | ForEach-Object { if ($_ -match \'^\\s*nx\\s+(OptOut|AlwaysOn)\\s*$\') { \'Compliant\' } }"'
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': title,
    }


def _defender_av_get_mppreference_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'defender' not in stig_id.lower():
        return None
    vuln_id = rule.get('vuln_id', '')
    title = rule.get('title', '') or ''
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = '\n'.join(part for part in (content, fix_text) if part)
    preference_map = {
        'V-278657': ('Turn off routine remediation', 'DisableRoutinelyTakingAction', 'False'),
        'V-278663': ('Turn on behavior monitoring', 'DisableBehaviorMonitoring', 'False'),
        'V-278664': ('Scan all downloaded files and attachments', 'DisableIOAVProtection', 'False'),
        'V-278665': ('Monitor file and program activity on your computer', 'DisableOnAccessProtection', 'False'),
        'V-278666': ('Turn off real-time protection', 'DisableRealtimeMonitoring', 'False'),
        'V-278667': ('Turn on process scanning whenever real-time protection is enabled', 'DisableProcessScanning', 'False'),
        'V-278670': ('Configure monitoring for incoming and outgoing file and program activity', 'RealTimeScanDirection', '0'),
        'V-278671': ('Configure Controlled folder access', 'EnableControlledFolderAccess', 'not_disabled'),
    }
    if vuln_id not in preference_map:
        return None
    policy_name, preference_name, expected_value = preference_map[vuln_id]
    if policy_name.lower() not in combined.lower():
        return None
    if vuln_id in {'V-278657', 'V-278666'}:
        if not re.search(re.escape(policy_name) + r'[^\n.]+is\s+set\s+to\s+["“]Disabled["”]', content, re.IGNORECASE):
            return None
        if not re.search(re.escape(policy_name) + r'[^\n.]+to\s+["“]Disabled["”]', fix_text, re.IGNORECASE):
            return None
    elif vuln_id == 'V-278670':
        if not re.search(re.escape(policy_name) + r'[^\n.]+is\s+set\s+to\s+["“]Enabled["”][^\n.]+bi-directional\s+\(full\s+on-access\)', content, re.IGNORECASE):
            return None
        if not re.search(re.escape(policy_name) + r'[^\n.]+to\s+["“]Enabled["”]', fix_text, re.IGNORECASE):
            return None
        if not re.search(r'policy\s+option\s+(?:to|of)\s+["“]bi-directional\s+\(full\s+on-access\)["”]', fix_text, re.IGNORECASE):
            return None
    elif vuln_id == 'V-278671':
        if not re.search(re.escape(policy_name) + r'[^\n.]+is\s+set\s+to\s+["“]Enabled["”][^\n.]+Audit\s+Mode', content, re.IGNORECASE):
            return None
        if not re.search(r'All\s+other\s+policy\s+options\s+aside\s+from\s+["“]Disable["”]\s+are\s+allowed', content, re.IGNORECASE):
            return None
        if not re.search(r'policy\s+option\s+for\s+["“]Configure\s+Controlled\s+folder\s+access["”]\s+is\s+set\s+to\s+["“]Disable["”],\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        if not re.search(re.escape(policy_name) + r'[^\n.]+to\s+["“]Enabled["”]', fix_text, re.IGNORECASE):
            return None
        if not re.search(r'policy\s+option\s+value\s+to\s+["“]Audit\s+Mode["”]\s+or\s+anything\s+other\s+than\s+["“]Disable["”]', fix_text, re.IGNORECASE):
            return None
    else:
        if not re.search(re.escape(policy_name) + r'[^\n.]+is\s+set\s+to\s+["“]Enabled["”]', content, re.IGNORECASE):
            return None
        if not re.search(re.escape(policy_name) + r'[^\n.]+to\s+["“]Enabled["”]', fix_text, re.IGNORECASE):
            return None
    expected = {'type': 'equals', 'value': expected_value}
    command = f'powershell -NoProfile -Command "(Get-MpPreference).{preference_name}"'
    if expected_value == 'not_disabled':
        expected = {'type': 'equals', 'value': 'Compliant'}
        command = 'powershell -NoProfile -Command "if ((Get-MpPreference).EnableControlledFolderAccess -ne 0) { \'Compliant\' }"'
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': expected,
        'description': title,
    }


def _windows_event_log_size_minimum_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    vuln_match = re.search(r'V-\d+', vuln_id)
    allowed_vulns = {
        'V-254358', 'V-254359', 'V-254360',
        'V-205796', 'V-205797', 'V-205798',
        'V-253337', 'V-253338', 'V-253339',
        'V-220779', 'V-220781',
    }
    if not vuln_match or vuln_match.group(0) not in allowed_vulns:
        return None
    title = rule.get('title', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = '\n'.join(part for part in (title, fix_text) if part)
    log_match = re.search(r'\b(Application|Security|System)\s+event\s+log\s+size\s+must\s+be\s+configured\s+to', title, re.IGNORECASE)
    if not log_match:
        return None
    size_match = re.search(r'Maximum\s+Log\s+Size\s*\(KB\)["”]?\s+of\s+["“]?(\d+)["”]?\s+or\s+greater', fix_text, re.IGNORECASE)
    if not size_match:
        size_match = re.search(r'event\s+log\s+size\s+must\s+be\s+configured\s+to\s+(\d+)\s+KB\s+or\s+greater', combined, re.IGNORECASE)
    if not size_match:
        return None
    log_name = log_match.group(1).capitalize()
    minimum_kb = int(size_match.group(1))
    if minimum_kb <= 0:
        return None
    command = (
        'powershell -NoProfile -Command '
        f'"$log=\'{log_name}\'; $minKb={minimum_kb}; $cfg=wevtutil gl $log; '
        "$max=($cfg | Select-String -Pattern '^maxSize:\\s*(\\d+)' | ForEach-Object { [int64]$_.Matches[0].Groups[1].Value } | Select-Object -First 1); "
        "if ($max -ge ($minKb * 1024)) { 'Compliant' }\""
    )
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': title,
    }


def _windows_event_log_file_acl_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    policy_text = '\n'.join(part for part in (content, fix_text) if part)
    log_match = re.search(r'permissions\s+for\s+the\s+(Application|Security|System)\s+event\s+log\s+must\s+prevent\s+access\s+by\s+non[- ]?privileged\s+accounts', title, re.IGNORECASE)
    if not log_match:
        return None
    log_name = log_match.group(1).capitalize()
    if f'{log_name}.evtx' not in policy_text:
        return None
    if not re.search(re.escape(r'%SystemRoot%\System32\winevt\Logs'), policy_text, re.IGNORECASE):
        return None
    required_acl_lines = (
        r'Eventlog\s+-\s+Full\s+Control',
        r'SYSTEM\s+-\s+Full\s+Control',
        r'Administrators\s+-\s+Full\s+Control',
    )
    if not all(re.search(line, policy_text, re.IGNORECASE) for line in required_acl_lines):
        return None
    finding_patterns = (
        r'If\s+the\s+permissions\s+for\s+the\s+["“]' + re.escape(f'{log_name}.evtx') + r'["”]\s+file\s+are\s+not\s+as\s+restrictive\s+as\s+the\s+default\s+permissions\s+listed\s+below,\s+this\s+is\s+a\s+finding',
        r'If\s+the\s+permissions\s+for\s+these\s+files\s+are\s+not\s+as\s+restrictive\s+as\s+the\s+ACLs\s+listed,\s+this\s+is\s+a\s+finding',
    )
    if not any(re.search(pattern, content, re.IGNORECASE) for pattern in finding_patterns):
        return None
    fix_patterns = (
        r'Configure\s+the\s+permissions\s+on\s+the\s+' + re.escape(log_name) + r'\s+event\s+log\s+file',
        r'(?:Ensure|Configure)\s+the\s+permissions\s+on\s+the\s+' + re.escape(log_name) + r'\s+event\s+log\s+\(' + re.escape(f'{log_name}.evtx') + r'\)\s+are\s+configured\s+to\s+prevent\s+standard\s+user\s+accounts\s+or\s+groups\s+from\s+having\s+access',
    )
    if not any(re.search(pattern, fix_text, re.IGNORECASE) for pattern in fix_patterns):
        return None
    command = (
        'powershell -NoProfile -Command '
        f'"$log=\'{log_name}\'; $line=wevtutil gl $log | Select-String -Pattern \'^\\s*logFileName:\' | Select-Object -First 1; '
        "$p=($line.Line -replace '^\\s*logFileName:\\s*',''); $p=[Environment]::ExpandEnvironmentVariables($p); "
        "$acl=Get-Acl -LiteralPath $p; $need=@('NT SERVICE\\EventLog','NT AUTHORITY\\SYSTEM','BUILTIN\\Administrators'); "
        "$ok=$true; foreach ($n in $need) { if (-not ($acl.Access | Where-Object { $_.IdentityReference -eq $n -and $_.FileSystemRights.ToString() -match 'FullControl' })) { $ok=$false } }; "
        "if ($ok) { 'Compliant' }\""
    )
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': title,
    }


def _windows_event_viewer_executable_acl_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    if rule.get('vuln_id') != 'V-254299':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    policy_text = '\n'.join(part for part in (content, fix_text) if part)
    if not re.search(r'Event\s+Viewer\s+must\s+be\s+protected\s+from\s+unauthorized\s+modification\s+and\s+deletion', title, re.IGNORECASE):
        return None
    required_phrases = (
        r'View\s+the\s+permissions\s+on\s+["“]Eventvwr\.exe["”]',
        r'If\s+any\s+groups\s+or\s+accounts\s+other\s+than\s+TrustedInstaller\s+have\s+["“]Full\s+control["”]\s+or\s+["“]Modify["”]\s+permissions,\s+this\s+is\s+a\s+finding',
        r'TrustedInstaller\s+-\s+Full\s+Control',
        r'Administrators,\s+SYSTEM,\s+Users,\s+ALL\s+APPLICATION\s+PACKAGES,\s+ALL\s+RESTRICTED\s+APPLICATION\s+PACKAGES\s+-\s+Read\s+&\s+Execute',
        r'%SystemRoot%\\System32',
    )
    if not all(re.search(phrase, policy_text, re.IGNORECASE) for phrase in required_phrases):
        return None
    if not re.search(r'Configure\s+the\s+permissions\s+on\s+the\s+["“]Eventvwr\.exe["”]\s+file\s+to\s+prevent\s+modification\s+by\s+any\s+groups\s+or\s+accounts\s+other\s+than\s+TrustedInstaller', fix_text, re.IGNORECASE):
        return None
    command = (
        'powershell -NoProfile -Command '
        '"$p=Join-Path $env:SystemRoot \'System32\\Eventvwr.exe\'; $acl=Get-Acl -LiteralPath $p; '
        '$violations=$acl.Access | Where-Object { ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -and ($_.IdentityReference -notmatch \'TrustedInstaller$\') }; '
        "if (-not $violations) { 'Compliant' }\""
    )
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': title,
    }


def _tomcat_service_account_nologin_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'tomcat' not in stig_id.lower() or rule.get('vuln_id') != 'V-222983':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    if not re.search(r'cat\s+/etc/passwd\s*\|\s*grep\s+-i\s+tomcat', content, re.IGNORECASE):
        return None
    if not re.search(r'command/shell\s+field\s+of\s+the\s+passwd\s+file\s+is\s+not\s+set\s+to\s+["“]/usr/sbin/nologin["”]', content, re.IGNORECASE):
        return None
    if not re.search(r'usermod\s+-s\s+/usr/sbin/nologin\s+tomcat', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': "getent passwd tomcat | awk -F: '{print $7}'"},
        'expected': {'type': 'equals', 'value': '/usr/sbin/nologin'},
        'description': title,
    }


def _tomcat_fips_mode_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'tomcat' not in stig_id.lower() or rule.get('vuln_id') != 'V-222968':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    title = rule.get('title', '') or ''
    if not all(token in content for token in ('$CATALINA_BASE/conf/server.xml', '$CATALINA_BASE/logs/catalina.out')):
        return None
    if not re.search(r'server\.xml\s+does\s+not\s+contain\s+FIPSMode=["“]on["”]', content, re.IGNORECASE):
        return None
    if not re.search(r'failed\s+to\s+set\s+property\[FIPSMODE\]\s+to\s+\[on\]', content, re.IGNORECASE):
        return None
    if not re.search(r'FIPSMode\s*=\s*["“]on["”]', fix_text, re.IGNORECASE):
        return None
    command = 'sh -c "grep -Eiq \'FIPSMode[[:space:]]*=[[:space:]]*\\"on\\"\' \\"$CATALINA_BASE/conf/server.xml\\" && ! grep -Eiq \'failed to set property\\\\[FIPSMODE\\\\] to \\\\[on\\\\]\' \\"$CATALINA_BASE/logs/catalina.out\\" && printf Compliant"'
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': title,
    }


def _tomcat_web_xml_boolean_param_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'tomcat' not in stig_id.lower():
        return None
    content = rule.get('check_content', '') or ''
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-222928', 'V-222953', 'V-222954'}:
        return None
    command_match = re.search(
        r'(?:^|\n)\s*(?:[$#>]\s*)?(?:sudo\s+)?(?:cat\s+)?(?:(?P<path>\$CATALINA_BASE/conf/web\.xml)\s*\|?\s*)?grep\s+-i\s+(?P<after>-A\d+)\s+(?P<before>-B\d+)\s+(?P<token>[A-Za-z0-9_.-]+)(?:\s+\$CATALINA_BASE/conf/web\.xml(?:\s+file\.?)?)?\s*(?:\n|$)',
        content,
        re.IGNORECASE,
    )
    if not command_match:
        return None
    finding_match = re.search(
        r'If\s+(?:[^.]*?\bor\s+if\s+)?(?:the\s+)?["“]?(?P<param>[A-Za-z0-9_.-]+)["”]?\s+(?:param-value\s+)?(?:for\s+the\s+["“]DefaultServlet["”]\s+servlet\s+class\s+)?(?:does\s+not\s+=|is\s+not\s+set\s+to)\s+["“]?(?P<value>true|false|0)["”]?,?\s+this\s+is\s+a\s+finding\.',
        content,
        re.IGNORECASE,
    )
    if not finding_match:
        return None
    param = finding_match.group('param')
    value = finding_match.group('value').lower()
    token = command_match.group('token')
    if vuln_id == 'V-222928':
        if param.lower() not in {'hstsenable', 'hstsenabled'} or token.lower() != 'hstsenable':
            return None
        param = 'hstsEnabled'
    elif token.lower() != 'defaultservlet' or param.lower() not in {'debug', 'listings'}:
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'generic',
        'check': {
            'type': 'command_output',
            'command': f'grep -i {command_match.group("after")} {command_match.group("before")} {token} $CATALINA_BASE/conf/web.xml',
        },
        'expected': {'type': 'contains', 'substring': f'<param-name>{param}</param-name>\n<param-value>{value}</param-value>'},
        'description': rule.get('title', ''),
    }


def _windows_bluetooth_support_service_disabled_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id) or rule.get('vuln_id', '') != 'V-278018':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not re.search(r'Bluetooth\s+Support\s+Service', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+this\s+is\s+set\s+to\s+["“]automatic["”],?\s+this\s+is\s+a\s+finding\.', content, re.IGNORECASE):
        return None
    if not re.search(r'Bluetooth\s+Support\s+Service[^.]+set\s+this\s+to\s+["“]Disabled["”]', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': "powershell -NoProfile -Command \"$svc=Get-CimInstance Win32_Service -Filter \\\"Name='bthserv'\\\" -ErrorAction SilentlyContinue; if (-not $svc -or $svc.StartMode -eq 'Disabled' -or $svc.StartMode -eq 'Manual') { 'Compliant' }\"",
        },
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
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


def _iis_session_state_use_cookies_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id != 'V-218804' or stig_id != 'IIS_10-0_Server_STIG':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    policy_text = '\n'.join(part for part in (content, fix_text) if part)
    if not re.search(r'system\.web/sessionState', policy_text, re.IGNORECASE):
        return None
    if not re.search(r'\bcookieless\b[^.\n]*(?:is\s+set\s+to|to)\s+["“]?UseCookies["”]?', policy_text, re.IGNORECASE):
        return None
    if not re.search(r'If\s+the\s+["“]?cookieless["”]?\s+is\s+not\s+set\s+to\s+["“]?UseCookies["”]?,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {
            'type': 'command_output',
            'command': r'%windir%\system32\inetsrv\appcmd.exe list config /section:system.web/sessionState /text:cookieless',
        },
        'expected': {'type': 'equals', 'value': 'UseCookies'},
        'description': rule.get('title', ''),
    }


def _iis_hsts_site_defaults_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id != 'V-218827' or stig_id != 'IIS_10-0_Server_STIG':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = f'{content}\n{fix_text}'
    required_check_snippets = (
        r'system\.applicationHost/sites',
        r'siteDefaults\s+and\s+HSTS',
        r'If\s+enabled\s+is\s+not\s+set\s+to\s+True,\s+this\s+is\s+a\s+finding',
        r'If\s+includeSubDomains\s+is\s+not\s+set\s+to\s+True,\s+this\s+is\s+a\s+finding',
        r'If\s+max-age\s+is\s+not\s+set\s+to\s+a\s+value\s+greater\s+than\s+0,\s+this\s+is\s+a\s+finding',
        r'If\s+redirectHttpToHttps\s+is\s+not\s+True,\s+this\s+is\s+a\s+finding',
    )
    required_fix_snippets = (
        r'Powershell',
        r'Enable\s+HSTS',
        r'Set\s+includeSubDomains\s+to\s+True',
        r'Set\s+max-age\s+to\s+a\s+value\s+greater\s+than\s+0',
        r'Set\s+redirectHttpToHttps\s+to\s+True',
    )
    if not all(re.search(snippet, content, re.IGNORECASE) for snippet in required_check_snippets):
        return None
    if not all(re.search(snippet, combined, re.IGNORECASE) for snippet in required_fix_snippets):
        return None
    command = "powershell -NoProfile -Command \"Import-Module WebAdministration; $h=Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/siteDefaults/hsts' -Name '.'; if ($h.enabled -eq $true -and $h.includeSubDomains -eq $true -and [int]$h.maxAge -gt 0 -and $h.redirectHttpToHttps -eq $true) { 'Compliant' }\""
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _iis_tls_12_enabled_legacy_protocols_disabled_candidate(rule: dict, stig_id: str) -> dict | None:
    vuln_id = rule.get('vuln_id', '')
    if vuln_id != 'V-218821' or stig_id != 'IIS_10-0_Server_STIG':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = f'{content}\n{fix_text}'
    required_snippets = (
        r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS\s+1\.2\\Server',
        r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS\s+1\.0\\Server',
        r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS\s+1\.1\\Server',
        r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL\s+3\.0\\Server',
        r'TLS\s+1\.2[\s\S]*(?:Enabled["”]?\s+with\s+a\s+value\s+of\s+["“]?1|Enabled\s*=\s*1|use\s+Enabled\s*=\s*1)',
        r'TLS\s+1\.2[\s\S]*(?:DisabledByDefault["”]?\s+with\s+a\s+value\s+of\s+["“]?0|DisabledByDefault\s*=\s*0|use\s+Enabled\s*=\s*1\s+and\s+DisabledByDefault\s*=\s*0)',
        r'For\s+each\s+protocol:[\s\S]*(?:Enabled["”]?\s+with\s+a\s+value\s+of\s+["“]?0|Enabled\s*=\s*0)',
        r'For\s+each\s+protocol:[\s\S]*(?:DisabledByDefault["”]?\s+with\s+a\s+value\s+of\s+["“]?1|DisabledByDefault\s*=\s*1)',
        r'If\s+any\s+of\s+the\s+respective\s+registry\s+paths\s+do\s+not\s+exist\s+or\s+are\s+configured\s+with\s+the\s+wrong\s+value,\s+this\s+is\s+a\s+finding',
    )
    if not all(re.search(snippet, combined, re.IGNORECASE) for snippet in required_snippets):
        return None
    command = "powershell -NoProfile -Command \"$expected=@{'TLS 1.2'=@{Enabled=1;DisabledByDefault=0};'TLS 1.0'=@{Enabled=0;DisabledByDefault=1};'TLS 1.1'=@{Enabled=0;DisabledByDefault=1};'SSL 3.0'=@{Enabled=0;DisabledByDefault=1}}; foreach($protocol in $expected.Keys){$path='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\'+$protocol+'\\Server'; $item=Get-ItemProperty -Path $path -ErrorAction SilentlyContinue; if(-not $item){exit 1}; foreach($name in $expected[$protocol].Keys){ if([int]$item.$name -ne [int]$expected[$protocol][$name]){exit 1}}}; 'Compliant'\""
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _iis_server_exact_candidate(rule: dict, stig_id: str) -> dict | None:
    if stig_id != 'IIS_10-0_Server_STIG':
        return None
    vuln_id = rule.get('vuln_id', '')
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = '\n'.join(part for part in (content, fix_text, rule.get('title', '') or '') if part)

    if vuln_id == 'V-218808':
        if not re.search(r'Directory\s+Browsing', combined, re.IGNORECASE):
            return None
        if not re.search(r'If\s+["“]?Directory\s+Browsing["”]?\s+is\s+not\s+disabled,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        if not re.search(r'(?:click|select)\s+["“]?Disabled["”]?', fix_text, re.IGNORECASE):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': r'%windir%\system32\inetsrv\appcmd.exe list config /section:system.webServer/directoryBrowse /text:enabled'},
            'expected': {'type': 'equals', 'value': 'false'},
            'description': rule.get('title', ''),
        }

    if vuln_id == 'V-218824':
        if not all(re.search(snippet, combined, re.IGNORECASE) for snippet in (r'Allow\s+unspecified\s+CGI\s+modules', r'Allow\s+unspecified\s+ISAPI\s+modules')):
            return None
        if not re.search(r'(?:If\s+either\s+or\s+both|If\s+either).*checked,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE | re.DOTALL):
            return None
        if not re.search(r'Remove\s+the\s+check\s+from', fix_text, re.IGNORECASE):
            return None
        command = "powershell -NoProfile -Command \"Import-Module WebAdministration -ErrorAction SilentlyContinue; $cgi=(Get-WebConfigurationProperty -PSPath 'IIS:\\' -Filter '/system.webServer/security/isapiCgiRestriction' -Name notListedCgisAllowed -ErrorAction SilentlyContinue).Value; $isapi=(Get-WebConfigurationProperty -PSPath 'IIS:\\' -Filter '/system.webServer/security/isapiCgiRestriction' -Name notListedIsapisAllowed -ErrorAction SilentlyContinue).Value; if (($cgi -eq $false) -and ($isapi -eq $false)) { 'Compliant' }\""
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'Compliant'},
            'description': rule.get('title', ''),
        }

    if vuln_id == 'V-241789':
        if not all(re.search(snippet, combined, re.IGNORECASE) for snippet in (r'HTTP\s+Response\s+Headers', r'X-Powered-By')):
            return None
        if not re.search(r'If\s+["“]?X-Powered-By["”]?\s+has\s+not\s+been\s+removed,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        if not re.search(r'Click\s+["“]?Remove["”]?\s+in\s+the\s+Actions\s+Panel', fix_text, re.IGNORECASE):
            return None
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': r"%windir%\system32\inetsrv\appcmd.exe list config /section:system.webServer/httpProtocol /text:customHeaders.[name='X-Powered-By'].value"},
            'expected': {'type': 'equals', 'value': ''},
            'description': rule.get('title', ''),
        }

    if vuln_id == 'V-218818':
        if not all(re.search(snippet, combined, re.IGNORECASE) for snippet in (r'Internet\s+Printing\s+Protocol', r'%windir%\\web\\printers', r'Internet\s+Printing\s+option')):
            return None
        if not re.search(r'If\s+this\s+folder\s+exists,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        if not re.search(r'If\s+the\s+Internet\s+Printing\s+option\s+is\s+enabled,\s+this\s+is\s+a\s+finding', content, re.IGNORECASE):
            return None
        if not re.search(r'Internet\s+Printing\s+option\s+is\s+checked', fix_text, re.IGNORECASE):
            return None
        command = "powershell -NoProfile -Command \"$feature=Get-WindowsFeature Web-Printing -ErrorAction SilentlyContinue; if ((-not $feature -or -not $feature.Installed) -and -not (Test-Path -LiteralPath (Join-Path $env:windir 'web\\printers'))) { 'Disabled' }\""
        return {
            'vuln_id': vuln_id,
            'platform': 'windows',
            'check': {'type': 'command_output', 'command': command},
            'expected': {'type': 'equals', 'value': 'Disabled'},
            'description': rule.get('title', ''),
        }

    return None


def _windows_local_volume_filesystem_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-277997', 'V-254250', 'V-205663', 'xccdf_mil.disa.stig_group_V-254250', 'xccdf_mil.disa.stig_group_V-205663'}:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = '\n'.join(part for part in (content, fix_text, rule.get('title', '') or '') if part)
    if not re.search(r'local\s+volumes?\s+must\s+use\s+a\s+format\s+that\s+supports\s+(?:New\s+Technology\s+File\s+System\s+\()?NTFS', combined, re.IGNORECASE):
        return None
    if not re.search(r'For\s+each\s+local\s+volume,\s+if\s+the\s+file\s+system\s+does\s+not\s+indicate\s+["“]NTFS["”],\s+this\s+is\s+a\s+finding', combined, re.IGNORECASE):
        return None
    if not re.search(r'Format\s+volumes\s+to\s+use\s+NTFS,\s+ReFS,\s+or\s+CSVFS', combined, re.IGNORECASE):
        return None
    if not all(re.search(rf'\b{fs}\b', combined, re.IGNORECASE) for fs in ('NTFS', 'ReFS', 'CSVFS')):
        return None
    command = "powershell -NoProfile -Command \"Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.FileSystemLabel -notmatch '^(?i:Recovery|EFI System Partition)$' -and $_.FileSystem -notin @('NTFS','ReFS','CSVFS') } | Select-Object -ExpandProperty DriveLetter\""
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _windows_system_drive_root_icacls_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _windows_platform(stig_id):
        return None
    vuln_id = rule.get('vuln_id', '')
    if vuln_id not in {'V-205734', 'V-277998'}:
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = '\n'.join(part for part in (content, fix_text, rule.get('title', '') or '') if part)
    required_acl_lines = [
        r'NT AUTHORITY\SYSTEM:(OI)(CI)(F)',
        r'BUILTIN\Administrators:(OI)(CI)(F)',
        r'BUILTIN\Users:(OI)(CI)(RX)',
        r'BUILTIN\Users:(CI)(AD)',
        r'BUILTIN\Users:(CI)(IO)(WD)',
        r'CREATOR OWNER:(OI)(CI)(IO)(F)',
    ]
    if not re.search(r'permissions\s+for\s+the\s+system\s+drive\s+root\s+directory', rule.get('title', '') or '', re.IGNORECASE):
        return None
    if not re.search(r'icacls["”]?\s+(?:c:\\|c:\\\\)', combined, re.IGNORECASE):
        return None
    if not all(line in combined for line in required_acl_lines):
        return None
    command = "powershell -NoProfile -Command \"$required=@('NT AUTHORITY\\SYSTEM:(OI)(CI)(F)','BUILTIN\\Administrators:(OI)(CI)(F)','BUILTIN\\Users:(OI)(CI)(RX)','BUILTIN\\Users:(CI)(AD)','BUILTIN\\Users:(CI)(IO)(WD)','CREATOR OWNER:(OI)(CI)(IO)(F)'); $out=(icacls 'C:\\') -join [Environment]::NewLine; $missing=@(); foreach($line in $required){ if($out -notlike ('*'+$line+'*')){ $missing += $line } }; $missing -join ';'\""
    return {
        'vuln_id': vuln_id,
        'platform': 'windows',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _linux_grub_superusers_nondefault_candidate(rule: dict, stig_id: str) -> dict | None:
    if not _linux_platform(stig_id):
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = f'{content}\n{fix_text}'
    if not re.search(r'grep\s+-A1\s+["“]superusers["”]\s+/etc/grub2\.cfg', content, re.IGNORECASE):
        return None
    if not re.search(r'If\s+superusers\s+contains\s+easily\s+guessable\s+usernames,\s*this\s+is\s+a\s+finding', content, re.IGNORECASE):
        return None
    if not re.search(r'set\s+superusers\s*=', combined, re.IGNORECASE):
        return None
    if not re.search(r'root\s*,\s*admin\s*,\s*or\s*administrator', combined, re.IGNORECASE):
        return None
    command = 'sh -c \'out=$(grep -A1 "superusers" /etc/grub2.cfg 2>/dev/null); printf "%s\\n" "$out" | grep -Eq "^[[:space:]]*set[[:space:]]+superusers=\\\"(root|admin|administrator)\\\"[[:space:]]*$" && exit 1; printf "%s\\n" "$out" | grep -Eq "^[[:space:]]*set[[:space:]]+superusers=\\\"[^\\\"[:space:]]+\\\"[[:space:]]*$" && printf "%s\\n" "$out" | grep -Eq "^[[:space:]]*export[[:space:]]+superusers[[:space:]]*$" && echo Compliant\''
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': 'Compliant'},
        'description': rule.get('title', ''),
    }


def _rhel7_interactive_home_directory_candidate(rule: dict, stig_id: str) -> dict | None:
    if stig_id != 'RHEL_7_STIG':
        return None
    vuln_id = rule.get('vuln_id', '')
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    combined = f'{content}\n{fix_text}'
    interactive_users = "awk -F: '\\''($3>=1000)&&($7 !~ /(nologin|false)$/){print $1 \":\" $6}'\\'' /etc/passwd"
    command_prefix = "sh -c '" + interactive_users + " | "
    command_by_vuln = {
        'V-204469': (
            'assigned home directory of all local interactive users on the system exists',
            'home directories referenced in "/etc/passwd" are not owned by the interactive user',
            command_prefix + "while IFS=: read -r user home; do [ -n \"$home\" ] || { echo \"$user:missing-home\"; continue; }; [ -d \"$home\" ] || { echo \"$user:$home:missing\"; continue; }; owner=$(stat -c %U \"$home\" 2>/dev/null || true); [ \"$owner\" = \"$user\" ] || echo \"$user:$home:$owner\"; done'",
        ),
        'V-204471': (
            'files and directories in a local interactive user\'s home directory have a valid owner',
            'files or directories are found without an owner',
            command_prefix + "while IFS=: read -r _ home; do [ -d \"$home\" ] && find \"$home\" -xdev -nouser -print -quit; done | head -n 1'",
        ),
        'V-204473': (
            'excluding local initialization files, have a mode of "0750"',
            'mode more permissive than "0750"',
            command_prefix + "while IFS=: read -r _ home; do [ -d \"$home\" ] && find \"$home\" -xdev ! -name .\\* -perm /027 -print -quit; done | head -n 1'",
        ),
        'V-204474': (
            'local initialization files of all local interactive users are owned by that user',
            'initialization files are not owned by that user or root',
            command_prefix + "while IFS=: read -r user home; do [ -d \"$home\" ] && find \"$home\" -maxdepth 1 -name .[!.]\\* ! -user \"$user\" ! -user root -print -quit; done | head -n 1'",
        ),
    }

    expected = command_by_vuln.get(vuln_id)
    if not expected:
        return None
    required_check, finding_text, command = expected
    if not re.search(re.escape(required_check), combined, re.IGNORECASE):
        return None
    if not re.search(re.escape(finding_text), combined, re.IGNORECASE):
        return None
    if 'home' not in (rule.get('title', '') or '').lower():
        return None
    return {
        'vuln_id': vuln_id,
        'platform': 'linux',
        'check': {'type': 'command_output', 'command': command},
        'expected': {'type': 'equals', 'value': ''},
        'description': rule.get('title', ''),
    }


def _sles_gdm_dconf_banner_message_candidate(rule: dict, stig_id: str) -> dict | None:
    if stig_id != 'SLES_15_STIG' or rule.get('vuln_id') != 'V-234809':
        return None
    content = rule.get('check_content', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if not all(phrase in content for phrase in ('grep banner-message-text /etc/dconf/db/gdm.d/*', 'exact approved Standard Mandatory DoD Notice')):
        return None
    if 'dconf/db/gdm.d/01-banner-message' not in fix_text or '[org/gnome/login-screen]' not in fix_text:
        return None
    match = re.search(r'(banner-message-text="You are accessing a U\.S\. Government \(USG\) Information System \(IS\).*?")', fix_text, re.DOTALL)
    if not match:
        return None
    pattern = match.group(1).strip()
    if 'organization-defined' in pattern.lower() or len(pattern) < 80:
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'linux',
        'check': {
            'type': 'file_content',
            'path': '/etc/dconf/db/gdm.d/01-banner-message',
            'pattern': pattern,
        },
        'expected': {'type': 'contains'},
        'description': rule.get('title', ''),
    }


def _windows_fix_only_removed_feature_candidate(rule: dict, stig_id: str) -> dict | None:
    if 'windows' not in stig_id.lower():
        return None
    title = rule.get('title', '') or ''
    fix_text = rule.get('fix_text', '') or ''
    if re.search(r'\b(?:unless\s+required\s+by\s+the\s+organization|organization-defined|documented|approved)\b', title + '\n' + fix_text, re.IGNORECASE):
        return None
    vuln_match = re.search(r'V-\d+', rule.get('vuln_id', '') or '')
    vuln_id = vuln_match.group(0) if vuln_match else ''
    feature_by_vuln = {
        'V-205678': ('Fax Server', 'Fax'),
        'V-205679': ('Peer Name Resolution Protocol', 'PNRP'),
        'V-205680': ('Simple TCP/IP Services', 'Simple-TCPIP'),
        'V-205681': ('TFTP Client', 'TFTP-Client'),
        'V-205682': ('SMBv1 protocol', 'FS-SMB1'),
        'V-205685': ('Windows PowerShell 2.0 Engine', 'PowerShell-V2'),
        'V-205698': ('Telnet Client', 'Telnet-Client'),
        'V-254269': ('Fax Server', 'Fax'),
        'V-254271': ('Peer Name Resolution Protocol', 'PNRP'),
        'V-254272': ('Simple TCP/IP Services', 'Simple-TCPIP'),
        'V-254273': ('Telnet Client', 'Telnet-Client'),
        'V-254274': ('TFTP Client', 'TFTP-Client'),
        'V-254275': ('SMBv1 protocol', 'FS-SMB1'),
        'V-254278': ('Windows PowerShell 2.0 Engine', 'PowerShell-V2'),
    }
    expected = feature_by_vuln.get(vuln_id)
    if not expected:
        return None
    display_name, feature_name = expected
    if not re.search(rf'Uninstall\s+the\s+["“]?{re.escape(display_name)}["”]?', fix_text, re.IGNORECASE):
        return None
    if display_name != 'SMBv1 protocol' and not re.search(r'\b(?:feature|role)\b', fix_text, re.IGNORECASE):
        return None
    return {
        'vuln_id': rule.get('vuln_id', ''),
        'platform': 'windows',
        'check': {'type': 'windows_feature', 'name': feature_name, 'should_be_installed': False},
        'expected': {'type': 'is_false'},
        'description': rule.get('title', ''),
    }


def infer_candidate_check(rule: dict, stig_id: str) -> dict | None:
    """Infer a conservative executable check candidate from DISA prose.

    Candidates are not marked validated; they are scaffolds requiring fixture proof
    before a rule can be promoted from planned to implemented/validated.
    """
    content = rule.get('check_content', '') or ''
    kubernetes_admission_candidate = _kubernetes_validating_admission_webhook_candidate(rule, stig_id)
    if kubernetes_admission_candidate:
        return kubernetes_admission_candidate
    kubernetes_kubelet_config_value_candidate = _kubernetes_kubelet_config_value_candidate(rule, stig_id)
    if kubernetes_kubelet_config_value_candidate:
        return kubernetes_kubelet_config_value_candidate
    kubernetes_api_server_cipher_suites_candidate = _kubernetes_api_server_cipher_suites_candidate(rule, stig_id)
    if kubernetes_api_server_cipher_suites_candidate:
        return kubernetes_api_server_cipher_suites_candidate
    kubernetes_manifest_grep_candidate = _kubernetes_manifest_grep_candidate(rule, stig_id)
    if kubernetes_manifest_grep_candidate:
        return kubernetes_manifest_grep_candidate
    sles_gdm_dconf_banner_candidate = _sles_gdm_dconf_banner_message_candidate(rule, stig_id)
    if sles_gdm_dconf_banner_candidate:
        return sles_gdm_dconf_banner_candidate
    windows_pki_certificate_candidate = _windows_domain_controller_pki_certificate_exists_candidate(rule, stig_id)
    if windows_pki_certificate_candidate:
        return windows_pki_certificate_candidate
    windows_legal_notice_caption_candidate = _windows_legal_notice_caption_candidate(rule, stig_id)
    if windows_legal_notice_caption_candidate:
        return windows_legal_notice_caption_candidate
    windows_legal_notice_text_candidate = _windows_legal_notice_text_candidate(rule, stig_id)
    if windows_legal_notice_text_candidate:
        return windows_legal_notice_text_candidate
    windows_run_as_different_user_candidate = _windows_run_as_different_user_context_menu_candidate(rule, stig_id)
    if windows_run_as_different_user_candidate:
        return windows_run_as_different_user_candidate
    ol9_crypto_policy_not_overridden_candidate = _ol9_crypto_policy_not_overridden_candidate(rule, stig_id)
    if ol9_crypto_policy_not_overridden_candidate:
        return ol9_crypto_policy_not_overridden_candidate
    vcenter_lookup_core_setting_candidate = _vcenter_lookup_core_setting_candidate(rule, stig_id)
    if vcenter_lookup_core_setting_candidate:
        return vcenter_lookup_core_setting_candidate
    vcenter_lookup_optional_xml_value_candidate = _vcenter_lookup_optional_xml_value_candidate(rule, stig_id)
    if vcenter_lookup_optional_xml_value_candidate:
        return vcenter_lookup_optional_xml_value_candidate
    vcenter_lookup_removed_webapp_directory_candidate = _vcenter_lookup_removed_webapp_directory_candidate(rule, stig_id)
    if vcenter_lookup_removed_webapp_directory_candidate:
        return vcenter_lookup_removed_webapp_directory_candidate
    combined_registry_content = '\n'.join(part for part in (content, rule.get('fix_text', '') or '') if part)
    hives = [next(group for group in match if group).strip() for match in re.findall(r'Registry[ \t]+Hive(?::[ \t]*([^\n\r]+)|([A-Z][^\n\r]+))', combined_registry_content, re.IGNORECASE)]
    paths = [next(group for group in match if group).strip().strip('\\/') for match in re.findall(r'Registry[ \t]*Path(?::[ \t]*([^:\n\r][^\n\r]*)|(\\[^\n\r]+))', combined_registry_content, re.IGNORECASE)]
    value_names = [re.sub(r'\s+Value\s+Data\s*:.*$', '', next(group for group in match if group).strip(), flags=re.IGNORECASE).strip() for match in re.findall(r'Value[ \t]+Name(?::[ \t]*([^\n\r]+)|([A-Za-z0-9_.-][^\n\r]+))', combined_registry_content, re.IGNORECASE)]
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

    iis_session_state_candidate = _iis_session_state_use_cookies_candidate(rule, stig_id)
    if iis_session_state_candidate:
        return iis_session_state_candidate

    iis_hsts_candidate = _iis_hsts_site_defaults_candidate(rule, stig_id)
    if iis_hsts_candidate:
        return iis_hsts_candidate

    iis_tls_candidate = _iis_tls_12_enabled_legacy_protocols_disabled_candidate(rule, stig_id)
    if iis_tls_candidate:
        return iis_tls_candidate

    iis_server_exact_candidate = _iis_server_exact_candidate(rule, stig_id)
    if iis_server_exact_candidate:
        return iis_server_exact_candidate

    if _windows_platform(stig_id) or any(token in stig_id.lower() for token in ('chrome', 'edge', 'defender', 'office', 'adobe', 'acrobat')):
        firmware_state_candidate = _windows_firmware_state_candidate(rule, stig_id)
        if firmware_state_candidate:
            return firmware_state_candidate

        windows_11_enterprise_64bit_candidate = _windows_11_enterprise_64bit_candidate(rule, stig_id)
        if windows_11_enterprise_64bit_candidate:
            return windows_11_enterprise_64bit_candidate

        host_firewall_candidate = _windows_host_firewall_enabled_candidate(rule, stig_id)
        if host_firewall_candidate:
            return host_firewall_candidate

        local_volume_filesystem_candidate = _windows_local_volume_filesystem_candidate(rule, stig_id)
        if local_volume_filesystem_candidate:
            return local_volume_filesystem_candidate

        system_drive_root_icacls_candidate = _windows_system_drive_root_icacls_candidate(rule, stig_id)
        if system_drive_root_icacls_candidate:
            return system_drive_root_icacls_candidate

        hardened_unc_candidate = _windows_hardened_unc_paths_candidate(rule, stig_id)
        if hardened_unc_candidate:
            return hardened_unc_candidate

        apache_windows_directive_candidate = _apache_windows_httpd_conf_directive_candidate(rule, stig_id)
        if apache_windows_directive_candidate:
            return apache_windows_directive_candidate

        apache_windows_module_candidate = _apache_windows_module_candidate(rule, stig_id)
        if apache_windows_module_candidate:
            return apache_windows_module_candidate

        defender_registry_absent_candidate = _windows_defender_registry_absent_candidate(rule, stig_id)
        if defender_registry_absent_candidate:
            return defender_registry_absent_candidate

        defender_av_preference_candidate = _defender_av_get_mppreference_candidate(rule, stig_id)
        if defender_av_preference_candidate:
            return defender_av_preference_candidate

        defender_registry_criteria_candidate = _windows_defender_registry_criteria_candidate(rule, stig_id)
        if defender_registry_criteria_candidate:
            return defender_registry_criteria_candidate

        office_registry_key_absent_candidate = _office_disabled_policy_registry_key_absent_candidate(rule, stig_id)
        if office_registry_key_absent_candidate:
            return office_registry_key_absent_candidate

        office_all_installed_programs_candidate = _office_all_installed_programs_feature_control_candidate(rule, stig_id)
        if office_all_installed_programs_candidate:
            return office_all_installed_programs_candidate

        office_forms3_candidate = _office_forms3_absent_or_dword_one_candidate(rule, stig_id)
        if office_forms3_candidate:
            return office_forms3_candidate

        office_file_validation_candidate = _office_file_validation_protected_view_candidate(rule, stig_id)
        if office_file_validation_candidate:
            return office_file_validation_candidate

        office_exchange_candidate = _office_exchange_kerberos_authentication_candidate(rule, stig_id)
        if office_exchange_candidate:
            return office_exchange_candidate

        policy_candidate = _windows_registry_policy_candidate(rule, stig_id)
        if policy_candidate:
            return policy_candidate

        ftp_anonymous_authentication_candidate = _windows_ftp_anonymous_authentication_disabled_candidate(rule, stig_id)
        if ftp_anonymous_authentication_candidate:
            return ftp_anonymous_authentication_candidate

        dep_candidate = _windows_dep_bcdedit_at_least_optout_candidate(rule, stig_id)
        if dep_candidate:
            return dep_candidate

        event_log_size_candidate = _windows_event_log_size_minimum_candidate(rule, stig_id)
        if event_log_size_candidate:
            return event_log_size_candidate

        event_log_acl_candidate = _windows_event_log_file_acl_candidate(rule, stig_id)
        if event_log_acl_candidate:
            return event_log_acl_candidate

        event_viewer_acl_candidate = _windows_event_viewer_executable_acl_candidate(rule, stig_id)
        if event_viewer_acl_candidate:
            return event_viewer_acl_candidate

        services_msc_candidate = _windows_services_msc_candidate(rule, stig_id)
        if services_msc_candidate:
            return services_msc_candidate

        bluetooth_service_candidate = _windows_bluetooth_support_service_disabled_candidate(rule, stig_id)
        if bluetooth_service_candidate:
            return bluetooth_service_candidate

        office_absent_or_dword_candidate = _office_registry_absent_or_dword_value_candidate(rule, stig_id)
        if office_absent_or_dword_candidate:
            return office_absent_or_dword_candidate

        adobe_repair_installation_candidate = _adobe_dc_repair_installation_disabled_candidate(rule, stig_id)
        if adobe_repair_installation_candidate:
            return adobe_repair_installation_candidate

        adobe_block_websites_candidate = _adobe_reader_dc_block_websites_candidate(rule, stig_id)
        if adobe_block_websites_candidate:
            return adobe_block_websites_candidate

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

        ie11_disabled_candidate = _windows_ie11_standalone_browser_disabled_candidate(rule, stig_id)
        if ie11_disabled_candidate:
            return ie11_disabled_candidate

        unused_accounts_candidate = _windows_unused_accounts_35_days_candidate(rule, stig_id)
        if unused_accounts_candidate:
            return unused_accounts_candidate

        account_password_expires_candidate = _windows_account_password_expires_candidate(rule, stig_id)
        if account_password_expires_candidate:
            return account_password_expires_candidate

        local_admin_password_age_candidate = _windows_enabled_local_admin_password_age_candidate(rule, stig_id)
        if local_admin_password_age_candidate:
            return local_admin_password_age_candidate

        krbtgt_password_age_candidate = _windows_krbtgt_password_age_candidate(rule, stig_id)
        if krbtgt_password_age_candidate:
            return krbtgt_password_age_candidate

        fix_only_removed_feature_candidate = _windows_fix_only_removed_feature_candidate(rule, stig_id)
        if fix_only_removed_feature_candidate:
            return fix_only_removed_feature_candidate

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

    cisco_nxos_static_config_command_candidate = _cisco_nxos_static_config_command_candidate(rule, stig_id)
    if cisco_nxos_static_config_command_candidate:
        return cisco_nxos_static_config_command_candidate

    cisco_nxos_no_ip_source_route_candidate = _cisco_nxos_no_ip_source_route_candidate(rule, stig_id)
    if cisco_nxos_no_ip_source_route_candidate:
        return cisco_nxos_no_ip_source_route_candidate

    scap_fix_only_systemctl_service_candidate = _scap_fix_only_systemctl_service_candidate(rule, stig_id)
    if scap_fix_only_systemctl_service_candidate:
        return scap_fix_only_systemctl_service_candidate

    ubuntu_rsyslog_candidate = _ubuntu_rsyslog_remote_access_methods_candidate(rule, stig_id)
    if ubuntu_rsyslog_candidate:
        return ubuntu_rsyslog_candidate

    ubuntu_aide_filesystem_candidate = _ubuntu_aide_filesystem_integrity_check_candidate(rule, stig_id)
    if ubuntu_aide_filesystem_candidate:
        return ubuntu_aide_filesystem_candidate

    sles_aide_cron_mail_candidate = _sles_aide_cron_mail_notification_candidate(rule, stig_id)
    if sles_aide_cron_mail_candidate:
        return sles_aide_cron_mail_candidate

    ubuntu_aide_default_cron_script_candidate = _ubuntu_aide_default_cron_script_candidate(rule, stig_id)
    if ubuntu_aide_default_cron_script_candidate:
        return ubuntu_aide_default_cron_script_candidate

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

    esxi_auditrecords_candidate = _esxi_auditrecords_enabled_candidate(rule, stig_id)
    if esxi_auditrecords_candidate:
        return esxi_auditrecords_candidate

    esxi_advanced_setting_candidate = _esxi_advanced_setting_exact_value_candidate(rule, stig_id)
    if esxi_advanced_setting_candidate:
        return esxi_advanced_setting_candidate

    vcenter_lookup_service_grep_property_candidate = _vcenter_lookup_service_grep_property_candidate(rule, stig_id)
    if vcenter_lookup_service_grep_property_candidate:
        return vcenter_lookup_service_grep_property_candidate

    vcenter_lookup_security_listener_candidate = _vcenter_lookup_security_listener_candidate(rule, stig_id)
    if vcenter_lookup_security_listener_candidate:
        return vcenter_lookup_security_listener_candidate

    ol8_mitigations_not_off_candidate = _ol8_mitigations_not_off_candidate(rule, stig_id)
    if ol8_mitigations_not_off_candidate:
        return ol8_mitigations_not_off_candidate

    ol8_nx_bit_candidate = _oracle_linux_8_nx_bit_candidate(rule, stig_id)
    if ol8_nx_bit_candidate:
        return ol8_nx_bit_candidate

    firefox_policy_boolean_candidate = _firefox_policy_boolean_candidate(rule, stig_id)
    if firefox_policy_boolean_candidate:
        return firefox_policy_boolean_candidate

    tomcat_systemd_boolean_property_candidate = _tomcat_systemd_boolean_property_candidate(rule, stig_id)
    if tomcat_systemd_boolean_property_candidate:
        return tomcat_systemd_boolean_property_candidate

    tomcat_autodeploy_candidate = _tomcat_autodeploy_disabled_candidate(rule, stig_id)
    if tomcat_autodeploy_candidate:
        return tomcat_autodeploy_candidate

    tomcat_manager_client_cert_candidate = _tomcat_manager_client_cert_auth_candidate(rule, stig_id)
    if tomcat_manager_client_cert_candidate:
        return tomcat_manager_client_cert_candidate

    tomcat_ldap_realm_ldaps_candidate = _tomcat_ldap_realm_ldaps_candidate(rule, stig_id)
    if tomcat_ldap_realm_ldaps_candidate:
        return tomcat_ldap_realm_ldaps_candidate

    tomcat_jmx_false_property_candidate = _tomcat_jmx_false_property_absent_candidate(rule, stig_id)
    if tomcat_jmx_false_property_candidate:
        return tomcat_jmx_false_property_candidate

    tomcat_error_report_valve_candidate = _tomcat_error_report_valve_boolean_candidate(rule, stig_id)
    if tomcat_error_report_valve_candidate:
        return tomcat_error_report_valve_candidate

    tomcat_service_account_candidate = _tomcat_service_account_nologin_candidate(rule, stig_id)
    if tomcat_service_account_candidate:
        return tomcat_service_account_candidate

    tomcat_fips_mode_candidate = _tomcat_fips_mode_candidate(rule, stig_id)
    if tomcat_fips_mode_candidate:
        return tomcat_fips_mode_candidate

    tomcat_web_xml_boolean_param_candidate = _tomcat_web_xml_boolean_param_candidate(rule, stig_id)
    if tomcat_web_xml_boolean_param_candidate:
        return tomcat_web_xml_boolean_param_candidate

    tomcat_removed_webapp_directory_candidate = _tomcat_removed_webapp_directory_candidate(rule, stig_id)
    if tomcat_removed_webapp_directory_candidate:
        return tomcat_removed_webapp_directory_candidate

    tomcat_connector_boolean_candidate = _tomcat_connector_boolean_absent_or_false_candidate(rule, stig_id)
    if tomcat_connector_boolean_candidate:
        return tomcat_connector_boolean_candidate

    linux_shadow_password_lifetime_candidate = _linux_shadow_password_lifetime_candidate(rule, stig_id)
    if linux_shadow_password_lifetime_candidate:
        return linux_shadow_password_lifetime_candidate

    scap_rhel_sshd_fix_candidate = _scap_rhel_sshd_effective_config_from_fix_candidate(rule, stig_id)
    if scap_rhel_sshd_fix_candidate:
        return scap_rhel_sshd_fix_candidate

    ubuntu_ssh_confirm_banner_candidate = _ubuntu_ssh_confirm_banner_candidate(rule, stig_id)
    if ubuntu_ssh_confirm_banner_candidate:
        return ubuntu_ssh_confirm_banner_candidate

    linux_issue_banner_candidate = _linux_issue_banner_candidate(rule, stig_id)
    if linux_issue_banner_candidate:
        return linux_issue_banner_candidate

    linux_device_file_selinux_label_candidate = _linux_device_file_selinux_label_candidate(rule, stig_id)
    if linux_device_file_selinux_label_candidate:
        return linux_device_file_selinux_label_candidate

    sles_gdm_banner_file_candidate = _sles_gdm_banner_file_candidate(rule, stig_id)
    if sles_gdm_banner_file_candidate:
        return sles_gdm_banner_file_candidate

    linux_world_writable_directory_owner_candidate = _linux_world_writable_directory_owner_candidate(rule, stig_id)
    if linux_world_writable_directory_owner_candidate:
        return linux_world_writable_directory_owner_candidate

    command_candidate = _command_output_candidate(rule, stig_id)
    if command_candidate:
        return command_candidate

    oracle_database_public_empty_result_candidate = _oracle_database_public_empty_result_candidate(rule, stig_id)
    if oracle_database_public_empty_result_candidate:
        return oracle_database_public_empty_result_candidate

    oracle_database_exact_parameter_candidate = _oracle_database_exact_parameter_candidate(rule, stig_id)
    if oracle_database_exact_parameter_candidate:
        return oracle_database_exact_parameter_candidate

    sql_server_sa_candidate = _sql_server_sa_login_renamed_candidate(rule, stig_id)
    if sql_server_sa_candidate:
        return sql_server_sa_candidate

    sql_server_audit_action_groups_candidate = _sql_server_audit_action_groups_candidate(rule, stig_id)
    if sql_server_audit_action_groups_candidate:
        return sql_server_audit_action_groups_candidate

    sql_server_sa_disabled_candidate = _sql_server_sa_login_disabled_candidate(rule, stig_id)
    if sql_server_sa_disabled_candidate:
        return sql_server_sa_disabled_candidate

    sql_server_audit_status_started_candidate = _sql_server_audit_status_started_candidate(rule, stig_id)
    if sql_server_audit_status_started_candidate:
        return sql_server_audit_status_started_candidate

    sql_server_common_criteria_enabled_candidate = _sql_server_common_criteria_enabled_candidate(rule, stig_id)
    if sql_server_common_criteria_enabled_candidate:
        return sql_server_common_criteria_enabled_candidate

    tomcat_lockout_realm_candidate = _tomcat_lockout_realm_candidate(rule, stig_id)
    if tomcat_lockout_realm_candidate:
        return tomcat_lockout_realm_candidate

    tomcat_auditctl_candidate = _tomcat_auditctl_expected_rule_candidate(rule, stig_id)
    if tomcat_auditctl_candidate:
        return tomcat_auditctl_candidate

    grub_superusers_candidate = _linux_grub_superusers_nondefault_candidate(rule, stig_id)
    if grub_superusers_candidate:
        return grub_superusers_candidate

    if _linux_platform(stig_id):
        for infer_with_stig in (_linux_interactive_shadow_sha512_candidate, _linux_sudoers_default_include_directory_candidate, _linux_shadow_password_lifetime_candidate, _sles_bios_grub_password_pbkdf2_candidate, _linux_sudoers_no_nopasswd_or_no_authenticate_candidate, _sles_ctrl_alt_del_burst_action_candidate, _linux_sssd_certmap_candidate, _sles_mfa_required_packages_candidate, _linux_removable_media_mount_option_candidate, _linux_nfs_imported_mount_option_candidate, _linux_fixed_mount_option_candidate, _linux_interactive_home_mount_option_candidate, _rhel7_interactive_home_directory_candidate, _sles_interactive_home_nosuid_candidate, _linux_audit_configuration_file_modes_candidate, _linux_faillock_conf_exact_setting_candidate, _linux_login_defs_fix_line_candidate, _linux_passwd_home_directory_assigned_candidate, _linux_aide_selection_line_token_candidate):
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


def _artifact_rule_keys(rule: dict) -> set[str]:
    keys = {str(value) for value in (rule.get('vuln_id'), rule.get('rule_id')) if value}
    for value in list(keys):
        for match in re.findall(r'V-\d+', value):
            keys.add(match)
    return keys


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
                mapped = {}
                for rule in inv.get('rules', []):
                    for key in _artifact_rule_keys(rule):
                        mapped[key] = rule
                cache[path] = mapped
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
            artifact_rule = {}
            for key in _artifact_rule_keys(rule):
                if key in artifact_rules:
                    artifact_rule = artifact_rules[key]
                    break
            for k, v in artifact_rule.items():
                if not v:
                    continue
                if k in {'vuln_id', 'rule_id'} and enriched.get(k):
                    continue
                enriched[k] = v
            vuln = enriched.get('vuln_id') or enriched.get('rule_id') or 'unknown'
            out = implementation_root / stig_slug / f'{slug(vuln)}.json'
            existing_spec = {}
            if out.exists():
                try:
                    existing_spec = json.loads(out.read_text())
                except Exception:
                    existing_spec = {}
                # Some authoritative SCAP inventories expose only fixture metadata in
                # the current extractor, while earlier generated specs may already
                # contain DISA check/fix excerpts. Reuse those committed excerpts as
                # authoritative evidence for conservative inference instead of
                # discarding them on regeneration.
                if not enriched.get('check_content') and existing_spec.get('check_content_excerpt'):
                    enriched['check_content'] = existing_spec['check_content_excerpt']
                if not enriched.get('fix_text') and existing_spec.get('fix_text_excerpt'):
                    enriched['fix_text'] = existing_spec['fix_text_excerpt']
            new_spec = spec_from_rule(manifest_path, manifest, enriched)
            if out.exists() and 'candidate_check' not in new_spec:
                if existing_spec.get('candidate_check'):
                    new_spec = existing_spec
            write_json(out, new_spec)
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
