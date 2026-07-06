# Check Packs

Check packs are deterministic JSON definitions for automated rule evaluation.

Code reference: `crates/core/src/checks`.

## CheckPack

```json
{
  "stig_id": "MS_Windows_Server_2022_STIG",
  "platform": "windows",
  "version": "1.0.0",
  "checks": []
}
```

Fields:

- `stig_id`
- `platform`
- `version`
- `checks`

## CheckDefinition

```json
{
  "vuln_id": "V-254239",
  "platform": "windows",
  "check": {
    "type": "registry",
    "path": "HKLM\\Software\\Example",
    "value_name": "Enabled",
    "value_type": "REG_DWORD"
  },
  "expected": {
    "type": "equals",
    "value": 1
  },
  "description": "Example registry check"
}
```

Fields:

- `vuln_id`
- `platform`
- `check`
- `expected`
- `description`, optional

## Platforms

Platforms are lowercase:

- `windows`
- `linux`
- `ciscoios`
- `cisconxos`
- `ciscoasa`
- `generic`

The snake_case Cisco aliases `cisco_ios`, `cisco_nxos`, and `cisco_asa` are also accepted.

## Check Types

Checks use a snake_case `type` tag.

| Type | Fields |
| --- | --- |
| `registry` | `path`, `value_name`, optional `value_type` |
| `security_policy` | `section`, `key` |
| `audit_policy` | `subcategory`, `setting` |
| `service` | `name`, `expected_status` of `running`, `stopped`, or `disabled` |
| `windows_feature` | `name`, `should_be_installed` |
| `file_content` | `path`, `pattern`, optional `is_regex` |
| `file_permission` | `path`, optional `owner`, optional `group`, optional `mode` |
| `sysctl` | `key` |
| `package` | `name`, `should_be_installed` |
| `config_line` | `pattern`, optional `context`, optional `should_exist` |
| `command` | `command`, optional `shell` |
| `all` | `checks` |
| `any` | `checks` |

## Expected Results

Expected results also use a snake_case `type` tag.

| Type | Fields |
| --- | --- |
| `equals` | `value` |
| `matches` | `pattern` |
| `greater_or_equal` | `value` |
| `less_or_equal` | `value` |
| `contains` | `substring` |
| `not_contains` | `substring` |
| `is_true` | none |
| `is_false` | none |
| `all_pass` | none |

## Load Locations

Packs load from:

- `<data_dir>/plugins`
- `content/check_packs`
- `<library>/auto_check_packs`

## Auto-Generation Scope

DISA import converts structured check-content into deterministic checks where it can be mapped safely:

- Windows registry blocks.
- Linux sysctl and systemd content.

Unstructured and manual-review controls are intentionally left unautomated. For example, Windows Server 2022 V2R8 auto-generates about 96 checks from 282 rules; the remainder require manual review.
