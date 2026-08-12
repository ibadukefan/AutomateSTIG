# Check Packs

Check packs are deterministic JSON definitions for automated rule evaluation.

Code reference: `crates/core/src/checks`.

The end-user scanner resolves only the immutable check pack bound into its
release-bundled profile. The mutable library paths below exist for protected
maintainer and legacy-compatibility work; importing there does not alter the
installed product's scanner scope.

## CheckPack

```json
{
  "stig_id": "NetApp_ONTAP_DSC_9-x_STIG",
  "platform": "ontap",
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
  "vuln_id": "V-246923",
  "platform": "ontap",
  "check": {
    "type": "command",
    "command": "system timeout show"
  },
  "expected": {
    "type": "matches",
    "pattern": "(?i)timeout[^0-9]*(1[0-5]|[1-9])\\b"
  },
  "description": "CLI session timeout must be 15 minutes or less",
  "implementation_class": "legacy_declarative",
  "introduction_release": "0.3"
}
```

Fields:

- `vuln_id`
- `platform`
- `check`
- `expected`
- `description`, optional
- `implementation_class`: `declarative_predicate`, `legacy_declarative`, or
  `reviewed_imperative`; executable release content may not leave this unknown
- `introduction_release`: numeric `MAJOR.MINOR` or `MAJOR.MINOR.PATCH`

Previously reviewed legacy extension packs that omit both metadata fields still
deserialize as `unknown` for compatibility. Scorecards do not infer their class
or release, and supported release content cannot ship that way. All three v0.3
bundled packs have been explicitly classified per automation.

## Platforms

The v0.3 candidate's platform identifiers are:

- `ontap`
- `bsd`
- `cisco_ios`

Evidence v2, check packs, and API payloads all serialize the IOS-XE identifier
as `cisco_ios`. The legacy `ciscoios` spelling is accepted only while reading
older local data. No other Cisco or operating-system platform is a v0.3 target.

## Check Types

Checks use a snake_case `type` tag.

| Type | Fields |
| --- | --- |
| `predicate` | `program`; versioned pure AST over collected evidence |
| `config_line` | `pattern`, optional `context`, optional `should_exist` |
| `command` | `command`, optional `pattern` and `is_regex` |
| `all` | `checks` |
| `any` | `checks` |
| `bsd_audit_class_selection` | `classes`; reserved for the four reviewed OpenBSM rules |
| `bsd_pf_enabled` | None |
| `cisco_vty_session_limit` | None; the maximum is read from the verified organization policy |
| `cisco_login_block_for` | None |
| `cisco_interface_acl_deny_log_input` | None |
| `cisco_persistent_audit_modification_protection` | None; emits NotApplicable when persistent logging is disabled |
| `cisco_persistent_audit_deletion_protection` | None; emits NotApplicable when persistent logging is disabled |
| `cisco_file_system_privilege` | None |
| `cisco_single_local_fallback_account` | None |
| `cisco_password_minimum_length` | None |
| `cisco_management_idle_timeout` | None |
| `cisco_logging_buffer_capacity` | None; the minimum byte count is read from the verified organization policy |
| `cisco_logging_trap_severity` | None |
| `cisco_redundant_authoritative_ntp_sources` | None; approved sources are read from the verified organization policy |
| `cisco_ntp_authentication` | None |
| `cisco_ssh_mac_algorithms` | None |
| `cisco_ssh_encryption_algorithms` | None |
| `cisco_syslog_server_count` | None |

The three policy-bound Cisco checks fail closed unless evaluation includes a
currently effective, asset-bound organization policy with a trusted Ed25519
signature.

## Predicate programs

`predicate` is the preferred implementation for new automation that fits the
bounded language. It consumes only an existing adapter observation or an
operator-supplied `network_config`; it cannot open a file, invoke a process,
run a shell command, or make a network request. Remote collection is a separate
allowlisted adapter boundary. A predicate observation key does not itself
authorize collection.

Only `schema_version: 1` is executable. The evaluator caps input at 4 MiB,
tables at 4,096 rows and 128 columns, parsed documents at 16,384 nodes and depth
24, and the predicate AST at 256 nodes and depth 16. Strings, sets, selectors,
compound children, and structured-configuration depth have smaller explicit
limits. Numeric ordering/ranges reject non-finite values and magnitudes above
JSON's exact-integer range (`9,007,199,254,740,991`). Missing required values,
invalid types, duplicate fields/headers,
malformed JSON, inconsistent tables/configuration indentation, collection
errors, and limit violations produce an evaluation error (Not Reviewed), never
a passing result. Evaluation also stops at 100,000 predicate steps, preventing
nested row quantifiers from multiplying otherwise-valid inputs into unbounded
work.

The v1 AST supports:

- `present`;
- `equal` between literals and/or fields;
- `in_set`;
- inclusive or exclusive `numeric_range` bounds;
- numeric or string `ordered` relationships between literals and/or fields;
- cross-field constraints by using two field operands; and
- `table_rows` with `every`, `any`, or `none` quantifiers and row-relative
  selectors.

Inputs may be `text`, `json`, unique `key_value` lines, a
`delimited_table`, or `structured_config`. Structured configuration becomes a
hierarchy of `{text, tokens, children}` nodes, so block and child-line meaning
can be evaluated through `table_rows` rather than substring heuristics.

Example: every normalized row must be enabled, use an approved role, remain in
the idle-time range, and configure at least its required minimum:

```json
{
  "type": "predicate",
  "program": {
    "schema_version": 1,
    "source": {"type": "observation", "key": "normalized-users"},
    "input": {"type": "json"},
    "predicate": {
      "op": "table_rows",
      "rows": {"pointer": "/rows"},
      "quantifier": "every",
      "predicate": {
        "op": "all",
        "predicates": [
          {
            "op": "equal",
            "left": {"type": "value", "value": {"scope": "current_row", "pointer": "/enabled"}},
            "right": {"type": "literal", "value": true}
          },
          {
            "op": "in_set",
            "value": {"type": "value", "value": {"scope": "current_row", "pointer": "/role"}},
            "values": ["admin", "audit"]
          },
          {
            "op": "numeric_range",
            "value": {"type": "value", "value": {"scope": "current_row", "pointer": "/idle_minutes"}},
            "min": 1,
            "max": 15
          },
          {
            "op": "ordered",
            "left": {"type": "value", "value": {"scope": "current_row", "pointer": "/required"}},
            "relation": "less_than_or_equal",
            "right": {"type": "value", "value": {"scope": "current_row", "pointer": "/configured"}},
            "value_type": "number"
          }
        ]
      }
    }
  }
}
```

Predicate checks use `expected: {"type":"is_true"}`. Any intended negation
must be visible in the AST. Reviewed imperative variants remain available for
checks whose platform semantics cannot be represented safely and completely by
v1; their `implementation_class` must say `reviewed_imperative`.

## Expected Results

Expected results also use a snake_case `type` tag.

| Type | Fields |
| --- | --- |
| `matches` | `pattern` |
| `not_contains` | `substring` |
| `is_true` | none |
| `match_count_at_least` | `pattern`, `min` |

## Maintainer Load Locations

Protected maintainer/legacy library code loads packs in deterministic priority
order from:

- `content/check_packs` or the equivalent packs embedded in the binary
- `<library>/custom_checks`
- `<library>/reviewed_check_packs` (promoted only by trusted signed `.stigpack` import)

Invalid pack content is fatal; it is not silently skipped.
Filesystem location alone never establishes trust. Both library directories are
loaded only through `trusted-executable-content.json`, which retains the exact
signed manifest, signature, signer key, member mapping, and SHA-256 hash from
the journaled import. Runtime verifies those proofs against the current trust
directory. Bare files, changed bytes, changed proofs, and revoked keys are
rejected before parsing or execution.

The three packs bound into the v0.3 candidate are listed in
`content/supported-targets.json`. `scripts/validate-check-packs.py` rejects an
extra shipped pack, a missing pack, target metadata drift, or coverage/check ID
mismatches.

Custom and imported content does not expand the advertised target matrix.
Adding a target requires the complete review and live-acceptance process in
[Supported Targets](supported-targets.md).

Raw XCCDF/DISA import never generates executable checks from prose. Signed
`.stigpack` archives retain the compatible `auto_check_packs/` member name, but
trusted import validates those definitions and promotes them into
`<library>/reviewed_check_packs`; legacy local `auto_check_packs` files are never
loaded. ONTAP and FreeBSD product scans always use their release-bundled
reviewed packs. A trusted reviewed extension imported during content
preparation does not enter the product runtime until it passes release review
and is bound into a new signed scanner profile.
