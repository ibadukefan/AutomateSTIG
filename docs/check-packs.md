# Check Packs

Check packs are deterministic JSON definitions for automated rule evaluation.

Code reference: `crates/core/src/checks`.

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
  "description": "CLI session timeout must be 15 minutes or less"
}
```

Fields:

- `vuln_id`
- `platform`
- `check`
- `expected`
- `description`, optional

## Platforms

The v0.3 shipped platform identifiers are:

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
| `config_line` | `pattern`, optional `context`, optional `should_exist` |
| `command` | `command`, optional `pattern` and `is_regex` |
| `all` | `checks` |
| `any` | `checks` |
| `cisco_vty_session_limit` | None; the maximum is read from the verified organization policy |
| `cisco_logging_buffer_capacity` | None; the minimum byte count is read from the verified organization policy |
| `cisco_logging_trap_severity` | None |

The first two typed Cisco checks fail closed unless evaluation includes a
currently effective, asset-bound organization policy with a trusted Ed25519
signature.

## Expected Results

Expected results also use a snake_case `type` tag.

| Type | Fields |
| --- | --- |
| `matches` | `pattern` |
| `not_contains` | `substring` |
| `is_true` | none |
| `match_count_at_least` | `pattern`, `min` |

## Load Locations

Packs load in deterministic priority order from:

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

The three packs shipped by v0.3 are listed in
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
loaded. ONTAP and FreeBSD use their reviewed curated packs unless an operator
explicitly imports a trusted reviewed extension.
