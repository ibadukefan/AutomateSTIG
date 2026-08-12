# Cisco IOS-XE Router NDM Evaluation

The unreleased AutomateSTIG v0.3 pilot candidate evaluates Cisco IOS-XE Router
NDM from an operator-supplied running configuration. It does not log in to the
router or execute collection
commands. Capture `show running-config` through the organization's authorized
device-management process and handle the file as sensitive configuration data.

The `cisco_ios_xe_router_ndm` pack targets
`Cisco_IOS-XE_Router_NDM_STIG` V3R7, which contains 42 rules. Its reviewed
inventory now tracks all 42 rules: 33 have conservative executable checks and
nine remain manual. The pack is experimental and does not claim that every
benchmark rule is automated.

The evaluator parses command lines rather than searching arbitrary file text.
It ignores IOS comments and complete banner payloads, treats positive commands
as disabled when their `no` form is present, requires token boundaries, and
applies context checks to every matching block. These constraints prevent prose
in a banner or description from becoming compliance evidence.

Sixteen controls use typed, fail-closed evaluation:

- `V-215807` requires exactly one numeric `session-limit` in every VTY block
  and, when HTTP(S) management is enabled, exactly one
  `ip http max-connections`; all values must be within the signed
  organization-policy maximum.
- `V-215836` parses the single numeric `logging buffered` capacity and compares
  it with the signed organization-policy minimum.
- `V-215837` resolves the effective `logging trap` severity, including IOS's
  informational default. Critical through informational pass; emergencies,
  alerts, debugging, malformed, ambiguous, or globally disabled logging fail.
- `V-215813` parses the attempt count, lockout duration, and observation window
  numerically.
- `V-215818` resolves IPv4/IPv6 ACLs actually bound to interfaces and checks
  every deny entry for `log-input`, including sequence-numbered entries.
- `V-215820` and `V-215821` preserve the benchmark's `NotApplicable` outcome
  when persistent logging is disabled; otherwise they require the effective
  file privilege to be the default or explicit level 15.
- `V-215822` uses the same effective privilege parser without the persistent-
  logging applicability gate, so explicit `file privilege 15` no longer
  false-fails.
- `V-215824` requires exactly one Common-Criteria-bound local username; every
  AAA login list must contain only recognized RADIUS/TACACS group methods
  followed immediately by `local`.
- `V-215826` checks every Common Criteria policy block for one numeric
  `min-length` of at least 15.
- `V-215833` checks every console, VTY, and auxiliary line block and, when
  enabled, the independent HTTP(S) timeout path.
- `V-215838` requires at least two distinct configured NTP sources and checks
  every source against the signed asset-specific authoritative-source list.
- `V-215843` links every NTP server key through `ntp trusted-key` to an
  `hmac-sha2-256` definition.
- `V-215844` and `V-215845` inspect the complete SSH MAC and cipher allowlists;
  mixed approved/unapproved lists fail.
- `V-220139` counts distinct modern and legacy remote syslog destinations.

`V-215807`, `V-215836`, and `V-215838` do not execute without a verified policy. The policy
uses [the closed schema](../schemas/organization-policy.schema.json), is bound
to the exact STIG release and configuration hostname, has an effective/expiry
window, and carries a detached Ed25519 signature from the dedicated
organization-policy trust directory. The checklist records the policy ID,
version, SHA-256, signer fingerprint, signature result, canonical imported
benchmark digest, check-pack digest, and evaluation-plan digest.

The following rules remain absent from the executable pack and stay
`NotReviewed` until an assessor completes the indicated review:

- `V-215812`: inbound direction and the approved contents of the management ACL
- `V-215814`: the complete mandatory banner text and presentation
- `V-215823`: the complete service inventory and any call-home exception
- `V-215841` and `V-215842`: active SNMP users and approved auth/privacy algorithms
- `V-215854`: two authentication servers and all management-path AAA bindings
- `V-215855`: alternate valid change-triggered configuration-backup designs
- `V-215856`: certificate-chain validation to a DoD-approved CA
- `V-220140`: current Cisco lifecycle support, which requires `show version`
  and authoritative lifecycle data

The sanitized
`fixtures/network/ios_xe_router_semantic_counterexamples.txt` file records the
specific false-pass cases that forced these fail-closed classifications.

## GUI

On **Scan**, select a live existing STIG Manager asset with
`Cisco_IOS-XE_Router_NDM_STIG` V3R7 assigned and choose the release-bundled
`cisco_ios_xe_router_ndm` profile. Attach the complete running configuration,
organization-policy JSON, and detached signature. Preflight binds the single
configuration hostname, observed IOS-XE major version 17, exact assignment,
configuration digest, policy metadata, and profile hashes before evaluation.

Install only the approving public key in the dedicated trust directory before
launching the GUI. Keep the private signing key offline. Cisco is configuration
ingestion, not a remote SSH scan. A complete result proposes only 33
scanner-owned reviews; nine manual rules remain untouched in STIG Manager.

## CLI

```bash
automatestig evaluate \
  --stig Cisco_IOS-XE_Router_NDM_STIG \
  --config router01-running-config.txt \
  --organization-policy router01-policy.json \
  --organization-policy-signature router01-policy.sig \
  --host router01 \
  --output router01.scanner-result.json
```

This CLI evaluation path is the supported disconnected and reproducible path.
The normal scanner GUI uses the bundled exact V3R7 benchmark subset and does
not require broad DISA content import.

Create a dedicated key pair and detached signature only on the offline signing
host:

```bash
cargo run --release --features maintainer --bin automatestig -- \
  generate-signing-key \
  --output /offline/organization-policy.key

cargo run --release --features maintainer --bin automatestig -- \
  sign-organization-policy \
  --policy router01-policy.json \
  --signing-key /offline/organization-policy.key \
  --output router01-policy.sig
```

Transfer only the policy, signature, and `.pub` trust anchor to the evaluation
host. Put the public key in
`$AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR`, or in
`~/.automatestig/organization_policy_keys` when the override is unset. Do not
reuse the executable-content signing key or copy the private key to an
evaluation runner.

`--config` and `--evidence` are mutually exclusive. The asset hostname is
derived from the configuration's single top-level `hostname` command. When
`--host` is supplied, it is a corroborating claim and must match that command
case-insensitively; it cannot relabel another device's configuration.

AutomateSTIG cannot independently prove that an operator's capture includes the
entire device configuration. A partial or redacted capture is not valid release
evidence and its results must not be used as an audit decision. Preserve the
exact source file and its SHA-256 with the assessment record so a reviewer can
reproduce the evaluation.

## Release Acceptance

The live device gate requires a fresh configuration from representative,
authorized IOS-XE hardware or an approved equivalent. On the protected runner,
set `AUTOMATESTIG_LIVE_CISCO_IOS_XE_CONFIG` to that file,
`AUTOMATESTIG_LIVE_CISCO_IOS_XE_NEGATIVE_CONFIG` to a separately captured
negative-control state for the same lab asset, and run the target gate documented
in [Live External Acceptance](live-external-acceptance.md). The gate also
requires `AUTOMATESTIG_LIVE_CISCO_IOS_XE_ORACLE`, prepared by a named independent
adjudicator and bound to both configurations plus the exact benchmark and
check-pack hashes. It also requires a signed, asset-bound organization policy
whose protected SHA-256 pin is included in the oracle and release evidence.
Every executable-rule status in both scenarios must match;
merely executing the expected rule set or recording an all-pass state is not
acceptance.
The sanitized files under `fixtures/network/` are deterministic regressions,
not live-device evidence.
