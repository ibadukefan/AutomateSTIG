# Cisco IOS-XE Router NDM Evaluation

AutomateSTIG v0.3 evaluates Cisco IOS-XE Router NDM from an operator-supplied
running configuration. It does not log in to the router or execute collection
commands. Capture `show running-config` through the organization's authorized
device-management process and handle the file as sensitive configuration data.

The `cisco_ios_xe_router_ndm` pack targets
`Cisco_IOS-XE_Router_NDM_STIG` V3R7, which contains 42 rules. Its reviewed
candidate inventory tracks 34 rules: 21 have conservative executable checks
and 13 remain manual. Eight additional benchmark rules are outside the current
candidate inventory and remain `NotReviewed`: `V-215818`, `V-215820`,
`V-215821`, `V-215824`, `V-215838`, `V-215855`, `V-220139`, and `V-220140`.
The governed inventory is exactly 34 reviewed/21 automated/13 manual. The pack
is experimental and does not claim that every benchmark rule is automated.

The evaluator parses command lines rather than searching arbitrary file text.
It ignores IOS comments and complete banner payloads, treats positive commands
as disabled when their `no` form is present, requires token boundaries, and
applies context checks to every matching block. These constraints prevent prose
in a banner or description from becoming compliance evidence.

Three controls now use typed, fail-closed evaluation:

- `V-215807` requires exactly one numeric `session-limit` in every VTY block
  and, when HTTP(S) management is enabled, exactly one
  `ip http max-connections`; all values must be within the signed
  organization-policy maximum.
- `V-215836` parses the single numeric `logging buffered` capacity and compares
  it with the signed organization-policy minimum.
- `V-215837` resolves the effective `logging trap` severity, including IOS's
  informational default. Critical through informational pass; emergencies,
  alerts, debugging, malformed, ambiguous, or globally disabled logging fail.

`V-215807` and `V-215836` do not execute without a verified policy. The policy
uses [the closed schema](../schemas/organization-policy.schema.json), is bound
to the exact STIG release and configuration hostname, has an effective/expiry
window, and carries a detached Ed25519 signature from the dedicated
organization-policy trust directory. The checklist records the policy ID,
version, SHA-256, signer fingerprint, signature result, canonical imported
benchmark digest, check-pack digest, and evaluation-plan digest.

The following rules remain absent from the executable pack and stay
`NotReviewed` until an assessor completes the indicated review:

- `V-215812`: inbound direction and the approved contents of the management ACL
- `V-215813`: typed invalid-attempt and lockout-duration semantics
- `V-215814`: the complete mandatory banner text and presentation
- `V-215823`: the complete service inventory and any call-home exception
- `V-215826`: the scoped password policy and numeric minimum
- `V-215833`: every VTY and console timeout, plus HTTP when enabled
- `V-215841` and `V-215842`: active SNMP users and approved auth/privacy algorithms
- `V-215843`: NTP algorithm, trusted-key linkage, and every server-key binding
- `V-215844` and `V-215845`: the complete SSH MAC/cipher allowlists
- `V-215854`: two authentication servers and all management-path AAA bindings
- `V-215856`: certificate-chain validation to a DoD-approved CA

The sanitized
`fixtures/network/ios_xe_router_semantic_counterexamples.txt` file records the
specific false-pass cases that forced these fail-closed classifications.

## GUI

Import the matching DISA benchmark under `Standards`. On `Assessments`, select
the Cisco IOS-XE Router NDM benchmark, enter the asset hostname, and attach the
running configuration, organization-policy JSON, and detached signature. The
GUI derives `cisco_ios` and the configuration input type from the benchmark.
Install the approving public key in the dedicated trust directory before
launching the GUI. Cisco is intentionally absent from Remote Scan.

## CLI

```bash
automatestig disa-import \
  --input U_Cisco_IOS-XE_Router_Y26M04_STIG.zip

automatestig evaluate \
  --stig Cisco_IOS-XE_Router_NDM_STIG \
  --config router01-running-config.txt \
  --organization-policy router01-policy.json \
  --organization-policy-signature router01-policy.sig \
  --host router01 \
  --output router01.ckl \
  --format ckl
```

Create a dedicated key pair and detached signature only on the offline signing
host:

```bash
automatestig generate-signing-key \
  --output /offline/organization-policy.key

automatestig sign-organization-policy \
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
