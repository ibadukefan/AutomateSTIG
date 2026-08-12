# STIG Coverage Policy

The unreleased AutomateSTIG v0.3 pilot candidate contains deterministic
evidence collection and evaluation for NetApp ONTAP 9.x and FreeBSD over SSH,
plus Cisco IOS-XE Router NDM running configurations. It does not claim to
replace a general-purpose host scanner. The exact target, benchmark, input,
pack, and acceptance-gate mappings live in `content/supported-targets.json`.

AutomateSTIG must not advertise a STIG/platform as comprehensive unless every DISA rule for that release is represented in a coverage manifest.

## Rule Classification

Every rule in a supported STIG must be classified as one of:

- `automated` — AutomateSTIG executes a check and records evidence.
- `manual` — Human review is required; the manifest explains why.
- `not_applicable` — Always not applicable for the supported platform profile; reason required.
- `unsupported` — Known gap; reason and tracking issue required.

## Supported vs Experimental

A check pack is **supported** only when:

1. The coverage manifest lists the DISA STIG release and every rule.
2. Every `automated` entry references an existing check definition.
3. Every manual/NA/unsupported entry includes a reason.
4. Fixture or unit tests validate the important status mappings.
5. CI runs the coverage validator.

A check pack without this proof is **experimental** even if it contains useful checks.

## Validation Command

Coverage validation is protected maintainer tooling and is not compiled into
the installed analyst CLI. From a reviewed source checkout, run:

```bash
cargo run --release --features maintainer --bin automatestig -- \
  coverage validate --manifest content/coverage/<manifest>.json
```

The validator fails closed for internal inconsistencies, duplicate rule IDs, missing reasons, missing automation metadata, unsupported entries without `tracking_issue`, and automated entries that lack validation evidence references.

## Evidence Requirement

Automated checks must record evidence sufficient for an auditor to understand the result:

- check ID
- target asset
- source type
- command/query/file/config path used
- expected value
- actual value
- timestamp
- normalized evidence summary

## Release Claims

Coverage claims must name the exact device class, STIG release, check pack, evidence mode, and validation fixture or authorized acceptance run. Repository manifest counts are content-governance metrics; they do not establish that a deployment is audit-ready or accepted by an external system of record.
