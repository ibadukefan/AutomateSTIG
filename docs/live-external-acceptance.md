# Live External Acceptance

Release acceptance has five mandatory gates: NetApp ONTAP, FreeBSD, Cisco
IOS-XE Router NDM, DoD STIG Viewer, and STIG Manager. Offline fixtures are
regression tests, not a substitute. A skipped gate blocks a release tag.

## ONTAP, FreeBSD, and Cisco IOS-XE

Use authorized, representative non-production systems with the target STIG
revision. ONTAP and FreeBSD require a dedicated read-only SSH account, command
authorization, and host keys pinned out of band in
`~/.automatestig/known_hosts`. Cisco uses an operator-captured running
configuration, not an AutomateSTIG SSH session.

Configure the `AUTOMATESTIG_LIVE_ONTAP_*`,
`AUTOMATESTIG_LIVE_FREEBSD_*`, and `AUTOMATESTIG_LIVE_CISCO_IOS_XE_*`
variables documented below, then run:

```bash
cargo build --release --locked --bin automatestig
python3 scripts/run-live-device-acceptance.py \
  --repo-root . --require-live --target all \
  --evidence-output live-device-acceptance.json
sha256sum live-device-acceptance.json
```

Each configured target also requires `ORACLE`, the protected-runner path to an
independently adjudicated decision-oracle bundle conforming to
`schemas/live-decision-oracle.schema.json`. The named adjudicator must apply the
DISA check procedure and vendor guidance without consulting AutomateSTIG's
result. `ORACLE_SHA256` is the bundle's exact lowercase SHA-256, committed as a
protected-environment variable before dispatch. The adjudicator must be named by
GitHub login, be the environment's sole required reviewer, verify that pin out
of band before approval, and differ from both the workflow actor and triggering
actor. The bundle has exactly one representative baseline and one independently
captured negative-control scenario. Each scenario must cover every and only
executable rule, bind its exact source state and asset, and contain no
`NotReviewed` result. The negative control must differ from the baseline and
contain at least one `Finding`; an all-pass-only oracle is rejected.
`source_state_sha256` must match each fresh command-state/configuration digest
exactly. `benchmark_sha256` binds the exact authorized DISA source artifact,
while `evaluated_benchmark_sha256` is the canonical JSON SHA-256 of the
effective imported benchmark model. `check_pack_sha256` is the canonical JSON
SHA-256 of the effective
embedded pack set: the selected source pack is normalized to its runtime serde
defaults, assigned `priority: 0`, wrapped in a one-item list, recursively
key-sorted, encoded as whitespace-free UTF-8 JSON, and hashed. Every oracle also
carries `organization_policy_sha256`,
`organization_policy_signature_sha256`, and
`organization_policy_signer_fingerprint`. They bind the exact signed policy,
detached signature, and trusted signer for Cisco and are `null` for ONTAP and
FreeBSD. For ONTAP and FreeBSD, `ssh_server_key_fingerprint` is the exact
independently pinned SSH fingerprint in `SHA256:<43 base64 characters>` form;
it is `null` for Cisco. Both live evidence scenarios and their checklist
provenance must retain that exact key. Oracles older than 90 days are rejected.
Derive the state bindings
without running an evaluation:

```bash
python3 scripts/run-live-device-acceptance.py \
  --hash-source-state independent-evidence.json --source-kind evidence
python3 scripts/run-live-device-acceptance.py \
  --hash-source-state authorized-running-config.txt --source-kind config
```

For SSH targets, other required suffixes are `HOST`, `USERNAME`,
`NEGATIVE_EVIDENCE` (a complete evidence-v2 capture from the independently
adjudicated negative state), and either `KEY` (plus optional
`KEY_PASSPHRASE`) or `PASSWORD`. Optional suffixes are `PORT`, `HOSTNAME`,
`XCCDF`, and `TIMEOUT_SECS`. If `HOSTNAME` is set, it must equal `HOST` after
case and trailing DNS-dot normalization; aliases cannot replace the SSH
endpoint identity bound by the evidence and oracle. This runner rejects
`TRUST_ON_FIRST_USE`; perform and record enrollment separately, then pin the
host key out of band. The redacted evidence stores matching expected/observed
status-map digests, but never the status map, credentials, commands, target
output, or host addresses.

Cisco acceptance is deliberately file-based. Set
`AUTOMATESTIG_LIVE_CISCO_IOS_XE_CONFIG` to a protected path containing a fresh,
authorized running configuration captured from the representative device.
Set `AUTOMATESTIG_LIVE_CISCO_IOS_XE_ORACLE` to its independently adjudicated
oracle bundle, `AUTOMATESTIG_LIVE_CISCO_IOS_XE_NEGATIVE_CONFIG` to the separately
captured negative-control configuration, and bind both scenario hashes.
`AUTOMATESTIG_LIVE_CISCO_IOS_XE_HOSTNAME` is required and must match both
configurations; `XCCDF` is optional.

The organization-defined Cisco checks also require these protected-environment
paths and bindings:

- `AUTOMATESTIG_LIVE_CISCO_IOS_XE_ORGANIZATION_POLICY` points to the exact
  asset/STIG-bound policy JSON;
- `AUTOMATESTIG_LIVE_CISCO_IOS_XE_ORGANIZATION_POLICY_SIGNATURE` points to its
  raw 64-byte detached Ed25519 signature;
- `AUTOMATESTIG_LIVE_CISCO_IOS_XE_ORGANIZATION_POLICY_SHA256` is the exact
  lowercase SHA-256 committed before dispatch; and
- `AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR` points to the protected directory
  containing the independently installed organization-policy public trust
  anchor.

The policy JSON must be runner-user or root owned, single-linked, and mode
`0600`; the detached signature may be mode `0644` but must not be group/world
writable. The runner snapshots both through no-follow descriptors, rejects a
policy that differs from the protected digest, and passes only those snapshots
to the CLI. The Cisco oracle must carry the same policy digest, detached
signature digest, and trusted signer fingerprint. Acceptance then requires
equality among the protected pin, snapshots, oracle, and verified checklist
provenance, including `signature_verified=true`.

For every device target, the checklist must also retain the exact input digest,
the canonical imported-benchmark digest, the canonical effective check-pack
digest, and the canonical evaluation-plan digest derived from the STIG
identity/release, imported-benchmark digest, check-pack digest, and nullable
organization-policy digest. Both scenarios must agree on the benchmark, pack,
and plan.
Release validation recomputes those bindings and rejects substituted runtime
content or inputs. Configurations and policy bytes are hashed but never copied
into the release artifact.

The manual `Live Device Acceptance` workflow runs on an environment-protected
Linux x64 self-hosted runner labeled `automatestig-live-devices`. Its
environment must require reviewer approval and contain the lab secrets,
protected oracle paths, and protected Cisco configuration. A target-specific
run is useful for diagnosis; release evidence needs passing results for all
three device targets,
including exact agreement with both scenarios in all three independent oracle
bundles. Oracle and detached-signature files may be runner-user or root owned,
must have one hard link, and must not be group/world writable. Raw
configurations, organization-policy JSON, negative evidence, and other private
source files must additionally have no group/other permissions (for example,
mode `0600`).

ONTAP simulator media is distributed through NetApp support channels and cannot
be checked into or fetched by this project. A real or licensed simulator lab is
therefore an external prerequisite. FreeBSD requires a real host or VM kernel;
a Linux container is not equivalent. Cisco acceptance requires a configuration
from representative IOS-XE hardware or an authorized equivalent; the sanitized
repository fixture is only a regression test.

## DoD STIG Viewer

STIG Viewer 3 is a desktop GUI on supported Windows/Linux x86-64 systems; a
successful executable `--help` is not interoperability acceptance. Build the
CLI, copy the sanitized CKL and CKLB fixtures to the test workstation, and for
each format:

1. open the source checklist in the exact deployed STIG Viewer version;
2. confirm the asset, STIG, Rule IDs, statuses, details, and comments render;
3. save/export it as a different round-trip file without editing findings;
4. reopen the round-trip file in STIG Viewer;
5. run the semantic verifier:

```bash
python3 scripts/run-stig-viewer-acceptance.py \
  --binary ./automatestig \
  --ckl-source windows_server_2022_sanitized.ckl \
  --ckl-roundtrip viewer-roundtrip.ckl \
  --cklb-source windows_server_2022_sanitized.cklb \
  --cklb-roundtrip viewer-roundtrip.cklb \
  --product-version '<exact STIG Viewer version>' \
  --platform '<Windows/Linux version>' \
  --operator '<named tester>' \
  --output stig-viewer-acceptance.json
```

Use the checked-in sanitized fixtures without clearing their deliberately
non-default technology area, web/database site and instance, CKLB OS metadata,
or repeated CCI/legacy identifiers. The verifier first reads each source and
Viewer output independently, then compares those raw projections with
AutomateSTIG's first parse. It rejects a missing/duplicate STIG, a missing or
duplicate Rule ID, any exact Rule-ID set/count change, and any modeled asset,
STIG, group/title/content, severity, status, detail, comment, CCI, or legacy-ID
change. It also rejects a byte-for-byte copy presented as a Viewer round trip
and obvious placeholder product, platform, or operator metadata. This makes
loss during AutomateSTIG's initial parse visible instead of
allowing the same loss on both sides to cancel out. Keep screenshots/product
logs in the referenced assessment record and hash the JSON evidence.

## STIG Manager

`staging/stigman/` uses the real STIG Manager, Keycloak, and MySQL containers.
It provisions OAuth client credentials, imports the authoritative XCCDF as
reference benchmark content, and creates a pre-existing Cisco asset with the
exact V3R7 assignment. The scanner evaluates an authorized configuration with
a currently effective signed Cisco policy and produces one selected-run sparse
handoff. The acceptance runner verifies that bundle offline, proves the
supplemental XCCDF mirrors its sparse rows, maps only `sparse-reviews.json`
through a controlled receiver to the Review API, and reads the destination
back to prove exact semantic agreement. It does not exercise STIG Manager's
browser-side result-XCCDF import wizard. AutomateSTIG never creates the remote
asset or assignment and never uses the GUI or retired unversioned push route to
write a changed review.

AutomateSTIG receives no STIG Manager URL or credential. It runs disconnected,
so there is no HTTPS bridge and no invalid-certificate product exception. Only
the explicit rig administrator/receiver script talks to the loopback HTTP
containers:

```bash
cargo build --release --locked --bin automatestig --bin automatestig-gui
docker compose -f staging/stigman/docker-compose.yml up -d
python3 staging/stigman/run-staging-acceptance.py \
  --binary target/release/automatestig-gui \
  --cli-binary target/release/automatestig
docker compose -f staging/stigman/docker-compose.yml down -v
```

The gate must run `automatestig scanner verify-handoff` before receiver mapping.
The receiver then explicitly selects and revalidates the existing collection,
asset, and exact assignment before mapping only `sparse-reviews.json`; it
rejects extra, manual, `NotReviewed`, or outside-profile rows. The gate also
asserts that the retired `/api/stigman/push/{checklist_id}` route returns
`410 Gone` and that AutomateSTIG performed zero direct changed-review writes. An
exact remote no-op may be verified through the versioned API, but it does not
replace the changed-result handoff case.

The policy private seed is deleted immediately after signing. The remaining
signed policy, trust anchor, handoff, and GUI state are removed on exit.

The project also runs this on demand in a protected environment. Production
release evidence should use the deployed STIG Manager version in an authorized
staging environment, not the demo credentials or `latest` tag.

## Combined gate

`scripts/validate-external-workflows.py` validates offline CKL/CKLB/STIG Manager
and bounded DISA ZIP contracts in normal CI. The opt-in combined gate reruns the
hardened Viewer comparison from the raw source and GUI-saved paths; it does not
trust a prewritten `passed` boolean. It also requires an authenticated STIG
Manager endpoint:

```bash
export STIG_VIEWER_AUTOMATESTIG_BINARY=./target/release/automatestig
export STIG_VIEWER_CKL_SOURCE=/viewer/windows_server_2022_sanitized.ckl
export STIG_VIEWER_CKL_ROUNDTRIP=/viewer/viewer-roundtrip.ckl
export STIG_VIEWER_CKLB_SOURCE=/viewer/windows_server_2022_sanitized.cklb
export STIG_VIEWER_CKLB_ROUNDTRIP=/viewer/viewer-roundtrip.cklb
export STIG_VIEWER_PRODUCT_VERSION='<exact STIG Viewer version>'
export STIG_VIEWER_PLATFORM='<Windows/Linux version>'
export STIG_VIEWER_OPERATOR='<named tester>'
export STIG_VIEWER_EVIDENCE_OUTPUT=/evidence/stig-viewer-acceptance.json
export STIG_MANAGER_URL=https://stig-manager.staging.example
export STIG_MANAGER_TOKEN=...
python3 scripts/run-live-external-acceptance.py --repo-root . --require-live
```

The HTTP smoke in the combined gate is supplementary; the full staging
round-trip above is the STIG Manager release evidence.

## Evaluate-STIG and commercial A/B evidence

Live target acceptance proves AutomateSTIG agrees with an independent oracle;
it does not prove an advantage over another product. Use the separate
[controlled scanner comparison](commercial-scanner-comparison.md) on the same
representative target states to compare Evaluate-STIG, Tenable, Nipper, or
another scanner. That protocol requires repeated randomized runs, exact tool
and content hashes, retained native exports, and an oracle established before
the tool outputs are visible. Licensed products and their reports remain on the
protected runner and are never fetched by normal CI.

## Authoritative references

- [DoD STIG Viewer 3.x User Guide V1R7](https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_STIG_Viewer_3-x_User_Guide_V1R7.pdf)
- [STIG Manager installation and setup](https://stig-manager.readthedocs.io/en/latest/installation-and-setup/installation-and-setup.html)
- [STIG Manager container quick start](https://stig-manager.readthedocs.io/en/1.6.2/the-project/DockerHub_Readme.html)
