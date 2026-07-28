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
result. The bundle has exactly one representative baseline and one independently
captured negative-control scenario. Each scenario must cover every and only
executable rule, bind its exact source state and asset, and contain no
`NotReviewed` result. The negative control must differ from the baseline and
contain at least one `Finding`; an all-pass-only oracle is rejected.
`source_state_sha256` must match each fresh command-state/configuration digest
exactly. Oracles older than 90 days are rejected. Derive the state bindings
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
`XCCDF`, and `TIMEOUT_SECS`. This runner rejects `TRUST_ON_FIRST_USE`; perform
and record enrollment separately, then pin the host key out of band. The
redacted evidence stores matching expected/observed status-map digests, but
never the status map, credentials, commands, target output, or host addresses.

Cisco acceptance is deliberately file-based. Set
`AUTOMATESTIG_LIVE_CISCO_IOS_XE_CONFIG` to a protected path containing a fresh,
authorized running configuration captured from the representative device.
Set `AUTOMATESTIG_LIVE_CISCO_IOS_XE_ORACLE` to its independently adjudicated
oracle bundle, `AUTOMATESTIG_LIVE_CISCO_IOS_XE_NEGATIVE_CONFIG` to the separately
captured negative-control configuration, and bind both scenario hashes.
`AUTOMATESTIG_LIVE_CISCO_IOS_XE_HOSTNAME` is required and must match both
configurations; `XCCDF` is optional. The configurations themselves are hashed
in the acceptance record but are never copied into the release artifact.

The manual `Live Device Acceptance` workflow runs on an environment-protected
self-hosted runner labeled `automatestig-live-devices`. Its environment must
require reviewer approval and contain the lab secrets, protected oracle paths,
and protected Cisco configuration. A target-specific run is useful for
diagnosis; release evidence needs passing results for all three device targets,
 including exact agreement with both scenarios in all three independent oracle
 bundles.

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
It provisions OAuth client credentials, imports authoritative XCCDF, evaluates
a Cisco device fixture in AutomateSTIG, pushes twice, compares every review, and
round-trips the CKL served by STIG Manager:

```bash
cargo build --release --locked --bin automatestig-gui
docker compose -f staging/stigman/docker-compose.yml up -d
python3 staging/stigman/run-staging-acceptance.py \
  --binary target/release/automatestig-gui
docker compose -f staging/stigman/docker-compose.yml down -v
```

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

## Authoritative references

- [DoD STIG Viewer 3.x User Guide V1R7](https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_STIG_Viewer_3-x_User_Guide_V1R7.pdf)
- [STIG Manager installation and setup](https://stig-manager.readthedocs.io/en/latest/installation-and-setup/installation-and-setup.html)
- [STIG Manager container quick start](https://stig-manager.readthedocs.io/en/1.6.2/the-project/DockerHub_Readme.html)
