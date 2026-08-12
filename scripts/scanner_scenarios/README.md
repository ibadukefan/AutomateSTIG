# Localhost scanner API scenarios

This harness exercises the scanner-first workflow through a real running GUI
API. It uses no device or STIG Manager credentials and makes no connection
outside the explicit loopback URL.

The Rust generator first converts the reviewed synthetic ONTAP and FreeBSD
command fixtures into the production native adapter envelope. The adapter
itself supplies the operation plan, profile/check-pack bindings, response
digests, evidence digest, and replay result. Six envelopes are generated:
compliant, findings, and incomplete for each target.

The live suite also uploads the complete synthetic Cisco IOS-XE running
configuration with its detached test-policy signature. The corresponding
public test key in `fixtures/scanner_scenarios/inputs/` must be decoded to a
32-byte `.pub` file in the GUI's dedicated organization-policy trust directory.
These public/signature fixtures are acceptance material only, not production
trust anchors or private signing material.

The live run then performs:

1. disconnected preflight and upload of complete FreeBSD evidence;
2. immutable run reads plus selected-run handoff download and hash checks;
3. the same complete handoff path for ONTAP and signed Cisco configuration;
4. signed-policy provenance for the Cisco result; and
5. an incomplete ONTAP transport-failure upload that must contain no sparse
   reviews, delivery record, delivery action, or handoff.

## Run

From the repository root, start the GUI on a known loopback port with a
throwaway local session token:

```bash
PORT=8787 \
  AUTOMATESTIG_AUTH_TOKEN=local-scanner-scenario-token-2026 \
  AUTOMATESTIG_DATA_DIR=/tmp/automatestig-scanner-live \
  AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR=/path/to/test-policy-keys \
  cargo run -p automatestig-gui
```

In a second terminal:

```bash
python3 scripts/scanner_scenarios/run_localhost.py \
  --base-url http://127.0.0.1:8787 \
  --auth-token local-scanner-scenario-token-2026 \
  --artifacts-dir /tmp/automatestig-scanner-scenarios
```

The final JSON summary names each immutable run, handoff ZIP, handoff SHA-256,
and manifest SHA-256. When `--artifacts-dir` is supplied, the same result is
retained as `summary.json`. A nonzero exit status identifies the first violated
contract. The token is used only as an HTTP header and is not written to the
artifacts.

To generate and replay-check the native evidence without a running GUI:

```bash
python3 scripts/scanner_scenarios/run_localhost.py \
  --generate-only \
  --artifacts-dir /tmp/automatestig-native-evidence
```

The generator can also be invoked directly:

```bash
cargo run -p automatestig-core --example scanner_scenario_evidence -- \
  --output-dir /tmp/automatestig-native-evidence \
  --fixtures-root fixtures
```

## What is verified

- preflight discloses a nonempty read-only plan and binds exact file metadata;
- upload returns `202` and an immutable run projection;
- POST, repeated GET, and run-list projections are byte-equivalent after
  canonical JSON encoding;
- every persisted request/result/content/evidence binding is lowercase SHA-256;
- handoff ZIP members are unique, unencrypted, path-safe, and exactly the six
  expected files;
- `integrity.json` hashes the exact manifest bytes, and the manifest hashes all
  four payload files, including retained replay evidence;
- handoff bindings equal the immutable run bindings;
- sparse reviews in the native scanner artifact and CKLB handoff agree in
  count, and the evidence envelope is complete;
- downloading a handoff does not mutate the run; and
- transport-failure evidence stays incomplete with zero proposed reviews,
  zero delivery counts, no delivery ID, and rejected delivery/handoff calls.

## Deliberate limitations

This is a deterministic localhost acceptance harness, not live-device
acceptance. It does not test an SSH server, STIG Manager authentication,
connected sparse delivery, ownership conflicts, transient retry behavior,
Cisco policy signatures, or Evaluate-STIG parity. Those require separate
authorized environments.

The four created scan runs are immutable and remain in the GUI data directory.
Use a dedicated `AUTOMATESTIG_DATA_DIR`, as shown above, when isolation is
required. The harness never deletes existing user data or its own run records.
