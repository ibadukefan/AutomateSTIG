# STIG Manager Scanner-Handoff Acceptance Rig

This localhost/CI rig uses real STIG Manager, Keycloak, and MySQL containers to
test the scanner-first product boundary. Its credentials are demo-grade and
must never be used outside an isolated acceptance environment.

AutomateSTIG supplements STIG Manager; it does not create or manage STIG
Manager inventory. `run-staging-acceptance.py` therefore assigns two explicit
roles:

1. The **rig administrator** imports the authorized Cisco IOS-XE Router NDM
   benchmark and creates the collection, asset, and exact V3R7 assignment
   directly through STIG Manager.
2. **AutomateSTIG** receives no STIG Manager URL or credential. It evaluates the
   Cisco running-configuration fixture with the existing signed organization
   policy through the disconnected `/api/v1` scanner flow and produces one
   selected-run handoff.
3. The acceptance script downloads that ZIP and executes
   `automatestig scanner verify-handoff` before reading it.
4. AutomateSTIG is stopped. The script then acts as the **receiving operator**
   and maps only `sparse-reviews.json` to STIG Manager's JSON Review API for the
   already-existing exact assignment. It does not import manual, Not Reviewed,
   or out-of-profile rows.
5. The script independently checks the stored STIG Manager reviews and the CKL
   STIG Manager exports. It also confirms the handoff's supplemental XCCDF and
   CKLB projections are sparse and equivalent while the authoritative STIG
   Manager export retains the full benchmark.

STIG Manager's web client can parse a selected XCCDF file and translate it to
review writes, but the STIG Manager server API has no native result-XCCDF upload
endpoint. This rig does not automate or claim acceptance of that browser import
wizard. `results.xccdf.xml` is verified as a standards-based supplemental
artifact; `sparse-reviews.json` is the only tested receiver transport.

The acceptance explicitly asserts that:

- the retired `POST /api/stigman/push/{id}` route returns HTTP 410;
- AutomateSTIG made zero direct STIG Manager review writes;
- the receiving operator wrote exactly the sparse scanner-owned Rule-ID set;
- the supplemental XCCDF matched the sparse result/detail/comment set but was
  not used as a native import;
- statuses round-trip through STIG Manager; and
- the redacted evidence artifact contains hashes, counts, and boundary facts,
  but no token, client secret, raw configuration, policy contents, or handoff.

## Usage

```bash
cargo build --release --locked --bin automatestig --bin automatestig-gui
docker compose -f staging/stigman/docker-compose.yml up -d
python3 staging/stigman/run-staging-acceptance.py \
  --binary target/release/automatestig-gui \
  --cli-binary target/release/automatestig \
  --evidence-output stig-manager-acceptance.json
docker compose -f staging/stigman/docker-compose.yml down -v
```

The one-run Ed25519 private seed is deleted immediately after signing. The
remaining policy, detached signature, public trust anchor, GUI database, and
downloaded handoff are removed when the run ends.

No HTTPS bridge or invalid-certificate product exception is involved. The GUI
runs disconnected and never needs to trust the rig's HTTP-only STIG Manager
container. Only the explicit Python rig administrator/receiver talks to the
loopback STIG Manager API.

The protected workflow is
`.github/workflows/stigman-staging.yml`. All three container images are pinned
by digest. Updating a digest is a reviewed dependency change and requires a
complete rerun of this acceptance.

The STIG Manager images publish linux/amd64 only. The compose file pins
`platform: linux/amd64`, so Apple Silicon hosts run them under emulation.
