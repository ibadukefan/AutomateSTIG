# Accreditation Dossier

A single reference for security reviewers evaluating AutomateSTIG for use in a closed or accredited environment. Every claim links to the artifact that proves it.

## What the software is

Two statically built binaries — `automatestig` (CLI) and `automatestig-gui` (local web GUI) — that collect read-only evidence from network devices, Linux/UNIX systems, NetApp ONTAP, and FreeBSD, evaluate it deterministically against imported DISA benchmarks, and emit CKL/CKLB checklists or push reviews to STIG Manager. No agents are installed on evaluated devices.

## Security posture

| Property | Detail | Evidence |
|---|---|---|
| Offline by default | No network calls unless a connected feature (DISA fetch, STIG Manager push, SSH scan) is explicitly configured | [Security Model](security-model.md); GUI binds 127.0.0.1 unless overridden |
| Deterministic | Same inputs produce identical findings — no AI/ML in the evaluation path; reviewers can re-run and diff | Determinism check in `scripts/e2e-acceptance.py` (byte-stable evaluation) |
| No secret collection | Collectors gather configuration text only; no password hashes, no credential stores | `scripts/collectors/*.sh` (read-only command lists) |
| Content integrity | `.stigpack` content is SHA-256 verified; unsigned packs are refused unless a lab override is set; trusted keys are Ed25519 | [STIG Pack Files](stigpack.md); `AUTOMATESTIG_TRUSTED_KEYS_DIR` |
| Authenticated GUI | All API routes require a session token; non-loopback binds require an explicit strong token | `crates/gui/src/main.rs` auth middleware |
| Dependency hygiene | `cargo audit` gates every CI run (one documented exception) | [Audit Exceptions](audit-exceptions.md); CI `dependency-audit` job |
| SBOM | CycloneDX 1.5 SBOM generated per release | `scripts/generate-cyclonedx-sbom.py`; attached to GitHub releases from v0.2.0 |

## Verification evidence

- **Unit/integration tests:** `cargo test --workspace` — 14 suites, every CI run, three OSes.
- **Black-box acceptance:** `scripts/e2e-acceptance.py` runs the release binaries end-to-end against official DISA benchmark fixtures with independently computed oracles (per-rule status assertions for ONTAP, FreeBSD, and Cisco evidence). Gates every push.
- **External integration:** `staging/stigman/` stands up a real STIG Manager (containerized) and verifies push, review-for-review accuracy, and CKL round-trip weekly and on demand.
- **Content validation:** coverage manifests, corpus regression floors, and authorized-fixture SHA-256 manifests validate on every CI run.

## Data handling

Evidence transcripts, checklists, and the SQLite database stay on the host under `~/.automatestig/`. Nothing is transmitted unless the operator configures STIG Manager push (OAuth2 client-credentials; client secret stored encrypted) or DISA fetch (allowlisted to `*.cyber.mil` domains only).

## Known gaps (disclosed)

- **Code signing:** installers are not yet signed/notarized (requires organizational Apple Developer and Windows signing certificates). First-launch OS warnings and their workarounds are documented in [Installation](installation.md). Signing will be wired into the release workflow when certificates are available.
- **Experimental check packs:** ONTAP/FreeBSD/Cisco packs are calibrated against canonical output until validated per [Field Calibration](field-calibration.md).
- **Network coverage scope:** the Cisco IOS-XE Router **NDM** benchmark is automated; the separate **RTR** benchmark (routing-plane rules) is not yet covered and its rules remain Not_Reviewed. Other vendors (Juniper, Arista, Palo Alto, F5) are on the roadmap.
- Rules the packs cannot honestly automate remain `Not_Reviewed` — the tool never fabricates a compliance result.
