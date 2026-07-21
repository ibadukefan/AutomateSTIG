# Dependency Audit Exceptions

AutomateSTIG CI must fail on RustSec vulnerabilities unless an exception is explicit, documented, and periodically revisited.

## Active exceptions

### RUSTSEC-2023-0071 — `rsa` Marvin timing side-channel

- Status: temporary exception
- Source: transitive dependency through the current `russh`/`russh-keys` SSH stack
- Current remediation status: no fixed upgrade is available in the affected dependency path
- CI behavior: `cargo audit --ignore RUSTSEC-2023-0071`
- Review cadence: revisit before each release and whenever the SSH dependency stack is upgraded
- Removal criteria: remove the ignore once an upstream fixed version is available or the SSH stack is replaced with one that does not pull the vulnerable `rsa` version

Warnings that do not make `cargo audit` fail are still tracked during release review, especially unmaintained dependencies and advisories with practical exploitability in AutomateSTIG's supported modes.

## Recently cleared advisory backlog

- Removed the GUI dependency on `scraper`, which removed the transitive unmaintained `fxhash` warning from the audit graph.
- Updated the lockfile to `rand 0.8.6`, clearing the prior `rand 0.8.5` RustSec warning.

## Current warning backlog

`cargo audit --ignore RUSTSEC-2023-0071` may still report warning-only dependency hygiene items. These do not currently fail CI, but they must be reviewed before release:

- `proc-macro-error2` unmaintained via `include-flate`/`rust-embed`.
- `anyhow` unsound advisory `RUSTSEC-2026-0190`; monitor for upstream fixed release and upgrade promptly.
- `spin 0.9.8` yanked via the current Axum/multipart dependency graph.

These warnings are tracked separately from failing vulnerability advisories because the current supported AutomateSTIG modes do not expose a practical exploit path for them.
