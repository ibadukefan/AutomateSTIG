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

- 2026-11: refreshed the lockfile (rustls, rustls-webpki, webpki-roots, h2, quinn-proto, tokio, anyhow, crypto-bigint, ctutils, zstd family and others) and moved `zip` 2 to 9, clearing 22 advisories and all warning-only items. ZIP entry guards now also reject symlink entries and absolute names, because `zip` 9's `enclosed_name()` rewrites absolute names instead of rejecting them.
- Removed the GUI dependency on `scraper`, which removed the transitive unmaintained `fxhash` warning from the audit graph.
- Updated the lockfile to `rand 0.8.6`, clearing the prior `rand 0.8.5` RustSec warning.

## Current warning backlog

`cargo audit --ignore RUSTSEC-2023-0071` currently reports no warnings. Re-review before each release.
