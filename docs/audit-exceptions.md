# Dependency Audit Exceptions

AutomateSTIG CI must fail on RustSec vulnerabilities unless an exception is explicit, documented, and periodically revisited.

## Active exceptions

None. CI runs `cargo audit` without ignored advisories.

Warnings that do not make `cargo audit` fail are still tracked during release review, especially unmaintained dependencies and advisories with practical exploitability in AutomateSTIG's supported modes.

## Recently cleared advisory backlog

- Disabled russh's default RSA feature while retaining its `aws-lc-rs`
  cryptography backend. This removes the transitive vulnerable `rsa` package
  covered by RUSTSEC-2023-0071. SSH now fails clearly on RSA private keys and
  supports Ed25519/ECDSA keys instead.
- Removed the GUI dependency on `scraper`, which removed the transitive unmaintained `fxhash` warning from the audit graph.
- Updated the lockfile to `rand 0.8.6`, clearing the prior `rand 0.8.5` RustSec warning.
- Updated `anyhow` to `1.0.103`, which includes the fix for RUSTSEC-2026-0190.
- Removed unused rust-embed compression, eliminating the unmaintained `proc-macro-error2` dependency reported by RUSTSEC-2026-0173.
- Updated the transitive multipart dependency from yanked `spin 0.9.8` to
  `spin 0.9.9`, which fixes the upstream `Once` ownership unsoundness and
  clears the yanked-package warning.

The release audit currently reports no vulnerability or warning-only dependency
backlog. Any future advisory or warning must be resolved or recorded here
before a release is approved.
