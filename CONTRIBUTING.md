# Contributing to AutomateSTIG

AutomateSTIG accepts focused fixes and evidence-backed improvements to its
difficult-device scanner and handoff workflow. It is not a replacement for
STIG Manager.

## Before opening code

1. Read the [product boundary](docs/scanner-product-plan.md#product-decision).
2. Open or link an issue for a nontrivial change.
3. Do not include device evidence, configurations, credentials, private keys,
   or controlled data.
4. Keep changes narrow. New targets require an exact STIG, a read-only evidence
   path, representative lab access, negative cases, and an authorized SME.

Features for asset management, STIG assignment, human finding edits, risk
acceptance, dashboards, portfolio reports, or long-term compliance history
belong in STIG Manager and will not be added here.

## Development setup

Install stable Rust and Python 3.10 or newer, then run:

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
python3 -m unittest discover -s scripts/disa_corpus/tests -v
```

Frontend changes also require:

```bash
cd crates/gui/frontend/scanner
npm ci
npm test
npm run check
```

See the [documentation index](docs/README.md) for architecture, adapter,
security, and release guidance.

## Security and evidence rules

- Missing, denied, timed-out, truncated, malformed, ambiguous, or unsupported
  evidence must fail closed; it must never become a pass.
- Automated results must remain bound to exact target, content, policy,
  evidence, and build provenance.
- Sparse handoffs must never overwrite manual or human-owned reviews.
- Tests should include positive, negative, incomplete, and adversarial cases.
- Fixtures must be synthetic or explicitly authorized and sanitized.

## Pull requests

Use the pull request template. Product changes during the `v0.3.0` feature
freeze require the repository's independent approval label and reviewers. Do
not weaken or bypass that gate. Documentation-only changes should still state
whether they alter operator behavior or security expectations.
