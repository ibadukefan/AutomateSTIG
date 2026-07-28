## Change boundary

- [ ] This change is inside the scanner-only product scope.
- [ ] No unrelated feature work is bundled into this pull request.
- [ ] Product-code changes carry the `release-freeze-approved` label and name the release manager who approved the exception.

Freeze exception / defect being corrected:

## Decision and evidence impact

- [ ] I identified every path that can change a compliance result, evidence completeness, provenance, import, signature, or audit record.
- [ ] New failure modes fail closed (`NotReviewed`/error), never as a pass.
- [ ] Tests include malformed, partial, timeout, truncation, and adversarial inputs where relevant.
- [ ] Documentation and operator runbooks are updated.

## Independent review

- [ ] Software reviewer (not the author):
- [ ] Security reviewer (not the author):
- [ ] Code-owner review completed for all security-critical paths.
- [ ] All review threads are resolved by code or an explicit, time-bounded risk acceptance.

## Acceptance and release

- [ ] Rust, Python, end-to-end, content, fuzz, dependency, and release-build gates pass.
- [ ] ONTAP / FreeBSD / Cisco IOS-XE / STIG Viewer / STIG Manager live-acceptance impact is stated.
- [ ] Release evidence is updated if this change is intended for a release tag.
