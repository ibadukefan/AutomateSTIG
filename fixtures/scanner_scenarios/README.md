# Scanner workflow scenarios

These fixtures exercise AutomateSTIG as a scanner that supplements STIG
Manager. They do not model local asset management, finding editing, approval,
portfolio reporting, or any other STIG Manager-owned workflow.

The scenarios reuse the deterministic device inputs in `fixtures/ontap/`,
`fixtures/bsd/`, and `fixtures/network/`, then bind them to a synthetic STIG
Manager collection, existing assets, exact assignments, remote review state,
expected safety-gate behavior, selected-run handoffs, and one synthetic receipt
for an exact no-op delivery. Changed create/update proposals are never modeled
as direct writes because STIG Manager does not provide an atomic conditional
review-write operation. All names use the reserved `.invalid` domain, all
identifiers are synthetic, and no password, token, private key, or usable
signature is checked in.

## Coverage

| Scenario | Actor flow | Expected behavior |
| --- | --- | --- |
| `ontap-connected-pass-create` | Analyst | Complete ONTAP V2R4 evidence previews 15 creates with zero direct writes and provides a handoff; seven reviewed-manual and seven out-of-profile rules stay untouched. |
| `ontap-connected-fail-update` | Analyst | All 15 scanner-owned results differ from prior scanner reviews; the preview is safety-gated with zero direct writes and a handoff. |
| `ontap-connected-incomplete` | Analyst | A typed transport failure remains incomplete and creates no delivery. |
| `freebsd-disconnected-pass-handoff` | Analyst | Complete FreeBSD evidence produces one selected-run handoff; 24 reviewed-manual and 173 out-of-profile rules remain remote work. |
| `freebsd-connected-fail-unchanged` | Analyst/manager | An identical scanner-owned result is a direct no-op; a transient `503` retry changes no remote review, produces a receipt, and retains the handoff. |
| `freebsd-disconnected-incomplete` | Analyst | Incomplete evidence produces no compliance handoff. |
| `cisco-connected-pass-preview` | Analyst/manager | A 33-create preview is safety-gated with zero direct writes and a handoff; all nine evidence-insufficient rules remain untouched. |
| `cisco-connected-fail-conflict` | Analyst/manager | A human-owned remote review causes a reconciliation conflict; no review is written and the handoff remains available. |
| `cisco-disconnected-incomplete` | Analyst | A truncated configuration fails closed before evaluation or handoff. |

`pass` and `fail` mean the synthetic device state is respectively compliant or
noncompliant for every currently automated rule. They do not mean that the
entire STIG is complete: manual rules remain for STIG Manager reviewers.

The Cisco policy files are unsigned templates. A live harness must generate an
ephemeral signing key, install only its public key in a temporary trust store,
and sign the exact template bytes for that run. The private test key and raw
signature must remain outside the repository.

## Validate

Run the dependency-free validator from the repository root:

```bash
python3 scripts/validate-scanner-scenarios.py
```

The validator checks JSON structure, input hashes, exact supported
profile/release/count bindings, existing-asset assignments, synthetic-only
destinations, fail-closed incomplete runs, sparse review counts, the zero-write
gate for creates and updates, retained conflict handoffs, exact no-op retry
digest stability, and the absence of likely secrets. It does not claim
live-device, live-STIG-Manager, or Evaluate-STIG acceptance.
