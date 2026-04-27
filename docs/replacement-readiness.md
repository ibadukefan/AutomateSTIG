# AutomateSTIG Evaluate-STIG Replacement Readiness

AutomateSTIG should claim "Evaluate-STIG replacement" status only for capabilities backed by automated tests, sanitized fixtures, and rule-by-rule coverage manifests.

## Readiness Levels

| Level | Meaning | User-facing claim allowed |
|---|---|---|
| Planned | Designed but not implemented | Roadmap only |
| Prototype | Code exists, synthetic tests only | Experimental |
| Validated | Real sanitized fixtures and golden tests pass | Supported capability |
| Production | Validated plus hardened security, docs, CI, and release artifacts | Replacement-ready |

## Capability Matrix

| Capability | Required for full replacement | Current status | Proof artifact required | Release target |
|---|---:|---|---|---|
| CKL parse/write | Yes | Prototype/Validated | Golden CKL roundtrip fixtures accepted by STIG Viewer | v0.2 |
| CKLB parse/write | Yes | Prototype/Validated | Golden CKLB roundtrip fixtures accepted by STIG Viewer/STIG Manager | v0.2 |
| DISA XCCDF benchmark import | Yes | Prototype | Real DISA XCCDF ZIP fixture tests | v0.3 |
| SCC XCCDF result import | Yes | Partial | Sanitized SCC result fixtures with expected status/evidence mapping | v0.3 |
| OpenSCAP XCCDF result import | Yes | Partial | Sanitized OpenSCAP result fixtures with expected status/evidence mapping | v0.3 |
| ACAS/Nessus import | Only if claimed | Not validated | `.nessus`/ACAS fixture parser and golden tests | v0.4 |
| STIG Manager export | Yes | Prototype | Payload golden tests + integration contract docs | v0.3 |
| eMASS/POA&M export | Better-than feature | Prototype | CSV schema and fixture tests | v0.4 |
| Signed offline content packs | Yes for air-gapped claim | Prototype | Trusted-signature-required import tests | v0.2 |
| Windows Server 2022 STIG | Flagship support | Partial | 100% rule classification coverage manifest + fixture tests | v0.5 |
| RHEL 8 STIG | Flagship support | Partial | 100% rule classification coverage manifest + fixture tests | v0.5 |
| GUI desktop mode | Yes | Prototype | localhost-only default, random auth, end-to-end smoke test | v0.2 |
| GUI server mode | Enterprise feature | Not production-ready | explicit auth, CORS, audit, no demo defaults | v0.4 |
| Remote SSH scan | Better-than feature | Prototype | strict host key tests + sanitized Linux fixtures | v0.4 |
| Remote WinRM scan | Better-than feature | Prototype | HTTPS-default tests + sanitized Windows fixtures | v0.4 |
| Structured evidence | Yes | Partial | evidence model preserved through CKL/CKLB/STIG Manager exports | v0.3 |
| Coverage reporting | Yes | Missing/Scaffolded | CI gate rejects unsupported comprehensive claims | v0.3 |

## Replacement Claim Policy

AutomateSTIG may be called a **validated Evaluate-STIG replacement** only for platforms and workflows listed as `Production` in this matrix and backed by CI artifacts.

Until then, public wording should say:

> AutomateSTIG is being built as a validated Evaluate-STIG replacement. Supported replacement-ready platforms and workflows are listed in the readiness matrix.

## Initial Flagship Targets

1. Windows Server 2022
2. RHEL 8
3. Windows Server 2019
4. RHEL 9
5. Windows 10/11
6. Ubuntu 22.04

Other check packs remain experimental/community until they have coverage manifests and fixture proof.
