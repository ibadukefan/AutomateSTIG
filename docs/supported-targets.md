# Supported Targets

AutomateSTIG v0.3 ships immutable scanner profiles for exactly three target
families. Each profile binds the supported-target contract, exact benchmark
subset, executable check pack, coverage manifest, target adapter, compatibility
grammar, and integrity hashes. A fresh install does not require a normal user
to import raw XCCDF or manage the general DISA catalog.

The machine-readable contract is `content/supported-targets.json`; CI fails if
an extra pack is shipped or a required pack/coverage manifest is missing.

| Target | Benchmark contract | Evidence input | Compatibility rejection boundary | Automated | Manual | Reviewed profile | Full benchmark | Release acceptance gate |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| NetApp ONTAP 9.x | `NetApp_ONTAP_DSC_9-x_STIG` V2R4 | Read-only SSH/native adapter evidence; legacy strict evidence v2 during migration | ONTAP major 9 | 15 | 7 | 22 | 29 | Real or licensed ONTAP target |
| FreeBSD / DISA GPOS | `General_Purpose_Operating_System` V3R3 | Read-only SSH/native adapter evidence; legacy strict evidence v2 during migration | FreeBSD major 13–14 | 6 | 24 | 30 | 203 | Real FreeBSD host or VM kernel |
| Cisco IOS-XE Router NDM | `Cisco_IOS-XE_Router_NDM_STIG` V3R7 | Complete running configuration plus signed organization policy | IOS-XE major 17 | 33 | 9 | 42 | 42 | Representative IOS-XE device configuration |
| **Total** |  |  |  | **54** | **40** | **94** | **274** |  |

The automated counts describe only rules whose collected evidence proves the
full decision. The reviewed profile is the automated plus reviewed-manual
scope. The full-benchmark denominator comes from the exact bundled benchmark;
it makes the 180 rules outside the reviewed profiles visible rather than
silently treating them as assessed. Partial observations such as
configured ACL names, raw PAM or rc.conf
text, banner fragments, CA names, backup existence, and current vendor-support
status remain `NotReviewed`; they are not inferred into compliance. The current
rule-by-rule pack inventories and adapter profiles remain `experimental` until
the required live acceptance evidence is attached to a release. The version
grammars above reject obviously mismatched devices; they are not a published
tested-firmware matrix. `accepted_tested_versions` remains empty until an
authorized release gate records those exact versions.

## Scope Boundary

AutomateSTIG v0.3 does not scan general Linux distributions, AIX, Solaris,
Windows, Cisco NX-OS, or Cisco ASA. Cisco IOS-XE is evaluated from a running
configuration, not by the SSH collector. CKL/CKLB parsing, legacy XCCDF import,
and STIG Manager interoperability may process content for other products, but
those format operations are not scanner support.

STIG Manager content or assignment breadth also does not expand scanner scope.
The GUI shows unsupported assignments with a reason and does not attempt to
create an asset, change its assignment, or scan it with a nearby profile.

The checked-in DISA download catalog and artifact metadata are research and
content-ingestion inputs. Their breadth and counts must not be reported as
AutomateSTIG device coverage.

## Adding A Target

Adding a target is a release-scope change. It requires an updated target
contract and schema, a curated pack, exact coverage inventory, deterministic
fixtures, a live acceptance gate, operator documentation, and independent
software/security review. Merely adding JSON beneath `content/check_packs` is
rejected by CI.
