# Supported Targets

AutomateSTIG v0.3 ships scanner content for exactly three target families. The
machine-readable contract is `content/supported-targets.json`; CI fails if an
extra pack is shipped or a required pack/coverage manifest is missing.

| Target | Benchmark contract | Evidence input | Reviewed inventory | Automated | Manual | Release acceptance gate |
| --- | --- | --- | ---: | ---: | ---: | --- |
| NetApp ONTAP 9.x | `NetApp_ONTAP_DSC_9-x_STIG` V2R2 | Plan-bound read-only SSH transcript | 22 | 16 | 6 | Real or licensed ONTAP target |
| FreeBSD / DISA GPOS | `General_Purpose_Operating_System` V3R3 | Plan-bound read-only SSH transcript | 30 | 3 | 27 | Real FreeBSD host or VM kernel |
| Cisco IOS-XE Router NDM | `Cisco_IOS-XE_Router_NDM_STIG` V3R7 | Authorized running configuration plus signed organization policy | 34 | 21 | 13 | Representative IOS-XE device configuration |
| **Total** |  |  | **86** | **40** | **46** |  |

The automated counts describe only rules whose collected evidence proves the
full decision. The reviewed counts are curated candidate inventories, not the
complete ONTAP or GPOS benchmark inventories. Partial observations such as
configured ACL names, raw PAM or rc.conf
text, banner fragments, CA names, backup existence, and current vendor-support
status remain `NotReviewed`; they are not inferred into compliance. The current
rule-by-rule pack inventories remain `experimental` until the required live
acceptance evidence is attached to a release.

## Scope Boundary

AutomateSTIG v0.3 does not scan general Linux distributions, AIX, Solaris,
Windows, Cisco NX-OS, or Cisco ASA. Cisco IOS-XE is evaluated from a running
configuration, not by the SSH collector. CKL/CKLB parsing, XCCDF import, and
STIG Manager interoperability may process content for other products, but
those format operations are not scanner support.

The checked-in DISA download catalog and artifact metadata are research and
content-ingestion inputs. Their breadth and counts must not be reported as
AutomateSTIG device coverage.

## Adding A Target

Adding a target is a release-scope change. It requires an updated target
contract and schema, a curated pack, exact coverage inventory, deterministic
fixtures, a live acceptance gate, operator documentation, and independent
software/security review. Merely adding JSON beneath `content/check_packs` is
rejected by CI.
