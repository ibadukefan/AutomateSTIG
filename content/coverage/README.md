# Coverage Manifests

This directory contains rule-by-rule coverage manifests for STIGs that AutomateSTIG claims to support.

A supported manifest answers three questions for every DISA rule:

1. Does AutomateSTIG automate it, import it from a scanner, or require manual review?
2. Where is the implementation or evidence mapping?
3. What tests prove the behavior?

Check packs without matching manifests are experimental/community content.

Manifest tiers:

- `*.example.json` manifests exercise sanitized fixture workflows.
- `*.full.json` manifests enumerate every rule currently represented in the corresponding AutomateSTIG check pack for flagship targets, but remain `experimental` because they are not authoritative DISA inventories.
- `current-checkpacks/*.current.json` manifests enumerate every rule in every current AutomateSTIG check pack. They prove 100% coverage of the current in-repository automated-check inventory: 100 manifests covering 2,215 automated checks. This is intentionally narrower than claiming 100% authoritative DISA benchmark automation.
- `*.disa-*.json` manifests are generated from official public DISA XCCDF ZIPs stored under `fixtures/authorized/disa-public-2026-04/`. These are the authoritative rule inventories currently used for replacement-readiness accounting:
  - `windows_server_2022.disa-v2r8.json`: 282 DISA rules, 60 currently mapped to executable AutomateSTIG checks, 222 represented as manual-review workflow items.
  - `rhel8.disa-v2r7.json`: 366 DISA rules, 50 currently mapped to executable AutomateSTIG checks, 316 represented as manual-review workflow items.

Regenerate the DISA manifests with:

```bash
python3 scripts/generate-disa-coverage.py \
  --zip fixtures/authorized/disa-public-2026-04/U_MS_Windows_Server_2022_V2R8_STIG.zip \
  --member U_MS_Windows_Server_2022_V2R8_Manual_STIG/U_MS_Windows_Server_2022_STIG_V2R8_Manual-xccdf.xml \
  --check-pack content/check_packs/windows_server_2022.json \
  --output content/coverage/windows_server_2022.disa-v2r8.json \
  --stig-id Windows_Server_2022_STIG \
  --version V2R8 \
  --source 'DISA public Microsoft Windows Server 2022 STIG Ver 2 Rel 8'

python3 scripts/generate-disa-coverage.py \
  --zip fixtures/authorized/disa-public-2026-04/U_RHEL_8_V2R7_STIG.zip \
  --member U_RHEL_8_V2R7_Manual_STIG/U_RHEL_8_STIG_V2R7_Manual-xccdf.xml \
  --check-pack content/check_packs/rhel8.json \
  --output content/coverage/rhel8.disa-v2r7.json \
  --stig-id RHEL_8_STIG \
  --version V2R7 \
  --source 'DISA public Red Hat Enterprise Linux 8 STIG Ver 2 Rel 7'
```

`production` coverage manifests are validation-gated: they must declare an authoritative `generated_from` fixture and provide evidence references for every evidence-required rule. Do not claim full replacement-ready status while authoritative manifests still classify large portions of the DISA rule inventory as manual-only without external acceptance evidence.
