# Field Calibration Checklist

The ONTAP, FreeBSD, and Cisco check packs are written against canonical device output and are marked **experimental** until validated against your real devices. Calibration needs exactly three sanitized artifacts, collected once. Everything below is read-only.

## What to capture

1. **One NetApp ONTAP filer** — from any host with SSH access to the cluster management LIF:

   ```bash
   AUTOMATESTIG_SSH_PASSWORD='...' scripts/collectors/ontap-collect.sh admin@filer ontap-evidence.json
   ```

2. **One FreeBSD host**:

   ```bash
   AUTOMATESTIG_SSH_PASSWORD='...' scripts/collectors/bsd-collect.sh admin@bsdhost bsd-evidence.json
   ```

3. **One representative Cisco IOS-XE router running config** — an authorized
   config backup (for example, RANCID, Oxidized, or SolarWinds NCM) or a manual
   `show running-config` capture. No AutomateSTIG collector is used for IOS-XE.

## Sanitization

Before the artifacts leave the enclave, replace — do not delete — sensitive values, so line structure survives:

- Hostnames/FQDNs → `host01.example.test`
- IP addresses → RFC 5737 addresses (`192.0.2.x`, `198.51.100.x`)
- Usernames/groups → `user01`, `DOMAIN\group01`
- Any secret material (SNMP communities, NTP keys, type-7 strings) → `XXXXXXXX`

Do **not** reword command output, change column spacing, or drop "N entries were displayed" style summary lines — formatting is exactly what calibration verifies.

## Running the calibration

```bash
automatestig evaluate --stig NetApp_ONTAP_DSC_9-x_STIG --evidence ontap-evidence.json --output filer01.scanner-result.json
automatestig evaluate --stig General_Purpose_Operating_System --evidence bsd-evidence.json --output bsdhost01.scanner-result.json
automatestig evaluate --stig Cisco_IOS-XE_Router_NDM_STIG --config router-config.txt --host rtr01 --output rtr01.scanner-result.json
```

Review each native scanner result against what you know to be true about the
device. A complete result can additionally be written as CKLB with
`--format cklb`; CKLB is a projection, not the authoritative scanner record.

- A rule you know is compliant showing **Open** → the pattern is too strict for your output format. Report the rule ID and the relevant sanitized output block.
- A rule you know is misconfigured showing **NotAFinding** → report immediately; false-pass patterns are treated as defects.
- Rules in the documented manual-review sets showing **Not_Reviewed** is correct behavior.

Interpret counts against the complete benchmark, not just the reviewed
profile: ONTAP is 15 automated/7 manual/22 reviewed/29 full, FreeBSD is
6/24/30/203, and Cisco is 33/9/42/42. Across all three profiles that is 54
automated, 40 manual, 94 reviewed, and 274 full-benchmark rules. Rules outside
the reviewed profile remain work for STIG Manager; they are not implicit
passes or scanner results.

## Recording site conventions

Do not edit a scanner result to encode site convention. Complete human
determinations and supporting comments in STIG Manager. A scanner check may
consume a typed, asset-bound, signed organization policy only when the profile
explicitly declares an organization-defined parameter (currently the relevant
Cisco controls); that policy is not a substitute for device evidence.

## Chain of Custody

Every completed checklist evaluated from an evidence document or config file records the SHA-256 of the exact input bytes in each finding's comments (`Supplied evidence provenance ... SHA-256: <hex>`). A reviewer can independently confirm a specific artifact with `sha256sum ontap-evidence.json` (or `shasum -a 256`). Evidence v2 also carries the exact collection-plan digest and observed SSH server-key fingerprint.
