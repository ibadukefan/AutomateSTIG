# Field Calibration Checklist

The ONTAP, FreeBSD, and Cisco check packs are written against canonical device output and are marked **experimental** until validated against your real devices. Calibration needs exactly three sanitized artifacts, collected once. Everything below is read-only.

## What to capture

1. **One NetApp ONTAP filer** — from any host with SSH access to the cluster management LIF:

   ```bash
   scripts/collectors/ontap-collect.sh admin@filer > ontap-evidence.txt
   ```

2. **One FreeBSD host**:

   ```bash
   scripts/collectors/bsd-collect.sh admin@bsdhost > bsd-evidence.txt
   ```

3. **One router/switch running config** — any existing config backup (RANCID, Oxidized, SolarWinds NCM export) or a manual `show running-config` capture. No collector needed.

## Sanitization

Before the artifacts leave the enclave, replace — do not delete — sensitive values, so line structure survives:

- Hostnames/FQDNs → `host01.example.test`
- IP addresses → RFC 5737 addresses (`192.0.2.x`, `198.51.100.x`)
- Usernames/groups → `user01`, `DOMAIN\group01`
- Any secret material (SNMP communities, NTP keys, type-7 strings) → `XXXXXXXX`

Do **not** reword command output, change column spacing, or drop "N entries were displayed" style summary lines — formatting is exactly what calibration verifies.

## Running the calibration

```bash
automatestig evaluate --stig NetApp_ONTAP_DSC_9-x_STIG --evidence ontap-evidence.txt --host filer01 --output filer01.ckl --format ckl
automatestig evaluate --stig General_Purpose_Operating_System --evidence bsd-evidence.txt --host bsdhost01 --output bsdhost01.ckl --format ckl
automatestig evaluate --stig Cisco_IOS-XE_Router_NDM_STIG --config router-config.txt --host rtr01 --output rtr01.ckl --format ckl
```

Review each CKL against what you know to be true about the device:

- A rule you know is compliant showing **Open** → the pattern is too strict for your output format. Report the rule ID and the relevant sanitized output block.
- A rule you know is misconfigured showing **NotAFinding** → report immediately; false-pass patterns are treated as defects.
- Rules in the documented manual-review sets showing **Not_Reviewed** is correct behavior.

## Recording site conventions

Where your site meets a requirement through a different-but-compliant mechanism (e.g., a stricter password minimum than the canonical pattern expects), record it with an [answer file](answer-files.md) rather than editing the check pack — answer files are versioned, auditable, and survive content updates.

## Chain of Custody

Every checklist evaluated from an evidence transcript or config file records the SHA-256 of the exact input bytes in each finding's comments (`Automated evaluation provenance: ... SHA-256: <hex>`). A reviewer can independently confirm the checklist came from a specific artifact with `sha256sum evidence.txt` (or `shasum -a 256`). If the evidence is altered by a single byte, the digest no longer matches — this is the audit anchor binding results to collected evidence.
