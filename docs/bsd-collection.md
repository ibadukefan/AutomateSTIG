# FreeBSD Collection and Evaluation

AutomateSTIG evaluates FreeBSD hosts from read-only evidence transcripts. DISA publishes no vendor BSD STIG, so evaluation targets the DISA General Purpose Operating System SRG — the baseline all OS STIGs derive from.

The `freebsd_gpos` check pack targets GPOS SRG V3R3. That release contains 203 requirements:

- 30 requirements automated by the `freebsd_gpos` check pack from configuration evidence.
- The remainder stay `Not_Reviewed` for manual assessment — notably multifactor authentication, FIPS-validated cryptographic modules, and judgment-based requirements that cannot be honestly claimed from configuration text.

## Collecting Evidence

Use one of these collection paths.

### Connected GUI Scan

On the `Assessments` page, start a GUI SSH scan with `Platform = FreeBSD`.

The GUI connects over SSH, runs the FreeBSD collection commands, and stores the transcript as assessment evidence.

### Air-Gapped Transcript

From any host with SSH access to the target, run:

```bash
scripts/collectors/bsd-collect.sh admin@bsdhost > bsdhost-evidence.txt
```

Transfer `bsdhost-evidence.txt` into the AutomateSTIG environment.

All collection commands are read-only and gather configuration text only — no password hashes or other secrets are collected. The transcript uses plain `### automatestig:command <command>` delimiters, so evidence can also be captured manually in a recorded terminal session.

## Evaluating

Import the SRG once:

```bash
automatestig disa-import --input U_GPOS_V3R3_SRG.zip
```

Then evaluate a transcript:

```bash
automatestig evaluate --stig General_Purpose_Operating_System \
  --evidence bsdhost-evidence.txt --host bsdhost01 \
  --output bsdhost01.ckl --format ckl
```

Results merge with answer files as usual and can be pushed to STIG Manager or imported as CKL.

## Conventions the Pack Expects (Calibration Note)

The automated checks match specific FreeBSD hardening conventions:

- Password policy via `pam_passwdqc` in `/etc/pam.d/passwd` with `min=disabled,disabled,disabled,disabled,15`.
- OpenBSM auditing via `/etc/security/audit_control` flags (`lo`, `aa`, `ad`, `f*`) with `expire-after` of at least 7 days, plus `auditdistd` for off-load.
- `rc.conf` enables for `blacklistd`, `auditdistd`, `ntpd`, and a host firewall (`pf`, `ipfw`, or `ipfilter`).
- An OpenSSH `Ciphers`/`MACs` allowlist (AES-CTR/GCM, HMAC-SHA2).

Sites that meet a requirement through a different-but-compliant mechanism should record those rules via [answer files](answer-files.md) rather than editing the check pack. The pack is marked experimental; verify results against the manual SRG on first use.

## Chain of Custody

Every checklist evaluated from an evidence transcript or config file records the SHA-256 of the exact input bytes in each finding's comments (`Automated evaluation provenance: ... SHA-256: <hex>`). A reviewer can independently confirm the checklist came from a specific artifact with `sha256sum evidence.txt` (or `shasum -a 256`). If the evidence is altered by a single byte, the digest no longer matches — this is the audit anchor binding results to collected evidence.
