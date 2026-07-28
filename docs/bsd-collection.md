# FreeBSD Collection and Evaluation

AutomateSTIG evaluates FreeBSD hosts from read-only, plan-bound SSH evidence. DISA publishes no vendor BSD STIG, so evaluation targets the DISA General Purpose Operating System SRG — the baseline all OS STIGs derive from.

The `freebsd_gpos` check pack targets GPOS SRG V3R3, which contains 203
requirements. Its reviewed candidate inventory contains 30 requirements:

- 3 are automated from direct effective-state evidence: the running state of
  `auditd`, the configured UTC/GMT time zone, and the effective 64-bit ASLR
  sysctl.
- 27 reviewed candidates remain manual because their former raw-file or token
  checks could not prove effective OpenSSH, `rc.conf`, PAM, login-class,
  OpenBSM audit-class, banner-display, service, or vendor-support semantics.

The other 173 GPOS requirements are outside the current reviewed candidate
inventory and also remain `Not_Reviewed`. The governed inventory is therefore
exactly 30 reviewed/3 automated/27 manual; it is not a claim of complete GPOS
coverage.

## Collecting Evidence

Use one of these collection paths.

### Connected GUI Scan

On the `Assessments` page, start a GUI SSH scan and select the GPOS benchmark;
the FreeBSD platform is derived from that supported benchmark.

The GUI connects over SSH and runs the generated FreeBSD plan through the shared fail-closed collector. Incomplete collection returns HTTP 207 with diagnostic errors and dependent controls marked `Not_Reviewed`, but does not persist a checklist or compliance score.

### Air-Gapped Transcript

From any host with SSH access to the target, run:

```bash
AUTOMATESTIG_SSH_PASSWORD='...' \
  scripts/collectors/bsd-collect.sh admin@bsdhost bsdhost-evidence.json
```

For key authentication, set `AUTOMATESTIG_SSH_KEY` to the private-key path. The script delegates to `automatestig collect`; transfer `bsdhost-evidence.json` into the AutomateSTIG environment.

All three commands are read-only and collect only the `auditd` service state, `/var/db/zoneinfo`, and `kern.elf64.aslr.enable` — no password hashes or other secrets are collected. Evidence v2 is strict JSON with separate stdout, stderr, exit status, duration, and typed error records plus a platform and plan digest. Marker-based transcripts cannot establish command success and are rejected by default. The CLI-only `--allow-legacy-evidence` switch is an unsafe fixture-migration aid, not a collection workflow.

## Evaluating

Import the SRG once:

```bash
automatestig disa-import --input U_GPOS_V3R3_SRG.zip
```

Then evaluate the evidence document:

```bash
automatestig evaluate --stig General_Purpose_Operating_System \
  --evidence bsdhost-evidence.json \
  --output bsdhost01.ckl --format ckl
```

Completed results can merge with answer files, be pushed to STIG Manager, or be imported as CKL. An incomplete document produces only an `evaluation.incomplete` audit event and a nonzero CLI exit; no checklist is written or saved, and answer files/merge input cannot override the collection errors.

## FreeBSD Collection Semantics

`service auditd onestatus` uses exit status 1 to report the successfully observed stopped-service state. The plan accepts that status, but only the complete canonical running-state output can satisfy V-203615. A stopped state evaluates `Open`. A transport failure, authentication/RBAC failure, timeout, missing status, or malformed output remains `Not_Reviewed`.

V-203714 accepts only a complete `/var/db/zoneinfo` value of `UTC`, `GMT`, `Etc/UTC`, or `Etc/GMT`; substrings and fixed-offset `Etc/GMT+N` zones do not pass. V-203754 accepts only the complete effective sysctl result `kern.elf64.aslr.enable: 1`. Conflicting or additional output cannot produce `NotAFinding`.

## Deliberate Manual-Review Boundary

The pack does not infer effective policy from raw files. In particular:

- OpenSSH uses first-effective directives, `Include`, and `Match` scopes; banner text must also be bound to the configured banner path.
- `rc.conf` assignments do not prove the final `rc` variable value or a running service.
- PAM results depend on control flow, module order, and enforcement options.
- OpenBSM audit prefixes and classes have semantics which token-presence regexes do not establish.
- `login.conf` values are scoped to login classes, and vendor-supported FreeBSD releases change over time.

Those requirements remain `Not_Reviewed` until AutomateSTIG collects and parses authoritative effective-state output for them. Sites may record independently reviewed results with [answer files](answer-files.md). The retained pack is still marked experimental until its release acceptance gate is satisfied.

## Chain of Custody

Every completed checklist evaluated from an evidence document records the SHA-256 of the exact input bytes in each finding's comments (`Supplied evidence provenance ... SHA-256: <hex>`). A reviewer can independently confirm the artifact with `sha256sum bsdhost-evidence.json` (or `shasum -a 256`). Evidence v2 additionally binds each record to the requested command and the complete document to the installed collection plan and observed SSH server key.
