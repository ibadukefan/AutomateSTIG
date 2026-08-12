# FreeBSD Collection and Evaluation

AutomateSTIG evaluates FreeBSD hosts from read-only, plan-bound SSH evidence. DISA publishes no vendor BSD STIG, so evaluation targets the DISA General Purpose Operating System SRG — the baseline all OS STIGs derive from.

The `freebsd_gpos` check pack targets GPOS SRG V3R3, which contains 203
requirements. Its reviewed candidate inventory contains 30 requirements:

- 6 are automated from reviewed native evidence: four effective OpenBSM
  event-selection requirements, the running state of `auditd`, and the live PF
  state.
- 24 reviewed candidates remain manual because the available evidence cannot
  prove complete OpenSSH, PAM, login-class, banner-display, audit retention or
  off-load, authoritative-time-source, timestamp-offset, complete ASLR,
  time-correction threshold, all-access-path, or vendor-support semantics.

The other 173 GPOS requirements are outside the current reviewed candidate
inventory and also remain `Not_Reviewed`. The governed inventory is therefore
exactly 30 reviewed/6 automated/24 manual; it is not a claim of complete GPOS
coverage.

## Collecting Evidence

Use one of these collection paths.

### Connected GUI Scan

On **Scan**, select a live existing STIG Manager asset with
`General_Purpose_Operating_System` V3R3 assigned, then select the
release-bundled `freebsd_gpos` profile. Preflight verifies the observed FreeBSD
13–14 identity, endpoint/host key, exact assignment, privilege, hashes, and all
six read-only operations.

The GUI runs the adapter plan through the shared fail-closed collector.
Incomplete collection persists diagnostic run state only and creates no
handoff. A complete run previews only six scanner-owned rules. An identical
remote result can receive an exact-no-op receipt; any create or update uses the
selected-run handoff. The 24 reviewed manual rules and out-of-profile
assignment rules stay untouched.

### Air-Gapped Transcript

From any host with SSH access to the target, run:

```bash
AUTOMATESTIG_SSH_PASSWORD='...' \
  scripts/collectors/bsd-collect.sh admin@bsdhost bsdhost-evidence.json
```

For key authentication, set `AUTOMATESTIG_SSH_KEY` to the private-key path. The script delegates to `automatestig collect`; transfer `bsdhost-evidence.json` into the AutomateSTIG environment.

The six exact read-only commands are:

```text
service auditd onestatus
cat /etc/security/audit_control
cat /etc/security/audit_user
sha256 -q /etc/security/audit_class
sha256 -q /etc/security/audit_event
service pf onestatus
```

No password hashes or file contents outside these two OpenBSM policy files are
collected. Because `audit_user` may contain account names,
the evidence artifact is still sensitive operational data. Evidence v2 keeps
stdout, stderr, exit status, duration, and typed errors separate and binds the
platform and exact plan digest. Marker-based transcripts cannot establish
command success and are rejected by the product CLI, GUI, and API with no
unsafe override.

## Evaluating

The scanner GUI uses its release-bundled exact benchmark subset. The following
raw-content import is a legacy CLI/maintainer transition path, not a normal GUI
prerequisite:

```bash
automatestig disa-import --input U_GPOS_V3R3_SRG.zip
```

Then evaluate the evidence document:

```bash
automatestig evaluate --stig General_Purpose_Operating_System \
  --evidence bsdhost-evidence.json \
  --output bsdhost01.scanner-result.json
```

The scanner-first delivery path does not merge answer files or prior
checklists. Human determinations and the remaining GPOS review occur in STIG
Manager. An incomplete legacy CLI document produces only an
`evaluation.incomplete` audit event and a nonzero exit; no checklist is written
or saved, and answer/merge input cannot override collection errors.

## FreeBSD Collection Semantics

`service auditd onestatus` uses exit status 1 to report the successfully observed stopped-service state. The plan accepts that status, but only the complete canonical running-state output can satisfy V-203615. A stopped state evaluates `Open`. A transport failure, authentication/RBAC failure, timeout, missing status, or malformed output remains `Not_Reviewed`.

V-203767, V-203621, V-203774, and V-203772 use FreeBSD OpenBSM's documented
left-to-right selection grammar. Both the attributable `flags` and
non-attributable `naflags` masks must select successful and failed events, and
no `audit_user` never-audit mask may remove a required outcome. The required
native classes are respectively `lo`, `aa`, `ad`, and the complete
`fr,fw,fa,fm,fc,fd` file-object set. The scanner also binds those symbols and
their event memberships to the reviewed FreeBSD 13.4–13.5 and 14.0–14.4
`audit_class` and `audit_event` digests; an edited, missing, or unrecognized
mapping fails closed. Duplicate fields, unknown classes, malformed user
entries, one-sided `+`/`-` selection, or a stopped `auditd` cannot pass.

V-203784 accepts only one canonical PF `Status` field in the live service
output and requires it to be `Enabled`. An absent, duplicated, or unknown
status remains `Not_Reviewed`; canonical `Disabled` is `Open`.

For every automated rule, transport errors, missing status, output-limit
truncation, pagination/error markers, missing commands, and malformed or
ambiguous native output fail closed and cannot become a passing result.

## Deliberate Manual-Review Boundary

The pack does not infer effective policy from raw files. In particular:

- OpenSSH uses first-effective directives, `Include`, and `Match` scopes; banner text must also be bound to the configured banner path.
- `rc.conf` assignments do not prove the final `rc` variable value or a running service.
- PAM results depend on control flow, module order, and enforcement options.
- Active NTP state does not prove the greater-than-one-second correction
  behavior required by V-203712 or that the selected source for V-203711 is an
  organization-approved authoritative source.
- A `UTC`/`GMT` zone-name check would falsely fail valid V-203714 local
  timestamps carrying a UTC offset; a zone name alone also does not prove the
  audit-record representation.
- One 64-bit ASLR sysctl does not establish the 32-bit, PIE, and stack controls
  needed to defend V-203754 across the supported FreeBSD versions.
- Running audit services do not prove retention capacity, successful remote
  delivery, or weekly standalone off-load.
- `login.conf` values are scoped to login classes, and vendor-supported FreeBSD releases change over time.

Those requirements remain `Not_Reviewed` until AutomateSTIG collects and parses
authoritative effective-state output for them. Complete those reviews in STIG
Manager. The retained pack is still marked experimental until its release
acceptance gate is satisfied.

## Chain of Custody

Every completed checklist evaluated from an evidence document records the SHA-256 of the exact input bytes in each finding's comments (`Supplied evidence provenance ... SHA-256: <hex>`). A reviewer can independently confirm the artifact with `sha256sum bsdhost-evidence.json` (or `shasum -a 256`). Evidence v2 additionally binds each record to the requested command and the complete document to the installed collection plan and observed SSH server key.
