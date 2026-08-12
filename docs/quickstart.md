# AutomateSTIG Quickstart

AutomateSTIG collects and evaluates evidence for a small set of
difficult-to-scan devices, then prepares a sparse result for an **existing**
STIG Manager asset and assignment. STIG Manager remains the system of record
for assets, manual reviews, findings, approvals, dashboards, reports, and
history.

This guide is for the scanner-first `v0.3.x` pilot. If the
[GitHub Releases page](https://github.com/ibadukefan/AutomateSTIG/releases)
shows only `v0.2.x`, the scanner-first package has not been published yet. Do
not install `v0.2.x` and expect the workflow described here. Pilot
administrators may instead build an explicitly reviewed commit as described in
[Installation](installation.md).

## The shortest safe path

1. Install one verified `v0.3.x` release for macOS or Linux. The installer
   launches the app and opens your browser.
2. If you return later, run `~/.local/bin/automatestig-gui` to reopen the app.
3. Select **Open sample result** to learn the result screen without touching a
   device or saving data.
4. Select **Run disconnected** for the first authorized scan.
5. When the run is complete, download and verify its selected-run ZIP.
6. Use the site's approved receiver to reconcile only the sparse reviews with
   the existing STIG Manager assignment.
7. Finish all manual and management work in STIG Manager.

There is no catalog to initialize, benchmark to import, asset to create, or
local checklist to manage.

## What is supported

AutomateSTIG pilot packages are produced for macOS and GNU/Linux on
Intel/x86-64 and arm64/Apple Silicon. Windows is tested for source portability
but is not a supported deployment platform. A complete minimum macOS and Linux
distro/glibc matrix has not yet been published, so do not infer RHEL or musl
compatibility from the presence of a Linux archive. The installer executes the
verified staged CLI and makes no installation change if it cannot run on the
host.

Only these exact experimental profiles can run:

| Target | Exact STIG | Version gate | Input | Automated scope |
| --- | --- | --- | --- | ---: |
| NetApp ONTAP 9.x | ONTAP DSC STIG V2R4 | ONTAP major version 9 | Read-only SSH or native AutomateSTIG evidence | 15 of 29 rules |
| FreeBSD | GPOS V3R3 | FreeBSD major versions 13–14 | Read-only SSH or native AutomateSTIG evidence | 6 of 203 rules |
| Cisco IOS-XE Router NDM | Router NDM STIG V3R7 | IOS-XE major version 17 | Complete running configuration plus a trusted signed organization policy | 33 of 42 rules |

These version checks are rejection boundaries, not a published tested-firmware
matrix. The GUI therefore asks the operator to acknowledge the experimental
pilot status. Automation coverage is scanner capability, not a compliance
score. Every other rule remains for an analyst to review in STIG Manager.

## Before you install

For the normal prebuilt installation, have:

- a supported macOS or Linux workstation controlled by one user;
- `curl`, `tar`, `gh` (GitHub CLI), and either `sha256sum` or `shasum`;
- an approved `v0.3.x` release tag; and
- a current browser.

The installer uses an existing
[Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) command
or temporarily downloads the installer's pinned, checksum-verified Cosign
version. Python 3.10 or newer is needed only when using the optional installed
backup/restore utility; it is not needed to install, launch, scan, or verify a
handoff.

For a real scan, also have written authorization for the target, a
least-privilege read-only collection account or approved input file, the
expected device identity, and an approved path for the resulting sensitive
evidence. For SSH, have the expected host-key fingerprint enrolled through an
authenticated process. Do not make trust on first use the routine default.

For connected operation, the pilot currently requires:

- STIG Manager build `1.6.13+1`;
- the HTTPS API URL, HTTPS GUI base URL, and HTTPS OAuth token URL;
- a least-privilege client ID and secret with collection, asset, assignment,
  and current-review read access; and
- an existing collection, asset, and exact supported STIG assignment.

AutomateSTIG neither creates those records nor directly writes changed
reviews.

## Install

macOS and Linux use the same noninteractive installer. Set `version` to the
exact release approved by the site; the installer and application payload are
both pinned to that immutable tag:

```bash
version=v0.3.0
gh release verify "$version" --repo ibadukefan/AutomateSTIG
gh release download "$version" --repo ibadukefan/AutomateSTIG \
  --pattern install.sh --output automatestig-install.sh
sh ./automatestig-install.sh --version "$version"
```

The installer asks no questions. It detects the operating system and CPU,
selects the requested scanner release, verifies the archive's
checksum and Sigstore workflow identity, and atomically installs or upgrades
the CLI, GUI, and recovery utility together in `~/.local/bin`. It never uses
`sudo`, starts the GUI automatically, and prints the exact absolute commands
for later use. To upgrade later, set `version` to the newly approved tag and
repeat the same four commands.

Until a gated `v0.3.x` release is published, this sequence stops and makes no
installation changes. It must never substitute the current legacy `v0.2.0`
release.

To install without starting the app, add `--no-launch`. See every supported
option without installing:

```bash
sh ./automatestig-install.sh --help
```

After installation, launch or relaunch the application with:

```bash
"$HOME/.local/bin/automatestig-gui"
```

The GUI binds to `127.0.0.1` on a random port and opens the browser
automatically. The installer starts it in the background; a later manual
launch remains attached to that terminal. Local state defaults to
`~/.automatestig`; protect and back up that directory as sensitive assessment
data. Leave the default 30-day evidence and operational retention settings in
place unless the site's records policy says otherwise.

Uninstall the application binaries without deleting assessment data:

```bash
sh ./automatestig-install.sh --uninstall
```

Use only the installer file downloaded from the verified exact tag. Download
and verify it again if that file is no longer available. The uninstall leaves
`~/.automatestig` in place intentionally. Follow the site's records and
media-sanitization process before removing that data.

If your organization blocks an unnotarized macOS binary, use its approved
Gatekeeper exception process or build the reviewed source. Do not clear
quarantine merely to bypass the warning.

## Learn the screen without running a scan

On first open, select **Open sample result**.

The page is a browser-only training walkthrough. Review the distinction among
automated results, manual rules, out-of-profile rules, create/update/unchanged
reviews, conflicts, and the handoff steps. The page makes no API request,
contacts no device, saves no run, and cannot create a handoff. It is not
assessment evidence.

Select **Back to start** when finished.

## First disconnected scan

Disconnected means AutomateSTIG is not connected to STIG Manager during the
run. It does not mean that SSH collection from an authorized ONTAP or FreeBSD
target is prohibited.

1. Select **Run disconnected**.
2. Confirm the destination collection, asset, and assignment that will
   eventually receive the result. Nothing is selected remotely in this mode,
   so record those identifiers in the operator log.
3. Select the exact scanner profile for the target.
4. Select the least complicated approved collection method:

   - For ONTAP or FreeBSD, use **Collect live over SSH** when the workstation
     can reach the device. Enter its endpoint, port, username, and a one-time
     password or approved Ed25519/ECDSA private-key path. The GUI does not save
     the credential.
   - Use **Evaluate supplied evidence** only with a native evidence envelope
     produced by the same AutomateSTIG scanner contract. A hand-written
     transcript, old checklist, or arbitrary JSON file is not accepted.
   - For Cisco IOS-XE, attach the complete authorized running configuration,
     its asset-and-STIG-bound organization-policy JSON, and the policy's exact
     detached Ed25519 signature. Install the approving public key in
     `~/.automatestig/organization_policy_keys` before launching the GUI. The
     private signing key must stay off the scanner workstation.

5. Read and select the experimental-pilot acknowledgement only if the run is
   within the site's approved pilot.
6. Select **Check readiness**. Confirm the observed hostname, device version,
   host key or file identity, profile and content hashes, privilege, and every
   displayed read-only operation. Correct a mismatch; there is no bypass.
7. Select **Collect and evaluate**.
8. Review the completed result. A timeout, denied command, truncated or
   malformed output, unsupported version, incomplete configuration, or invalid
   policy creates an **Incomplete** diagnostic run. It cannot produce a
   compliance handoff. Correct the source condition and start a new run.
9. For a complete run, review every scanner-owned result and the counts of
   manual and out-of-profile rules that remain untouched. Then select
   **Download selected-run handoff**. The file name is
   `automatestig-run-<RUN_ID>.zip`.

Do not import the CKLB and XCCDF members as additional result sets. They are
supplemental projections of the same sparse result.

## Verify the handoff

Transfer the ZIP to the receiving workstation through the site's approved
channel. Install the same approved `v0.3.x` product CLI there and run:

```bash
automatestig scanner verify-handoff automatestig-run-<RUN_ID>.zip
```

The command is read-only. It checks the bounded ZIP structure, every digest,
run and target bindings, scanner ownership, sparse JSON, CKLB and XCCDF
equivalence, and—when retained evidence is present—deterministic replay. A
successful unsigned verification proves internal integrity, **not who
produced the ZIP**. Confirm the run ID and ZIP SHA-256 through an independent
authenticated channel.

When the protected producer-signing workflow supplies a detached signature
sidecar, verify producer identity as well:

```bash
automatestig scanner verify-handoff automatestig-run-<RUN_ID>.zip \
  --signature automatestig-run-<RUN_ID>.zip.signature.json \
  --trust-dir /approved/automatestig-handoff-keys
```

The trust directory must contain the independently distributed producer
public key. A key included beside the ZIP is not a trust anchor. If the site
has not completed producer-key custody and the independent receiver ceremony,
retain the unsigned authenticity warning in the assessment record.

Verification does not import reviews or change either local state or STIG
Manager. If it exits nonzero, quarantine the package and return to the source
run; do not extract and use individual files from a rejected handoff.

## Continue in STIG Manager

After verification:

1. Confirm the existing destination collection, asset, STIG assignment, and
   exact revision.
2. Use the site's approved receiver to map only `sparse-reviews.json` to that
   assignment. Omitted rules must remain untouched.
3. Read the resulting reviews back from STIG Manager and compare their rule
   IDs and statuses with the verified sparse payload.
4. Record the destination receipt with the run ID and payload digest.
5. Complete manual rules, comments, adjudication, submission, validation,
   findings analysis, dashboards, and reports in STIG Manager.

The pilot does not ship an end-user command or button that imports changed
reviews into STIG Manager. If the site has no approved receiver and semantic
readback procedure, stop after verification and give the handoff to the STIG
Manager administrator. Do not improvise bulk writes.

## Connected scan

Connected mode removes manual destination selection from the scanner flow. It
still does not make AutomateSTIG the system of record or allow changed-review
writes.

1. Launch `automatestig-gui` and select **Connect to STIG Manager**.
2. Enter the API URL, credential-free GUI base URL ending in `/`, OAuth token
   URL, client ID, and client secret. Select **Test and save connection**.
   Confirm the returned identity, exact server version, capabilities, and read
   privileges. The form clears the secret after the request.
3. Open **Scan** and select, in order, the live collection, existing asset, and
   exact runnable assigned profile. If none is runnable, correct the asset or
   assignment in STIG Manager; AutomateSTIG will not create or substitute it.
4. Choose the input, acknowledge the authorized pilot, select **Check
   readiness**, and verify the destination and device bindings.
5. Select **Collect and evaluate** and review the sparse result.
6. If every proposed review is already the identical AutomateSTIG-owned remote
   result, select **Confirm remote no-op** to recheck and retain a technical
   receipt. This performs no review write.
7. If any review is a create or update, download and verify the selected-run
   handoff, then use the approved receiver procedure above. If any row is a
   conflict, resolve review ownership in STIG Manager and deliberately recheck;
   never overwrite the human review from AutomateSTIG.
8. Select **Open STIG Manager** and finish the assessment there.

The connected adapter accepts only STIG Manager `1.6.13+1`. With another
version, use the disconnected workflow until that version passes the project's
staging and semantic-readback gates.

## Network defaults

Keep the GUI bound to localhost. A non-loopback deployment requires a separate
TLS, authentication, and access-control boundary and is outside this
quickstart.

Private STIG Manager, OAuth, and SSH endpoints must be authorized with narrow
destination allowlists. A site administrator should provide the exact values;
for example:

```bash
AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST='10.20.0.0/16' \
AUTOMATESTIG_SSH_TARGET_ALLOWLIST='10.30.40.25' \
automatestig-gui
```

Use the smallest exact IP or CIDR set that covers the approved endpoints.
Invalid, reserved, multicast, documentation, mixed-scope DNS, and unapproved
link-local destinations remain blocked.

## Common problems

**No installable scanner release is found.** The scanner-first release has not
been published, or the site approved another exact `v0.3.x` tag. The public
`v0.2.x` release does not have the scanner workflow or required release
signature bundle, so the installer correctly leaves the machine unchanged.
Ask the pilot administrator for the reviewed tag or commit.

**`automatestig-gui` is not found after installation.** Use the exact absolute
command printed by the installer. With the default installation, run
`~/.local/bin/automatestig-gui`. Adding `~/.local/bin` to `PATH` is an optional
site or shell configuration decision; the installer does not modify it.

**The browser did not open.** Keep the GUI process running and open the
`http://127.0.0.1:<port>` address printed in its terminal. Do not expose that
address on the network.

**SSH reports an unknown host key.** Have the expected key enrolled out of
band. For a deliberate one-time enrollment only, independently verify the
fingerprint and launch one process with:

```bash
AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE=1 automatestig-gui
```

That process can enroll at most one target. Restart normally afterward. A
changed enrolled key always fails.

**A private endpoint is rejected before connection.** Add its exact numeric IP
or narrow CIDR to the appropriate allowlist before launch. A hostname alone
does not authorize a private DNS answer.

**A private key is rejected.** Use an absolute path to a current-user-owned,
non-symlink Ed25519 or ECDSA key under `~/.ssh` or
`~/.automatestig/ssh_keys`. Remove group/other access. RSA keys are not
supported.

**No runnable assignment appears.** Confirm STIG Manager `1.6.13+1`, the
service account's read access, the asset identity, and the exact V2R4, V3R3, or
V3R7 assignment. Do not choose a nearby revision.

**The run is incomplete.** Read the collection diagnostics, correct the target
or input, run **Check readiness** again, and create a new run. Incomplete runs
have no handoff by design.

**Verification says authenticity was not verified.** That is expected for an
unsigned GUI-produced ZIP. Integrity can still pass, but producer identity
requires the protected detached-signature workflow or an authenticated
transfer plus independent run-ID and digest confirmation.

For less common errors, see [Troubleshooting](troubleshooting.md). For the full
operational and security boundaries, see [Scanner Operations](scanner-operations.md),
[Handoff Verification](handoff-verification.md), and the
[Security Model](security-model.md).
