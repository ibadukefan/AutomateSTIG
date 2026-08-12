# Troubleshooting

## Install Or Launch Fails

Start with the [Installation](installation.md) checklist. The supported
installer is non-interactive: it detects Linux or macOS and CPU architecture,
verifies the release, installs all three entry points together, and prints the
exact GUI command.

Common causes:

- GitHub Releases still shows only `v0.2.x`. The scanner-first `v0.3.0` pilot
  has not been published; do not substitute the legacy release.
- The host is Windows. Windows is tested for source portability but has no
  supported scanner release artifact.
- `curl`, `tar`, or SHA-256 tooling is missing. Install the named standard
  utility and run the same installer again. Cosign is used when present or a
  pinned checksum-verified copy is downloaded temporarily. Python 3.10+ is
  needed only when the optional recovery utility is used.
- The default user-local directory is not on `PATH`. Run the absolute GUI path
  printed by the installer, then add that directory to `PATH` for future
  shells.
- macOS Gatekeeper blocks the unnotarized binary. Use the site's approved
  exception process or a reviewed source build; the installer never removes
  quarantine metadata.

Do not use `sudo`, clear quarantine, disable TLS, skip signature verification,
or install a different release merely to get past an error.

## The GUI Starts But The Browser Does Not Open

The GUI prints `GUI running at: http://127.0.0.1:<port>`. Open that exact
address in a browser on the same workstation. The port is intentionally chosen
at startup unless `PORT` is set. If you launched the GUI directly in a
terminal, keep that process running while using the app. The installer starts
the first launch in the background.

If the page still does not load, confirm a local security product is not
blocking loopback connections and that another process did not terminate the
GUI. Do not expose the built-in HTTP listener to a network merely to work
around a local browser problem.

## DISA XML Or ZIP Is Rejected As A `.stigpack`

Cause: a maintainer/legacy import command received the wrong format. Ordinary
DISA XCCDF and an AutomateSTIG signed pack are different formats. Neither is a
normal scanner-first GUI action because exact profiles ship with the release.

Normal analysts do not fix this by importing content: supported scanner
profiles are bundled with the release. A content maintainer may use an
explicit `maintainer` source build for raw DISA import or curated `.stigpack`
import. Those hidden commands are absent from the installed analyst product.

Renaming a DISA ZIP to `.stigpack` does not convert or sign it.

## Unsigned `.stigpack` Import Fails

Cause: unsigned packs are blocked by default.

This is a content-maintainer error, not a normal scan setup step. The supported
analyst release contains only trusted, release-bundled scanner profiles.

For an explicit isolated content-development lab, use a reviewed source build
with the `maintainer` feature. The lab-only override remains intentionally
outside the installed product:

```bash
AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1 \
  cargo run --release --features maintainer --bin automatestig -- \
  import --pack lab-only.stigpack
```

Preferred fix: import a signed pack and configure trusted keys.

## Trusted Key Missing

Cause: `.stigpack` import requires a trusted Ed25519 public key.

This is also a maintainer-only path. For a reviewed maintainer build:

1. Place trusted `.pub` files in `~/.automatestig/trusted_keys`, or set `AUTOMATESTIG_TRUSTED_KEYS_DIR`.
2. Re-run verification or import.

```bash
AUTOMATESTIG_TRUSTED_KEYS_DIR=/path/to/trusted_keys \
  cargo run --release --features maintainer --bin automatestig -- \
  verify --pack content.stigpack
```

This trust store is only for signed content packs. Cisco organization policies
use the separate `AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR` trust store.

## A Supported Scanner Profile Is Missing

Cause: the requested target/STIG/revision is outside the release-bundled
scanner contract, or the installed files are not one coherent release.

Fix: run `automatestig status`, compare the requested exact revision with
[Supported Targets](supported-targets.md), and reinstall the same verified
release if its bundled-content check fails. Do not import a nearby benchmark
or general DISA catalog to make an unsupported target appear runnable.

## Non-Loopback Server Refuses To Start

Cause: non-loopback binds require `AUTOMATESTIG_AUTH_TOKEN` with at least 32 visible ASCII characters and no whitespace. Spaces, tabs, line breaks, and non-ASCII characters are rejected so the configured value can be represented reliably in the browser request header.

Fix:

```bash
AUTOMATESTIG_AUTH_TOKEN=replace-with-a-random-32-plus-character-token cargo run --release --bin automatestig-gui
```

`/api/status` is unauthenticated. All other `/api/*` routes require the token.
The non-loopback GUI asks for this same value when it opens. Paste it into the
`Connect to AutomateSTIG` dialog; the browser keeps it only in the current
tab's memory. If the dialog returns after a server restart, enter the current
token again. Use a trusted TLS reverse proxy for any non-loopback deployment—
the built-in listener does not encrypt the token in transit.

## SSH Connection Fails On Host Key

Cause: SSH rejects unknown host keys by default.

Fix:

- Pre-enroll the expected `host:port` fingerprint in
  `~/.automatestig/known_hosts` through an authenticated out-of-band process;
  or
- use trust-on-first-use only for deliberate enrollment:

```bash
AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE=1 cargo run --release --bin automatestig-gui
```

The GUI environment switch arms at most one enrollment for that process. Stop
and restart the GUI to arm it deliberately; do not leave it enabled as a normal
operating mode. The first TOFU connection is not independently authenticated,
and an already enrolled key that changes is always rejected.

## SSH Target Is Rejected Before Connection

Cause: the endpoint does not satisfy the outbound destination policy.

Fix:

1. Confirm `Host` is the exact endpoint intended for the assessment. If an
   inventory asset is selected, it must be enabled and its platform, address,
   and configured/default port must match the standard and SSH request. The
   verified request host becomes the checklist hostname.
2. Add the exact public hostname/IP, or a narrow CIDR, to
   `AUTOMATESTIG_SSH_TARGET_ALLOWLIST` when an allowlist is configured.
3. For a private, local, link-local, or other non-global DNS answer, authorize
   the numeric IP/CIDR. A hostname-only entry is not sufficient.
4. Use `AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN=1` only for an explicit isolated
   lab when a narrow allowlist cannot be used.

Invalid, reserved, multicast, documentation, and mixed-scope DNS results remain
blocked. Changing the asset label does not authorize a different network
destination.

## SSH Private-Key Authentication Fails

Cause: the key type, path, ownership, or permissions do not meet the collector
policy.

Fix:

- Use an Ed25519 or ECDSA private key. RSA private keys are unsupported.
- Place the key under the absolute-path equivalent of `~/.ssh` or
  `~/.automatestig/ssh_keys`, or configure an additional secure root with
  `AUTOMATESTIG_SSH_KEY_ROOTS`. Enter the key file's absolute path in the GUI;
  `~` is not expanded, and a relative path is resolved from the GUI process's
  working directory.
- Ensure the key is a bounded regular file, not a symlink, owned by the current
  user, and inaccessible to group/other users. Its parent and configured root
  must also pass the ownership and permission checks.
- Enter the passphrase for the current scan when the key is encrypted. The GUI
  does not store the key or passphrase.

## Compatible Assignment Is Not Available For A Scan

Cause: STIG Manager does not expose the selected collection/asset to the service
account, the exact supported STIG revision is not assigned, the profile does
not match the asset, or live lookup failed.

Fix:

1. Verify the STIG Manager connection and effective read privileges.
2. In STIG Manager, confirm the existing asset and exact V2R4, V3R3, or V3R7
   assignment as applicable.
3. Refresh **Scan** and read any unsupported-assignment reason.
4. Confirm the requested endpoint matches the authoritative asset identity.

AutomateSTIG never creates the missing asset or assignment. Use disconnected
mode when there is intentionally no reachable destination, then bind the
validated selected-run handoff to the existing remote asset later.

## Answer File Does Not Appear Or Does Not Change A Finding

Answer files are not available in the scanner-first GUI. Complete human and
manual determinations in STIG Manager. The retired `Settings`, `Assessments`,
answer-file, and finding-edit routes return `410 Gone`; there is no legacy GUI
procedure to restore a missing template or apply it to a new scanner run.

To preserve or diagnose pre-scanner data, use a protected `transition` build
and run `automatestig-transition migration inventory` and
`automatestig-transition migration export`, then inspect the preserved attribution and
answer-file bytes offline. Do not relabel an `AnswerFile`, `Manual`, or
`Imported` result as scanner automation. If a current scanner result needs a
human determination, open the existing exact assignment in STIG Manager.

## Cisco Configuration Evaluation Is Rejected

Cause: the running configuration, organization policy, signature, trusted key,
or selected benchmark does not form one valid bound input set.

Fix:

1. Select the exact supported Cisco IOS-XE Router NDM benchmark release.
2. Supply a complete, authorized running configuration with one top-level
   `hostname` command matching the assessment asset/hostname.
3. Supply the organization-policy JSON for that same asset and STIG release.
   The policy must be currently effective and not expired.
4. Supply its exact 64-byte detached Ed25519 signature.
5. Install the approving `.pub` key in
   `~/.automatestig/organization_policy_keys` or
   `AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR`, then restart the GUI.

Do not put the organization-policy key in the `.stigpack` trust directory, and
do not use a policy written for another benchmark release or hostname.

## STIG Manager Connection Test Fails

**Test and save connection** validates the values currently shown, performs a
live OAuth/API capability test, and saves only after that test succeeds. A
failed test does not replace the working saved connection.

If the client-secret field is blank, the action may reuse the saved secret only
while the API URL, token URL, and client ID are unchanged. Re-enter the secret
after changing any of those identity fields.

Both endpoints must use `https://`, and TLS certificate verification cannot be
disabled. Install the correct CA trust instead of bypassing validation. Private
or other non-global API/OAuth endpoints require an exact matching IP or CIDR in
`AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST`.

## Remote Scan Does Not Produce Expected Results

Remote SSH scans require the matching release-bundled scanner profile, an authorized
reachable destination, an enrolled host key, valid password or private-key
credentials, and successful typed collection commands.
If any required command fails, times out, or returns malformed/oversized data,
the attempt is recorded as incomplete and no delivery is created. Correct the
reported collection error and start a new scan; importing an old checklist
does not retry collection.
