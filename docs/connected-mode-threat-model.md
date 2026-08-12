# Connected-Mode Threat Model

AutomateSTIG is safest as a localhost desktop/offline evaluator. Connected mode adds controlled outbound integrations and must fail closed around network destinations and imported content.

## Boundaries

| Feature | Boundary | Default control |
| --- | --- | --- |
| Maintainer DISA corpus fetch (not the end-user GUI) | Outbound HTTPS to public DISA hosts | Parsed URL allowlist for exact DISA hosts; redirects revalidated; response body streamed with hard byte cap; ZIP member/path/size limits before XML parsing. |
| STIG Manager OAuth/API | Outbound HTTPS to operator-configured API and token endpoints | HTTPS-only; no embedded credentials; local/metadata hostnames rejected; non-global special-use/private/local/link-local addresses require explicit authorization; invalid/reserved/multicast/documentation addresses are always rejected. |
| SSH scan | Outbound SSH to operator-selected assets | Host syntax validation, optional exact host/IP/CIDR allowlist, non-global special-use/private/local/link-local addresses blocked by default, invalid addresses always rejected, and host-key pinning/changed-key rejection. |

## Operator guidance

- Prefer explicit allowlists over broad lab overrides.
- Use `AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST` and `AUTOMATESTIG_SSH_TARGET_ALLOWLIST` for connected deployments.
- Treat `AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN` as a temporary isolated-lab
  setting only.
- Pre-populate SSH `known_hosts` for high-assurance scans instead of relying on trust-on-first-use.
- Keep the GUI localhost-only unless a separate front-door/auth/audit layer is provided.

## Current product posture

Current scope is deterministic collection and evaluation for NetApp ONTAP 9
and FreeBSD over SSH, plus Cisco IOS-XE Router NDM running configurations.
Changed scanner reviews move through a verified sparse handoff to an existing
exact STIG Manager assignment; the connected API directly records only an
exact remote no-op verification. The exact supported-target contract is
`content/supported-targets.json`; AutomateSTIG supplements STIG Manager and
does not claim to be a general-purpose host scanner or Evaluate-STIG
replacement.
