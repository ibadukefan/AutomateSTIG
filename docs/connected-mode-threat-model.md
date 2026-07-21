# Connected-Mode Threat Model

AutomateSTIG is safest as a localhost desktop/offline evaluator. Connected mode adds controlled outbound integrations and must fail closed around network destinations and imported content.

## Boundaries

| Feature | Boundary | Default control |
| --- | --- | --- |
| DISA content fetch | Outbound HTTPS to public DISA hosts | Parsed URL allowlist for exact DISA hosts; redirects revalidated; response body streamed with hard byte cap; ZIP member/path/size limits before XML parsing. |
| STIG Manager OAuth/API | Outbound HTTPS to operator-configured API and token endpoints | HTTPS-only; no embedded credentials; local/metadata hostnames rejected; literal and resolved private/local/link-local addresses rejected unless allowlisted or explicit lab override is set. |
| SSH scan | Outbound SSH to operator-selected assets | Host syntax validation, optional exact host/IP/CIDR allowlist, private/local/link-local literal and resolved addresses blocked by default, host-key pinning/changed-key rejection. |
| Webhooks | Outbound HTTPS notifications/tests | HTTPS-only, no embedded credentials, private/local targets blocked unless explicit lab override is set. |

## Operator guidance

- Prefer explicit allowlists over broad lab overrides.
- Use `AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST` and `AUTOMATESTIG_SSH_TARGET_ALLOWLIST` for connected deployments.
- Treat `AUTOMATESTIG_ALLOW_PRIVATE_*` overrides as temporary isolated-lab settings only.
- Pre-populate SSH `known_hosts` for high-assurance scans instead of relying on trust-on-first-use.
- Keep the GUI localhost-only unless a separate front-door/auth/audit layer is provided.

## Current product posture

Current scope is evidence collection and deterministic evaluation for device classes that scripted scanners cannot reach — network device configuration files, Linux/UNIX over SSH, NetApp ONTAP, and FreeBSD evidence transcripts — with results exported or pushed to STIG Manager. Broad Evaluate-STIG replacement material in older docs is retained as historical context, not a current production claim.
