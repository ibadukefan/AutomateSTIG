# Agent And Scheduling

Agent mode and schedules run real remote collection and evaluation when configured. Validating the success path requires reachable hosts, credentials, network access, and working SSH/WinRM collectors.

WinRM's WS-Man lifecycle is implemented, but it needs validation against a live Windows listener.

## Schedules

Schedules are configured in `Settings`.

Scope:

- Assets.
- Tags.

Frequencies:

- Once.
- Hourly.
- Daily.
- Weekly.
- Monthly.
- Custom minutes.

Post-actions:

- Webhook alerts on CAT I findings.
- Webhook alerts below a compliance threshold.
- Webhook alerts on drift.
- CKL report artifacts.
- STIG-Manager push.

A background dispatcher runs due schedules. `Run now` executes a schedule immediately. Schedule `Run now` performs real evaluations.

## Agent Mode

Agent mode continuously monitors configured targets on an interval.

Settings include:

- Enable.
- Interval.
- Alerts.
- Auto-push.
- Webhook.
- Targets.

Targets map to registered assets by hostname. Agent mode can generate drift alerts and optionally auto-push results.

## Remote Collection

Both schedules and agent mode perform real remote SSH/WinRM collection. They are connected features, not offline-only workflows.

SSH host key and WinRM transport hardening are described in [Security Model](security-model.md).
