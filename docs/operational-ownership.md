# Operational Ownership

Every deployment must name people, not just teams, for the following roles.

| Activity | Responsible | Accountable | Consulted / required approval |
| --- | --- | --- | --- |
| Scanner host and backups | Scanner operator | Service owner | Security operations |
| Device inventory, RBAC, and host-key fingerprint | Device owner | Device service owner | Scanner operator |
| Check-pack or evaluator change | Software maintainer | Product owner | Code owner and security reviewer |
| DISA content intake and pack manifest | Content maintainer | Content approver | Key custodian |
| Content signing and rotation | Key custodian | Security owner | Content approver |
| STIG Manager staging integration | Integration operator | Service owner | STIG Manager owner |
| Manual finding edit | Assigned reviewer | Assessment owner | Audit owner |
| Release tag and publication | Release manager | Product owner | Independent software and security reviewers |
| Recovery drill and restore | Scanner operator | Service owner | Security operations and audit owner |
| Incident/revocation response | Security operations | Security owner | Product, device, key, and assessment owners |

No one may self-approve their own code or satisfy both independent release
review roles. The application audit log supports investigation but is local
state; export signed release evidence and assessment records to the designated
system of record according to the site's retention policy.

## Cadence

- Before each scan window: confirm target authorization, account scope, host-key
  pins, time sync, disk capacity, and destination STIG Manager collection.
- Weekly: review failed/incomplete scans, rejected host keys, import failures,
  and audit-log write failures.
- Monthly: test backups, reconcile trust stores and device inventory, review
  dependency/security alerts, and assign DISA content drift.
- Quarterly and before a release: run all five required acceptance gates
  (three device families, STIG Viewer, and STIG Manager) and the
  transaction-recovery drill.
- Annually or on role change: rotate content/SSH credentials and review this
  ownership table.

Open findings, incomplete evidence, `NotReviewed`, audit failures, recovery
failures, and missing live gates must have a named owner and due date. They are
never counted as passed work.
