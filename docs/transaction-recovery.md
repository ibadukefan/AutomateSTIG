# Transaction Recovery

Library imports and ancillary content writes use a library-scoped,
cross-process lock. Writers stage files under the library root and maintain a
durable transaction journal before replacing destinations. Existing files move
to transaction-owned backups; the library index commits last.
For signed executable content, the retained manifest/signature/hash catalog
(`trusted-executable-content.json`) is an artifact in that same transaction, so
executable bytes cannot commit independently of their runtime trust proof.

On library open, AutomateSTIG takes the same exclusive lock and recovers any
abandoned transaction before loading the index. An uncommitted journal rolls
back in reverse order. A committed journal finishes cleanup without reverting
the new state. If rollback or cleanup fails, the transaction directory and its
only backups are preserved and opening the library fails closed with its path.
Do not manually remove it.

## Operator procedure

1. Stop every AutomateSTIG CLI/GUI process using the library and preserve a
   filesystem snapshot.
2. From the same reviewed source, start one maintainer process with the `library list` command (`cargo run --release --features maintainer --bin automatestig -- library list`). Library startup recovery either completes or returns a transaction path and error. The installed analyst CLI deliberately has no `library` command.
3. If recovery succeeds, load every indexed benchmark and run the content and
   evaluation smoke tests. Retain the snapshot until validation completes.
4. If recovery fails, leave the transaction directory untouched. Give the
   snapshot, journal, application log, and filesystem error to the service owner.
   Restore the whole recovery set if repair cannot be independently reviewed.
5. Record the incident/recovery outcome in the external system of record.

## Required recovery drill

At least quarterly and before a release, on a disposable copy:

- terminate a writer after a destination backup and after artifact install;
- open the library and prove automatic rollback/restoration;
- terminate after the durable commit marker and prove the new state remains;
- run two independent writer processes and prove serialization/no lost index;
- inject a rollback failure and prove backups remain preserved;
- verify benchmark hashes and run an evaluation after every recovered state.

Hash the redacted drill report and reference it from release evidence. A failed
or skipped drill blocks publication.

The scheduled/manual `Transaction Recovery Drill` workflow runs the same
scenarios and retains a JSON report plus its hash-bound test log. Locally, run
it from the reviewed clean commit:

```bash
python3 scripts/run-transaction-recovery-drill.py --repo-root . \
  --output transaction-recovery-drill.json \
  --log-output transaction-recovery-drill.log
```
