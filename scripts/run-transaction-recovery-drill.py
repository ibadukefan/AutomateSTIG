#!/usr/bin/env python3
"""Run the crash/concurrency recovery drill and emit hashable evidence."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys

REQUIRED_SCENARIOS = (
    "abandoned_applying_transaction_is_rolled_back_on_next_lock",
    "abandoned_committed_transaction_is_kept_and_cleaned_on_next_lock",
    "rollback_failure_preserves_the_journal_and_original_backup",
    "cleanup_failure_preserves_the_active_transaction_backup",
    "concurrent_stale_handles_do_not_lose_either_import",
    "concurrent_processes_do_not_lose_either_import",
    "staged_write_artifact_commit_and_index_commit_failures_roll_back",
)


def run(command, repo):
    return subprocess.run(command, cwd=repo, text=True, capture_output=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".", type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--log-output", type=pathlib.Path)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    status = run(["git", "status", "--porcelain", "--untracked-files=no"], repo)
    if status.returncode:
        raise SystemExit(f"cannot inspect worktree: {status.stderr.strip()}")
    dirty = bool(status.stdout.strip())
    if dirty and not args.allow_dirty:
        raise SystemExit("recovery evidence requires a clean tracked worktree (use --allow-dirty only for development)")
    commit = run(["git", "rev-parse", "HEAD"], repo)
    if commit.returncode:
        raise SystemExit(commit.stderr.strip())
    rustc = run(["rustc", "--version"], repo)
    if rustc.returncode:
        raise SystemExit(rustc.stderr.strip())

    command = [
        "cargo", "test", "--locked", "-p", "automatestig-core", "library", "--", "--nocapture",
    ]
    result = run(command, repo)
    combined = result.stdout + result.stderr
    output_sha256 = hashlib.sha256(combined.encode()).hexdigest()
    missing = [scenario for scenario in REQUIRED_SCENARIOS if scenario not in combined]
    passed = result.returncode == 0 and not missing
    if args.log_output:
        args.log_output.parent.mkdir(parents=True, exist_ok=True)
        args.log_output.write_text(combined, encoding="utf-8")

    evidence = {
        "schema": "automatestig-transaction-recovery-drill/v1",
        "passed": passed,
        "executed_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_commit": commit.stdout.strip(),
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "tracked_worktree_dirty": dirty,
        "rustc": rustc.stdout.strip(),
        "command": command,
        "output_sha256": output_sha256,
        "required_scenarios": [
            {"name": scenario, "observed": scenario not in missing}
            for scenario in REQUIRED_SCENARIOS
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not passed:
        print(combined[-4000:], file=sys.stderr)
        if missing:
            print(f"ERROR: drill did not exercise required scenarios: {missing}", file=sys.stderr)
        raise SystemExit(1)
    print(f"PASS: transaction recovery drill; evidence={args.output}; output_sha256={output_sha256}")


if __name__ == "__main__":
    main()
