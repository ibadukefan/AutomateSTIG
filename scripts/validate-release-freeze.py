#!/usr/bin/env python3
"""Enforce AutomateSTIG's release feature freeze on pull requests."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_config(config: object, source: str) -> dict:
    if not isinstance(config, dict):
        fail(f"{source} must contain a JSON object")
    try:
        schema_version = config["schema_version"]
        active = config["active"]
        target_release = config["target_release"]
        approval_label = config["approval_label"]
        paths = config["non_product_paths"]
    except KeyError as error:
        fail(f"{source} is missing {error.args[0]!r}")
    required = {
        "schema_version",
        "active",
        "target_release",
        "approval_label",
        "non_product_paths",
    }
    missing = required - set(config)
    if missing:
        fail(f"{source} is missing {sorted(missing)}")
    if schema_version != 1 or not isinstance(active, bool):
        fail(f"{source} has an unsupported schema or invalid active value")
    if not isinstance(target_release, str) or not re.fullmatch(
        r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", target_release
    ):
        fail(f"{source} target_release must be a semantic version tag beginning with v")
    if not isinstance(approval_label, str) or not approval_label.strip():
        fail(f"{source} approval_label must be a non-empty string")
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p for p in paths):
        fail(f"{source} non_product_paths must be a non-empty string array")
    return config


def load_config(repo: Path) -> dict:
    path = repo / ".github/release-freeze.json"
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load {path}: {error}")
    return validate_config(config, str(path))


def load_config_at(repo: Path, revision: str) -> dict | None:
    commit = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
        cwd=repo,
        text=True,
        capture_output=True,
    )
    if commit.returncode:
        fail(f"cannot resolve base commit {revision}: {commit.stderr.strip()}")
    blob = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}:.github/release-freeze.json"],
        cwd=repo,
        text=True,
        capture_output=True,
    )
    if blob.returncode:
        return None
    result = subprocess.run(
        ["git", "show", f"{revision}:.github/release-freeze.json"],
        cwd=repo,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        fail(f"cannot load release-freeze config from base commit: {result.stderr.strip()}")
    try:
        config = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"base release-freeze config is invalid JSON: {error}")
    return validate_config(config, "base release-freeze config")


def pull_request_context(event_path: str | None) -> tuple[str, str, set[str]] | None:
    if not event_path:
        return None
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read GitHub event payload: {error}")
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        return None
    try:
        base = pull_request["base"]["sha"]
        head = pull_request["head"]["sha"]
    except (KeyError, TypeError):
        fail("pull-request payload is missing base/head commit SHAs")
    labels = {
        item.get("name", "")
        for item in pull_request.get("labels", [])
        if isinstance(item, dict)
    }
    return base, head, labels


def changed_paths(repo: Path, base: str, head: str) -> list[str]:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", base) or not re.fullmatch(r"[0-9a-fA-F]{40}", head):
        fail("base and head must be full Git commit SHAs")
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRD", f"{base}...{head}"],
        cwd=repo,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        fail(f"cannot determine pull-request paths: {result.stderr.strip()}")
    return sorted({line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()})


def is_non_product(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".", type=Path)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--label", action="append", default=[])
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    config = load_config(repo)

    context = None
    if args.base or args.head:
        if not (args.base and args.head):
            fail("--base and --head must be provided together")
        context = (args.base, args.head, set(args.label))
    else:
        context = pull_request_context(os.environ.get("GITHUB_EVENT_PATH"))

    if context is None:
        print(
            f"Release freeze configuration valid: active={str(config['active']).lower()} "
            f"target={config['target_release']}"
        )
        return
    base, head, labels = context
    changed = changed_paths(repo, base, head)
    base_config = load_config_at(repo, base)
    active_configs = [
        item for item in (base_config, config) if item is not None and item["active"]
    ]
    if not active_configs:
        print("Release freeze is inactive in both the base and proposed trees")
        return

    # Evaluate both revisions so a pull request cannot weaken or disable the
    # freeze before this job decides what is protected.
    product_paths: set[str] = set()
    required_labels: set[str] = set()
    for active_config in active_configs:
        product_paths.update(
            path
            for path in changed
            if not is_non_product(path, active_config["non_product_paths"])
        )
        required_labels.add(active_config["approval_label"])
    if base_config is None:
        # Bootstrap the policy without trusting its own non-product allowlist:
        # the first active policy must approve its addition with its declared
        # release-manager label.
        product_paths.add(".github/release-freeze.json")
        required_labels.add(config["approval_label"])
    elif config != base_config:
        product_paths.add(".github/release-freeze.json")
        required_labels.add(base_config["approval_label"])
    missing_labels = sorted(required_labels - labels) if product_paths else []
    if missing_labels:
        preview = "\n  ".join(sorted(product_paths)[:30])
        suffix = "\n  ..." if len(product_paths) > 30 else ""
        fail(
            "feature freeze blocks product-code or freeze-policy changes without "
            f"the required label(s) {missing_labels}:\n  {preview}{suffix}"
        )
    print(
        f"Release freeze passed: {len(changed)} changed paths, "
        f"{len(product_paths)} protected paths, approval="
        f"{not missing_labels}"
    )


if __name__ == "__main__":
    main()
