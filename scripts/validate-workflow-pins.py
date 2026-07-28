#!/usr/bin/env python3
"""Reject mutable GitHub Action references in workflow files."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)
PIN = re.compile(r"^[0-9a-f]{40}$")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".", type=Path)
    args = parser.parse_args()
    workflow_root = args.repo_root.resolve() / ".github/workflows"
    failures: list[str] = []
    uses_count = 0
    for path in sorted(workflow_root.glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        for match in USES.finditer(text):
            reference = match.group(1)
            if reference.startswith(("./", "docker://")):
                continue
            uses_count += 1
            if "@" not in reference or not PIN.fullmatch(reference.rsplit("@", 1)[1]):
                line = text.count("\n", 0, match.start()) + 1
                failures.append(f"{path.relative_to(args.repo_root.resolve())}:{line}: {reference}")
    if failures:
        print("ERROR: workflow actions must be pinned to full 40-character commit SHAs:", file=sys.stderr)
        print("\n".join(f"  {item}" for item in failures), file=sys.stderr)
        raise SystemExit(1)
    print(f"Validated {uses_count} immutable GitHub Action references")


if __name__ == "__main__":
    main()
