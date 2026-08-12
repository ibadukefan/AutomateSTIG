#!/usr/bin/env python3
"""Validate the public documentation map and local Markdown links."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote


INLINE_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
REFERENCE_LINK = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.MULTILINE)


def public_markdown(repo: Path) -> list[Path]:
    roots = [
        repo / "README.md",
        repo / "CHANGELOG.md",
        repo / "CODE_OF_CONDUCT.md",
        repo / "CONTRIBUTING.md",
        repo / "SECURITY.md",
        repo / "SUPPORT.md",
    ]
    roots.extend(sorted((repo / "docs").rglob("*.md")))
    roots.extend(sorted((repo / ".github" / "ISSUE_TEMPLATE").glob("*.md")))
    roots.append(repo / ".github" / "pull_request_template.md")
    return [path for path in roots if path.is_file()]


def link_target(raw: str) -> str | None:
    value = raw.strip()
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    value = value.split(maxsplit=1)[0]
    if not value or value.startswith(("#", "mailto:")) or "://" in value:
        return None
    return unquote(value.split("#", 1)[0])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    failures: list[str] = []
    files = public_markdown(repo)

    for path in files:
        text = path.read_text(encoding="utf-8")
        matches = [*INLINE_LINK.finditer(text), *REFERENCE_LINK.finditer(text)]
        for match in matches:
            target = link_target(match.group(1))
            if target is None:
                continue
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(repo)
            except ValueError:
                failures.append(f"{path.relative_to(repo)}: link escapes repository: {target}")
                continue
            if not resolved.exists():
                line = text.count("\n", 0, match.start()) + 1
                failures.append(
                    f"{path.relative_to(repo)}:{line}: missing local link target {target}"
                )

    index = (repo / "docs" / "README.md").read_text(encoding="utf-8")
    for path in sorted((repo / "docs").glob("*.md")):
        if path.name != "README.md" and f"({path.name})" not in index:
            failures.append(f"docs/README.md does not index {path.name}")

    required_quickstart_links = {
        "README.md": "(docs/quickstart.md)",
        "docs/README.md": "(quickstart.md)",
        "SUPPORT.md": "(docs/quickstart.md)",
    }
    for relative, marker in required_quickstart_links.items():
        text = (repo / relative).read_text(encoding="utf-8")
        if marker not in text:
            failures.append(f"{relative} must link to the canonical quickstart")

    user_docs = "\n".join(
        (repo / relative).read_text(encoding="utf-8")
        for relative in ("README.md", "docs/quickstart.md", "docs/installation.md")
    )
    if "raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install" in user_docs:
        failures.append("user installation docs must not execute an installer from mutable main")
    for relative in ("README.md", "docs/quickstart.md", "docs/installation.md"):
        text = (repo / relative).read_text(encoding="utf-8").lower()
        if "v0.2" not in text or "legacy" not in text:
            failures.append(f"{relative} must distinguish the legacy v0.2 release")
        if "windows" not in text or "unsupported" not in text:
            failures.append(f"{relative} must state the unsupported Windows deployment boundary")

    if failures:
        print("Documentation validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Validated {len(files)} public Markdown files and the complete documentation index")


if __name__ == "__main__":
    main()
