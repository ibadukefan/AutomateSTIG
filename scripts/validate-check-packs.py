#!/usr/bin/env python3
"""Validate check-pack content structure and security-relevant invariants.

Check packs are security-critical logic: a bad pattern silently flips a
fleet's compliance results. This gate runs in CI on every change so a
malformed or dangerous pack cannot merge. Dependency-free by design.

Exits non-zero on any violation.
"""
import glob
import json
import os
import re
import sys

REPO = os.environ.get("REPO_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

KNOWN_PLATFORMS = {
    "windows", "linux", "cisco_ios", "cisco_nxos", "cisco_asa",
    "ontap", "bsd", "generic",
}
KNOWN_CHECK_TYPES = {
    "registry", "security_policy", "audit_policy", "service", "windows_feature",
    "file_content", "file_permission", "sysctl", "package", "config_line",
    "command", "all", "any",
}
KNOWN_EXPECTED_TYPES = {
    "equals", "matches", "greater_or_equal", "less_or_equal", "contains",
    "not_contains", "is_true", "is_false", "all_pass", "match_count_at_least",
}

errors = []


def err(pack, msg):
    errors.append(f"{pack}: {msg}")


def validate_check(pack, vid, chk):
    t = chk.get("type")
    if t not in KNOWN_CHECK_TYPES:
        err(pack, f"{vid}: unknown check type {t!r}")
        return
    if t == "config_line":
        if not isinstance(chk.get("pattern"), str) or not chk["pattern"].strip():
            err(pack, f"{vid}: config_line needs a non-empty pattern")
        if not isinstance(chk.get("should_exist"), bool):
            err(pack, f"{vid}: config_line needs a boolean should_exist")
        if isinstance(chk.get("pattern"), str) and chk["pattern"] != chk["pattern"].strip():
            err(pack, f"{vid}: config_line pattern has leading/trailing whitespace "
                      f"(token matching will not behave as written): {chk['pattern']!r}")
    elif t == "command":
        if not isinstance(chk.get("command"), str) or not chk["command"].strip():
            err(pack, f"{vid}: command check needs a non-empty command")
    elif t in ("all", "any"):
        subs = chk.get("checks")
        if not isinstance(subs, list) or not subs:
            err(pack, f"{vid}: {t} needs a non-empty checks[]")
        else:
            for sub in subs:
                validate_check(pack, vid, sub)


def validate_expected(pack, vid, exp):
    t = exp.get("type")
    if t not in KNOWN_EXPECTED_TYPES:
        err(pack, f"{vid}: unknown expected type {t!r}")
        return
    if t == "match_count_at_least":
        if not isinstance(exp.get("min"), int) or exp["min"] < 1:
            err(pack, f"{vid}: match_count_at_least needs an integer min >= 1")
        if not isinstance(exp.get("pattern"), str) or not exp["pattern"]:
            err(pack, f"{vid}: match_count_at_least needs a pattern")
    if t == "matches" and not isinstance(exp.get("pattern"), str):
        err(pack, f"{vid}: matches needs a pattern string")


def validate_pack(path):
    name = os.path.relpath(path, REPO)
    try:
        d = json.load(open(path))
    except Exception as e:
        err(name, f"not valid JSON: {e}")
        return
    for field in ("stig_id", "platform", "version", "checks"):
        if field not in d:
            err(name, f"missing required field {field!r}")
    if d.get("platform") not in KNOWN_PLATFORMS:
        err(name, f"unknown pack platform {d.get('platform')!r}")
    if "priority" in d and not isinstance(d["priority"], int):
        err(name, "priority must be an integer")
    checks = d.get("checks", [])
    if not isinstance(checks, list) or not checks:
        err(name, "checks[] must be a non-empty array")
        return
    seen = set()
    for c in checks:
        vid = c.get("vuln_id")
        if not vid:
            err(name, "a check is missing vuln_id")
            continue
        if vid in seen:
            err(name, f"duplicate vuln_id {vid} within pack")
        seen.add(vid)
        if c.get("platform") not in KNOWN_PLATFORMS:
            err(name, f"{vid}: unknown check platform {c.get('platform')!r}")
        if "check" not in c:
            err(name, f"{vid}: missing check")
        else:
            validate_check(name, vid, c["check"])
        if "expected" not in c:
            err(name, f"{vid}: missing expected")
        else:
            validate_expected(name, vid, c["expected"])


def main():
    packs = sorted(glob.glob(os.path.join(REPO, "content/check_packs/*.json")))
    if not packs:
        print("no check packs found", file=sys.stderr)
        sys.exit(1)
    for p in packs:
        validate_pack(p)
    if errors:
        print(f"Check-pack validation FAILED ({len(errors)} issue(s)):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Validated {len(packs)} check packs — structure and invariants OK")


if __name__ == "__main__":
    main()
