#!/usr/bin/env python3
"""Black-box E2E acceptance harness for AutomateSTIG release binaries.

Usage: python3 scripts/e2e-acceptance.py   (after `cargo build --release`)

Every scenario runs the real `automatestig` / `automatestig-gui` binaries and
verifies outputs against oracles computed independently from the input
fixtures (never against the app's own claims). Exits non-zero on any failure.

Verified app conventions (confirmed against golden fixtures / STIG standards):
- CLI human output goes to stderr (p.combined merges both streams).
- STIG-Manager export includes ALL findings; Not_Reviewed -> "notchecked".
- Compliance % = (NaF + NA) / evaluated, app-wide (core finding.rs compliance_pct).
- Unsigned .stigpack import is blocked unless AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
import tempfile
import xml.etree.ElementTree as ET
import zipfile

REPO = os.environ.get(
    "E2E_REPO_ROOT",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXE = ".exe" if sys.platform == "win32" else ""
BIN = os.environ.get("AUTOMATESTIG_BIN", f"{REPO}/target/release/automatestig{EXE}")
GUI_BIN = os.environ.get("AUTOMATESTIG_GUI_BIN", f"{REPO}/target/release/automatestig-gui{EXE}")
WORK = os.environ.get("E2E_WORK") or tempfile.mkdtemp(prefix="automatestig-e2e-")
FIX = f"{REPO}/fixtures"
WS2022_ZIP = f"{FIX}/authorized/disa-public-2026-04/U_MS_Windows_Server_2022_V2R8_STIG.zip"
RHEL8_ZIP = f"{FIX}/authorized/disa-public-2026-04/U_RHEL_8_V2R7_STIG.zip"
SCC_XML = f"{FIX}/scc-results/windows_server_2022_scc_results.xml"
OSCAP_XML = f"{FIX}/openscap-results/rhel8_openscap_results.xml"
SAN_CKL = f"{FIX}/ckl/windows_server_2022_sanitized.ckl"

DB = f"{WORK}/data.db"
LIB = f"{WORK}/library"
OUT = f"{WORK}/out"

RESULTS = []


def check(section, name, ok, detail=""):
    RESULTS.append((section, name, bool(ok), detail))
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {section} :: {name}" + (f" — {detail}" if detail and not ok else ""))


def run_cli(*args, cwd=REPO, expect_ok=True, env_extra=None):
    cmd = [BIN, "--db", DB, "--library", LIB, *args]
    env = dict(os.environ)
    env.update(env_extra or {})
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env=env)
    p.combined = p.stdout + p.stderr  # CLI prints human output to stderr
    if expect_ok and p.returncode != 0:
        print(f"  cmd failed: {' '.join(args)}\n  output: {p.combined[:600]}")
    return p


def norm_status(s):
    return re.sub(r"[^a-z]", "", (s or "").lower())


# --- Oracles computed from raw inputs -------------------------------------

def base_rule_id(rid):
    m = re.match(r"(SV-\d+)", rid or "")
    return m.group(1) if m else rid


def parse_scan_results(path):
    tree = ET.parse(path)
    out = {}
    for rr in tree.iter():
        if not rr.tag.endswith("rule-result"):
            continue
        rid = rr.get("idref", "")
        res = ""
        for child in rr:
            if child.tag.endswith("result"):
                res = (child.text or "").strip()
        out[base_rule_id(rid)] = res
    return out


def benchmark_rules_from_zip(zip_path):
    """[(vuln_id, full_rule_id)] straight from the DISA XCCDF in the zip."""
    with zipfile.ZipFile(zip_path) as z:
        names = [n for n in z.namelist() if n.lower().endswith(".xml") and "xccdf" in n.lower()]
        data = z.read(sorted(names, key=len)[0])
    root = ET.fromstring(data)
    rules = []
    for group in root.iter():
        if not group.tag.endswith("}Group"):
            continue
        gid = group.get("id", "")
        for rule in group:
            if rule.tag.endswith("}Rule"):
                rules.append((gid, rule.get("id", "")))
    return rules


def parse_ckl(path):
    tree = ET.parse(path)
    out = {}
    for vuln in tree.iter("VULN"):
        attrs = {}
        for sd in vuln.findall("STIG_DATA"):
            attrs[sd.findtext("VULN_ATTRIBUTE")] = sd.findtext("ATTRIBUTE_DATA") or ""
        out[attrs.get("Vuln_Num", "")] = {
            "status": vuln.findtext("STATUS") or "",
            "rule_id": attrs.get("Rule_ID", ""),
            "severity": attrs.get("Severity", ""),
            "details": vuln.findtext("FINDING_DETAILS") or "",
            "comments": vuln.findtext("COMMENTS") or "",
        }
    return out


def parse_cklb(path):
    data = json.load(open(path))
    out = {}
    for stig in data.get("stigs", []):
        for rule in stig.get("rules", []):
            vid = rule.get("group_id") or rule.get("group_id_src") or ""
            out[vid] = {
                "status": rule.get("status", ""),
                "rule_id": rule.get("rule_id", ""),
                "severity": rule.get("severity", ""),
                "details": rule.get("finding_details", ""),
                "comments": rule.get("comments", ""),
            }
    return out


def parse_native_json(path):
    data = json.load(open(path))
    out = {}
    for f in data.get("findings", []):
        st = f.get("status")
        if isinstance(st, dict):
            st = next(iter(st.keys()))
        out[f.get("vuln_id") or f.get("group_id")] = {
            "status": str(st),
            "rule_id": f.get("rule_id", ""),
            "severity": str(f.get("severity", "")),
            "details": f.get("finding_details", ""),
            "comments": f.get("comments", ""),
        }
    return out


RAW_TO_STATUS = {
    "pass": "notafinding",
    "fail": "open",
    "notapplicable": "notapplicable",
    "notchecked": "notreviewed",
}
STIGMAN_MAP = {
    "notafinding": "pass",
    "open": "fail",
    "notapplicable": "notapplicable",
    "notreviewed": "notchecked",
}


def make_scan_xml(dest, assignments, target="synthetic.example.test"):
    """Write an SCC-style XCCDF result file: assignments = [(full_rule_id, raw_result)]."""
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">',
             '  <TestResult id="scc_result_synth" test-system="cpe:/a:disa:scc:5.7">',
             f'    <target>{target}</target>',
             '    <profile>MAC-2_Sensitive</profile>']
    for rid, res in assignments:
        lines.append(f'    <rule-result idref="{rid}"><result>{res}</result></rule-result>')
    lines += ['  </TestResult>', '</Benchmark>']
    open(dest, "w").write("\n".join(lines))


def status_counts(ckl):
    c = {}
    for e in ckl.values():
        k = norm_status(e["status"])
        c[k] = c.get(k, 0) + 1
    return c


# ==========================================================================

def sec_cli_basics():
    S = "cli-basics"
    p = run_cli("--version")
    check(S, "--version reports 0.1.1", "0.1.1" in p.stdout, p.stdout.strip())
    p = run_cli("library", "init")
    check(S, "library init succeeds", p.returncode == 0, p.combined[:200])
    p = run_cli("library", "list")
    check(S, "empty library lists cleanly", p.returncode == 0, p.combined[:200])
    p = run_cli("status")
    check(S, "status runs and shows version", p.returncode == 0 and "0.1.1" in p.combined,
          p.combined[:200])


def sec_disa_import():
    S = "disa-import"
    for zp, label in [(WS2022_ZIP, "WS2022"), (RHEL8_ZIP, "RHEL8")]:
        p = run_cli("disa-import", "--input", zp)
        check(S, f"disa-import {label} succeeds", p.returncode == 0, p.combined[:400])
    p = run_cli("library", "list")
    # Oracle: rule counts in `library list` must equal rule counts in the zips.
    ws_rules = len(benchmark_rules_from_zip(WS2022_ZIP))
    rh_rules = len(benchmark_rules_from_zip(RHEL8_ZIP))
    check(S, f"listed WS2022 rule count matches zip ({ws_rules})",
          re.search(rf"Windows_Server_2022\S*\s+\S+\s+\S+\s+{ws_rules}", p.combined),
          p.combined[-400:])
    check(S, f"listed RHEL8 rule count matches zip ({rh_rules})",
          re.search(rf"RHEL_8\S*\s+\S+\s+\S+\s+{rh_rules}", p.combined), p.combined[-400:])
    p2 = run_cli("library", "show", "MS_Windows_Server_2022_STIG")
    check(S, "library show works", p2.returncode == 0, p2.combined[:200])
    return "MS_Windows_Server_2022_STIG", "RHEL_8_STIG"


def sec_evaluate(ws_id):
    S = "evaluate-ws2022"
    os.makedirs(OUT, exist_ok=True)
    outs = {}
    for fmt, ext in [("ckl", "ckl"), ("cklb", "cklb"), ("json", "json")]:
        dest = f"{OUT}/ws2022.{ext}"
        p = run_cli("evaluate", "--stig", ws_id, "--scan", SCC_XML,
                    "--host", "e2ehost01", "--output", dest, "--format", fmt)
        check(S, f"evaluate → {fmt} succeeds", p.returncode == 0 and os.path.exists(dest),
              p.combined[:400])
        outs[fmt] = dest

    bench = dict(benchmark_rules_from_zip(WS2022_ZIP))
    scan = parse_scan_results(SCC_XML)
    ckl = parse_ckl(outs["ckl"])
    cklb = parse_cklb(outs["cklb"])
    native = parse_native_json(outs["json"])

    check(S, "CKL finding count == benchmark rule count",
          len(ckl) == len(bench), f"ckl={len(ckl)} bench={len(bench)}")
    check(S, "CKL/CKLB/JSON same finding count",
          len(ckl) == len(cklb) == len(native), f"{len(ckl)}/{len(cklb)}/{len(native)}")

    rule_to_vuln = {base_rule_id(e["rule_id"]): v for v, e in ckl.items()}
    mismatch, matched = [], 0
    for brid, raw in scan.items():
        expected = RAW_TO_STATUS.get(raw)
        vid = rule_to_vuln.get(brid)
        if vid is None or expected is None:
            continue
        if norm_status(ckl[vid]["status"]) == expected:
            matched += 1
        else:
            mismatch.append((vid, brid, raw, ckl[vid]["status"]))
    check(S, "every matched scan result produced the correct CKL status",
          not mismatch and matched > 0, f"matched={matched} mismatches={mismatch[:5]}")

    scanned = set(scan.keys())
    wrong = [v for v, e in ckl.items()
             if base_rule_id(e["rule_id"]) not in scanned and norm_status(e["status"]) != "notreviewed"]
    check(S, "unscanned rules stay Not_Reviewed", not wrong, f"{len(wrong)} e.g. {wrong[:5]}")

    diff_ab = [v for v in ckl if v in cklb and norm_status(ckl[v]["status"]) != norm_status(cklb[v]["status"])]
    diff_ac = [v for v in ckl if v in native and norm_status(ckl[v]["status"]) != norm_status(native[v]["status"])]
    check(S, "CKL and CKLB statuses agree per vuln", not diff_ab, str(diff_ab[:5]))
    check(S, "CKL and native JSON statuses agree per vuln", not diff_ac, str(diff_ac[:5]))

    prov = [v for v, e in ckl.items()
            if base_rule_id(e["rule_id"]) in scanned and RAW_TO_STATUS.get(scan[base_rule_id(e["rule_id"])]) in ("open", "notafinding")
            and "scanner" not in (e["comments"] + e["details"]).lower()]
    check(S, "scan-evaluated findings carry scanner provenance", not prov, f"{prov[:3]}")
    check(S, "CKL carries the asset hostname", "e2ehost01" in open(outs["ckl"]).read())
    return outs, ckl


def sec_synthetic_full(ws_id):
    """Full-coverage synthetic scan: every benchmark rule gets a result."""
    S = "synthetic-full-scan"
    rules = benchmark_rules_from_zip(WS2022_ZIP)
    raws = ["pass", "fail", "notapplicable", "notchecked"]
    assignments = [(rid, raws[i % 4]) for i, (_, rid) in enumerate(rules)]
    scan_path = f"{WORK}/synthetic_ws.xml"
    make_scan_xml(scan_path, assignments)

    dest = f"{OUT}/synth.ckl"
    p = run_cli("evaluate", "--stig", ws_id, "--scan", scan_path,
                "--host", "synthhost01", "--output", dest, "--format", "ckl")
    check(S, f"evaluate with {len(assignments)}-rule synthetic scan succeeds",
          p.returncode == 0, p.combined[:400])
    ckl = parse_ckl(dest)

    expected_by_rule = {base_rule_id(rid): RAW_TO_STATUS[raw] for rid, raw in assignments}
    bad = []
    for v, e in ckl.items():
        exp = expected_by_rule.get(base_rule_id(e["rule_id"]))
        if exp and norm_status(e["status"]) != exp:
            bad.append((v, e["rule_id"], exp, e["status"]))
    check(S, f"ALL {len(ckl)} rule statuses exactly match the synthetic scan",
          not bad and len(ckl) == len(rules), f"{len(bad)} wrong, e.g. {bad[:5]}")

    counts = status_counts(ckl)
    print(f"  synthetic status distribution: {counts}")

    # summary accuracy on a rich checklist
    p = run_cli("summary", "--input", dest)
    nums = {int(n) for n in re.findall(r"\b(\d+)\b", p.combined)}
    missing = {k: v for k, v in counts.items() if v and v not in nums}
    check(S, "summary reports the true status counts", p.returncode == 0 and not missing,
          f"expected {counts}, got numbers {sorted(nums)}")

    # stig-manager export accuracy on a rich checklist
    sm = f"{OUT}/synth_stigman.json"
    run_cli("export", "--input", dest, "--output", sm, "--format", "stig-manager",
            "--collection", "Synth Collection")
    data = json.load(open(sm))
    reviews = [r for a in data.get("assets", []) for s in a.get("stigs", []) for r in s.get("reviews", [])]
    check(S, "stig-manager exports one review per finding", len(reviews) == len(ckl),
          f"reviews={len(reviews)} findings={len(ckl)}")
    rule_to_vuln = {base_rule_id(e["rule_id"]): v for v, e in ckl.items()}
    bad = []
    from collections import Counter
    for r in reviews:
        vid = rule_to_vuln.get(base_rule_id(r.get("ruleId", "")))
        want = STIGMAN_MAP.get(norm_status(ckl.get(vid, {}).get("status", "")))
        if r.get("result") != want:
            bad.append((vid, r.get("result"), want))
    check(S, "every stig-manager result maps correctly", not bad, f"{len(bad)} e.g. {bad[:5]}")
    print(f"  stig-manager result distribution: {Counter(r['result'] for r in reviews)}")

    return dest, ckl


def sec_determinism(ws_id):
    S = "determinism"
    a, b = f"{OUT}/det_a.ckl", f"{OUT}/det_b.ckl"
    for dest in (a, b):
        run_cli("evaluate", "--stig", ws_id, "--scan", SCC_XML,
                "--host", "e2ehost01", "--output", dest, "--format", "ckl")
    ta, tb = open(a).read(), open(b).read()
    if ta == tb:
        check(S, "two identical evaluations are byte-identical", True)
    else:
        strip = lambda t: re.sub(r"\d{4}-\d{2}-\d{2}[T ]?[\d:.Z+-]*", "<TS>", t)
        check(S, "two identical evaluations differ only in timestamps",
              strip(ta) == strip(tb), "non-timestamp diff found")


def sec_answer_file(ws_id, ckl_before):
    S = "answer-files"
    target = next((v for v, e in ckl_before.items() if norm_status(e["status"]) == "open"), None)
    check(S, "found an open vuln to override", target is not None)
    if not target:
        return
    af = f"{WORK}/answers.json"
    json.dump({"name": "E2E Answers", "stig_id": ws_id, "version": "1.0",
               "entries": [{"vuln_id": target, "status": "Not_Applicable",
                            "comments": "E2E waiver justification ABC123",
                            "force_override": True}]}, open(af, "w"), indent=2)
    dest = f"{OUT}/ws2022_answered.ckl"
    p = run_cli("evaluate", "--stig", ws_id, "--scan", SCC_XML, "--answer", af,
                "--host", "e2ehost01", "--output", dest, "--format", "ckl")
    check(S, "evaluate with answer file succeeds", p.returncode == 0, p.combined[:400])
    if p.returncode != 0:
        return
    after = parse_ckl(dest)
    e = after.get(target, {})
    check(S, f"answer file flipped {target} to Not_Applicable",
          norm_status(e.get("status")) == "notapplicable", e.get("status"))
    check(S, "justification text present in finding",
          "ABC123" in (e.get("comments", "") + e.get("details", "")))
    others = [v for v in ckl_before
              if v != target and norm_status(ckl_before[v]["status"]) != norm_status(after.get(v, {}).get("status", ""))]
    check(S, "no other finding changed", not others, str(others[:5]))


def sec_convert(outs):
    S = "convert-roundtrip"
    c1, c2, c3 = f"{OUT}/rt.cklb", f"{OUT}/rt.json", f"{OUT}/rt.ckl"
    p1 = run_cli("convert", "--input", outs["ckl"], "--output", c1, "--format", "cklb")
    p2 = run_cli("convert", "--input", c1, "--output", c2, "--format", "json")
    p3 = run_cli("convert", "--input", c2, "--output", c3, "--format", "ckl")
    check(S, "ckl→cklb→json→ckl chain succeeds", all(p.returncode == 0 for p in (p1, p2, p3)))
    if all(p.returncode == 0 for p in (p1, p2, p3)):
        orig, final = parse_ckl(outs["ckl"]), parse_ckl(c3)
        check(S, "roundtrip preserves finding count", len(orig) == len(final), f"{len(orig)} vs {len(final)}")
        lost = [v for v in orig if v in final and (
            norm_status(orig[v]["status"]) != norm_status(final[v]["status"])
            or orig[v]["details"].strip() != final[v]["details"].strip()
            or orig[v]["comments"].strip() != final[v]["comments"].strip()
            or orig[v]["severity"] != final[v]["severity"])]
        check(S, "roundtrip preserves status/details/comments/severity", not lost, str(lost[:5]))

    f1, f2 = f"{OUT}/san.cklb", f"{OUT}/san_back.ckl"
    q1 = run_cli("convert", "--input", SAN_CKL, "--output", f1, "--format", "cklb")
    q2 = run_cli("convert", "--input", f1, "--output", f2, "--format", "ckl")
    ok = q1.returncode == 0 and q2.returncode == 0
    check(S, "sanitized DISA CKL fixture roundtrips", ok, (q1.combined + q2.combined)[:200])
    if ok:
        a, b = parse_ckl(SAN_CKL), parse_ckl(f2)
        bad = [v for v in a if norm_status(a[v]["status"]) != norm_status(b.get(v, {}).get("status"))]
        check(S, "fixture statuses preserved", len(a) == len(b) and not bad, f"count {len(a)}/{len(b)} bad={bad[:5]}")


def sec_gen_answer(outs):
    S = "gen-answer"
    dest = f"{OUT}/template.json"
    p = run_cli("gen-answer", "--input", outs["ckl"], "--output", dest)
    check(S, "gen-answer runs", p.returncode == 0 and os.path.exists(dest), p.combined[:300])
    if os.path.exists(dest):
        data = json.load(open(dest))
        entries = data.get("entries", [])
        check(S, "template contains entries for evaluated findings", len(entries) > 0, str(len(entries)))
        full = f"{OUT}/template_full.json"
        p = run_cli("gen-answer", "--input", outs["ckl"], "--output", full, "--include-unreviewed")
        if p.returncode == 0 and os.path.exists(full):
            n_full = len(json.load(open(full)).get("entries", []))
            src = parse_ckl(outs["ckl"])
            check(S, "--include-unreviewed covers every finding", n_full == len(src),
                  f"{n_full} vs {len(src)}")


def sec_evaluate_rhel(rhel_id):
    S = "evaluate-rhel8"
    outs = {}
    for fmt, ext in [("ckl", "ckl"), ("cklb", "cklb"), ("json", "json")]:
        dest = f"{OUT}/rhel8.{ext}"
        p = run_cli("evaluate", "--stig", rhel_id, "--scan", OSCAP_XML,
                    "--host", "e2erhel01", "--output", dest, "--format", fmt)
        check(S, f"evaluate rhel8 → {fmt}", p.returncode == 0 and os.path.exists(dest), p.combined[:300])
        outs[fmt] = dest
    scan = parse_scan_results(OSCAP_XML)
    ckl = parse_ckl(outs["ckl"])
    rule_to_vuln = {base_rule_id(e["rule_id"]): v for v, e in ckl.items()}
    mismatch, matched = [], 0
    for brid, raw in scan.items():
        expected = RAW_TO_STATUS.get(raw)
        vid = rule_to_vuln.get(brid)
        if vid is None or expected is None:
            continue
        if norm_status(ckl[vid]["status"]) == expected:
            matched += 1
        else:
            mismatch.append((vid, raw, ckl[vid]["status"]))
    check(S, "OpenSCAP statuses map correctly", not mismatch and matched > 0,
          f"matched={matched} mismatches={mismatch[:5]}")
    return outs


def sec_stigpack():
    S = "stigpack"
    src_dir = f"{WORK}/pack_src"
    os.makedirs(f"{src_dir}/benchmarks", exist_ok=True)
    shutil.copy(f"{LIB}/benchmarks/MS_Windows_Server_2022_STIG.json",
                f"{src_dir}/benchmarks/MS_Windows_Server_2022_STIG.json")
    empty_dir = f"{WORK}/pack_src_empty"
    os.makedirs(empty_dir, exist_ok=True)
    p = run_cli("build-pack", "--id", "empty", "--name", "Empty", "--version", "1.0.0",
                "--source", empty_dir, "--output", f"{WORK}/empty.stigpack", expect_ok=False)
    check(S, "build-pack refuses an empty source directory",
          p.returncode != 0 and "no pack content" in p.combined, p.combined[:200])
    pack = f"{WORK}/e2e.stigpack"
    p = run_cli("build-pack", "--id", "e2e_ws2022", "--name", "E2E WS2022",
                "--version", "1.0.0", "--source", src_dir, "--output", pack)
    check(S, "build-pack succeeds", p.returncode == 0 and os.path.exists(pack), p.combined[:400])
    if not os.path.exists(pack):
        return
    p = run_cli("verify", "--pack", pack)
    check(S, "verify accepts the built pack", p.returncode == 0, p.combined[:300])

    bad = f"{WORK}/tampered.stigpack"
    data = bytearray(open(pack, "rb").read())
    data[len(data) // 2] ^= 0xFF
    open(bad, "wb").write(bytes(data))
    p = run_cli("verify", "--pack", bad, expect_ok=False)
    check(S, "verify rejects a tampered pack", p.returncode != 0 or "fail" in p.combined.lower())

    p = run_cli("import", "--pack", pack, expect_ok=False)
    check(S, "unsigned pack import is blocked by default (security)",
          p.returncode != 0 and "signature" in p.combined.lower(), p.combined[:200])
    p = run_cli("import", "--pack", pack,
                env_extra={"AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK": "1"})
    check(S, "unsigned import succeeds with explicit lab override", p.returncode == 0, p.combined[:300])
    check(S, "import ingested the benchmark from the pack",
          re.search(r"Benchmarks\s+1", p.combined), p.combined[:300])


def sec_coverage():
    S = "coverage"
    p = run_cli("coverage", "validate", "--manifest", f"{REPO}/content/coverage/rhel8.example.json")
    check(S, "coverage validate (example manifest)", p.returncode == 0, p.combined[:300])
    auth_root = f"{REPO}/content/coverage/disa-authoritative"
    manifest = None
    for root, _, files in os.walk(auth_root):
        js = [f for f in files if f.endswith(".json")]
        if js:
            manifest = os.path.join(root, js[0])
            break
    if manifest:
        p = run_cli("coverage", "validate", "--manifest", manifest)
        check(S, f"coverage validate (authoritative {os.path.basename(manifest)})",
              p.returncode == 0, p.combined[:300])


# ==========================================================================
G = "gui"
GUI_PORT = 18321
TOKEN = "e2e-test-token-0123456789abcdef"


def gui_req(path, method="GET", port=GUI_PORT):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    req.add_header("X-Auth-Token", TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)


def unwrap(body):
    """API envelope: {"data": ..., "error": ..., "success": ...}"""
    try:
        j = json.loads(body)
    except Exception:
        return None
    return j.get("data") if isinstance(j, dict) and "data" in j else j


def curl_multipart(path, fields, files, port=GUI_PORT):
    cmd = ["curl", "-s", "-H", f"X-Auth-Token: {TOKEN}", f"http://127.0.0.1:{port}{path}"]
    for k, v in fields.items():
        cmd += ["-F", f"{k}={v}"]
    for k, fp in files.items():
        cmd += ["-F", f"{k}=@{fp}"]
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def start_gui(home, port, extra_env=None):
    env = dict(os.environ)
    env.update({"HOME": home, "USERPROFILE": home, "PORT": str(port),
                "AUTOMATESTIG_AUTH_TOKEN": TOKEN})
    env.update(extra_env or {})
    os.makedirs(home, exist_ok=True)
    proc = subprocess.Popen([GUI_BIN], env=env, cwd=REPO,
                            stdout=open(f"{home}/gui.log", "w"), stderr=subprocess.STDOUT)
    for _ in range(60):
        st, _ = gui_req("/api/status", port=port)
        if st == 200:
            return proc
        time.sleep(0.5)
    proc.kill()
    raise RuntimeError(f"GUI failed to start; log: {open(home + '/gui.log').read()[:1000]}")


def urllib_no_token(path, port=GUI_PORT):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return -1, str(e)


def sec_gui(cli_ckl):
    home = f"{WORK}/gui_home"
    proc = start_gui(home, GUI_PORT)
    try:
        st, body = gui_req("/api/status")
        check(G, "GET /api/status returns 200", st == 200, f"{st} {body[:200]}")
        check(G, "status reports version 0.1.1", "0.1.1" in body, body[:200])

        st, _ = urllib_no_token("/api/checklists")
        check(G, "API rejects requests without auth token", st in (401, 403), str(st))

        st, body = gui_req("/api/checklists")
        check(G, "fresh install has ZERO checklists (no demo data)",
              st == 200 and unwrap(body) == [], body[:200])
        st, body = gui_req("/api/assets")
        check(G, "fresh install has ZERO assets (no demo data)",
              st == 200 and unwrap(body) == [], body[:200])
        st, body = gui_req("/api/library/benchmarks")
        check(G, "fresh install has empty STIG library",
              st == 200 and unwrap(body) == [], body[:200])

        st, html = gui_req("/")
        check(G, "frontend index served", st == 200 and "<html" in html.lower(), str(st))
        check(G, "frontend has no demo markers",
              not re.search(r"demo seed|WEB-APP-01|lorem", html, re.I))

        out = curl_multipart("/api/library/import-disa", {}, {"file": WS2022_ZIP})
        check(G, "POST /api/library/import-disa imports WS2022",
              '"success":true' in out.replace(" ", "") or '"imported"' in out, out[:300])
        st, body = gui_req("/api/library/benchmarks")
        benches = unwrap(body) or []
        check(G, "benchmark visible after import", len(benches) >= 1, body[:300])
        stig_id = None
        if benches and isinstance(benches, list) and isinstance(benches[0], dict):
            stig_id = benches[0].get("id") or benches[0].get("stig_id")

        out = curl_multipart("/api/evaluate/with-scan",
                             {"stig_id": stig_id or "", "hostname": "e2ehost01"},
                             {"scan": SCC_XML})
        cid = None
        try:
            ev = unwrap(out)
            if isinstance(ev, dict):
                cid = ev.get("checklist_id") or ev.get("id")
        except Exception:
            pass
        check(G, "POST /api/evaluate/with-scan returns a checklist", bool(cid), out[:300])

        if cid:
            st, ckl_body = gui_req(f"/api/export/ckl/{cid}")
            check(G, "GET /api/export/ckl works", st == 200 and "<CHECKLIST" in ckl_body, str(st))
            gui_path = f"{OUT}/gui.ckl"
            open(gui_path, "w").write(ckl_body)
            gui_ckl = parse_ckl(gui_path)
            diff = [v for v in cli_ckl
                    if norm_status(cli_ckl[v]["status"]) != norm_status(gui_ckl.get(v, {}).get("status"))]
            check(G, "GUI evaluation matches CLI evaluation per vuln",
                  len(gui_ckl) == len(cli_ckl) and not diff,
                  f"counts {len(gui_ckl)}/{len(cli_ckl)} diffs={diff[:5]}")
            st, cb = gui_req(f"/api/export/cklb/{cid}")
            check(G, "GET /api/export/cklb works", st == 200 and cb.lstrip().startswith("{"), str(st))
    finally:
        proc.kill()
        proc.wait()



# ==========================================================================

def main():
    for b in (BIN, GUI_BIN):
        if not os.path.exists(b):
            sys.exit(f"binary not found: {b} — run `cargo build --release` first")
    if os.path.exists(WORK):
        shutil.rmtree(WORK)
    os.makedirs(OUT, exist_ok=True)

    sec_cli_basics()
    ws_id, rhel_id = sec_disa_import()
    outs, ckl = sec_evaluate(ws_id)
    sec_synthetic_full(ws_id)
    sec_determinism(ws_id)
    sec_answer_file(ws_id, ckl)
    sec_convert(outs)
    sec_gen_answer(outs)
    sec_evaluate_rhel(rhel_id)
    sec_stigpack()
    sec_coverage()
    sec_gui(ckl)

    print("\n" + "=" * 70)
    fails = [r for r in RESULTS if not r[2]]
    print(f"E2E RESULT: {len(RESULTS) - len(fails)}/{len(RESULTS)} checks passed")
    for s, n, ok, d in fails:
        print(f"  FAIL {s} :: {n} — {d[:300]}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
