#!/usr/bin/env python3
"""Black-box acceptance tests for the hard-to-scan-device product scope."""

import json
import hashlib
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

REPO = os.environ.get("E2E_REPO_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXE = ".exe" if sys.platform == "win32" else ""
BIN = os.environ.get("AUTOMATESTIG_BIN", f"{REPO}/target/release/automatestig{EXE}")
GUI_BIN = os.environ.get("AUTOMATESTIG_GUI_BIN", f"{REPO}/target/release/automatestig-gui{EXE}")
WORK = os.environ.get("E2E_WORK") or tempfile.mkdtemp(prefix="automatestig-e2e-")
FIX = f"{REPO}/fixtures"
CHECK_PACKS = f"{REPO}/content/check_packs"
ONTAP_ZIP = f"{FIX}/authorized/disa-public-2026-07/U_NetApp_ONTAP_DSC_9-x_V2R4_STIG.zip"
ONTAP_FINDINGS = f"{FIX}/ontap/ontap_evidence_findings.json"
ONTAP_COMPLIANT = f"{FIX}/ontap/ontap_evidence_compliant.json"
ONTAP_MANUAL = {
    "V-246925", "V-246927", "V-246930", "V-246931", "V-246932", "V-246933",
    "V-246938", "V-246939", "V-246940", "V-246944", "V-246945", "V-246946",
    "V-246948", "V-246949",
}
GPOS_ZIP = f"{FIX}/authorized/disa-public-2026-07/U_GPOS_V3R3_SRG.zip"
BSD_FINDINGS = f"{FIX}/bsd/bsd_evidence_findings.json"
BSD_COMPLIANT = f"{FIX}/bsd/bsd_evidence_compliant.json"
ONTAP_TRANSPORT_FAILURE = f"{FIX}/ontap/ontap_evidence_transport_failure.json"
BSD_TRANSPORT_FAILURE = f"{FIX}/bsd/bsd_evidence_transport_failure.json"
BSD_TOTAL = 203
CISCO_ZIP = f"{FIX}/authorized/disa-public-2026-07/U_Cisco_IOS-XE_Router_Y26M04_STIG.zip"
IOS_COMPLIANT = f"{FIX}/network/ios_xe_router_compliant.txt"
IOS_FINDINGS = f"{FIX}/network/ios_xe_router_findings.txt"
IOS_TOTAL = 42


def shipped_vuln_ids(filename):
    path = f"{CHECK_PACKS}/{filename}"
    with open(path, encoding="utf-8") as stream:
        document = json.load(stream)
    checks = document.get("checks")
    if not isinstance(checks, list) or not checks:
        raise RuntimeError(f"shipped check pack has no checks: {path}")
    vuln_ids = [check.get("vuln_id") for check in checks if isinstance(check, dict)]
    if len(vuln_ids) != len(checks) or any(
        not isinstance(vuln_id, str) or not vuln_id for vuln_id in vuln_ids
    ):
        raise RuntimeError(f"shipped check pack has an invalid vulnerability ID: {path}")
    if len(set(vuln_ids)) != len(vuln_ids):
        raise RuntimeError(f"shipped check pack has duplicate vulnerability IDs: {path}")
    return frozenset(vuln_ids)


ONTAP_OPEN = shipped_vuln_ids("netapp_ontap9.json")
BSD_OPEN = shipped_vuln_ids("freebsd_gpos.json")
IOS_OPEN = shipped_vuln_ids("cisco_ios_xe_router_ndm.json")
AUTOMATED_OPEN_SETS = (ONTAP_OPEN, BSD_OPEN, IOS_OPEN)
AUTOMATED_OPEN_UNION = set().union(*AUTOMATED_OPEN_SETS)
if sum(map(len, AUTOMATED_OPEN_SETS)) != len(AUTOMATED_OPEN_UNION):
    raise RuntimeError("shipped check-pack vulnerability IDs are not disjoint")
if len(AUTOMATED_OPEN_UNION) != 54:
    raise RuntimeError(
        f"expected exactly 54 shipped automated rules, found {len(AUTOMATED_OPEN_UNION)}"
    )
ONTAP_AUTOMATED = len(ONTAP_OPEN)
BSD_AUTOMATED = len(BSD_OPEN)
IOS_AUTOMATED = len(IOS_OPEN)

DB = f"{WORK}/data.db"
LIB = f"{WORK}/library"
OUT = f"{WORK}/out"
HOME = f"{WORK}/home"
RESULTS = []


def check(section, name, ok, detail=""):
    RESULTS.append((section, name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {section} :: {name}" + (f" — {detail}" if detail and not ok else ""))


def run_cli(*args, cwd=REPO, expect_ok=True, env_extra=None):
    env = dict(os.environ)
    env.update({"HOME": HOME, "USERPROFILE": HOME})
    env.update(env_extra or {})
    command = [BIN, "--db", DB, "--library", LIB, *args]
    result = subprocess.run(command, capture_output=True, text=True, cwd=cwd, env=env)
    result.combined = result.stdout + result.stderr
    if expect_ok and result.returncode:
        print(f"  command failed: {' '.join(args)}\n  {result.combined[:600]}")
    return result


def norm_status(value):
    return re.sub(r"[^a-z]", "", (value or "").lower())


def parse_ckl(path):
    tree = ET.parse(path)
    output = {}
    for vuln in tree.iter("VULN"):
        attrs = {item.findtext("VULN_ATTRIBUTE"): item.findtext("ATTRIBUTE_DATA") or ""
                 for item in vuln.findall("STIG_DATA")}
        vuln_id = attrs.get("Vuln_Num", "")
        output[vuln_id] = {
            "status": vuln.findtext("STATUS") or "",
            "details": vuln.findtext("FINDING_DETAILS") or "",
            "comments": vuln.findtext("COMMENTS") or "",
            "group_title": attrs.get("Group_Title", ""),
        }
    return output


def status_counts(findings):
    counts = {}
    for finding in findings.values():
        status = norm_status(finding["status"])
        counts[status] = counts.get(status, 0) + 1
    return counts


def snapshot_tree(root):
    snapshot = {}
    if not os.path.isdir(root):
        return snapshot
    for path, directories, files in os.walk(root):
        directories.sort()
        for name in sorted(files):
            full = os.path.join(path, name)
            relative = os.path.relpath(full, root)
            with open(full, "rb") as stream:
                snapshot[relative] = hashlib.sha256(stream.read()).hexdigest()
    return snapshot


def create_hostile_archives():
    root = f"{WORK}/hostile"
    os.makedirs(root, exist_ok=True)
    paths = {
        "no_xccdf": f"{root}/no-xccdf.zip",
        "mixed": f"{root}/mixed.zip",
        "bomb": f"{root}/bomb.zip",
        "collision": f"{root}/collision.zip",
        "malformed": f"{root}/malformed.zip",
        "unsupported": f"{root}/unsupported.txt",
    }
    with zipfile.ZipFile(paths["no_xccdf"], "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", "not a benchmark")
    valid = b'''<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="Atomic_E2E_STIG">
      <title>Atomic E2E STIG</title><version>1</version>
      <Group id="V-900001"><title>Group</title>
        <Rule id="SV-900001" severity="medium"><version>R-1</version><title>Rule</title></Rule>
      </Group></Benchmark>'''
    with zipfile.ZipFile(paths["mixed"], "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("valid-xccdf.xml", valid)
        archive.writestr("invalid-xccdf.xml", b"<Benchmark")
    with zipfile.ZipFile(paths["bomb"], "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bomb-xccdf.xml", b"A" * (16 * 1024 * 1024 + 1))
    with zipfile.ZipFile(paths["collision"], "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("A/one-xccdf.xml", valid)
        archive.writestr("a/ONE-xccdf.xml", valid.replace(b"Atomic_E2E_STIG", b"Other_E2E_STIG"))
    with open(paths["malformed"], "wb") as stream:
        stream.write(b"PK\x03\x04truncated")
    with open(paths["unsupported"], "w", encoding="utf-8") as stream:
        stream.write("unsupported")
    return paths


def hostile_disa_flow(paths):
    section = "bounded-disa-import"
    baseline = snapshot_tree(LIB)
    cases = [
        ("ZIP without XCCDF is rejected", paths["no_xccdf"]),
        ("mixed valid/invalid batch is rejected", paths["mixed"]),
        ("decompression bomb is rejected", paths["bomb"]),
        ("case-colliding member paths are rejected", paths["collision"]),
        ("malformed ZIP is rejected", paths["malformed"]),
        ("unsupported extension is rejected", paths["unsupported"]),
    ]
    for name, path in cases:
        result = run_cli("disa-import", "--input", path, expect_ok=False)
        check(section, name, result.returncode != 0, result.combined[:300])
        check(section, f"{name} leaves library unchanged", snapshot_tree(LIB) == baseline)


def cli_basics():
    section = "cli-basics"
    check(section, "version", "0.3.0" in run_cli("--version").stdout)
    check(section, "library init", run_cli("library", "init").returncode == 0)
    check(section, "empty library", run_cli("library", "list").returncode == 0)
    empty = run_cli("evaluate", "--stig", "missing", expect_ok=False)
    check(section, "evidence is mandatory", empty.returncode != 0)


def evaluate_ontap():
    section = "ontap-evidence"
    result = run_cli("disa-import", "--input", ONTAP_ZIP)
    check(section, "import ONTAP V2R4", result.returncode == 0, result.combined[:300])

    legacy = f"{WORK}/legacy-evidence.txt"
    with open(legacy, "w", encoding="utf-8") as stream:
        stream.write("### automatestig:hostname legacy\n### automatestig:command hostname\nlegacy\n")
    legacy_result = run_cli(
        "evaluate", "--stig", "NetApp_ONTAP_DSC_9-x_STIG",
        "--evidence", legacy, "--output", f"{OUT}/legacy.ckl",
        expect_ok=False,
    )
    check(section, "legacy marker evidence is rejected by default", legacy_result.returncode != 0)

    with open(ONTAP_COMPLIANT, encoding="utf-8") as stream:
        stale_document = json.load(stream)
    stale_document["plan_sha256"] = "0" * 64
    stale = f"{WORK}/stale-plan-evidence.json"
    with open(stale, "w", encoding="utf-8") as stream:
        json.dump(stale_document, stream)
    stale_result = run_cli(
        "evaluate", "--stig", "NetApp_ONTAP_DSC_9-x_STIG",
        "--evidence", stale, "--output", f"{OUT}/stale.ckl",
        expect_ok=False,
    )
    check(section, "stale plan-bound evidence is rejected", stale_result.returncode != 0)

    outputs = {}
    for label, evidence in (("findings", ONTAP_FINDINGS), ("compliant", ONTAP_COMPLIANT)):
        dest = f"{OUT}/ontap_{label}.ckl"
        result = run_cli("evaluate", "--stig", "NetApp_ONTAP_DSC_9-x_STIG",
                         "--evidence", evidence,
                         "--output", dest, "--format", "ckl")
        check(section, f"evaluate {label}", result.returncode == 0 and os.path.exists(dest), result.combined[:300])
        outputs[label] = dest

    findings = parse_ckl(outputs["findings"])
    opens = {v for v, f in findings.items() if norm_status(f["status"]) == "open"}
    check(section, "findings fixture opens every shipped automated rule", opens == ONTAP_OPEN,
          f"extra={sorted(opens - ONTAP_OPEN)} missing={sorted(ONTAP_OPEN - opens)}")
    manual = {v for v, f in findings.items() if norm_status(f["status"]) == "notreviewed"}
    check(section, "manual findings remain unreviewed", manual == ONTAP_MANUAL)
    counts = status_counts(parse_ckl(outputs["compliant"]))
    check(section, "compliant oracle", counts.get("notafinding") == ONTAP_AUTOMATED
          and counts.get("notreviewed") == len(ONTAP_MANUAL)
          and not counts.get("open"), str(counts))

    partial = f"{OUT}/ontap_transport_failure.ckl"
    sentinel = b"existing checklist must remain untouched"
    with open(partial, "wb") as stream:
        stream.write(sentinel)
    result = run_cli("evaluate", "--stig", "NetApp_ONTAP_DSC_9-x_STIG",
                     "--evidence", ONTAP_TRANSPORT_FAILURE, "--output", partial,
                     "--format", "ckl", expect_ok=False)
    with open(partial, "rb") as stream:
        after = stream.read()
    check(section, "transport failures exit nonzero without writing a checklist",
          result.returncode != 0 and after == sentinel
          and "no checklist was written or saved" in result.combined,
          result.combined[:300])
    with sqlite3.connect(DB) as database:
        event_types = [row[0] for row in database.execute(
            "SELECT event_type FROM audit_log ORDER BY id"
        )]
        saved_partial = database.execute(
            "SELECT COUNT(*) FROM checklists WHERE asset_hostname = ?",
            ("ontap-transport-failure",),
        ).fetchone()[0]
    check(section, "failed CLI evaluation is logged only as incomplete",
          event_types[-1:] == ["evaluation.incomplete"]
          and event_types.count("evaluation.completed") == 2
          and saved_partial == 0, str(event_types))

    with sqlite3.connect(DB) as database:
        saved_json = database.execute(
            "SELECT data_json FROM checklists WHERE asset_hostname = ? LIMIT 1",
            ("ontap-findings-01",),
        ).fetchone()[0]
    incomplete_json = json.loads(saved_json)
    incomplete_json["evaluation_provenance"]["collection_complete"] = False
    incomplete_json["evaluation_provenance"]["collection_errors"] = ["injected timeout"]
    incomplete_path = f"{WORK}/incomplete-saved-checklist.json"
    with open(incomplete_path, "w", encoding="utf-8") as stream:
        json.dump(incomplete_json, stream)
    stigman_output = f"{OUT}/incomplete-stigman.json"
    with open(stigman_output, "wb") as stream:
        stream.write(sentinel)
    export_result = run_cli(
        "export", "--input", incomplete_path, "--output", stigman_output,
        "--format", "stig-manager", expect_ok=False,
    )
    with open(stigman_output, "rb") as stream:
        stigman_after = stream.read()
    check(section, "CLI external export rejects incomplete durable provenance",
          export_result.returncode != 0 and stigman_after == sentinel,
          export_result.combined[:300])
    return outputs


def evaluate_bsd():
    section = "bsd-evidence"
    check(section, "import GPOS", run_cli("disa-import", "--input", GPOS_ZIP).returncode == 0)
    for label, evidence in (("findings", BSD_FINDINGS), ("compliant", BSD_COMPLIANT)):
        dest = f"{OUT}/bsd_{label}.ckl"
        result = run_cli("evaluate", "--stig", "General_Purpose_Operating_System",
                         "--evidence", evidence,
                         "--output", dest, "--format", "ckl")
        check(section, f"evaluate {label}", result.returncode == 0, result.combined[:300])
        findings = parse_ckl(dest)
        if label == "findings":
            opens = {v for v, f in findings.items() if norm_status(f["status"]) == "open"}
            check(section, "findings fixture opens every shipped automated rule",
                  opens == BSD_OPEN,
                  f"extra={sorted(opens - BSD_OPEN)} missing={sorted(BSD_OPEN - opens)}")
            counts = status_counts(findings)
            check(section, "unproved FreeBSD rules remain unreviewed",
                  counts.get("notreviewed") == BSD_TOTAL - BSD_AUTOMATED,
                  str(counts))
        else:
            counts = status_counts(findings)
            check(section, "compliant oracle", counts.get("notafinding") == BSD_AUTOMATED
                  and counts.get("notreviewed") == BSD_TOTAL - BSD_AUTOMATED
                  and not counts.get("open"), str(counts))

    partial = f"{OUT}/bsd_transport_failure.ckl"
    result = run_cli("evaluate", "--stig", "General_Purpose_Operating_System",
                     "--evidence", BSD_TRANSPORT_FAILURE, "--output", partial,
                     "--format", "ckl", expect_ok=False)
    check(section, "transport failures exit nonzero without writing a checklist",
          result.returncode != 0 and not os.path.exists(partial)
          and "no checklist was written or saved" in result.combined,
          result.combined[:300])


def evaluate_network():
    section = "network-config"
    check(section, "import Cisco IOS-XE", run_cli("disa-import", "--input", CISCO_ZIP).returncode == 0)
    check(section, "DISA import does not create prose-derived executable checks",
          not os.path.exists(f"{LIB}/auto_check_packs/Cisco_IOS-XE_Router_NDM_STIG.json"))

    policy_key = f"{WORK}/offline-signing/organization-policy.key"
    generated = run_cli("generate-signing-key", "--output", policy_key)
    policy_trust = f"{HOME}/.automatestig/organization_policy_keys"
    os.makedirs(policy_trust, mode=0o700, exist_ok=True)
    if generated.returncode == 0:
        shutil.copy(
            f"{WORK}/offline-signing/organization-policy.pub",
            f"{policy_trust}/e2e-organization-policy.pub",
        )
    check(
        section,
        "dedicated offline organization-policy key is explicitly provisioned",
        generated.returncode == 0 and os.path.exists(policy_key),
        generated.combined[:300],
    )

    compliant_policy = None
    compliant_policy_signature = None
    for label, config, hostname in (
        ("findings", IOS_FINDINGS, "rtr-findings-01"),
        ("compliant", IOS_COMPLIANT, "rtr-compliant-01"),
    ):
        policy = f"{WORK}/ios-{label}-policy.json"
        signature = f"{WORK}/ios-{label}-policy.sig"
        with open(policy, "w", encoding="utf-8") as stream:
            json.dump(
                {
                    "schema": "automatestig-organization-policy/v1",
                    "policy_id": f"e2e-{label}",
                    "policy_version": "1",
                    "stig_id": "Cisco_IOS-XE_Router_NDM_STIG",
                    "stig_release": "V3R7",
                    "asset_hostname": hostname,
                    "effective_from": "2026-01-01T00:00:00Z",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "rules": {
                        "V-215807": {"max_concurrent_management_sessions": 2},
                        "V-215836": {"minimum_logging_buffer_bytes": 4096000},
                        "V-215838": {
                            "approved_authoritative_ntp_sources": [
                                "10.10.1.10",
                                "10.10.1.11",
                            ]
                        },
                    },
                },
                stream,
                separators=(",", ":"),
            )
        signed = run_cli(
            "sign-organization-policy",
            "--policy", policy,
            "--signing-key", policy_key,
            "--output", signature,
        )
        check(
            section,
            f"sign {label} organization policy offline",
            signed.returncode == 0 and os.path.getsize(signature) == 64,
            signed.combined[:300],
        )
        dest = f"{OUT}/ios_{label}.ckl"
        result = run_cli("evaluate", "--stig", "Cisco_IOS-XE_Router_NDM_STIG",
                         "--config", config, "--host", hostname,
                         "--organization-policy", policy,
                         "--organization-policy-signature", signature,
                         "--output", dest, "--format", "ckl")
        check(section, f"evaluate {label}", result.returncode == 0, result.combined[:300])
        findings = parse_ckl(dest)
        if label == "findings":
            opens = {v for v, f in findings.items() if norm_status(f["status"]) == "open"}
            check(section, "findings fixture opens every shipped automated rule",
                  opens == IOS_OPEN,
                  f"extra={sorted(opens - IOS_OPEN)} missing={sorted(IOS_OPEN - opens)}")
        else:
            counts = status_counts(findings)
            check(section, "compliant oracle", len(findings) == IOS_TOTAL
                  and counts.get("notafinding") == IOS_AUTOMATED
                  and counts.get("notreviewed") == IOS_TOTAL - IOS_AUTOMATED
                  and not counts.get("open"), str(counts))

        if label == "compliant":
            compliant_policy = policy
            compliant_policy_signature = signature
            mutated = json.loads(open(policy, encoding="utf-8").read())
            mutated["rules"]["V-215807"]["max_concurrent_management_sessions"] = 3
            tampered_policy = f"{WORK}/ios-tampered-policy.json"
            with open(tampered_policy, "w", encoding="utf-8") as stream:
                json.dump(mutated, stream, separators=(",", ":"))
            tampered_dest = f"{OUT}/ios-tampered-policy.ckl"
            tampered = run_cli(
                "evaluate",
                "--stig", "Cisco_IOS-XE_Router_NDM_STIG",
                "--config", config,
                "--host", hostname,
                "--organization-policy", tampered_policy,
                "--organization-policy-signature", signature,
                "--output", tampered_dest,
                "--format", "ckl",
                expect_ok=False,
            )
            check(
                section,
                "policy mutation is rejected before checklist output",
                tampered.returncode != 0 and not os.path.exists(tampered_dest)
                and "signature" in tampered.combined.lower(),
                tampered.combined[:300],
            )

    truncated = f"{WORK}/ios-truncated.cfg"
    with open(truncated, "w", encoding="utf-8") as stream:
        stream.write("version 17.9\nhostname rtr-compliant-01\ninterface Gi1\nend\n")
    destination = f"{OUT}/ios-truncated.ckl"
    result = run_cli("evaluate", "--stig", "Cisco_IOS-XE_Router_NDM_STIG",
                     "--config", truncated, "--host", "rtr-compliant-01",
                     "--organization-policy", compliant_policy,
                     "--organization-policy-signature", compliant_policy_signature,
                     "--output", destination, "--format", "ckl", expect_ok=False)
    check(section, "truncated config cannot produce a checklist or absence pass",
          result.returncode != 0 and not os.path.exists(destination)
          and "line/context structure" in result.combined,
          result.combined[:300])


def format_roundtrip(source):
    section = "format-roundtrip"
    cklb, native, final = f"{OUT}/roundtrip.cklb", f"{OUT}/roundtrip.json", f"{OUT}/roundtrip.ckl"
    results = [
        run_cli("convert", "--input", source, "--output", cklb, "--format", "cklb"),
        run_cli("convert", "--input", cklb, "--output", native, "--format", "json"),
        run_cli("convert", "--input", native, "--output", final, "--format", "ckl"),
    ]
    check(section, "CKL to CKLB to JSON to CKL", all(r.returncode == 0 for r in results))
    before, after = parse_ckl(source), parse_ckl(final)
    check(section, "statuses preserved", {v: norm_status(f["status"]) for v, f in before.items()}
          == {v: norm_status(f["status"]) for v, f in after.items()})
    check(section, "group titles preserved", {v: f["group_title"] for v, f in before.items()}
          == {v: f["group_title"] for v, f in after.items()})


def stigpack_flow():
    section = "signed-stigpack"
    source = f"{WORK}/pack-source"
    os.makedirs(f"{source}/benchmarks", exist_ok=True)
    os.makedirs(f"{source}/auto_check_packs", exist_ok=True)
    shutil.copy(f"{LIB}/benchmarks/NetApp_ONTAP_DSC_9-x_STIG.json", f"{source}/benchmarks/")
    reviewed = f"{LIB}/reviewed_check_packs"
    if os.path.isdir(reviewed):
        for name in os.listdir(reviewed):
            shutil.copy(os.path.join(reviewed, name), f"{source}/auto_check_packs/{name}")
    signing_key = f"{WORK}/offline-signing/content.key"
    generated = run_cli("generate-signing-key", "--output", signing_key)
    trust_dir = f"{HOME}/.automatestig/trusted_keys"
    os.makedirs(trust_dir, mode=0o700, exist_ok=True)
    shutil.copy(f"{WORK}/offline-signing/content.pub", f"{trust_dir}/e2e-content.pub")
    check(section, "offline key generation is explicit",
          generated.returncode == 0 and os.path.exists(signing_key), generated.combined[:300])
    pack = f"{WORK}/content.stigpack"
    built = run_cli("build-pack", "--id", "e2e-content", "--name", "E2E Content",
                    "--version", "1.0.0", "--source", source, "--output", pack,
                    "--signing-key", signing_key)
    check(section, "builder requires the explicit offline signing key",
          built.returncode == 0 and os.path.exists(pack), built.combined[:300])
    verified = run_cli("verify", "--pack", pack)
    check(section, "trusted verification succeeds", verified.returncode == 0 and "verified" in verified.combined.lower())
    imported = run_cli("import", "--pack", pack)
    check(section, "default trusted import succeeds", imported.returncode == 0, imported.combined[:300])
    data = bytearray(open(pack, "rb").read())
    data[len(data) // 2] ^= 0xFF
    tampered = f"{WORK}/tampered.stigpack"
    open(tampered, "wb").write(data)
    check(section, "tampering is rejected", run_cli("verify", "--pack", tampered, expect_ok=False).returncode != 0)


def coverage_flow():
    section = "coverage"
    manifest = f"{REPO}/content/coverage/current-checkpacks/netapp_ontap9.current.json"
    result = run_cli("coverage", "validate", "--manifest", manifest)
    check(section, "supported-target manifest validates", result.returncode == 0, result.combined[:300])


GUI_PORT = 18321
TOKEN = "e2e-test-token-0123456789abcdef"


def gui_request(path, method="GET", token=True):
    request = urllib.request.Request(f"http://127.0.0.1:{GUI_PORT}{path}", method=method)
    if token:
        request.add_header("X-Auth-Token", TOKEN)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except urllib.error.URLError:
        return 0, b""


def scanner_gui_flow():
    """Exercise only the scanner-first GUI/API and read-only handoff verifier.

    Legacy GUI import, local checklist, asset, finding, and portfolio mutations
    are intentionally not acceptance targets; STIG Manager owns those product
    surfaces. Their retired routes are checked separately below.
    """
    section = "scanner-gui"
    data_dir = f"{WORK}/scanner-gui-data"
    artifacts_dir = f"{WORK}/scanner-scenario-artifacts"
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(artifacts_dir, exist_ok=True)
    env = dict(os.environ)
    env.update({
        "PORT": str(GUI_PORT),
        "AUTOMATESTIG_AUTH_TOKEN": TOKEN,
        "AUTOMATESTIG_DATA_DIR": data_dir,
    })
    log_path = f"{data_dir}/gui.log"
    log = open(log_path, "w", encoding="utf-8")
    process = subprocess.Popen(
        [GUI_BIN], cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT
    )
    try:
        for _ in range(60):
            if gui_request("/api/v1/status")[0] == 200:
                break
            time.sleep(0.5)
        else:
            log.flush()
            detail = open(log_path, encoding="utf-8").read()[:800]
            check(section, "scanner API starts", False, detail)
            return

        check(
            section,
            "API requires authentication",
            gui_request("/api/v1/runs", token=False)[0] in (401, 403),
        )
        harness = subprocess.run(
            [
                sys.executable,
                f"{REPO}/scripts/scanner_scenarios/run_localhost.py",
                "--base-url",
                f"http://127.0.0.1:{GUI_PORT}",
                "--auth-token",
                TOKEN,
                "--artifacts-dir",
                artifacts_dir,
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=180,
        )
        check(
            section,
            "scanner-first localhost scenarios pass",
            harness.returncode == 0,
            (harness.stdout + harness.stderr)[-1200:],
        )

        summary_path = f"{artifacts_dir}/summary.json"
        summary = (
            json.load(open(summary_path, encoding="utf-8"))
            if os.path.exists(summary_path)
            else {}
        )
        check(
            section,
            "complete and incomplete scanner outcomes are exercised",
            len(summary.get("complete_handoff_runs") or []) == 2
            and bool(summary.get("incomplete_fail_closed_run")),
            str(summary)[:500],
        )

        handoffs = sorted(
            os.path.join(artifacts_dir, name)
            for name in os.listdir(artifacts_dir)
            if name.endswith(".handoff.zip")
        )
        verifier_results = [
            subprocess.run(
                [BIN, "scanner", "verify-handoff", handoff],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=60,
            )
            for handoff in handoffs
        ]
        check(
            section,
            "every selected-run handoff passes the offline verifier",
            len(handoffs) == 2
            and all(result.returncode == 0 for result in verifier_results),
            "\n".join(
                (result.stdout + result.stderr)[-500:]
                for result in verifier_results
            ),
        )

        for path in (
            "/api/assets",
            "/api/stigman/push/retired-checklist",
            "/api/evaluate/with-evidence",
            "/api/library/import-disa",
        ):
            status, body = gui_request(path, method="POST")
            check(
                section,
                f"retired manager-duplicate mutation returns 410: {path}",
                status == 410,
                body[:300].decode("utf-8", "replace"),
            )
    finally:
        process.kill()
        process.wait()
        log.close()


def main():
    for binary in (BIN, GUI_BIN):
        if not os.path.exists(binary):
            sys.exit(f"binary not found: {binary}; run cargo build --release")
    if os.path.exists(WORK):
        shutil.rmtree(WORK)
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(HOME, exist_ok=True)

    cli_basics()
    hostile = create_hostile_archives()
    hostile_disa_flow(hostile)
    ontap = evaluate_ontap()
    evaluate_bsd()
    evaluate_network()
    format_roundtrip(ontap["findings"])
    stigpack_flow()
    coverage_flow()
    scanner_gui_flow()

    failures = [result for result in RESULTS if not result[2]]
    print(f"\nE2E RESULT: {len(RESULTS) - len(failures)}/{len(RESULTS)} checks passed")
    for section, name, _, detail in failures:
        print(f"  FAIL {section} :: {name} — {detail[:300]}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
