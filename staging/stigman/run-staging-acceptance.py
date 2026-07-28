#!/usr/bin/env python3
"""STIG Manager staging acceptance: prove the full AutomateSTIG -> STIG Manager
round-trip against a real containerized STIG Manager + Keycloak.

Flow:
  1. Wait for Keycloak (demo realm) and the STIG Manager API.
  2. Provision a confidential OAuth2 client with a service account and the
     stig-manager client scopes (this is the client AutomateSTIG will use).
  3. Import the Cisco IOS-XE NDM benchmark into STIG Manager; create a collection.
  4. Start automatestig-gui, import the same benchmark, evaluate running-config evidence.
  5. Configure AutomateSTIG's STIG-Manager integration (client credentials),
     test the connection, and push the checklist.
  6. Independently verify in STIG Manager: asset exists, reviews match the
     checklist finding-for-finding, and the CKL STIG Manager serves back
     round-trips the same statuses (= what reviewers export to Vulnerator).
  7. Run scripts/run-live-external-acceptance.py against the rig.

Requires: docker compose rig already up (see docker-compose.yml), release
binaries built. Exits non-zero on any failure.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

REPO = os.environ.get(
    "E2E_REPO_ROOT",
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
EXE = ".exe" if sys.platform == "win32" else ""
GUI_BIN = os.environ.get("AUTOMATESTIG_GUI_BIN", f"{REPO}/target/release/automatestig-gui{EXE}")
CISCO_ZIP = f"{REPO}/fixtures/authorized/disa-public-2026-07/U_Cisco_IOS-XE_Router_Y26M04_STIG.zip"
CISCO_CONFIG = f"{REPO}/fixtures/network/ios_xe_router_findings.txt"
CISCO_HOSTNAME = "rtr-findings-01"

KC = os.environ.get("STAGING_AUTH_URL", "http://localhost:8080")
SM = os.environ.get("STAGING_API_URL", "http://localhost:54000/api")
KC_ADMIN_USER, KC_ADMIN_PASS = "admin", "Pa55w0rd"
CLIENT_ID = "automatestig-staging"
CLIENT_SECRET = "automatestig-staging-secret-0001"

AS_PORT = 18441
AS_TOKEN = "staging-acceptance-token-0123456789"

RESULTS = []
EVIDENCE_OUTPUT = None
EVIDENCE_ENVIRONMENT = "local containerized staging"
EVIDENCE_DETAILS = {}


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))


def file_sha256(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def product_version(body):
    try:
        value = json.loads(body)
    except Exception:
        return "unknown"
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if key.lower() in {"version", "apiversion", "appversion"} and isinstance(child, (str, int, float)):
                    return str(child)
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)
    return "unknown"


def req(url, method="GET", data=None, headers=None, form=None, timeout=60):
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers = {**(headers or {}), "Content-Type": "application/x-www-form-urlencoded"}
    elif isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
        headers = {**(headers or {}), "Content-Type": "application/json"}
    r = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)


def wait_for(name, url, ok_statuses=(200,), tries=120, sleep=2):
    for _ in range(tries):
        st, _ = req(url, timeout=10)
        if st in ok_statuses:
            print(f"  {name} is up ({url})")
            return True
    # fallthrough retry loop sleeps
        time.sleep(sleep)
    sys.exit(f"{name} did not come up at {url}")


# --- Keycloak provisioning -------------------------------------------------

def kc_admin_token():
    st, body = req(f"{KC}/realms/master/protocol/openid-connect/token",
                   method="POST",
                   form={"grant_type": "password", "client_id": "admin-cli",
                         "username": KC_ADMIN_USER, "password": KC_ADMIN_PASS})
    if st != 200:
        sys.exit(f"Keycloak admin token failed ({st}): {body[:300]}")
    return json.loads(body)["access_token"]


def kc(path, admin_token, method="GET", data=None):
    return req(f"{KC}/admin/realms/stigman{path}", method=method, data=data,
               headers={"Authorization": f"Bearer {admin_token}"})


def provision_client():
    tok = kc_admin_token()

    st, body = kc(f"/clients?clientId={CLIENT_ID}", tok)
    existing = json.loads(body) if st == 200 else []
    if existing:
        cid = existing[0]["id"]
        print(f"  client {CLIENT_ID} already provisioned")
    else:
        st, body = kc("/clients", tok, method="POST", data={
            "clientId": CLIENT_ID,
            "protocol": "openid-connect",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "secret": CLIENT_SECRET,
        })
        if st not in (201, 409):
            sys.exit(f"client create failed ({st}): {body[:300]}")
        st, body = kc(f"/clients?clientId={CLIENT_ID}", tok)
        cid = json.loads(body)[0]["id"]

    # Attach every stig-manager client scope as a default scope.
    st, body = kc("/client-scopes", tok)
    scopes = [s for s in json.loads(body) if s["name"].startswith("stig-manager")]
    for s in scopes:
        kc(f"/clients/{cid}/default-client-scopes/{s['id']}", tok, method="PUT")
    print(f"  attached {len(scopes)} stig-manager scopes: {[s['name'] for s in scopes]}")

    # Give the service account the realm roles STIG Manager recognizes.
    st, body = kc(f"/clients/{cid}/service-account-user", tok)
    sa_user = json.loads(body)["id"]
    st, body = kc("/roles", tok)
    wanted = [r for r in json.loads(body) if r["name"] in ("admin", "create_collection", "user")]
    kc(f"/users/{sa_user}/role-mappings/realm", tok, method="POST", data=wanted)
    print(f"  service account roles: {[r['name'] for r in wanted]}")


def sm_token():
    st, body = req(f"{KC}/realms/stigman/protocol/openid-connect/token",
                   method="POST",
                   form={"grant_type": "client_credentials",
                         "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})
    if st != 200:
        sys.exit(f"client_credentials token failed ({st}): {body[:300]}")
    return json.loads(body)["access_token"]


def sm(path, token, method="GET", data=None):
    return req(f"{SM}{path}", method=method, data=data,
               headers={"Authorization": f"Bearer {token}"})


# --- STIG Manager provisioning ---------------------------------------------

def import_benchmark(token):
    with zipfile.ZipFile(CISCO_ZIP) as z:
        names = [n for n in z.namelist()
                 if n.lower().endswith(".xml") and "xccdf" in n.lower()
                 and "_ndm_" in n.lower()]
        if len(names) != 1:
            sys.exit(f"expected one Cisco NDM XCCDF member, found {len(names)}")
        xccdf = z.read(names[0])

    boundary = "----automatestigstaging"
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="importFile"; filename="benchmark-xccdf.xml"\r\n'
            f"Content-Type: text/xml\r\n\r\n").encode() + xccdf + f"\r\n--{boundary}--\r\n".encode()
    st, resp = req(f"{SM}/stigs?elevate=true&clobber=true", method="POST", data=body,
                   headers={"Authorization": f"Bearer {token}",
                            "Content-Type": f"multipart/form-data; boundary={boundary}"})
    check("STIG Manager accepts DISA XCCDF import", st == 200, f"{st} {resp[:300]}")
    st, resp = sm("/stigs", token)
    benches = json.loads(resp) if st == 200 else []
    bid = benches[0]["benchmarkId"] if benches else None
    check("benchmark visible in STIG Manager", bool(bid), resp[:200])
    return bid


def create_collection(token):
    st, resp = sm("/user", token)
    my_id = json.loads(resp).get("userId") if st == 200 else None
    name = f"AutomateSTIG Staging {int(time.time())}"
    st, resp = sm("/collections", token, method="POST",
                  data={"name": name, "description": "acceptance rig",
                        "settings": {"fields": {"detail": {"enabled": "always", "required": "optional"},
                                                 "comment": {"enabled": "always", "required": "optional"}},
                                      "status": {"canAccept": True, "resetCriteria": "result", "minAcceptGrant": 3},
                                      "history": {"maxReviews": 5}},
                        "metadata": {}, "grants": [{"userId": my_id, "roleId": 4}]})
    ok = st in (200, 201)
    check("collection created", ok, f"{st} {resp[:300]}")
    return json.loads(resp)["collectionId"] if ok else None


# --- AutomateSTIG side -------------------------------------------------------

def as_req(path, method="GET", data=None):
    return req(f"http://127.0.0.1:{AS_PORT}{path}", method=method, data=data,
               headers={"X-Auth-Token": AS_TOKEN})


def as_multipart(path, fields, files):
    cmd = ["curl", "-s", "-H", f"X-Auth-Token: {AS_TOKEN}",
           f"http://127.0.0.1:{AS_PORT}{path}"]
    for k, v in fields.items():
        cmd += ["-F", f"{k}={v}"]
    for k, fp in files.items():
        cmd += ["-F", f"{k}=@{fp}"]
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def unwrap(body):
    try:
        j = json.loads(body)
    except Exception:
        return None
    return j.get("data") if isinstance(j, dict) and "data" in j else j


def start_automatestig(home):
    env = dict(os.environ)
    env.update({"HOME": home, "USERPROFILE": home, "PORT": str(AS_PORT),
                "AUTOMATESTIG_AUTH_TOKEN": AS_TOKEN})
    env.pop("AUTOMATESTIG_DEMO", None)
    os.makedirs(home, exist_ok=True)
    proc = subprocess.Popen([GUI_BIN], env=env, cwd=REPO,
                            stdout=open(f"{home}/gui.log", "w"), stderr=subprocess.STDOUT)
    for _ in range(60):
        st, _ = as_req("/api/status")
        if st == 200:
            return proc
        time.sleep(0.5)
    proc.kill()
    sys.exit("automatestig-gui failed to start: " + open(f"{home}/gui.log").read()[:800])


def main():
    global EVIDENCE_DETAILS
    for f in (GUI_BIN, CISCO_ZIP, CISCO_CONFIG):
        if not os.path.exists(f):
            sys.exit(f"missing prerequisite: {f}")

    print("== waiting for rig ==")
    wait_for("Keycloak", f"{KC}/realms/stigman")
    wait_for("STIG Manager API", f"{SM}/op/definition", ok_statuses=(200, 401))
    definition_status, definition_body = req(f"{SM}/op/definition")
    EVIDENCE_DETAILS["stig_manager_version"] = (
        product_version(definition_body) if definition_status == 200 else "unknown"
    )

    print("== provisioning Keycloak client ==")
    provision_client()
    token = sm_token()
    st, resp = sm("/user", token)
    check("service account recognized by STIG Manager", st == 200, f"{st} {resp[:200]}")

    print("== provisioning STIG Manager ==")
    benchmark_id = import_benchmark(token)
    collection_id = create_collection(token)
    check("collection id obtained", bool(collection_id), str(collection_id))
    if not (benchmark_id and collection_id):
        report()

    print("== driving AutomateSTIG ==")
    home = tempfile.mkdtemp(prefix="automatestig-staging-")
    proc = start_automatestig(home)
    try:
        out = as_multipart("/api/library/import-disa", {}, {"file": CISCO_ZIP})
        check("AutomateSTIG imports DISA zip", '"success":true' in out.replace(" ", ""), out[:200])
        st, body = as_req("/api/library/benchmarks")
        benchmarks = unwrap(body) or []
        stig_id = next((item.get("id") for item in benchmarks
                        if item.get("id") == "Cisco_IOS-XE_Router_NDM_STIG"), None)

        out = as_multipart("/api/evaluate/with-evidence",
                           {"stig_id": stig_id or "", "hostname": CISCO_HOSTNAME,
                            "platform": "cisco_ios", "input_type": "config"},
                           {"evidence": CISCO_CONFIG})
        cid = (unwrap(out) or {}).get("checklist_id") or (unwrap(out) or {}).get("id")
        check("AutomateSTIG evaluates Cisco running config", bool(cid), out[:300])

        st, body = as_req("/api/stigman/config", method="POST", data={
            "api_url": SM,
            "token_url": f"{KC}/realms/stigman/protocol/openid-connect/token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "default_collection_id": str(collection_id),
            "verify_tls": False,
        })
        check("STIG-Manager integration configured", st == 200 and '"success":true' in body.replace(" ", ""), body[:200])

        st, body = as_req("/api/stigman/test", method="POST")
        check("integration test-connection succeeds", st == 200 and '"success":true' in body.replace(" ", ""), body[:300])

        st, body = as_req(f"/api/stigman/push/{cid}", method="POST",
                          data={"collection_id": str(collection_id)})
        check("checklist pushed to STIG Manager", st == 200 and '"success":true' in body.replace(" ", ""), body[:400])

        # Idempotency: the routine re-push of the same host must reuse the
        # existing asset, not fail on a duplicate.
        st, body = as_req(f"/api/stigman/push/{cid}", method="POST",
                          data={"collection_id": str(collection_id)})
        check("re-pushing the same checklist succeeds (idempotent asset handling)",
              st == 200 and '"success":true' in body.replace(" ", ""), body[:400])

        # Source of truth for comparison: the checklist as AutomateSTIG stores it.
        st, body = as_req(f"/api/checklists/{cid}")
        cl = unwrap(body) or {}
        findings = cl.get("findings", [])
        expected = {}
        for f in findings:
            stv = f.get("status")
            if isinstance(stv, dict):
                stv = next(iter(stv))
            rule_id = f.get("rule_id")
            if not isinstance(rule_id, str) or not rule_id:
                check("source checklist has complete Rule IDs", False, str(rule_id))
                continue
            if rule_id in expected:
                check("source checklist has unique Rule IDs", False, rule_id)
                continue
            expected[rule_id] = re.sub(r"[^a-z]", "", str(stv).lower())
        check("source checklist contains findings", bool(expected), f"{len(expected)} findings")
    finally:
        proc.kill()
        proc.wait()
        shutil.rmtree(home, ignore_errors=True)

    print("== verifying in STIG Manager ==")
    st, resp = sm(f"/assets?collectionId={collection_id}&benchmarkId={benchmark_id}", token)
    assets = json.loads(resp) if st == 200 else []
    check("asset created in collection", len(assets) == 1 and assets[0]["name"] == CISCO_HOSTNAME,
          resp[:300])
    if not assets:
        report()
    asset_id = assets[0]["assetId"]

    st, resp = sm(f"/collections/{collection_id}/reviews?assetId={asset_id}&rules=default-mapped", token)
    if st != 200:
        st, resp = sm(f"/collections/{collection_id}/reviews?assetId={asset_id}", token)
    reviews = json.loads(resp) if st == 200 else []
    tostatus = {"pass": "notafinding", "fail": "open",
                "notapplicable": "notapplicable", "notchecked": "notreviewed"}
    observed = {}
    invalid_reviews = []
    for r in reviews:
        rule_id = r.get("ruleId")
        got = tostatus.get(r.get("result"))
        if not isinstance(rule_id, str) or not rule_id or got is None or rule_id in observed:
            invalid_reviews.append((rule_id, r.get("result")))
            continue
        observed[rule_id] = got
    missing_reviews = sorted(set(expected) - set(observed))
    extra_reviews = sorted(set(observed) - set(expected))
    mismatch = [
        (rule_id, observed[rule_id], expected[rule_id])
        for rule_id in sorted(set(expected) & set(observed))
        if observed[rule_id] != expected[rule_id]
    ]
    exact_reviews = (
        not invalid_reviews
        and not missing_reviews
        and not extra_reviews
        and len(reviews) == len(expected)
    )
    check(
        "STIG Manager contains the exact source Rule-ID set once",
        exact_reviews,
        f"invalid={invalid_reviews[:5]} missing={missing_reviews[:5]} extra={extra_reviews[:5]}",
    )
    check("every review result matches the source checklist", not mismatch, str(mismatch[:5]))
    print(f"  reviews in STIG Manager: {len(reviews)}; source findings: {len(expected)}")
    EVIDENCE_DETAILS.update({
        "review_count": len(reviews),
        "source_finding_count": len(expected),
        "rule_set_sha256": hashlib.sha256(
            json.dumps(sorted(expected), separators=(",", ":")).encode()
        ).hexdigest(),
        "benchmark_id": benchmark_id,
    })

    # The reviewer-facing round trip: the CKL STIG Manager serves back.
    st, resp = sm("/stigs", token)
    rev = (json.loads(resp)[0].get("lastRevisionStr") or "latest") if st == 200 else "latest"
    st, ckl_body = req(
        f"{SM}/assets/{asset_id}/checklists/{benchmark_id}/{rev}?format=ckl",
        headers={"Authorization": f"Bearer {token}"})
    if st == 200 and "<CHECKLIST" in ckl_body:
        by_rule = {}
        root = ET.fromstring(ckl_body)
        for vuln in root.iter("VULN"):
            attrs = {sd.findtext("VULN_ATTRIBUTE"): sd.findtext("ATTRIBUTE_DATA") or ""
                     for sd in vuln.findall("STIG_DATA")}
            rule_id = attrs.get("Rule_ID", "")
            if not rule_id or rule_id in by_rule:
                by_rule[rule_id] = "__duplicate_or_missing__"
                continue
            by_rule[rule_id] = re.sub(
                r"[^a-z]", "", (vuln.findtext("STATUS") or "").lower())
        missing_ckl = sorted(set(expected) - set(by_rule))
        extra_ckl = sorted(set(by_rule) - set(expected))
        bad = [
            (rid, by_rule[rid], expected[rid])
            for rid in sorted(set(expected) & set(by_rule))
            if by_rule[rid] != expected[rid]
        ]
        check(
            "CKL exported from STIG Manager preserves the exact Rule-ID set and statuses",
            not missing_ckl and not extra_ckl and not bad and len(by_rule) == len(expected),
            f"missing={missing_ckl[:5]} extra={extra_ckl[:5]} status={bad[:5]}",
        )
    else:
        check("CKL exported from STIG Manager round-trips statuses", False,
              f"ckl export {st}: {ckl_body[:200]}")

    print("== live external acceptance script ==")
    env = dict(os.environ)
    env.update({"STIG_MANAGER_URL": SM[:-4] if SM.endswith("/api") else SM,
                "STIG_MANAGER_TOKEN": token})
    p = subprocess.run([sys.executable, f"{REPO}/scripts/run-live-external-acceptance.py",
                        "--repo-root", REPO], env=env, capture_output=True, text=True)
    check("run-live-external-acceptance exercises STIG Manager",
          p.returncode == 0 and "STIG Manager endpoint accepted" in p.stdout,
          (p.stdout + p.stderr)[:300])

    report()


def report():
    print("\n" + "=" * 70)
    fails = [r for r in RESULTS if not r[1]]
    print(f"STAGING ACCEPTANCE: {len(RESULTS) - len(fails)}/{len(RESULTS)} checks passed")
    for n, ok, d in fails:
        print(f"  FAIL {n} — {d[:300]}")
    if EVIDENCE_OUTPUT:
        evidence = {
            "schema": "automatestig-stig-manager-acceptance/v1",
            "passed": not fails,
            "tested_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "product": "STIG Manager",
            "product_version": EVIDENCE_DETAILS.get("stig_manager_version", "unknown"),
            "environment": EVIDENCE_ENVIRONMENT,
            "source_commit": subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=REPO,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip(),
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
            "protected_environment": os.environ.get("AUTOMATESTIG_PROTECTED_ENVIRONMENT"),
            "automatestig_gui_sha256": file_sha256(GUI_BIN),
            "benchmark_sha256": file_sha256(CISCO_ZIP),
            "config_fixture_sha256": file_sha256(CISCO_CONFIG),
            "checks": [{"name": name, "passed": ok} for name, ok, _ in RESULTS],
            "metrics": {
                key: value for key, value in EVIDENCE_DETAILS.items()
                if key != "stig_manager_version"
            },
        }
        os.makedirs(os.path.dirname(os.path.abspath(EVIDENCE_OUTPUT)), exist_ok=True)
        with open(EVIDENCE_OUTPUT, "w", encoding="utf-8") as stream:
            json.dump(evidence, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(f"Redacted acceptance evidence written to {EVIDENCE_OUTPUT}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        help=(
            "automatestig-gui binary under test; overrides AUTOMATESTIG_GUI_BIN "
            "and is resolved relative to E2E_REPO_ROOT"
        ),
    )
    parser.add_argument("--evidence-output")
    parser.add_argument("--environment", default=EVIDENCE_ENVIRONMENT)
    arguments = parser.parse_args()
    if arguments.binary:
        GUI_BIN = arguments.binary
    if not os.path.isabs(GUI_BIN):
        GUI_BIN = os.path.abspath(os.path.join(REPO, GUI_BIN))
    EVIDENCE_OUTPUT = arguments.evidence_output
    EVIDENCE_ENVIRONMENT = arguments.environment
    main()
