#!/usr/bin/env python3
"""Scanner-handoff acceptance against a real STIG Manager + Keycloak rig.

The rig deliberately keeps the product boundary visible:

1. The rig administrator imports Cisco V3R7 and creates the collection, asset,
   and exact assignment directly in STIG Manager.
2. AutomateSTIG evaluates a signed Cisco configuration through only its
   disconnected ``/api/v1`` scanner flow.
3. The selected-run handoff is downloaded and checked by
   ``automatestig scanner verify-handoff``.
4. After AutomateSTIG has stopped, this script acts as the receiving operator:
   it verifies that ``results.xccdf.xml`` is an equivalent supplemental
   projection, then maps only ``sparse-reviews.json`` to STIG Manager Review
   API writes for the already-existing exact assignment.
5. STIG Manager and its exported CKL are read back independently.

AutomateSTIG never receives a STIG Manager URL or credential and never creates
manager inventory or writes a review. The receiving step is intentionally
separate operator-side rig code, not an AutomateSTIG product capability.
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
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
)
EXE = ".exe" if sys.platform == "win32" else ""
GUI_BIN = os.environ.get(
    "AUTOMATESTIG_GUI_BIN", f"{REPO}/target/release/automatestig-gui{EXE}"
)
CLI_BIN = os.environ.get(
    "AUTOMATESTIG_CLI_BIN", f"{REPO}/target/release/automatestig{EXE}"
)
CISCO_ZIP = (
    f"{REPO}/fixtures/authorized/disa-public-2026-07/"
    "U_Cisco_IOS-XE_Router_Y26M04_STIG.zip"
)
CISCO_CONFIG = f"{REPO}/fixtures/network/ios_xe_router_findings.txt"
CISCO_HOSTNAME = "rtr-findings-01"
CISCO_PROFILE = "cisco_ios_xe_router_ndm"
CISCO_STIG = "Cisco_IOS-XE_Router_NDM_STIG"
CISCO_REVISION = "V3R7"

XCCDF_NAMESPACE = "http://checklists.nist.gov/xccdf/1.2"
STIG_MANAGER_NAMESPACE = "http://github.com/nuwcdivnpt/stig-manager"
AUTOMATESTIG_XCCDF_NAMESPACE = "https://automatestig.local/ns/xccdf-results/1"
XCCDF_BENCHMARK_PREFIX = "xccdf_mil.disa.stig_benchmark_"
XCCDF_RULE_PREFIX = "xccdf_mil.disa.stig_rule_"
XCCDF_TEST_RESULT_PREFIX = "xccdf_org.automatestig_testresult_"

KC = os.environ.get("STAGING_AUTH_URL", "http://localhost:8080")
SM = os.environ.get("STAGING_API_URL", "http://localhost:54000/api")
KC_ADMIN_USER, KC_ADMIN_PASS = "admin", "Pa55w0rd"
CLIENT_ID = "automatestig-staging"
CLIENT_SECRET = "automatestig-staging-secret-0001"

AS_PORT = 18441
AS_TOKEN = "staging-acceptance-token-0123456789"

RESULTS = []
EVIDENCE_OUTPUT = None
HANDOFF_OUTPUT = None
EVIDENCE_ENVIRONMENT = "local containerized staging"
EVIDENCE_DETAILS = {}


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(
        f"[{'PASS' if ok else 'FAIL'}] {name}"
        + (f" — {detail}" if detail and not ok else "")
    )


def file_sha256(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def bytes_sha256(value):
    return hashlib.sha256(value).hexdigest()


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
                if key.lower() in {
                    "version",
                    "apiversion",
                    "appversion",
                } and isinstance(child, (str, int, float)):
                    return str(child)
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)
    return "unknown"


def raw_req(url, method="GET", data=None, headers=None, form=None, timeout=60):
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers = {
            **(headers or {}),
            "Content-Type": "application/x-www-form-urlencoded",
        }
    elif isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
        headers = {**(headers or {}), "Content-Type": "application/json"}
    request = urllib.request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(), dict(response.headers.items())
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers.items())
    except Exception as error:
        return -1, str(error).encode(), {}


def req(url, method="GET", data=None, headers=None, form=None, timeout=60):
    status, body, _ = raw_req(
        url, method=method, data=data, headers=headers, form=form, timeout=timeout
    )
    return status, body.decode("utf-8", "replace")


def wait_for(name, url, ok_statuses=(200,), tries=120, sleep=2):
    for _ in range(tries):
        status, _ = req(url, timeout=10)
        if status in ok_statuses:
            print(f"  {name} is up ({url})")
            return
        time.sleep(sleep)
    sys.exit(f"{name} did not come up at {url}")


# --- Keycloak provisioning -------------------------------------------------


def kc_admin_token():
    status, body = req(
        f"{KC}/realms/master/protocol/openid-connect/token",
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": KC_ADMIN_USER,
            "password": KC_ADMIN_PASS,
        },
    )
    if status != 200:
        sys.exit(f"Keycloak admin token failed ({status}): {body[:300]}")
    return json.loads(body)["access_token"]


def kc(path, admin_token, method="GET", data=None):
    return req(
        f"{KC}/admin/realms/stigman{path}",
        method=method,
        data=data,
        headers={"Authorization": f"Bearer {admin_token}"},
    )


def provision_client():
    token = kc_admin_token()
    status, body = kc(f"/clients?clientId={CLIENT_ID}", token)
    existing = json.loads(body) if status == 200 else []
    if existing:
        client_uuid = existing[0]["id"]
        print(f"  client {CLIENT_ID} already provisioned")
    else:
        status, body = kc(
            "/clients",
            token,
            method="POST",
            data={
                "clientId": CLIENT_ID,
                "protocol": "openid-connect",
                "publicClient": False,
                "serviceAccountsEnabled": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "secret": CLIENT_SECRET,
            },
        )
        if status not in (201, 409):
            sys.exit(f"client create failed ({status}): {body[:300]}")
        status, body = kc(f"/clients?clientId={CLIENT_ID}", token)
        client_uuid = json.loads(body)[0]["id"]

    status, body = kc("/client-scopes", token)
    scopes = [
        scope
        for scope in json.loads(body)
        if scope["name"].startswith("stig-manager")
    ]
    for scope in scopes:
        kc(
            f"/clients/{client_uuid}/default-client-scopes/{scope['id']}",
            token,
            method="PUT",
        )
    print(
        f"  attached {len(scopes)} stig-manager scopes: "
        f"{[scope['name'] for scope in scopes]}"
    )

    status, body = kc(f"/clients/{client_uuid}/service-account-user", token)
    service_account = json.loads(body)["id"]
    status, body = kc("/roles", token)
    wanted = [
        role
        for role in json.loads(body)
        if role["name"] in ("admin", "create_collection", "user")
    ]
    kc(
        f"/users/{service_account}/role-mappings/realm",
        token,
        method="POST",
        data=wanted,
    )
    print(f"  service account roles: {[role['name'] for role in wanted]}")


def sm_token():
    status, body = req(
        f"{KC}/realms/stigman/protocol/openid-connect/token",
        method="POST",
        form={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    if status != 200:
        sys.exit(f"client_credentials token failed ({status}): {body[:300]}")
    return json.loads(body)["access_token"]


def sm(path, token, method="GET", data=None):
    return req(
        f"{SM}{path}",
        method=method,
        data=data,
        headers={"Authorization": f"Bearer {token}"},
    )


# --- STIG Manager rig setup (not AutomateSTIG product behavior) -----------


def import_benchmark(token):
    with zipfile.ZipFile(CISCO_ZIP) as archive:
        names = [
            name
            for name in archive.namelist()
            if name.lower().endswith(".xml")
            and "xccdf" in name.lower()
            and "_ndm_" in name.lower()
        ]
        if len(names) != 1:
            sys.exit(f"expected one Cisco NDM XCCDF member, found {len(names)}")
        xccdf = archive.read(names[0])

    boundary = "----automatestigstaging"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="importFile"; '
        'filename="benchmark-xccdf.xml"\r\n'
        "Content-Type: text/xml\r\n\r\n"
    ).encode() + xccdf + f"\r\n--{boundary}--\r\n".encode()
    status, response = req(
        f"{SM}/stigs?elevate=true&clobber=true",
        method="POST",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    check(
        "STIG Manager accepts the authorized Cisco XCCDF as reference benchmark content",
        status == 200,
        f"{status} {response[:300]}",
    )
    status, response = sm("/stigs", token)
    stigs = json.loads(response) if status == 200 else []
    benchmark = next(
        (item for item in stigs if item.get("benchmarkId") == CISCO_STIG), None
    )
    check(
        "STIG Manager exposes Cisco IOS-XE Router NDM V3R7",
        benchmark is not None
        and benchmark.get("lastRevisionStr") == CISCO_REVISION,
        response[:300],
    )
    return benchmark.get("benchmarkId") if benchmark else None


def create_collection(token):
    status, response = sm("/user", token)
    user_id = json.loads(response).get("userId") if status == 200 else None
    name = f"AutomateSTIG Handoff Staging {int(time.time())}"
    status, response = sm(
        "/collections",
        token,
        method="POST",
        data={
            "name": name,
            "description": "scanner handoff acceptance rig",
            "settings": {
                "fields": {
                    "detail": {"enabled": "always", "required": "optional"},
                    "comment": {
                        "enabled": "always",
                        "required": "optional",
                    },
                },
                "status": {
                    "canAccept": True,
                    "resetCriteria": "result",
                    "minAcceptGrant": 3,
                },
                "history": {"maxReviews": 5},
            },
            "metadata": {},
            "grants": [{"userId": user_id, "roleId": 4}],
        },
    )
    ok = status in (200, 201)
    check("rig administrator creates the collection", ok, f"{status} {response[:300]}")
    return json.loads(response)["collectionId"] if ok else None


def create_asset_with_exact_assignment(token, collection_id, benchmark_id):
    status, response = sm(
        "/assets?projection=stigs",
        token,
        method="POST",
        data={
            "collectionId": collection_id,
            "name": CISCO_HOSTNAME,
            "description": "pre-existing Cisco staging router",
            "fqdn": None,
            "ip": None,
            "mac": None,
            "noncomputing": True,
            "metadata": {},
            "labelNames": [],
            "stigs": [benchmark_id],
        },
    )
    ok = status in (200, 201)
    check(
        "rig administrator creates the existing asset and assignment",
        ok,
        f"{status} {response[:400]}",
    )
    if not ok:
        return None, None
    asset_id = json.loads(response).get("assetId")
    status, response = sm(f"/assets/{asset_id}/stigs", token)
    assignments = json.loads(response) if status == 200 else []
    exact = next(
        (
            assignment
            for assignment in assignments
            if assignment.get("benchmarkId") == benchmark_id
            and assignment.get("revisionStr") == CISCO_REVISION
        ),
        None,
    )
    check(
        "STIG Manager rig creates the existing exact Cisco V3R7 assignment",
        exact is not None,
        response[:400],
    )
    return asset_id, exact


def read_reviews(token, collection_id, asset_id):
    for path in (
        f"/collections/{collection_id}/reviews?assetId={asset_id}&rules=default-mapped",
        f"/collections/{collection_id}/reviews?assetId={asset_id}&rules=mapped",
        f"/collections/{collection_id}/reviews?assetId={asset_id}",
    ):
        status, response = sm(path, token)
        if status == 200:
            return json.loads(response)
    return []


# --- AutomateSTIG disconnected scanner ------------------------------------


def as_req(path, method="GET", data=None):
    return req(
        f"http://127.0.0.1:{AS_PORT}{path}",
        method=method,
        data=data,
        headers={"X-Auth-Token": AS_TOKEN},
    )


def multipart_body(fields, files):
    boundary = "----automatestigscannerhandoff"
    parts = []
    for name, value in fields.items():
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        )
        parts.append(str(value).encode())
        parts.append(b"\r\n")
    for name, path, media_type in files:
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(
            (
                f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{os.path.basename(path)}"\r\n'
                f"Content-Type: {media_type}\r\n\r\n"
            ).encode()
        )
        with open(path, "rb") as stream:
            parts.append(stream.read())
        parts.append(b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return f"multipart/form-data; boundary={boundary}", b"".join(parts)


def as_multipart(path, fields, files):
    media_type, body = multipart_body(fields, files)
    status, response, _ = raw_req(
        f"http://127.0.0.1:{AS_PORT}{path}",
        method="POST",
        data=body,
        headers={"X-Auth-Token": AS_TOKEN, "Content-Type": media_type},
    )
    return status, response.decode("utf-8", "replace")


def unwrap(body):
    try:
        value = json.loads(body)
    except Exception:
        return None
    return value.get("data") if isinstance(value, dict) and "data" in value else value


def organization_policy_document(now):
    effective_from = (now - datetime.timedelta(minutes=5)).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    expires_at = (now + datetime.timedelta(days=1)).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    return {
        "schema": "automatestig-organization-policy/v1",
        "policy_id": "stigman-staging-cisco-ios-xe",
        "policy_version": now.strftime("%Y%m%dT%H%M%SZ"),
        "stig_id": CISCO_STIG,
        "stig_release": CISCO_REVISION,
        "asset_hostname": CISCO_HOSTNAME,
        "effective_from": effective_from,
        "expires_at": expires_at,
        "rules": {
            "V-215807": {"max_concurrent_management_sessions": 2},
            "V-215836": {"minimum_logging_buffer_bytes": 4096000},
            "V-215838": {
                "approved_authoritative_ntp_sources": [
                    "192.0.2.10",
                    "192.0.2.11",
                ]
            },
        },
    }


def run_policy_command(arguments, operation):
    result = subprocess.run(
        [CLI_BIN, *arguments], cwd=REPO, capture_output=True, text=True
    )
    if result.returncode != 0:
        sys.exit(f"{operation} failed: {(result.stdout + result.stderr)[:800]}")


def provision_organization_policy(root):
    """Create, sign, and trust a currently effective one-run Cisco policy."""
    signing_root = os.path.join(root, "ephemeral-policy-signing")
    trust_dir = os.path.join(root, "organization_policy_keys")
    os.makedirs(signing_root, mode=0o700)
    os.makedirs(trust_dir, mode=0o700)
    private_key = os.path.join(signing_root, "organization-policy.key")
    public_key = os.path.join(signing_root, "organization-policy.pub")
    policy_path = os.path.join(root, "organization-policy.json")
    signature_path = os.path.join(root, "organization-policy.sig")

    run_policy_command(
        ["generate-signing-key", "--output", private_key],
        "ephemeral Ed25519 key generation",
    )
    with open(policy_path, "w", encoding="utf-8") as stream:
        json.dump(
            organization_policy_document(datetime.datetime.now(datetime.timezone.utc)),
            stream,
            separators=(",", ":"),
            sort_keys=True,
        )
    os.chmod(policy_path, 0o600)
    try:
        run_policy_command(
            [
                "sign-organization-policy",
                "--policy",
                policy_path,
                "--signing-key",
                private_key,
                "--output",
                signature_path,
            ],
            "Cisco organization-policy signing",
        )
    finally:
        if os.path.exists(private_key):
            os.remove(private_key)

    if os.path.getsize(public_key) != 32 or os.path.getsize(signature_path) != 64:
        sys.exit("ephemeral organization-policy key or signature has the wrong size")
    trusted_key = os.path.join(trust_dir, "stigman-staging-policy.pub")
    shutil.copyfile(public_key, trusted_key)
    os.chmod(trusted_key, 0o644)
    os.chmod(signature_path, 0o644)
    with open(public_key, "rb") as stream:
        signer_fingerprint = f"SHA256:{hashlib.sha256(stream.read()).hexdigest()}"
    return {
        "path": policy_path,
        "signature_path": signature_path,
        "trust_dir": trust_dir,
        "sha256": file_sha256(policy_path),
        "signature_sha256": file_sha256(signature_path),
        "signer_fingerprint": signer_fingerprint,
    }


def cisco_evaluation_files(policy):
    return {
        "evidence": CISCO_CONFIG,
        "organization_policy": policy["path"],
        "organization_policy_signature": policy["signature_path"],
    }


def staging_process_environment(home, policy_trust_dir):
    env = dict(os.environ)
    env.update(
        {
            "HOME": home,
            "USERPROFILE": home,
            "PORT": str(AS_PORT),
            "AUTOMATESTIG_AUTH_TOKEN": AS_TOKEN,
            "AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR": policy_trust_dir,
        }
    )
    # This is a disconnected scanner exercise. Strip every demo/private/TLS
    # integration escape hatch so the GUI cannot contact the HTTP rig at all.
    for name in (
        "AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST",
        "AUTOMATESTIG_DEMO",
    ):
        env.pop(name, None)
    return env


def start_automatestig(home, policy_trust_dir):
    env = staging_process_environment(home, policy_trust_dir)
    os.makedirs(home, exist_ok=True)
    log_path = f"{home}/gui.log"
    log_stream = open(log_path, "w", encoding="utf-8")
    process = subprocess.Popen(
        [GUI_BIN],
        env=env,
        cwd=REPO,
        stdout=log_stream,
        stderr=subprocess.STDOUT,
    )
    for _ in range(60):
        status, _ = as_req("/api/v1/status")
        if status == 200:
            return process, log_stream
        time.sleep(0.5)
    process.kill()
    process.wait()
    log_stream.close()
    with open(log_path, encoding="utf-8") as stream:
        detail = stream.read()[:800]
    sys.exit("automatestig-gui failed to start: " + detail)


def file_metadata(path, media_type):
    return {
        "name": os.path.basename(path),
        "size": os.path.getsize(path),
        "type": media_type,
        "sha256": file_sha256(path),
    }


def run_disconnected_cisco_scan(policy):
    status, body = as_req("/api/v1/scanner/profiles")
    catalog = unwrap(body) or {}
    profiles = catalog.get("profiles") or []
    profile = next(
        (item for item in profiles if item.get("profile_id") == CISCO_PROFILE), None
    )
    check(
        "scanner catalog exposes the exact Cisco V3R7 profile",
        status == 200
        and profile is not None
        and profile.get("stig_id") == CISCO_STIG
        and profile.get("stig_revision") == CISCO_REVISION,
        body[:400],
    )

    status, body = as_req(
        "/api/v1/runs/preflight",
        method="POST",
        data={
            "mode": "disconnected",
            "profile_id": CISCO_PROFILE,
            "collection_method": "configuration",
            "pilot_acknowledged": True,
            "input": file_metadata(CISCO_CONFIG, "text/plain"),
            "organization_policy": file_metadata(
                policy["path"], "application/json"
            ),
            "organization_policy_signature": file_metadata(
                policy["signature_path"], "application/octet-stream"
            ),
        },
    )
    preflight = unwrap(body) or {}
    ready = status == 200 and preflight.get("ready") is True
    check(
        "disconnected Cisco scanner preflight binds all signed inputs",
        ready,
        f"{status} {body[:500]}",
    )
    if not ready:
        return None

    status, body = as_multipart(
        "/api/v1/runs/evidence",
        {
            "preflight_token": preflight["preflight_token"],
            "mode": "disconnected",
            "profile_id": CISCO_PROFILE,
            "input_type": "configuration",
        },
        [
            ("evidence", CISCO_CONFIG, "text/plain"),
            ("organization_policy", policy["path"], "application/json"),
            (
                "organization_policy_signature",
                policy["signature_path"],
                "application/octet-stream",
            ),
        ],
    )
    run = unwrap(body) or {}
    result = run.get("result") or {}
    complete = (
        status == 202
        and run.get("mode") == "disconnected"
        and result.get("collection_complete") is True
        and result.get("automated_count", 0) > 0
        and run.get("destination") is None
    )
    check(
        "AutomateSTIG completes disconnected Cisco scanner run with signed policy",
        complete,
        f"{status} {body[:700]}",
    )
    provenance = result.get("provenance") or {}
    policy_provenance = provenance.get("organization_policy") or {}
    check(
        "scanner run retains verified organization-policy provenance",
        policy_provenance.get("policy_sha256") == policy["sha256"]
        and policy_provenance.get("signer_fingerprint")
        == policy["signer_fingerprint"]
        and policy_provenance.get("signature_verified") is True,
        str(policy_provenance)[:400],
    )
    return run if complete else None


def download_and_verify_handoff(run, root):
    run_id = run["id"]
    handoff_url = run.get("handoff_url")
    expected_url = f"/api/v1/runs/{run_id}/handoff"
    status, body, headers = raw_req(
        f"http://127.0.0.1:{AS_PORT}{handoff_url}",
        headers={"X-Auth-Token": AS_TOKEN},
    )
    handoff_path = os.path.join(root, f"automatestig-run-{run_id}.zip")
    if status == 200:
        with open(handoff_path, "wb") as stream:
            stream.write(body)
    response_headers = {key.lower(): value for key, value in headers.items()}
    check(
        "selected-run handoff downloads from its run-bound URL",
        handoff_url == expected_url
        and status == 200
        and "no-store" in response_headers.get("cache-control", "").lower(),
        f"{status} {handoff_url} cache-control="
        f"{response_headers.get('cache-control')!r}",
    )
    verifier = subprocess.run(
        [CLI_BIN, "scanner", "verify-handoff", handoff_path],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=60,
    )
    check(
        "automatestig scanner verify-handoff accepts selected-run bundle",
        verifier.returncode == 0,
        (verifier.stdout + verifier.stderr)[-800:],
    )
    return handoff_path if status == 200 and verifier.returncode == 0 else None


def inspect_sparse_handoff(handoff_path, run_id):
    with zipfile.ZipFile(handoff_path) as archive:
        names = archive.namelist()
        check(
            "handoff ZIP contains no duplicate or traversal member",
            len(names) == len(set(names))
            and all(
                not name.startswith("/") and ".." not in name.split("/")
                for name in names
            ),
            str(names),
        )
        manifest_bytes = archive.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        integrity = json.loads(archive.read("integrity.json"))
        scanner_run = json.loads(archive.read("scanner-run.json"))
        sparse_reviews = json.loads(archive.read("sparse-reviews.json"))
        fallback = json.loads(archive.read("fallback.cklb"))
        xccdf = archive.read("results.xccdf.xml")

    check(
        "handoff manifest remains bound to the disconnected selected run",
        manifest.get("run_id") == run_id
        and scanner_run.get("mode") == "disconnected"
        and scanner_run.get("destination") is None
        and integrity.get("manifest_sha256") == bytes_sha256(manifest_bytes),
        str(manifest)[:500],
    )
    review_ids = [review.get("rule_id") for review in sparse_reviews]
    fallback_stigs = fallback.get("stigs") or []
    fallback_rules = fallback_stigs[0].get("rules") if len(fallback_stigs) == 1 else []
    fallback_ids = [rule.get("rule_id") for rule in fallback_rules]
    expected_status = {
        "pass": "not_a_finding",
        "fail": "open",
        "notapplicable": "not_applicable",
    }
    fallback_by_rule = {
        rule.get("rule_id"): rule.get("status") for rule in fallback_rules
    }
    sparse_is_safe = (
        bool(sparse_reviews)
        and len(review_ids) == len(set(review_ids))
        and set(review_ids) == set(fallback_ids)
        and len(fallback_ids) == len(set(fallback_ids))
        and all(rule.get("status") != "not_reviewed" for rule in fallback_rules)
        and all(
            expected_status.get(review.get("result"))
            == fallback_by_rule.get(review.get("rule_id"))
            for review in sparse_reviews
        )
    )
    check(
        "supplemental CKLB contains scanner-owned reviewed rows only",
        sparse_is_safe,
        f"reviews={len(sparse_reviews)} fallback={len(fallback_rules)}",
    )
    try:
        xccdf_reviews = supplemental_xccdf_reviews(
            xccdf, manifest, sparse_reviews
        )
        xccdf_is_equivalent = True
        xccdf_detail = f"reviews={len(xccdf_reviews)}"
    except (ET.ParseError, KeyError, TypeError, ValueError) as error:
        xccdf_reviews = {}
        xccdf_is_equivalent = False
        xccdf_detail = str(error)
    check(
        "supplemental XCCDF mirrors sparse reviews without becoming the receiver transport",
        xccdf_is_equivalent,
        xccdf_detail,
    )
    return (
        manifest,
        sparse_reviews,
        len(fallback_rules),
        len(xccdf_reviews),
        integrity["manifest_sha256"],
    )


def supplemental_xccdf_reviews(xccdf, manifest, sparse_reviews):
    """Return the XCCDF review projection after exact identity/parity checks.

    This validates a supplemental handoff member. It deliberately does not
    model a STIG Manager file upload: the tested receiver transport remains the
    JSON Review API mapping in ``receiver_review_writes``.
    """
    cdf = f"{{{XCCDF_NAMESPACE}}}"
    sm_namespace = f"{{{STIG_MANAGER_NAMESPACE}}}"
    ast = f"{{{AUTOMATESTIG_XCCDF_NAMESPACE}}}"
    root = ET.fromstring(xccdf)
    stig_id = manifest["stig_id"]
    run_id = manifest["run_id"]
    if root.tag != f"{cdf}Benchmark":
        raise ValueError("XCCDF root is not an XCCDF 1.2 Benchmark")
    if root.get("id") != f"{XCCDF_BENCHMARK_PREFIX}{stig_id}":
        raise ValueError("XCCDF Benchmark identity does not match manifest")

    test_results = root.findall(f"{cdf}TestResult")
    if len(test_results) != 1:
        raise ValueError("XCCDF must contain exactly one TestResult")
    test_result = test_results[0]
    if test_result.get("id") != f"{XCCDF_TEST_RESULT_PREFIX}{run_id}":
        raise ValueError("XCCDF TestResult identity does not match manifest")
    if test_result.get("version") != manifest["stig_revision"]:
        raise ValueError("XCCDF TestResult revision does not match manifest")

    provenances = test_result.findall(f"{cdf}metadata/{ast}provenance")
    if len(provenances) != 1 or provenances[0].get("stig-id") != stig_id:
        raise ValueError("XCCDF provenance STIG identity does not match manifest")
    fields = {
        field.get("name"): field.get("value")
        for field in provenances[0].findall(f"{ast}field")
    }
    if fields.get("run-id") != run_id:
        raise ValueError("XCCDF provenance run identity does not match manifest")

    expected = {}
    for review in sparse_reviews:
        rule_id = review["rule_id"]
        if rule_id in expected:
            raise ValueError(f"duplicate sparse review Rule ID {rule_id!r}")
        expected[rule_id] = (
            review["result"],
            review["detail"],
            review["comment"],
        )

    observed = {}
    for rule_result in test_result.findall(f"{cdf}rule-result"):
        identity = rule_result.find(f"{cdf}metadata/{ast}rule-identity")
        if identity is None:
            raise ValueError("XCCDF rule-result lacks exact rule identity")
        rule_id = identity.get("rule-id")
        if not rule_id or rule_result.get("idref") != f"{XCCDF_RULE_PREFIX}{rule_id}":
            raise ValueError("XCCDF rule-result idref does not match rule identity")
        if rule_id in observed:
            raise ValueError(f"duplicate XCCDF Rule ID {rule_id!r}")
        observed[rule_id] = (
            rule_result.findtext(f"{cdf}result", default=""),
            rule_result.findtext(f".//{sm_namespace}detail", default=""),
            rule_result.findtext(f".//{sm_namespace}comment", default=""),
        )
    if observed != expected:
        raise ValueError("XCCDF result/detail/comment projection differs from sparse reviews")
    return observed


# --- Explicit receiving-operator boundary ---------------------------------


def receiver_review_writes(sparse_reviews):
    """Translate only sparse-reviews.json rows to STIG Manager review writes."""
    writes = []
    for review in sparse_reviews:
        writes.append(
            {
                "ruleId": review["rule_id"],
                "result": review["result"],
                "detail": review["detail"].strip(" "),
                "comment": review["comment"].strip(" "),
                "autoResult": review.get("evidence_source") == "live_collection",
                "status": "saved",
                "resultEngine": {
                    "type": "script",
                    "product": "AutomateSTIG",
                    "time": review.get("evaluated_at"),
                },
            }
        )
    return writes


def reconcile_sparse_reviews(
    token, collection_id, asset_id, benchmark_id, sparse_reviews
):
    status, response = sm(f"/assets/{asset_id}/stigs", token)
    assignments = json.loads(response) if status == 200 else []
    exact_assignment = next(
        (
            item
            for item in assignments
            if item.get("benchmarkId") == benchmark_id
            and item.get("revisionStr") == CISCO_REVISION
        ),
        None,
    )
    check(
        "receiving operator revalidates the existing exact assignment",
        exact_assignment is not None,
        response[:400],
    )
    if exact_assignment is None:
        return []
    writes = receiver_review_writes(sparse_reviews)
    status, response = sm(
        f"/collections/{collection_id}/reviews/{asset_id}",
        token,
        method="POST",
        data=writes,
    )
    check(
        "receiving operator reconciles only sparse-reviews.json",
        status == 200,
        f"{status} {response[:500]}",
    )
    return writes if status == 200 else []


def normalized_review_status(value):
    return re.sub(r"[^a-z]", "", str(value).lower())


def verify_stig_manager_round_trip(
    token,
    collection_id,
    asset_id,
    benchmark_id,
    assignment,
    sparse_reviews,
):
    expected = {
        review["rule_id"]: normalized_review_status(review["result"])
        for review in sparse_reviews
    }
    expected_ckl_status = {
        "pass": "notafinding",
        "fail": "open",
        "notapplicable": "notapplicable",
    }
    expected_ckl = {
        review["rule_id"]: expected_ckl_status[
            normalized_review_status(review["result"])
        ]
        for review in sparse_reviews
    }
    reviews = read_reviews(token, collection_id, asset_id)
    observed = {}
    invalid = []
    for review in reviews:
        rule_id = review.get("ruleId")
        result = review.get("result")
        if not rule_id or rule_id in observed:
            invalid.append((rule_id, result))
            continue
        observed[rule_id] = normalized_review_status(result)
    mismatch = [
        (rule_id, observed.get(rule_id), wanted)
        for rule_id, wanted in sorted(expected.items())
        if observed.get(rule_id) != wanted
    ]
    exact = not invalid and set(observed) == set(expected) and not mismatch
    check(
        "STIG Manager contains exactly the received sparse Rule-ID set",
        exact,
        f"invalid={invalid[:5]} mismatch={mismatch[:5]} "
        f"extra={sorted(set(observed) - set(expected))[:5]}",
    )

    status, ckl_body = req(
        f"{SM}/assets/{asset_id}/checklists/"
        f"{benchmark_id}/{CISCO_REVISION}?format=ckl",
        headers={"Authorization": f"Bearer {token}"},
    )
    by_rule = {}
    if status == 200 and "<CHECKLIST" in ckl_body:
        root = ET.fromstring(ckl_body)
        for vuln in root.iter("VULN"):
            attrs = {
                item.findtext("VULN_ATTRIBUTE"): item.findtext("ATTRIBUTE_DATA")
                or ""
                for item in vuln.findall("STIG_DATA")
            }
            rule_id = attrs.get("Rule_ID", "")
            if rule_id in by_rule or not rule_id:
                by_rule[rule_id] = "__duplicate_or_missing__"
                continue
            by_rule[rule_id] = normalized_review_status(
                vuln.findtext("STATUS") or ""
            )
    reviewed_bad = [
        (rule_id, by_rule.get(rule_id), wanted)
        for rule_id, wanted in sorted(expected_ckl.items())
        if by_rule.get(rule_id) != wanted
    ]
    untouched_bad = [
        (rule_id, status_value)
        for rule_id, status_value in by_rule.items()
        if rule_id not in expected and status_value != "notreviewed"
    ]
    full_rule_count = assignment.get("ruleCount") if assignment else None
    round_trip = (
        status == 200
        and len(by_rule) == full_rule_count
        and not reviewed_bad
        and not untouched_bad
    )
    check(
        "STIG Manager rule/status round-trip matches sparse handoff",
        round_trip,
        f"HTTP={status} CKL={len(by_rule)}/{full_rule_count} "
        f"reviewed={reviewed_bad[:5]} untouched={untouched_bad[:5]}",
    )
    return len(reviews), len(by_rule)


def main():
    global EVIDENCE_DETAILS
    for path in (GUI_BIN, CLI_BIN, CISCO_ZIP, CISCO_CONFIG):
        if not os.path.exists(path):
            sys.exit(f"missing prerequisite: {path}")

    print("== waiting for rig ==")
    wait_for("Keycloak", f"{KC}/realms/stigman")
    wait_for("STIG Manager API", f"{SM}/op/definition", ok_statuses=(200, 401))
    definition_status, definition_body = req(f"{SM}/op/definition")
    EVIDENCE_DETAILS["stig_manager_version"] = (
        product_version(definition_body)
        if definition_status == 200
        else "unknown"
    )

    print("== provisioning receiving authority and STIG Manager inventory ==")
    provision_client()
    token = sm_token()
    status, response = sm("/user", token)
    check(
        "receiving service account is recognized by STIG Manager",
        status == 200,
        f"{status} {response[:200]}",
    )
    benchmark_id = import_benchmark(token)
    collection_id = create_collection(token)
    asset_id, assignment = create_asset_with_exact_assignment(
        token, collection_id, benchmark_id
    )
    if not (benchmark_id and collection_id and asset_id and assignment):
        report()
    initial_reviews = read_reviews(token, collection_id, asset_id)
    check(
        "pre-existing exact assignment begins with no saved reviews",
        initial_reviews == [],
        str(initial_reviews)[:300],
    )

    print("== running disconnected AutomateSTIG scanner ==")
    home = tempfile.mkdtemp(prefix="automatestig-staging-")
    handoff_copy = None
    run = None
    policy = None
    try:
        policy = provision_organization_policy(home)
        process, log_stream = start_automatestig(home, policy["trust_dir"])
        try:
            run = run_disconnected_cisco_scan(policy)
            if not run:
                report()
            handoff_path = download_and_verify_handoff(run, home)
            if not handoff_path:
                report()

            status, body = as_req(
                f"/api/stigman/push/{run['id']}", method="POST", data={}
            )
            check(
                "retired direct-push route returns 410",
                status == 410,
                f"{status} {body[:300]}",
            )
            reviews_before_receiver = read_reviews(token, collection_id, asset_id)
            check(
                "AutomateSTIG makes zero direct STIG Manager review writes",
                reviews_before_receiver == initial_reviews == [],
                str(reviews_before_receiver)[:300],
            )

            handoff_copy = os.path.join(
                tempfile.gettempdir(),
                f"automatestig-staging-{run['id']}.handoff.zip",
            )
            shutil.copyfile(handoff_path, handoff_copy)
        finally:
            process.kill()
            process.wait()
            log_stream.close()
    finally:
        shutil.rmtree(home, ignore_errors=True)

    print("== receiving selected-run handoff as an explicit operator ==")
    try:
        (
            manifest,
            sparse_reviews,
            fallback_count,
            xccdf_count,
            manifest_sha256,
        ) = inspect_sparse_handoff(
            handoff_copy, run["id"]
        )
        writes = reconcile_sparse_reviews(
            token,
            collection_id,
            asset_id,
            benchmark_id,
            sparse_reviews,
        )
        review_count, full_ckl_count = verify_stig_manager_round_trip(
            token,
            collection_id,
            asset_id,
            benchmark_id,
            assignment,
            sparse_reviews,
        )
        EVIDENCE_DETAILS.update(
            {
                "organization_policy_sha256": policy["sha256"],
                "organization_policy_signature_sha256": policy[
                    "signature_sha256"
                ],
                "organization_policy_signer_fingerprint": policy[
                    "signer_fingerprint"
                ],
                "boundary": "disconnected-selected-run-handoff",
                "automatestig_direct_review_writes": 0,
                "receiving_operator_review_writes": len(writes),
                "review_count": review_count,
                "source_finding_count": len(sparse_reviews),
                "fallback_sparse_rule_count": fallback_count,
                "xccdf_sparse_rule_count": xccdf_count,
                "stig_manager_review_transport": (
                    "sparse-reviews.json -> POST "
                    "/collections/{collectionId}/reviews/{assetId}"
                ),
                "xccdf_role": "supplemental-verified-not-native-imported",
                "xccdf_native_import_exercised": False,
                "full_assignment_rule_count": assignment.get("ruleCount"),
                "full_ckl_rule_count": full_ckl_count,
                "benchmark_id": benchmark_id,
                "assignment_revision": assignment.get("revisionStr"),
                "producer_handoff_filename": "producer-handoff.zip",
                "handoff_sha256": file_sha256(handoff_copy),
                "handoff_manifest_sha256": manifest_sha256,
                "rule_set_sha256": bytes_sha256(
                    json.dumps(
                        sorted(review["rule_id"] for review in sparse_reviews),
                        separators=(",", ":"),
                    ).encode()
                ),
            }
        )
        if HANDOFF_OUTPUT:
            destination = os.path.abspath(HANDOFF_OUTPUT)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            with open(handoff_copy, "rb") as source, open(destination, "xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            if file_sha256(destination) != EVIDENCE_DETAILS["handoff_sha256"]:
                raise RuntimeError("published handoff differs from the verified staging ZIP")
    finally:
        if handoff_copy and os.path.exists(handoff_copy):
            os.remove(handoff_copy)

    print("== authenticated external smoke ==")
    environment = dict(os.environ)
    environment.update(
        {
            "STIG_MANAGER_URL": SM[:-4] if SM.endswith("/api") else SM,
            "STIG_MANAGER_TOKEN": token,
        }
    )
    process = subprocess.run(
        [
            sys.executable,
            f"{REPO}/scripts/run-live-external-acceptance.py",
            "--repo-root",
            REPO,
        ],
        env=environment,
        capture_output=True,
        text=True,
    )
    check(
        "run-live-external-acceptance exercises STIG Manager",
        process.returncode == 0
        and "STIG Manager endpoint accepted" in process.stdout,
        (process.stdout + process.stderr)[:300],
    )
    report()


def report():
    print("\n" + "=" * 70)
    failures = [result for result in RESULTS if not result[1]]
    print(
        f"STAGING HANDOFF ACCEPTANCE: "
        f"{len(RESULTS) - len(failures)}/{len(RESULTS)} checks passed"
    )
    for name, _, detail in failures:
        print(f"  FAIL {name} — {detail[:300]}")
    if EVIDENCE_OUTPUT:
        evidence = {
            "schema": "automatestig-stig-manager-acceptance/v1",
            "passed": not failures,
            "tested_at": datetime.datetime.now(datetime.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "product": "STIG Manager",
            "product_version": EVIDENCE_DETAILS.get(
                "stig_manager_version", "unknown"
            ),
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
            "protected_environment": os.environ.get(
                "AUTOMATESTIG_PROTECTED_ENVIRONMENT"
            ),
            "automatestig_gui_sha256": file_sha256(GUI_BIN),
            "automatestig_cli_sha256": file_sha256(CLI_BIN),
            "benchmark_sha256": file_sha256(CISCO_ZIP),
            "config_fixture_sha256": file_sha256(CISCO_CONFIG),
            "checks": [
                {"name": name, "passed": ok} for name, ok, _ in RESULTS
            ],
            "metrics": {
                key: value
                for key, value in EVIDENCE_DETAILS.items()
                if key != "stig_manager_version"
            },
        }
        os.makedirs(
            os.path.dirname(os.path.abspath(EVIDENCE_OUTPUT)), exist_ok=True
        )
        with open(EVIDENCE_OUTPUT, "w", encoding="utf-8") as stream:
            json.dump(evidence, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(f"Redacted acceptance evidence written to {EVIDENCE_OUTPUT}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        help=(
            "automatestig-gui binary under test; overrides AUTOMATESTIG_GUI_BIN "
            "and is resolved relative to E2E_REPO_ROOT"
        ),
    )
    parser.add_argument(
        "--cli-binary",
        help=(
            "automatestig CLI used for policy signing and handoff verification; "
            "overrides AUTOMATESTIG_CLI_BIN"
        ),
    )
    parser.add_argument("--evidence-output")
    parser.add_argument(
        "--handoff-output",
        help=(
            "create-new output for the exact verified unsigned handoff used by "
            "the protected producer-signing/receiver ceremony"
        ),
    )
    parser.add_argument("--environment", default=EVIDENCE_ENVIRONMENT)
    arguments = parser.parse_args()
    if arguments.binary:
        GUI_BIN = arguments.binary
    if arguments.cli_binary:
        CLI_BIN = arguments.cli_binary
    if not os.path.isabs(GUI_BIN):
        GUI_BIN = os.path.abspath(os.path.join(REPO, GUI_BIN))
    if not os.path.isabs(CLI_BIN):
        CLI_BIN = os.path.abspath(os.path.join(REPO, CLI_BIN))
    EVIDENCE_OUTPUT = arguments.evidence_output
    HANDOFF_OUTPUT = arguments.handoff_output
    EVIDENCE_ENVIRONMENT = arguments.environment
    main()
