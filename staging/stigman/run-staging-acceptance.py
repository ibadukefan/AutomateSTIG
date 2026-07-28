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
import http.client
import http.server
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
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
CLI_BIN = os.environ.get("AUTOMATESTIG_CLI_BIN", f"{REPO}/target/release/automatestig{EXE}")
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

MAX_PROXY_BODY_BYTES = 32 * 1024 * 1024
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


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


# --- Isolated-lab HTTPS bridge ---------------------------------------------

def generate_lab_certificate(root):
    """Generate a one-run self-signed certificate for the loopback bridge."""
    certificate = os.path.join(root, "loopback-proxy.crt")
    private_key = os.path.join(root, "loopback-proxy.key")
    config = os.path.join(root, "loopback-proxy-openssl.cnf")
    with open(config, "w", encoding="utf-8") as stream:
        stream.write(
            "[req]\n"
            "distinguished_name = subject\n"
            "prompt = no\n"
            "x509_extensions = server\n"
            "[subject]\n"
            "CN = automatestig-staging-loopback\n"
            "[server]\n"
            "basicConstraints = critical,CA:FALSE\n"
            "keyUsage = critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n"
            "subjectAltName = IP:127.0.0.1\n"
        )
    command = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
        "-days", "1", "-keyout", private_key, "-out", certificate,
        "-config", config,
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"failed to generate isolated-lab TLS certificate: {result.stderr[:500]}")
    os.chmod(private_key, 0o600)
    os.chmod(certificate, 0o644)
    return certificate, private_key


def proxy_handler(upstream_host, upstream_port):
    """Build a bounded HTTP reverse-proxy handler for one loopback service."""
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def forward(self):
            if self.headers.get("Transfer-Encoding"):
                self.send_error(501, "streamed request bodies are not supported")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400, "invalid Content-Length")
                return
            if length < 0 or length > MAX_PROXY_BODY_BYTES:
                self.send_error(413, "request body exceeds staging bridge limit")
                return
            body = self.rfile.read(length) if length else None
            headers = {
                key: value
                for key, value in self.headers.items()
                if key.lower() not in HOP_BY_HOP_HEADERS
                and key.lower() not in {"host", "content-length"}
            }
            headers["Host"] = f"localhost:{upstream_port}"
            connection = http.client.HTTPConnection(
                upstream_host, upstream_port, timeout=60
            )
            try:
                connection.request(
                    self.command, self.path, body=body, headers=headers
                )
                response = connection.getresponse()
                response_body = response.read(MAX_PROXY_BODY_BYTES + 1)
                if len(response_body) > MAX_PROXY_BODY_BYTES:
                    self.send_error(502, "upstream response exceeds staging bridge limit")
                    return
                self.send_response(response.status, response.reason)
                for key, value in response.getheaders():
                    if (
                        key.lower() not in HOP_BY_HOP_HEADERS
                        and key.lower() not in {"content-length", "server", "date"}
                    ):
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(response_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                if self.command != "HEAD":
                    self.wfile.write(response_body)
            except Exception as error:
                self.send_error(502, f"loopback upstream failed: {error}")
            finally:
                connection.close()

        do_DELETE = forward
        do_GET = forward
        do_HEAD = forward
        do_OPTIONS = forward
        do_PATCH = forward
        do_POST = forward
        do_PUT = forward

        def log_message(self, format_string, *arguments):
            print(
                "  staging HTTPS bridge: " + (format_string % arguments),
                file=sys.stderr,
            )

    return Handler


class HttpsReverseProxy:
    """A loopback-only, self-signed HTTPS front end for one HTTP container."""

    def __init__(self, upstream_port, certificate, private_key):
        handler = proxy_handler("127.0.0.1", upstream_port)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, private_key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self):
        return self.server.server_port

    def start(self):
        self.thread.start()
        return self

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class LabHttpsRig:
    """Own both ephemeral HTTPS bridges used only by the staging GUI process."""

    def __init__(self, root):
        certificate, private_key = generate_lab_certificate(root)
        self.auth = HttpsReverseProxy(8080, certificate, private_key)
        self.api = HttpsReverseProxy(54000, certificate, private_key)

    @property
    def api_url(self):
        return f"https://127.0.0.1:{self.api.port}/api"

    @property
    def token_url(self):
        return (
            f"https://127.0.0.1:{self.auth.port}"
            "/realms/stigman/protocol/openid-connect/token"
        )

    def __enter__(self):
        self.auth.start()
        self.api.start()
        return self

    def __exit__(self, _exception_type, _exception, _traceback):
        self.api.close()
        self.auth.close()


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
        "stig_id": "Cisco_IOS-XE_Router_NDM_STIG",
        "stig_release": "V3R7",
        "asset_hostname": CISCO_HOSTNAME,
        "effective_from": effective_from,
        "expires_at": expires_at,
        "rules": {
            "V-215807": {"max_concurrent_management_sessions": 2},
            "V-215836": {"minimum_logging_buffer_bytes": 4096000},
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
            organization_policy_document(
                datetime.datetime.now(datetime.timezone.utc)
            ),
            stream,
            separators=(",", ":"),
            sort_keys=True,
        )
    os.chmod(policy_path, 0o600)
    try:
        run_policy_command(
            [
                "sign-organization-policy",
                "--policy", policy_path,
                "--signing-key", private_key,
                "--output", signature_path,
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
    env.update({
        "HOME": home,
        "USERPROFILE": home,
        "PORT": str(AS_PORT),
        "AUTOMATESTIG_AUTH_TOKEN": AS_TOKEN,
        # These permissions are intentionally scoped to this child process and
        # its numeric loopback-only, containerized acceptance bridge.
        "AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST": "127.0.0.1",
        "AUTOMATESTIG_ALLOW_INVALID_STIGMAN_CERTS": "1",
        "AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR": policy_trust_dir,
    })
    # An exact numeric allowlist already authorizes the loopback destination;
    # inherited broad private-destination overrides would weaken this exercise.
    env.pop("AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_DESTINATIONS", None)
    env.pop("AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS", None)
    env.pop("AUTOMATESTIG_DEMO", None)
    return env


def start_automatestig(home, policy_trust_dir):
    env = staging_process_environment(home, policy_trust_dir)
    os.makedirs(home, exist_ok=True)
    log_path = f"{home}/gui.log"
    with open(log_path, "w", encoding="utf-8") as log_stream:
        proc = subprocess.Popen(
            [GUI_BIN],
            env=env,
            cwd=REPO,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
        )
    for _ in range(60):
        st, _ = as_req("/api/status")
        if st == 200:
            return proc
        time.sleep(0.5)
    proc.kill()
    sys.exit("automatestig-gui failed to start: " + open(f"{home}/gui.log").read()[:800])


def main():
    global EVIDENCE_DETAILS
    for f in (GUI_BIN, CLI_BIN, CISCO_ZIP, CISCO_CONFIG):
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
    try:
        policy = provision_organization_policy(home)
        with LabHttpsRig(home) as https_rig:
            proc = start_automatestig(home, policy["trust_dir"])
            try:
                out = as_multipart("/api/library/import-disa", {}, {"file": CISCO_ZIP})
                check("AutomateSTIG imports DISA zip", '"success":true' in out.replace(" ", ""), out[:200])
                st, body = as_req("/api/library/benchmarks")
                benchmarks = unwrap(body) or []
                stig_id = next((item.get("id") for item in benchmarks
                                if item.get("id") == "Cisco_IOS-XE_Router_NDM_STIG"), None)

                out = as_multipart(
                    "/api/evaluate/with-evidence",
                    {"stig_id": stig_id or "", "hostname": CISCO_HOSTNAME,
                     "platform": "cisco_ios", "input_type": "config"},
                    cisco_evaluation_files(policy),
                )
                cid = (unwrap(out) or {}).get("checklist_id") or (unwrap(out) or {}).get("id")
                check("AutomateSTIG evaluates Cisco running config with a signed policy", bool(cid), out[:300])

                st, body = as_req("/api/stigman/config", method="POST", data={
                    "api_url": https_rig.api_url,
                    "token_url": https_rig.token_url,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "default_collection_id": str(collection_id),
                    "verify_tls": False,
                })
                check("STIG-Manager integration configured over HTTPS", st == 200 and '"success":true' in body.replace(" ", ""), body[:200])

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
                provenance = (
                    cl.get("evaluation_provenance", {})
                    .get("organization_policy", {})
                )
                policy_bound = (
                    provenance.get("policy_sha256") == policy["sha256"]
                    and provenance.get("signer_fingerprint")
                    == policy["signer_fingerprint"]
                    and provenance.get("signature_verified") is True
                )
                check(
                    "source checklist retains verified organization-policy provenance",
                    policy_bound,
                    str(provenance)[:300],
                )
                EVIDENCE_DETAILS.update({
                    "organization_policy_sha256": policy["sha256"],
                    "organization_policy_signature_sha256": policy[
                        "signature_sha256"
                    ],
                    "organization_policy_signer_fingerprint": policy[
                        "signer_fingerprint"
                    ],
                    "stig_manager_transport": "ephemeral-loopback-https",
                })
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
    finally:
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
            "automatestig_cli_sha256": file_sha256(CLI_BIN),
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
    parser.add_argument(
        "--cli-binary",
        help=(
            "automatestig CLI used to create the ephemeral Ed25519 policy "
            "signature; overrides AUTOMATESTIG_CLI_BIN"
        ),
    )
    parser.add_argument("--evidence-output")
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
    EVIDENCE_ENVIRONMENT = arguments.environment
    main()
