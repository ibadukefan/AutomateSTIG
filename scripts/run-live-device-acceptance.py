#!/usr/bin/env python3
"""Opt-in acceptance against real ONTAP, FreeBSD, and Cisco IOS-XE targets.

No network connection is attempted unless an SSH target is configured. Cisco
acceptance consumes an authorized real-device running configuration already on
the protected runner. Secrets and raw device content are never printed.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile


MAX_ORACLE_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024 * 1024
ORACLE_SCHEMA = "automatestig-live-decision-oracle/v2"
ORACLE_SCHEMA_URI = "https://automatestig.dev/schemas/live-decision-oracle.schema.json"
ORACLE_MAX_AGE_DAYS = 90
ALLOWED_DETERMINED_STATUSES = {"finding", "notafinding", "notapplicable"}
ORACLE_STATUSES = {
    "Finding": "finding",
    "NotAFinding": "notafinding",
    "NotApplicable": "notapplicable",
}

TARGETS = (
    {
        "name": "ONTAP",
        "stig": "NetApp_ONTAP_DSC_9-x_STIG",
        "stig_release": "V2R2",
        "fixture": "fixtures/authorized/disa-public-2026-07/U_NetApp_ONTAP_DSC_9-x_V2R2_STIG.zip",
        "check_pack": "content/check_packs/netapp_ontap9.json",
        "slug": "ontap",
        "mode": "ssh",
    },
    {
        "name": "FREEBSD",
        "stig": "General_Purpose_Operating_System",
        "stig_release": "V3R3",
        "fixture": "fixtures/authorized/disa-public-2026-07/U_GPOS_V3R3_SRG.zip",
        "check_pack": "content/check_packs/freebsd_gpos.json",
        "slug": "freebsd",
        "mode": "ssh",
    },
    {
        "name": "CISCO_IOS_XE",
        "stig": "Cisco_IOS-XE_Router_NDM_STIG",
        "stig_release": "V3R7",
        "fixture": "fixtures/authorized/disa-public-2026-07/U_Cisco_IOS-XE_Router_Y26M04_STIG.zip",
        "check_pack": "content/check_packs/cisco_ios_xe_router_ndm.json",
        "slug": "cisco_ios_xe",
        "mode": "config",
    },
)


def sha256_file(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def env_name(target, suffix):
    return f"AUTOMATESTIG_LIVE_{target['name']}_{suffix}"


def run(command, environment):
    return subprocess.run(command, capture_output=True, text=True, env=environment)


def require_setting(target, suffix):
    name = env_name(target, suffix)
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required for the configured {target['name']} acceptance target")
    return value


def normalized_status(value):
    return re.sub(r"[^a-z]", "", str(value).lower())


def canonical_set_sha256(values):
    encoded = json.dumps(sorted(values), separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_status_sha256(status_by_vuln):
    encoded = json.dumps(
        {key: status_by_vuln[key] for key in sorted(status_by_vuln)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def snapshot_regular_file(source, destination):
    """Copy one bounded regular file through one opened descriptor."""
    source = pathlib.Path(source)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as error:
        raise RuntimeError(f"cannot open protected source {source}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"protected source is not a regular file: {source}")
        if metadata.st_size <= 0 or metadata.st_size > MAX_SOURCE_BYTES:
            raise RuntimeError(
                f"protected source must be 1..{MAX_SOURCE_BYTES} bytes: {source}"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            raise RuntimeError(f"protected source exceeds {MAX_SOURCE_BYTES} bytes: {source}")
    finally:
        os.close(descriptor)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    try:
        destination.chmod(0o600)
    except OSError:
        pass
    return hashlib.sha256(raw).hexdigest()


def load_complete_evidence(path):
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"evidence is not valid UTF-8 JSON: {error}") from error
    if (
        not isinstance(document, dict)
        or document.get("schema") != "automatestig-evidence/v2"
        or document.get("complete") is not True
    ):
        raise RuntimeError("acceptance requires a complete evidence v2 document")
    commands = document.get("commands")
    if not isinstance(commands, list) or not commands:
        raise RuntimeError("complete evidence contains no command outcomes")
    if any(
        not isinstance(command, dict) or command.get("status") != "success"
        for command in commands
    ):
        raise RuntimeError("complete evidence contains a non-success command outcome")
    requested = [command.get("command") for command in commands]
    if any(not isinstance(command, str) or not command for command in requested):
        raise RuntimeError("collector evidence contains a missing command identity")
    if len(set(requested)) != len(requested):
        raise RuntimeError("collector evidence contains duplicate command outcomes")
    return document


def evidence_state_sha256(document):
    """Hash decision-relevant command state without volatile collection metadata."""
    commands = document.get("commands") or []
    state = [
        {
            "command": command.get("command"),
            "status": command.get("status"),
            "exit_code": command.get("exit_code"),
            "stdout": command.get("stdout"),
            "stderr": command.get("stderr"),
        }
        for command in commands
    ]
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_oracle_timestamp(value):
    if not isinstance(value, str):
        raise RuntimeError("decision oracle adjudicated_at must be an RFC 3339 timestamp")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeError(
            "decision oracle adjudicated_at must be an RFC 3339 timestamp"
        ) from error
    if parsed.tzinfo is None:
        raise RuntimeError("decision oracle adjudicated_at must include a timezone")
    parsed = parsed.astimezone(datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    if parsed > now + datetime.timedelta(minutes=5):
        raise RuntimeError("decision oracle adjudicated_at is in the future")
    if now - parsed > datetime.timedelta(days=ORACLE_MAX_AGE_DAYS):
        raise RuntimeError(
            f"decision oracle is older than {ORACLE_MAX_AGE_DAYS} days"
        )
    return parsed


def load_decision_oracle(
    target,
    oracle_path,
    curated_vulns,
    benchmark_sha256,
    check_pack_sha256,
    scenario_kind,
    hostname,
    source_state_sha256,
):
    path = pathlib.Path(oracle_path)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"decision oracle must be a regular nonsymlink file: {path}")
    if path.stat().st_size > MAX_ORACLE_BYTES:
        raise RuntimeError(f"decision oracle exceeds {MAX_ORACLE_BYTES} bytes")
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"decision oracle is not valid UTF-8 JSON: {error}") from error
    if not isinstance(document, dict):
        raise RuntimeError("decision oracle must be a JSON object")

    required = {
        "$schema",
        "schema",
        "target",
        "stig_id",
        "stig_release",
        "benchmark_sha256",
        "check_pack_sha256",
        "adjudicated_at",
        "adjudicator",
        "adjudication_basis",
        "independent_of_automatestig_output",
        "scenarios",
    }
    missing = sorted(required - set(document))
    extra = sorted(set(document) - required)
    if missing or extra:
        raise RuntimeError(
            f"decision oracle fields differ from the closed schema: "
            f"missing={missing} extra={extra}"
        )
    expected_identity = {
        "$schema": ORACLE_SCHEMA_URI,
        "schema": ORACLE_SCHEMA,
        "target": target["slug"],
        "stig_id": target["stig"],
        "stig_release": target["stig_release"],
        "benchmark_sha256": benchmark_sha256,
        "check_pack_sha256": check_pack_sha256,
    }
    for field, expected in expected_identity.items():
        if document.get(field) != expected:
            raise RuntimeError(
                f"decision oracle {field} mismatch: expected {expected!r}, "
                f"got {document.get(field)!r}"
            )
    if document.get("independent_of_automatestig_output") is not True:
        raise RuntimeError(
            "decision oracle must attest independence from AutomateSTIG output"
        )
    adjudicator = document.get("adjudicator")
    basis = document.get("adjudication_basis")
    if (
        not isinstance(adjudicator, str)
        or not 3 <= len(adjudicator.strip()) <= 200
    ):
        raise RuntimeError("decision oracle must name an independent adjudicator")
    if not isinstance(basis, str) or not 20 <= len(basis.strip()) <= 2000:
        raise RuntimeError("decision oracle must describe its independent basis")
    parse_oracle_timestamp(document.get("adjudicated_at"))

    scenarios = document.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != 2:
        raise RuntimeError(
            "decision oracle must contain exactly one baseline and one negative-control scenario"
        )
    scenario_required = {
        "id",
        "kind",
        "asset_hostname",
        "source_state_sha256",
        "expected_status_by_vuln",
    }
    normalized_by_id = {}
    scenarios_by_kind = {}
    for scenario in scenarios:
        if not isinstance(scenario, dict) or set(scenario) != scenario_required:
            raise RuntimeError("decision oracle scenario fields differ from the closed schema")
        scenario_id = scenario.get("id")
        kind = scenario.get("kind")
        if (
            not isinstance(scenario_id, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", scenario_id)
        ):
            raise RuntimeError("decision oracle scenario id is invalid")
        if scenario_id in normalized_by_id:
            raise RuntimeError("decision oracle scenario ids must be unique")
        if kind not in {"baseline", "negative_control"} or kind in scenarios_by_kind:
            raise RuntimeError(
                "decision oracle must contain exactly one baseline and one negative_control"
            )
        claimed_hostname = scenario.get("asset_hostname")
        if (
            not isinstance(claimed_hostname, str)
            or not 1 <= len(claimed_hostname.strip()) <= 255
        ):
            raise RuntimeError("decision oracle scenario asset_hostname is invalid")
        bound_state = scenario.get("source_state_sha256")
        if not isinstance(bound_state, str) or not re.fullmatch(
            r"[0-9a-f]{64}", bound_state
        ):
            raise RuntimeError("decision oracle scenario source_state_sha256 is invalid")
        raw_expected = scenario.get("expected_status_by_vuln")
        if not isinstance(raw_expected, dict) or set(raw_expected) != curated_vulns:
            keys = set(raw_expected) if isinstance(raw_expected, dict) else set()
            missing = sorted(curated_vulns - keys)[:10]
            extra = sorted(keys - curated_vulns)[:10]
            raise RuntimeError(
                "decision oracle scenario must adjudicate every and only automated rule: "
                f"missing={missing} extra={extra}"
            )
        invalid = sorted(
            vuln_id
            for vuln_id, status in raw_expected.items()
            if status not in ORACLE_STATUSES
        )
        if invalid:
            raise RuntimeError(
                "decision oracle scenario contains schema-invalid or unresolved "
                f"statuses: {invalid[:10]}"
            )
        normalized_by_id[scenario_id] = {
            vuln_id: ORACLE_STATUSES[status]
            for vuln_id, status in raw_expected.items()
        }
        scenarios_by_kind[kind] = scenario

    if set(scenarios_by_kind) != {"baseline", "negative_control"}:
        raise RuntimeError(
            "decision oracle must contain exactly one baseline and one negative_control"
        )
    baseline_id = scenarios_by_kind["baseline"]["id"]
    negative_id = scenarios_by_kind["negative_control"]["id"]
    if normalized_by_id[baseline_id] == normalized_by_id[negative_id]:
        raise RuntimeError(
            "negative-control oracle scenario must differ from the baseline decisions"
        )
    if "finding" not in normalized_by_id[negative_id].values():
        raise RuntimeError(
            "negative-control oracle scenario must contain at least one Finding"
        )

    selected = scenarios_by_kind.get(scenario_kind)
    if selected is None:
        raise RuntimeError(f"decision oracle has no {scenario_kind} scenario")
    if selected["asset_hostname"].strip().lower() != hostname.strip().lower():
        raise RuntimeError(
            "decision oracle scenario asset_hostname does not match the evaluated asset"
        )
    if selected["source_state_sha256"] != source_state_sha256:
        raise RuntimeError(
            "decision oracle scenario source state does not match the evaluated input"
        )
    expected = normalized_by_id[selected["id"]]
    return expected, {
        "oracle_sha256": hashlib.sha256(raw).hexdigest(),
        "oracle_adjudicated_at": document["adjudicated_at"],
        "oracle_adjudicator": adjudicator.strip(),
        "oracle_expected_status_sha256": canonical_status_sha256(normalized_by_id),
        "oracle_scenario_id": selected["id"],
    }


def validate_target_manifest(repo):
    path = repo / "content/supported-targets.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    entries = document.get("targets") or {}
    by_gate = {
        value.get("acceptance_gate"): value
        for value in entries.values()
        if isinstance(value, dict)
    }
    if set(by_gate) != {target["slug"] for target in TARGETS}:
        raise RuntimeError("live acceptance targets drift from supported-target gates")
    for target in TARGETS:
        entry = by_gate[target["slug"]]
        expected_mode = "ssh_transcript" if target["mode"] == "ssh" else "running_configuration"
        expected = {
            "stig_id": target["stig"],
            "stig_release": target["stig_release"],
            "check_pack": target["check_pack"],
            "evidence_mode": expected_mode,
        }
        for field, value in expected.items():
            if entry.get(field) != value:
                raise RuntimeError(
                    f"live acceptance {target['slug']} {field} drift: "
                    f"expected {value!r}, got {entry.get(field)!r}"
                )


def load_expected_rules(library, stig_id, expected_release):
    index = json.loads((library / "index.json").read_text(encoding="utf-8"))
    entry = (index.get("benchmarks") or {}).get(stig_id)
    if not isinstance(entry, dict):
        raise RuntimeError(f"imported library does not contain benchmark {stig_id}")
    relative = pathlib.PurePosixPath(str(entry.get("data_path", "")))
    if relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError("library index contains an unsafe benchmark path")
    benchmark_path = (library / pathlib.Path(*relative.parts)).resolve()
    if library.resolve() not in benchmark_path.parents:
        raise RuntimeError("library benchmark path escapes the library root")
    benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
    if benchmark.get("id") != stig_id:
        raise RuntimeError("library benchmark identity does not match the requested STIG")
    benchmark_release = f"V{benchmark.get('version')}R{benchmark.get('release')}"
    if benchmark_release != expected_release:
        raise RuntimeError(
            f"benchmark release mismatch: expected {expected_release}, got {benchmark_release}"
        )
    rule_ids = [item.get("rule_id") for item in benchmark.get("rules") or []]
    if not rule_ids or any(not isinstance(rule_id, str) or not rule_id for rule_id in rule_ids):
        raise RuntimeError("imported benchmark contains missing Rule IDs")
    if len(set(rule_ids)) != len(rule_ids):
        raise RuntimeError("imported benchmark contains duplicate Rule IDs")
    if entry.get("rule_count") != len(rule_ids):
        raise RuntimeError("library index rule count does not match imported benchmark")
    return set(rule_ids)


def load_curated_vulns(repo, target):
    pack_path = repo / target["check_pack"]
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    if pack.get("stig_id") != target["stig"]:
        raise RuntimeError(f"curated check pack does not match {target['stig']}")
    vuln_ids = [item.get("vuln_id") for item in pack.get("checks") or []]
    if not vuln_ids or any(not isinstance(vuln_id, str) or not vuln_id for vuln_id in vuln_ids):
        raise RuntimeError("curated check pack contains missing vulnerability IDs")
    if len(set(vuln_ids)) != len(vuln_ids):
        raise RuntimeError("curated check pack contains duplicate vulnerability IDs")
    return set(vuln_ids), sha256_file(pack_path)


def validate_checklist(
    checklist, expected_rule_ids, curated_vulns, expected_status_by_vuln
):
    with checklist.open(encoding="utf-8") as stream:
        result = json.load(stream)
    findings = result.get("findings") or []
    rule_ids = [finding.get("rule_id") for finding in findings]
    if len(rule_ids) != len(set(rule_ids)) or set(rule_ids) != expected_rule_ids:
        missing = sorted(expected_rule_ids - set(rule_ids))[:10]
        extra = sorted(set(rule_ids) - expected_rule_ids)[:10]
        raise RuntimeError(
            f"evaluation Rule-ID set differs from benchmark: missing={missing} extra={extra}"
        )
    status_by_vuln = {
        finding.get("vuln_id"): normalized_status(finding.get("status"))
        for finding in findings
    }
    determined_vulns = {
        vuln_id for vuln_id, status in status_by_vuln.items()
        if status != "notreviewed"
    }
    if determined_vulns != curated_vulns:
        missing = sorted(curated_vulns - determined_vulns)[:10]
        extra = sorted(determined_vulns - curated_vulns)[:10]
        raise RuntimeError(
            "automated determination set differs from the reviewed check pack: "
            f"missing={missing} extra={extra}"
        )
    observed = {vuln_id: status_by_vuln[vuln_id] for vuln_id in curated_vulns}
    if observed != expected_status_by_vuln:
        mismatches = [
            f"{vuln_id}: expected={expected_status_by_vuln.get(vuln_id)} "
            f"observed={observed.get(vuln_id)}"
            for vuln_id in sorted(curated_vulns)
            if observed.get(vuln_id) != expected_status_by_vuln.get(vuln_id)
        ]
        raise RuntimeError(
            "automated decisions differ from the independent oracle: "
            + "; ".join(mismatches[:10])
        )
    return len(findings), len(determined_vulns), observed


def initialize_target(target, repo, binary, root):
    target_root = root / target["slug"]
    library = target_root / "library"
    database = target_root / "data.db"
    checklist = target_root / "checklist.json"
    target_root.mkdir(parents=True, exist_ok=True)
    prefix = [str(binary), "--db", str(database), "--library", str(library)]
    environment = dict(os.environ)
    fixture = pathlib.Path(
        os.environ.get(env_name(target, "XCCDF"), repo / target["fixture"])
    )
    if not fixture.is_file():
        raise RuntimeError(f"configured XCCDF input does not exist: {fixture}")
    imported = run(prefix + ["disa-import", "--input", str(fixture)], environment)
    if imported.returncode:
        raise RuntimeError(f"benchmark import failed: {imported.stderr[-500:]}")
    expected_rule_ids = load_expected_rules(
        library, target["stig"], target["stig_release"]
    )
    curated_vulns, check_pack_sha256 = load_curated_vulns(repo, target)
    return (
        prefix,
        environment,
        fixture,
        checklist,
        expected_rule_ids,
        curated_vulns,
        check_pack_sha256,
    )


def evaluate_scenario(
    prefix,
    environment,
    target,
    input_flag,
    input_path,
    hostname,
    checklist,
    expected_rule_ids,
    curated_vulns,
    expected_status_by_vuln,
):
    evaluated = run(
        prefix
        + [
            "evaluate",
            "--stig",
            target["stig"],
            input_flag,
            str(input_path),
            "--host",
            hostname,
            "--output",
            str(checklist),
            "--format",
            "json",
        ],
        environment,
    )
    if evaluated.returncode:
        raise RuntimeError(f"scenario evaluation failed: {evaluated.stderr[-500:]}")
    return validate_checklist(
        checklist, expected_rule_ids, curated_vulns, expected_status_by_vuln
    )


def scenario_metrics(
    scenarios,
    findings,
    automated,
    check_pack_sha256,
    oracle_metadata,
):
    expected = {
        scenario["id"]: scenario["expected_status_by_vuln"]
        for scenario in scenarios
    }
    observed = {
        scenario["id"]: scenario["observed_status_by_vuln"]
        for scenario in scenarios
    }
    expected_sha256 = canonical_status_sha256(expected)
    observed_sha256 = canonical_status_sha256(observed)
    if expected_sha256 != oracle_metadata["oracle_expected_status_sha256"]:
        raise RuntimeError("selected scenario expectations do not match the oracle bundle")
    if expected_sha256 != observed_sha256:
        raise RuntimeError("observed scenario decisions do not match the oracle bundle")
    bindings = {
        scenario["id"]: {
            "kind": scenario["kind"],
            "hostname": scenario["hostname"].strip().lower(),
            "input_sha256": scenario["input_sha256"],
            "source_state_sha256": scenario["source_state_sha256"],
        }
        for scenario in scenarios
    }
    return {
        "findings": findings,
        "automated": automated,
        "scenario_count": len(scenarios),
        "negative_control_count": sum(
            scenario["kind"] == "negative_control" for scenario in scenarios
        ),
        "negative_finding_count": sum(
            status == "finding"
            for scenario in scenarios
            if scenario["kind"] == "negative_control"
            for status in scenario["expected_status_by_vuln"].values()
        ),
        "check_pack_sha256": check_pack_sha256,
        "input_sha256": canonical_status_sha256(
            {scenario["id"]: scenario["input_sha256"] for scenario in scenarios}
        ),
        "source_state_sha256": canonical_status_sha256(
            {
                scenario["id"]: scenario["source_state_sha256"]
                for scenario in scenarios
            }
        ),
        "scenario_bindings_sha256": canonical_status_sha256(bindings),
        "oracle_sha256": oracle_metadata["oracle_sha256"],
        "oracle_adjudicated_at": oracle_metadata["oracle_adjudicated_at"],
        "oracle_adjudicator": oracle_metadata["oracle_adjudicator"],
        "oracle_expected_status_sha256": expected_sha256,
        "observed_status_sha256": observed_sha256,
    }


def exercise_ssh(target, repo, binary, root):
    host = require_setting(target, "HOST")
    username = require_setting(target, "USERNAME")
    port = os.environ.get(env_name(target, "PORT"), "22")
    hostname = os.environ.get(env_name(target, "HOSTNAME"), host)
    (
        prefix, environment, fixture, checklist, expected_rule_ids,
        curated_vulns, check_pack_sha256,
    ) = initialize_target(target, repo, binary, root)
    target_root = checklist.parent
    evidence = target_root / "evidence.json"

    collect = prefix + [
        "collect",
        "--stig", target["stig"],
        "--host", host,
        "--hostname", hostname,
        "--username", username,
        "--port", port,
        "--output", str(evidence),
        "--timeout-secs", os.environ.get(env_name(target, "TIMEOUT_SECS"), "30"),
    ]
    key = os.environ.get(env_name(target, "KEY"))
    if key:
        collect += ["--key", key, "--passphrase-env", env_name(target, "KEY_PASSPHRASE")]
    else:
        require_setting(target, "PASSWORD")
        collect += ["--password-env", env_name(target, "PASSWORD")]
    if os.environ.get(env_name(target, "TRUST_ON_FIRST_USE"), "").lower() in {
        "1", "true", "yes"
    }:
        raise RuntimeError(
            "TRUST_ON_FIRST_USE is forbidden in live release acceptance; "
            "pin the host key out of band first"
        )

    collected = run(collect, environment)
    if collected.returncode:
        raise RuntimeError(f"collection was not complete: {collected.stderr[-500:]}")
    baseline_document = load_complete_evidence(evidence)
    negative_evidence = target_root / "negative-evidence.json"
    negative_input_sha256 = snapshot_regular_file(
        require_setting(target, "NEGATIVE_EVIDENCE"), negative_evidence
    )
    negative_document = load_complete_evidence(negative_evidence)
    oracle_path = require_setting(target, "ORACLE")
    scenarios = []
    counts = []
    for kind, input_path, document, input_sha256 in (
        ("baseline", evidence, baseline_document, sha256_file(evidence)),
        (
            "negative_control",
            negative_evidence,
            negative_document,
            negative_input_sha256,
        ),
    ):
        source_state_sha256 = evidence_state_sha256(document)
        expected_status_by_vuln, oracle = load_decision_oracle(
            target,
            oracle_path,
            curated_vulns,
            sha256_file(fixture),
            check_pack_sha256,
            kind,
            hostname,
            source_state_sha256,
        )
        scenario_id = oracle["oracle_scenario_id"]
        scenario_checklist = checklist.with_name(f"{scenario_id}-checklist.json")
        finding_count, automated_count, observed_status_by_vuln = evaluate_scenario(
            prefix,
            environment,
            target,
            "--evidence",
            input_path,
            hostname,
            scenario_checklist,
            expected_rule_ids,
            curated_vulns,
            expected_status_by_vuln,
        )
        if sha256_file(input_path) != input_sha256:
            raise RuntimeError("evidence input changed while it was being evaluated")
        counts.append((finding_count, automated_count))
        scenarios.append(
            {
                "id": scenario_id,
                "kind": kind,
                "hostname": hostname,
                "input_sha256": input_sha256,
                "source_state_sha256": source_state_sha256,
                "expected_status_by_vuln": expected_status_by_vuln,
                "observed_status_by_vuln": observed_status_by_vuln,
            }
        )
    if len(set(counts)) != 1:
        raise RuntimeError("scenario finding or automated-control counts drifted")
    metrics = scenario_metrics(
        scenarios, counts[0][0], counts[0][1], check_pack_sha256, oracle
    )
    metrics.update(
        {
            "commands": len(baseline_document["commands"])
            + len(negative_document["commands"]),
            "benchmark_rule_set_sha256": canonical_set_sha256(expected_rule_ids),
            "automated_vuln_set_sha256": canonical_set_sha256(curated_vulns),
        }
    )
    return metrics


def exercise_config(target, repo, binary, root):
    hostname = require_setting(target, "HOSTNAME")
    (
        prefix, environment, fixture, checklist, expected_rule_ids,
        curated_vulns, check_pack_sha256,
    ) = initialize_target(target, repo, binary, root)
    target_root = checklist.parent
    baseline_config = target_root / "baseline-running-config.txt"
    negative_config = target_root / "negative-running-config.txt"
    inputs = (
        (
            "baseline",
            baseline_config,
            snapshot_regular_file(require_setting(target, "CONFIG"), baseline_config),
        ),
        (
            "negative_control",
            negative_config,
            snapshot_regular_file(
                require_setting(target, "NEGATIVE_CONFIG"), negative_config
            ),
        ),
    )
    oracle_path = require_setting(target, "ORACLE")
    scenarios = []
    counts = []
    for kind, input_path, input_sha256 in inputs:
        source_state_sha256 = input_sha256
        expected_status_by_vuln, oracle = load_decision_oracle(
            target,
            oracle_path,
            curated_vulns,
            sha256_file(fixture),
            check_pack_sha256,
            kind,
            hostname,
            source_state_sha256,
        )
        scenario_id = oracle["oracle_scenario_id"]
        scenario_checklist = checklist.with_name(f"{scenario_id}-checklist.json")
        finding_count, automated_count, observed_status_by_vuln = evaluate_scenario(
            prefix,
            environment,
            target,
            "--config",
            input_path,
            hostname,
            scenario_checklist,
            expected_rule_ids,
            curated_vulns,
            expected_status_by_vuln,
        )
        if sha256_file(input_path) != input_sha256:
            raise RuntimeError("running configuration changed while it was being evaluated")
        counts.append((finding_count, automated_count))
        scenarios.append(
            {
                "id": scenario_id,
                "kind": kind,
                "hostname": hostname,
                "input_sha256": input_sha256,
                "source_state_sha256": source_state_sha256,
                "expected_status_by_vuln": expected_status_by_vuln,
                "observed_status_by_vuln": observed_status_by_vuln,
            }
        )
    if len(set(counts)) != 1:
        raise RuntimeError("scenario finding or automated-control counts drifted")
    metrics = scenario_metrics(
        scenarios, counts[0][0], counts[0][1], check_pack_sha256, oracle
    )
    metrics.update(
        {
            "commands": 0,
            "benchmark_rule_set_sha256": canonical_set_sha256(expected_rule_ids),
            "automated_vuln_set_sha256": canonical_set_sha256(curated_vulns),
        }
    )
    return metrics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--binary")
    parser.add_argument("--require-live", action="store_true")
    parser.add_argument(
        "--hash-source-state",
        type=pathlib.Path,
        help="print the oracle source-state digest for an evidence JSON or configuration file",
    )
    parser.add_argument(
        "--source-kind",
        choices=("evidence", "config"),
        help="input kind used with --hash-source-state",
    )
    parser.add_argument(
        "--target", choices=("all", "ontap", "freebsd", "cisco-ios-xe"), default="all",
        help="limit an authorized lab run to one target type",
    )
    parser.add_argument(
        "--evidence-output",
        type=pathlib.Path,
        help="write a redacted, hashable acceptance summary (never command output or credentials)",
    )
    args = parser.parse_args()

    repo = pathlib.Path(args.repo_root).resolve()
    if args.hash_source_state:
        if not args.source_kind:
            print("FAIL: --source-kind is required with --hash-source-state")
            return 1
        path = args.hash_source_state
        if not path.is_file() or path.is_symlink():
            print(f"FAIL: source state must be a regular nonsymlink file: {path}")
            return 1
        try:
            if args.source_kind == "config":
                print(sha256_file(path))
            else:
                document = json.loads(path.read_text(encoding="utf-8"))
                if (
                    not isinstance(document, dict)
                    or document.get("schema") != "automatestig-evidence/v2"
                    or document.get("complete") is not True
                ):
                    raise RuntimeError(
                        "evidence source state requires a complete evidence v2 document"
                    )
                print(evidence_state_sha256(document))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as error:
            print(f"FAIL: cannot hash source state: {error}")
            return 1
        return 0
    if args.source_kind:
        print("FAIL: --source-kind requires --hash-source-state")
        return 1
    try:
        validate_target_manifest(repo)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"FAIL: supported-target manifest mismatch: {error}")
        return 1
    suffix = ".exe" if sys.platform == "win32" else ""
    binary = pathlib.Path(
        args.binary or os.environ.get("AUTOMATESTIG_BIN", repo / f"target/release/automatestig{suffix}")
    )
    selected = [
        target for target in TARGETS
        if args.target == "all" or target["slug"].replace("_", "-") == args.target
    ]
    configured = [
        target for target in selected
        if os.environ.get(env_name(target, "HOST" if target["mode"] == "ssh" else "CONFIG"))
    ]
    if args.require_live and len(configured) != len(selected):
        missing = [
            env_name(target, "HOST" if target["mode"] == "ssh" else "CONFIG")
            for target in selected if target not in configured
        ]
        print(f"FAIL: required live targets are not configured: {', '.join(missing)}")
        return 1
    if configured and not binary.is_file():
        print(f"FAIL: collector binary does not exist: {binary}")
        return 1

    failures = 0
    records = []
    with tempfile.TemporaryDirectory(prefix="automatestig-live-devices-") as temporary:
        for target in selected:
            if target not in configured:
                setting = "SSH target" if target["mode"] == "ssh" else "running config"
                print(f"SKIP: {target['name']} live {setting} not configured")
                continue
            try:
                exercise = exercise_ssh if target["mode"] == "ssh" else exercise_config
                metrics = exercise(target, repo, binary, pathlib.Path(temporary))
                print(
                    f"PASS: {target['name']} commands={metrics['commands']} "
                    f"findings={metrics['findings']} automated={metrics['automated']}"
                )
                fixture = pathlib.Path(
                    os.environ.get(env_name(target, "XCCDF"), repo / target["fixture"])
                )
                records.append({
                    "target": target["slug"],
                    "stig_id": target["stig"],
                    "stig_release": target["stig_release"],
                    "status": "passed",
                    "commands": metrics["commands"],
                    "findings": metrics["findings"],
                    "automated_determinations": metrics["automated"],
                    "scenario_count": metrics["scenario_count"],
                    "negative_control_count": metrics["negative_control_count"],
                    "negative_finding_count": metrics["negative_finding_count"],
                    "benchmark_sha256": sha256_file(fixture),
                    "benchmark_rule_set_sha256": metrics["benchmark_rule_set_sha256"],
                    "automated_vuln_set_sha256": metrics["automated_vuln_set_sha256"],
                    "check_pack_sha256": metrics["check_pack_sha256"],
                    "input_sha256": metrics["input_sha256"],
                    "source_state_sha256": metrics["source_state_sha256"],
                    "scenario_bindings_sha256": metrics["scenario_bindings_sha256"],
                    "oracle_sha256": metrics["oracle_sha256"],
                    "oracle_adjudicated_at": metrics["oracle_adjudicated_at"],
                    "oracle_adjudicator": metrics["oracle_adjudicator"],
                    "oracle_expected_status_sha256": metrics[
                        "oracle_expected_status_sha256"
                    ],
                    "observed_status_sha256": metrics["observed_status_sha256"],
                })
            except Exception as error:  # acceptance runner must aggregate both targets
                failures += 1
                print(f"FAIL: {target['name']}: {error}")
                records.append({"target": target["name"].lower(), "status": "failed"})

    print(
        f"Live device acceptance completed: {len(configured) - failures}/"
        f"{len(configured)} configured targets passed"
    )
    if args.evidence_output:
        document = {
            "schema": "automatestig-live-device-acceptance/v1",
            "executed_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "binary_sha256": sha256_file(binary) if binary.is_file() else None,
            "source_commit": subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip(),
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
            "protected_environment": os.environ.get("AUTOMATESTIG_PROTECTED_ENVIRONMENT"),
            "requested_target": args.target,
            "passed": failures == 0 and len(configured) == len(selected),
            "results": records,
        }
        args.evidence_output.parent.mkdir(parents=True, exist_ok=True)
        args.evidence_output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        print(f"Redacted acceptance evidence written to {args.evidence_output}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
