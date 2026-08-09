#!/usr/bin/env python3
"""Build a fail-closed, target-specific scanner comparison report.

The harness consumes pre-collected results.  It never launches a scanner or
connects to a target, and it never treats a missing comparator result as a
zero.  Native XCCDF is preferred; a proprietary report may be represented by
a separately hashed, independently double-reviewed decision record.
"""

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import stat
import statistics
import sys
import xml.etree.ElementTree as ET

MANIFEST_SCHEMA = "automatestig-scanner-comparison/v2"
DRAFT_MANIFEST_SCHEMA = "automatestig-scanner-comparison-draft/v1"
LEGACY_MANIFEST_SCHEMA = "automatestig-scanner-comparison/v1"
MANIFEST_SCHEMA_URI = (
    "https://automatestig.dev/schemas/scanner-comparison-manifest.schema.json"
)
DECISION_SCHEMA = "automatestig-normalized-scanner-decisions/v1"
DECISION_SCHEMA_URI = (
    "https://automatestig.dev/schemas/normalized-scanner-decisions.schema.json"
)
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_XCCDF_BYTES = 32 * 1024 * 1024
MAX_DECISION_BYTES = 4 * 1024 * 1024
MAX_PROPRIETARY_EXPORT_BYTES = 256 * 1024 * 1024
MAX_BOUND_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_FAILURE_EVIDENCE_BYTES = 256 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
VULN_RE = re.compile(r"V-[0-9]+")
REQUIRED_CASE_KINDS = {
    "compliant",
    "noncompliant",
    "permission_denied",
    "transport_failure",
    "truncated_output",
    "ambiguous_output",
    "unsupported_version",
}
INCOMPLETE_CASE_KINDS = REQUIRED_CASE_KINDS - {"compliant", "noncompliant"}
CANONICAL_STATUSES = {"Finding", "NotAFinding", "NotApplicable"}
XCCDF_RESULTS = {
    "pass": "NotAFinding",
    "fail": "Finding",
    "notapplicable": "NotApplicable",
}
XCCDF_1_2_NAMESPACE = "http://checklists.nist.gov/xccdf/1.2"
XCCDF_CONTROLLED_ELEMENTS = {
    "Benchmark",
    "Group",
    "Rule",
    "TestResult",
    "rule-result",
    "result",
}
FAILURE_STAGES = {"setup", "preflight", "collection", "evaluation", "export", "normalization"}
FAILURE_CODES = {
    "permission_denied",
    "transport_failure",
    "truncated_output",
    "ambiguous_output",
    "unsupported_version",
    "tool_error",
    "no_usable_export",
    "license_unavailable",
    "operator_error",
    "other",
}


class ComparisonError(RuntimeError):
    """An input cannot support a defensible comparison."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ComparisonError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ComparisonError(f"non-finite JSON number is forbidden: {value}")


def _strict_json(raw, label):
    try:
        return json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except ComparisonError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ComparisonError(f"invalid {label} JSON: {error}") from error


def _canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _expect_object(value, label, required):
    if not isinstance(value, dict):
        raise ComparisonError(f"{label} must be an object")
    actual = set(value)
    expected = set(required)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ComparisonError(
            f"{label} members do not match the contract; missing={missing}, extra={extra}"
        )
    return value


def _expect_string(value, label, *, maximum=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ComparisonError(f"{label} must be a non-empty string of at most {maximum} characters")
    return value


def _expect_slug(value, label):
    _expect_string(value, label, maximum=128)
    if not SLUG_RE.fullmatch(value):
        raise ComparisonError(f"{label} is not a safe identifier")
    return value


def _expect_sha256(value, label):
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ComparisonError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _expect_integer(value, label, *, minimum=0, maximum=2**31 - 1):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ComparisonError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ComparisonError(f"{label} must be between {minimum} and {maximum}")
    return value


def _parse_time(value, label):
    _expect_string(value, label, maximum=40)
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ComparisonError(f"{label} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise ComparisonError(f"{label} must include a time-zone offset")
    return parsed.astimezone(datetime.timezone.utc)


def _file_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)


def _read_regular(path, maximum, label):
    path = pathlib.Path(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ComparisonError(f"cannot inspect {label} {path}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ComparisonError(f"{label} must be a regular, non-symlink file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise ComparisonError(f"{label} must be 1..{maximum} bytes: {path}")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ComparisonError(f"cannot read {label} {path}: {error}") from error
    try:
        after = path.lstat()
    except OSError as error:
        raise ComparisonError(f"cannot re-inspect {label} {path}: {error}") from error
    if len(raw) != metadata.st_size or _file_identity(after) != _file_identity(metadata):
        raise ComparisonError(f"{label} changed while it was being read: {path}")
    return raw


def _sha256_regular(path, maximum, label):
    path = pathlib.Path(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ComparisonError(f"cannot inspect {label} {path}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ComparisonError(f"{label} must be a regular, non-symlink file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise ComparisonError(f"{label} must be 1..{maximum} bytes: {path}")
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > maximum:
                    raise ComparisonError(f"{label} exceeds {maximum} bytes while being read: {path}")
                digest.update(chunk)
        after = path.lstat()
    except ComparisonError:
        raise
    except OSError as error:
        raise ComparisonError(f"cannot hash {label} {path}: {error}") from error
    if total != metadata.st_size or _file_identity(after) != _file_identity(metadata):
        raise ComparisonError(f"{label} changed while it was being hashed: {path}")
    return digest.hexdigest()


def _artifact_path(root, relative, label):
    _expect_string(relative, label, maximum=512)
    candidate = pathlib.Path(relative)
    if candidate.is_absolute() or not candidate.parts or any(
        part in {"", ".", ".."} for part in candidate.parts
    ):
        raise ComparisonError(f"{label} must be relative to the manifest directory")
    root = root.resolve()
    current = root
    for index, part in enumerate(candidate.parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ComparisonError(
                f"{label} escapes or is missing from the comparison directory"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ComparisonError(f"{label} must not contain a symlink component: {current}")
        if index < len(candidate.parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise ComparisonError(f"{label} has a non-directory path component: {current}")
    return current


def _verify_bound_artifact(root, relative, expected_sha256, label, bound_paths):
    _expect_sha256(expected_sha256, f"{label} sha256")
    path = _artifact_path(root, relative, f"{label} path")
    actual = _sha256_regular(path, MAX_BOUND_ARTIFACT_BYTES, label)
    if actual != expected_sha256:
        raise ComparisonError(f"{label} digest mismatch: {path.name}")
    bound_paths.add(path)
    return path


def _expanded_name(tag):
    if not isinstance(tag, str):
        return None, ""
    if tag.startswith("{") and "}" in tag:
        namespace, local = tag[1:].split("}", 1)
        return namespace, local
    return None, tag


def _vuln_from_text(value):
    match = VULN_RE.search(value or "")
    return match.group(0) if match else None


def _xccdf_qname(local):
    return f"{{{XCCDF_1_2_NAMESPACE}}}{local}"


def parse_xccdf(raw, expected_benchmark_id, expected_release, expected_test_result_id):
    lowered = raw.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ComparisonError("XCCDF DTD and entity declarations are forbidden")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise ComparisonError(f"invalid XCCDF XML: {error}") from error
    if root.tag != f"{{{XCCDF_1_2_NAMESPACE}}}Benchmark":
        raise ComparisonError("result XML root must be an XCCDF 1.2 Benchmark")
    for element in root.iter():
        namespace, local = _expanded_name(element.tag)
        if local in XCCDF_CONTROLLED_ELEMENTS and namespace != XCCDF_1_2_NAMESPACE:
            raise ComparisonError(
                f"XCCDF element {local} uses an unexpected namespace"
            )
    if root.get("id") != expected_benchmark_id:
        raise ComparisonError("XCCDF Benchmark id does not match the manifest benchmark")

    benchmark_versions = root.findall(_xccdf_qname("version"))
    if len(benchmark_versions) != 1 or (benchmark_versions[0].text or "").strip() != expected_release:
        raise ComparisonError("XCCDF Benchmark version does not match the manifest release")
    all_test_results = list(root.iter(_xccdf_qname("TestResult")))
    direct_test_results = root.findall(_xccdf_qname("TestResult"))
    if len(all_test_results) != 1 or direct_test_results != all_test_results:
        raise ComparisonError("XCCDF Benchmark must contain exactly one direct TestResult")
    test_result = all_test_results[0]
    if test_result.get("id") != expected_test_result_id:
        raise ComparisonError("XCCDF TestResult id does not match the declared run result")
    if test_result.get("version") != expected_release:
        raise ComparisonError("XCCDF TestResult version does not match the manifest release")

    rule_to_vuln = {}
    for group in root.iter():
        if group.tag != _xccdf_qname("Group"):
            continue
        vuln = _vuln_from_text(group.get("id", ""))
        if not vuln:
            for child in group:
                if child.tag in {_xccdf_qname("version"), _xccdf_qname("ident")}:
                    vuln = _vuln_from_text(child.text or "")
                    if vuln:
                        break
        if not vuln:
            continue
        for rule in group.iter():
            if rule.tag == _xccdf_qname("Rule") and rule.get("id"):
                existing = rule_to_vuln.setdefault(rule.get("id"), vuln)
                if existing != vuln:
                    raise ComparisonError(f"XCCDF rule identity maps to multiple vulnerabilities: {rule.get('id')}")

    statuses = {}
    for row in test_result.iter():
        if row.tag != _xccdf_qname("rule-result"):
            continue
        idref = row.get("idref", "")
        vuln = rule_to_vuln.get(idref) or _vuln_from_text(idref)
        result = next(
            (
                (child.text or "").strip().lower()
                for child in row
                if child.tag == _xccdf_qname("result")
            ),
            "",
        )
        determined = XCCDF_RESULTS.get(result)
        if determined is None:
            continue
        if not vuln:
            raise ComparisonError(f"determined XCCDF rule-result has no V-ID mapping: {idref}")
        if vuln in statuses:
            raise ComparisonError(f"duplicate determined XCCDF result for {vuln}")
        statuses[vuln] = determined
    return statuses


def parse_normalized_decisions(raw, expected_source_sha256, adjudicator_ids):
    document = _strict_json(raw, "normalized decision")
    _expect_object(
        document,
        "normalized decision",
        {
            "$schema",
            "schema",
            "source_export_sha256",
            "normalization",
            "status_by_vuln",
        },
    )
    if document["$schema"] != DECISION_SCHEMA_URI or document["schema"] != DECISION_SCHEMA:
        raise ComparisonError("normalized decision uses an unsupported schema")
    _expect_sha256(document["source_export_sha256"], "normalized decision source_export_sha256")
    if document["source_export_sha256"] != expected_source_sha256:
        raise ComparisonError("normalized decision is not bound to the declared proprietary export")
    normalization = _expect_object(
        document["normalization"],
        "normalized decision normalization",
        {
            "method",
            "procedure_sha256",
            "independent_of_oracle",
            "reviewers",
        },
    )
    if normalization["method"] != "double_reviewed_transcription":
        raise ComparisonError("proprietary results require double_reviewed_transcription")
    _expect_sha256(normalization["procedure_sha256"], "normalization procedure_sha256")
    if normalization["independent_of_oracle"] is not True:
        raise ComparisonError("normalization must be performed without access to the oracle")
    reviewers = normalization["reviewers"]
    if not isinstance(reviewers, list) or len(reviewers) < 2:
        raise ComparisonError("normalization requires at least two reviewers")
    reviewer_ids = []
    for index, reviewer in enumerate(reviewers):
        reviewer_ids.append(_expect_slug(reviewer, f"normalization reviewer {index}"))
    if len(set(reviewer_ids)) != len(reviewer_ids):
        raise ComparisonError("normalization reviewers must be distinct")
    if set(reviewer_ids) & adjudicator_ids:
        raise ComparisonError("normalization reviewers must be independent of ground-truth adjudicators")
    return _validate_status_map(document["status_by_vuln"], "normalized decision status_by_vuln", allow_empty=True)


def _validate_status_map(value, label, *, allow_empty):
    if not isinstance(value, dict) or (not allow_empty and not value):
        qualifier = "an object" if allow_empty else "a non-empty object"
        raise ComparisonError(f"{label} must be {qualifier}")
    statuses = {}
    for vuln, status in value.items():
        if not re.fullmatch(r"V-[0-9]+", vuln):
            raise ComparisonError(f"{label} has an invalid V-ID: {vuln}")
        if status not in CANONICAL_STATUSES:
            raise ComparisonError(f"{label} has an invalid status for {vuln}: {status}")
        statuses[vuln] = status
    return statuses


def expected_schedule(tool_ids, case_ids, repetitions, seed_sha256):
    seed = bytes.fromhex(seed_sha256)
    slots = [
        (tool_id, case_id, repetition)
        for tool_id in tool_ids
        for case_id in case_ids
        for repetition in range(1, repetitions + 1)
    ]
    return sorted(
        slots,
        key=lambda slot: hashlib.sha256(
            seed + b"\0" + "\0".join(map(str, slot)).encode("utf-8")
        ).digest(),
    )


def _validate_target(value, root, bound_paths):
    target = _expect_object(
        value,
        "target",
        {
            "family",
            "model",
            "software_version",
            "context",
            "hardware_identity_path",
            "hardware_identity_sha256",
            "privilege_profile_path",
            "privilege_profile_sha256",
            "network_path_artifact_path",
            "network_path_sha256",
            "site_policy_path",
            "site_policy_sha256",
            "representative_authorized_device",
            "synthetic",
        },
    )
    for member in ("family", "model", "software_version", "context"):
        _expect_string(target[member], f"target {member}", maximum=256)
    artifact_paths = {
        "hardware_identity": "hardware_identity_path",
        "privilege_profile": "privilege_profile_path",
        "network_path": "network_path_artifact_path",
        "site_policy": "site_policy_path",
    }
    for member, path_member in artifact_paths.items():
        _verify_bound_artifact(
            root,
            target[path_member],
            target[f"{member}_sha256"],
            f"target {member}",
            bound_paths,
        )
    if target["representative_authorized_device"] is not True or target["synthetic"] is not False:
        raise ComparisonError("comparison targets must be representative authorized devices, not fixtures")
    return target


def _validate_benchmark(value, root, bound_paths):
    benchmark = _expect_object(
        value,
        "benchmark",
        {
            "id",
            "release",
            "xccdf_benchmark_id",
            "source_path",
            "source_sha256",
            "effective_model_path",
            "effective_model_sha256",
        },
    )
    _expect_string(benchmark["id"], "benchmark id", maximum=256)
    _expect_string(
        benchmark["xccdf_benchmark_id"], "benchmark xccdf_benchmark_id", maximum=512
    )
    if not isinstance(benchmark["release"], str) or not re.fullmatch(r"V[0-9]+R[0-9]+", benchmark["release"]):
        raise ComparisonError("benchmark release must have the form VnRm")
    for member in ("source", "effective_model"):
        _verify_bound_artifact(
            root,
            benchmark[f"{member}_path"],
            benchmark[f"{member}_sha256"],
            f"benchmark {member}",
            bound_paths,
        )
    return benchmark


def _validate_oracle(value, created_at, target_software_version, root, bound_paths):
    oracle = _expect_object(
        value,
        "oracle",
        {
            "adjudicated_at",
            "adjudication_basis",
            "independent_of_tool_outputs",
            "adjudicators",
            "cases",
        },
    )
    adjudicated_at = _parse_time(oracle["adjudicated_at"], "oracle adjudicated_at")
    if adjudicated_at > created_at:
        raise ComparisonError("oracle adjudication cannot occur after manifest creation")
    basis = _expect_string(
        oracle["adjudication_basis"], "oracle adjudication_basis", maximum=4000
    )
    if len(basis.strip()) < 20:
        raise ComparisonError("oracle adjudication_basis must describe the independent procedure")
    if oracle["independent_of_tool_outputs"] is not True:
        raise ComparisonError("ground truth must be established independently of tool outputs")
    adjudicators = oracle["adjudicators"]
    if not isinstance(adjudicators, list) or len(adjudicators) < 2:
        raise ComparisonError("oracle requires a cybersecurity SME and a test owner")
    adjudicator_ids = set()
    cybersecurity_sme_count = 0
    test_owner_count = 0
    for index, entry in enumerate(adjudicators):
        entry = _expect_object(entry, f"oracle adjudicator {index}", {"id", "roles"})
        identifier = _expect_slug(entry["id"], f"oracle adjudicator {index} id")
        if identifier in adjudicator_ids:
            raise ComparisonError("oracle adjudicators must be distinct")
        adjudicator_ids.add(identifier)
        roles = entry["roles"]
        if (
            not isinstance(roles, list)
            or not roles
            or len(set(roles)) != len(roles)
            or not set(roles) <= {"cybersecurity_sme", "test_owner"}
        ):
            raise ComparisonError(
                "oracle adjudicator roles must be a unique list of cybersecurity_sme/test_owner"
            )
        cybersecurity_sme_count += "cybersecurity_sme" in roles
        test_owner_count += "test_owner" in roles
    if cybersecurity_sme_count < 2 or test_owner_count < 1:
        raise ComparisonError(
            "oracle requires two cybersecurity SMEs and at least one test owner"
        )

    cases_value = oracle["cases"]
    if not isinstance(cases_value, list) or not cases_value:
        raise ComparisonError("oracle cases must be a non-empty array")
    cases = {}
    kinds = set()
    for index, entry in enumerate(cases_value):
        entry = _expect_object(
            entry,
            f"oracle case {index}",
            {
                "id",
                "kind",
                "software_version",
                "source_state_path",
                "source_state_sha256",
                "collection_expected",
                "expected_status_by_vuln",
            },
        )
        identifier = _expect_slug(entry["id"], f"oracle case {index} id")
        if identifier in cases:
            raise ComparisonError(f"duplicate oracle case id: {identifier}")
        kind = entry["kind"]
        if kind not in REQUIRED_CASE_KINDS:
            raise ComparisonError(f"unsupported oracle case kind: {kind}")
        software_version = _expect_string(
            entry["software_version"],
            f"oracle case {identifier} software_version",
            maximum=256,
        )
        if kind == "unsupported_version":
            if software_version == target_software_version:
                raise ComparisonError(
                    "unsupported_version case must name a version outside the supported baseline"
                )
        elif software_version != target_software_version:
            raise ComparisonError(
                f"oracle case {identifier} must use the exact baseline software version"
            )
        _verify_bound_artifact(
            root,
            entry["source_state_path"],
            entry["source_state_sha256"],
            f"oracle case {identifier} source state",
            bound_paths,
        )
        if entry["collection_expected"] not in {"complete", "incomplete"}:
            raise ComparisonError(f"oracle case {identifier} has invalid collection_expected")
        if kind in {"compliant", "noncompliant"} and entry["collection_expected"] != "complete":
            raise ComparisonError(f"{kind} case must expect complete collection")
        if kind in INCOMPLETE_CASE_KINDS and entry["collection_expected"] != "incomplete":
            raise ComparisonError(f"{kind} case must expect incomplete collection")
        statuses = _validate_status_map(
            entry["expected_status_by_vuln"],
            f"oracle case {identifier} expected_status_by_vuln",
            allow_empty=kind in INCOMPLETE_CASE_KINDS,
        )
        if kind == "compliant" and "Finding" in statuses.values():
            raise ComparisonError("compliant oracle case cannot contain Finding")
        if kind == "noncompliant" and "Finding" not in statuses.values():
            raise ComparisonError("noncompliant oracle case must contain at least one Finding")
        cases[identifier] = {**entry, "expected_status_by_vuln": statuses}
        kinds.add(kind)
    missing_kinds = sorted(REQUIRED_CASE_KINDS - kinds)
    if missing_kinds:
        raise ComparisonError(f"oracle is missing required case kinds: {missing_kinds}")
    return oracle, adjudicator_ids, cases


def _validate_tools(value, root, bound_paths):
    if not isinstance(value, list) or len(value) < 2:
        raise ComparisonError("tools must contain AutomateSTIG and at least one comparator")
    tools = {}
    classifications = set()
    for index, entry in enumerate(value):
        entry = _expect_object(
            entry,
            f"tool {index}",
            {
                "id",
                "product",
                "vendor",
                "version",
                "artifact_path",
                "artifact_sha256",
                "content_path",
                "content_sha256",
                "classification",
                "setup_trials",
            },
        )
        identifier = _expect_slug(entry["id"], f"tool {index} id")
        if identifier in tools:
            raise ComparisonError(f"duplicate tool id: {identifier}")
        for member in ("product", "vendor", "version"):
            _expect_string(entry[member], f"tool {identifier} {member}", maximum=256)
        for member in ("artifact", "content"):
            _verify_bound_artifact(
                root,
                entry[f"{member}_path"],
                entry[f"{member}_sha256"],
                f"tool {identifier} {member}",
                bound_paths,
            )
        if entry["classification"] not in {"sut", "commercial", "government"}:
            raise ComparisonError(f"tool {identifier} has an invalid classification")
        setup_trials = entry["setup_trials"]
        if not isinstance(setup_trials, list) or len(setup_trials) < 3:
            raise ComparisonError(
                f"tool {identifier} requires at least three clean-workstation setup trials"
            )
        for trial_index, trial in enumerate(setup_trials):
            trial = _expect_object(
                trial,
                f"tool {identifier} setup trial {trial_index}",
                {"duration_ms", "analyst_actions"},
            )
            _expect_integer(
                trial["duration_ms"],
                f"tool {identifier} setup trial {trial_index} duration_ms",
            )
            _expect_integer(
                trial["analyst_actions"],
                f"tool {identifier} setup trial {trial_index} analyst_actions",
            )
        classifications.add(entry["classification"])
        tools[identifier] = entry
    if "automatestig" not in tools or tools["automatestig"]["classification"] != "sut":
        raise ComparisonError("the sut must have tool id automatestig")
    if [entry["classification"] for entry in tools.values()].count("sut") != 1:
        raise ComparisonError("exactly one tool may be classified as sut")
    if not classifications & {"commercial", "government"}:
        raise ComparisonError("at least one commercial or government comparator is required")
    return tools


def _load_run_statuses(result, root, adjudicator_ids, benchmark, used_paths):
    if result is None:
        return {}, "none"
    if not isinstance(result, dict) or "format" not in result:
        raise ComparisonError("run result must be null or an object with a format")
    result_format = result["format"]
    if result_format == "xccdf":
        _expect_object(
            result,
            "XCCDF result",
            {"format", "path", "sha256", "test_result_id"},
        )
        path = _artifact_path(root, result["path"], "XCCDF result path")
        _expect_sha256(result["sha256"], "XCCDF result sha256")
        _expect_string(result["test_result_id"], "XCCDF result test_result_id", maximum=512)
        if path in used_paths:
            raise ComparisonError(f"result artifacts must be unique per run: {path.name}")
        used_paths.add(path)
        raw = _read_regular(path, MAX_XCCDF_BYTES, "XCCDF result")
        if _sha256(raw) != result["sha256"]:
            raise ComparisonError(f"XCCDF result digest mismatch: {path.name}")
        return (
            parse_xccdf(
                raw,
                benchmark["xccdf_benchmark_id"],
                benchmark["release"],
                result["test_result_id"],
            ),
            "native_xccdf",
        )
    if result_format == "normalized-json":
        _expect_object(
            result,
            "normalized JSON result",
            {
                "format",
                "path",
                "sha256",
                "source_export_path",
                "source_export_sha256",
            },
        )
        decision_path = _artifact_path(root, result["path"], "normalized decision path")
        source_path = _artifact_path(root, result["source_export_path"], "proprietary export path")
        if decision_path in used_paths or source_path in used_paths:
            raise ComparisonError("result and source-export artifacts must be unique per run")
        used_paths.update({decision_path, source_path})
        _expect_sha256(result["sha256"], "normalized decision sha256")
        _expect_sha256(result["source_export_sha256"], "proprietary export sha256")
        decision_raw = _read_regular(
            decision_path, MAX_DECISION_BYTES, "normalized decision"
        )
        source_raw = _read_regular(
            source_path, MAX_PROPRIETARY_EXPORT_BYTES, "proprietary export"
        )
        if _sha256(decision_raw) != result["sha256"]:
            raise ComparisonError(f"normalized decision digest mismatch: {decision_path.name}")
        if _sha256(source_raw) != result["source_export_sha256"]:
            raise ComparisonError(f"proprietary export digest mismatch: {source_path.name}")
        return (
            parse_normalized_decisions(
                decision_raw,
                result["source_export_sha256"],
                adjudicator_ids,
            ),
            "double_reviewed_normalization",
        )
    raise ComparisonError(f"unsupported run result format: {result_format}")


def _load_failure(value, collection_complete, root, run_id, used_paths):
    if collection_complete:
        if value is not None:
            raise ComparisonError(f"run {run_id} cannot declare a failure after complete collection")
        return None
    if value is None:
        raise ComparisonError(f"incomplete run {run_id} requires a structured failure reason")
    failure = _expect_object(
        value,
        f"run {run_id} failure",
        {"stage", "code", "detail", "evidence_path", "evidence_sha256"},
    )
    if failure["stage"] not in FAILURE_STAGES:
        raise ComparisonError(f"run {run_id} failure has an invalid stage")
    if failure["code"] not in FAILURE_CODES:
        raise ComparisonError(f"run {run_id} failure has an invalid code")
    detail = _expect_string(failure["detail"], f"run {run_id} failure detail", maximum=2000)
    if len(detail.strip()) < 10:
        raise ComparisonError(f"run {run_id} failure detail is too short")
    _expect_sha256(failure["evidence_sha256"], f"run {run_id} failure evidence_sha256")
    path = _artifact_path(root, failure["evidence_path"], f"run {run_id} failure evidence_path")
    if path in used_paths:
        raise ComparisonError(f"run artifacts must be unique: {path.name}")
    used_paths.add(path)
    raw = _read_regular(path, MAX_FAILURE_EVIDENCE_BYTES, f"run {run_id} failure evidence")
    if _sha256(raw) != failure["evidence_sha256"]:
        raise ComparisonError(f"run {run_id} failure evidence digest mismatch: {path.name}")
    return failure


def _load_manifest_header(path):
    path = pathlib.Path(path).resolve()
    raw = _read_regular(path, MAX_MANIFEST_BYTES, "comparison manifest")
    manifest = _strict_json(raw, "comparison manifest")
    _expect_object(
        manifest,
        "comparison manifest",
        {
            "$schema",
            "schema",
            "comparison_id",
            "created_at",
            "target",
            "benchmark",
            "oracle",
            "randomization",
            "tools",
            "runs",
            "deviations",
        },
    )
    if manifest["$schema"] == MANIFEST_SCHEMA_URI and manifest["schema"] == LEGACY_MANIFEST_SCHEMA:
        raise ComparisonError(
            "comparison manifest v1 is not evidence-safe because its hashes have no verified "
            "artifact paths; migrate it to the draft/v1 or completed/v2 contract"
        )
    if manifest["$schema"] != MANIFEST_SCHEMA_URI or manifest["schema"] not in {
        MANIFEST_SCHEMA,
        DRAFT_MANIFEST_SCHEMA,
    }:
        raise ComparisonError("comparison manifest uses an unsupported schema")
    _expect_slug(manifest["comparison_id"], "comparison_id")
    created_at = _parse_time(manifest["created_at"], "created_at")
    if created_at > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5):
        raise ComparisonError("comparison manifest creation time is in the future")
    bound_paths = set()
    target = _validate_target(manifest["target"], path.parent, bound_paths)
    benchmark = _validate_benchmark(manifest["benchmark"], path.parent, bound_paths)
    oracle, adjudicator_ids, cases = _validate_oracle(
        manifest["oracle"],
        created_at,
        target["software_version"],
        path.parent,
        bound_paths,
    )
    tools = _validate_tools(manifest["tools"], path.parent, bound_paths)
    deviations_value = manifest["deviations"]
    if not isinstance(deviations_value, list):
        raise ComparisonError("deviations must be an array")
    deviation_ids = set()
    deviations = []
    for index, deviation in enumerate(deviations_value):
        deviation = _expect_object(
            deviation,
            f"deviation {index}",
            {"id", "description", "impact", "approved_by"},
        )
        identifier = _expect_slug(deviation["id"], f"deviation {index} id")
        if identifier in deviation_ids:
            raise ComparisonError(f"duplicate deviation id: {identifier}")
        deviation_ids.add(identifier)
        description = _expect_string(
            deviation["description"], f"deviation {identifier} description", maximum=2000
        )
        if len(description.strip()) < 20:
            raise ComparisonError(f"deviation {identifier} description is too short")
        if deviation["impact"] not in {"none", "limits_claim", "invalidates_claim"}:
            raise ComparisonError(f"deviation {identifier} has an invalid impact")
        approved_by = deviation["approved_by"]
        if not isinstance(approved_by, list):
            raise ComparisonError(f"deviation {identifier} approved_by must be an array")
        approved_ids = [
            _expect_slug(approver, f"deviation {identifier} approver")
            for approver in approved_by
        ]
        if (
            len(approved_ids) != len(set(approved_ids))
            or set(approved_ids) != adjudicator_ids
        ):
            raise ComparisonError(
                f"deviation {identifier} must be approved by every oracle adjudicator"
            )
        deviations.append(deviation)
    randomization = _expect_object(
        manifest["randomization"],
        "randomization",
        {"algorithm", "seed_sha256", "repetitions"},
    )
    if randomization["algorithm"] != "sha256-order-v1":
        raise ComparisonError("randomization algorithm must be sha256-order-v1")
    seed = _expect_sha256(randomization["seed_sha256"], "randomization seed_sha256")
    repetitions = _expect_integer(randomization["repetitions"], "randomization repetitions", minimum=3, maximum=100)
    if not isinstance(manifest["runs"], list):
        raise ComparisonError("runs must be an array")
    return {
        "path": path,
        "raw": raw,
        "manifest": manifest,
        "oracle": oracle,
        "benchmark": benchmark,
        "adjudicator_ids": adjudicator_ids,
        "cases": cases,
        "tools": tools,
        "deviations": deviations,
        "seed": seed,
        "repetitions": repetitions,
        "bound_paths": bound_paths,
    }


def prepare_schedule(path):
    """Expand a validated header-only manifest into a fillable run sheet."""
    loaded = _load_manifest_header(path)
    manifest = loaded["manifest"]
    if manifest["schema"] != DRAFT_MANIFEST_SCHEMA:
        raise ComparisonError(
            f"schedule preparation requires schema {DRAFT_MANIFEST_SCHEMA}"
        )
    if manifest["runs"]:
        raise ComparisonError("schedule preparation requires an empty runs array")
    schedule = expected_schedule(
        list(loaded["tools"]),
        list(loaded["cases"]),
        loaded["repetitions"],
        loaded["seed"],
    )
    manifest["runs"] = [
        {
            "id": f"run-{sequence:04}",
            "tool_id": tool_id,
            "case_id": case_id,
            "repetition": repetition,
            "sequence": sequence,
            "source_state_sha256": loaded["cases"][case_id]["source_state_sha256"],
            "collection_complete": None,
            "result": None,
            "failure": None,
            "duration_ms": None,
            "analyst_actions": None,
            "external_script_lines": None,
        }
        for sequence, (tool_id, case_id, repetition) in enumerate(schedule, 1)
    ]
    return manifest


def load_manifest(path):
    loaded = _load_manifest_header(path)
    path = loaded["path"]
    raw = loaded["raw"]
    manifest = loaded["manifest"]
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ComparisonError(
            f"report generation requires completed schema {MANIFEST_SCHEMA}"
        )
    oracle = loaded["oracle"]
    adjudicator_ids = loaded["adjudicator_ids"]
    cases = loaded["cases"]
    tools = loaded["tools"]
    seed = loaded["seed"]
    repetitions = loaded["repetitions"]

    runs_value = manifest["runs"]
    schedule = expected_schedule(list(tools), list(cases), repetitions, seed)
    if len(runs_value) != len(schedule):
        raise ComparisonError(f"runs must contain exactly {len(schedule)} tool/case/repetition slots")
    schedule_by_slot = {slot: index for index, slot in enumerate(schedule, 1)}
    run_ids = set()
    seen_slots = set()
    used_paths = set(loaded["bound_paths"])
    runs = []
    for index, entry in enumerate(runs_value):
        entry = _expect_object(
            entry,
            f"run {index}",
            {
                "id",
                "tool_id",
                "case_id",
                "repetition",
                "sequence",
                "source_state_sha256",
                "collection_complete",
                "result",
                "failure",
                "duration_ms",
                "analyst_actions",
                "external_script_lines",
            },
        )
        run_id = _expect_slug(entry["id"], f"run {index} id")
        if run_id in run_ids:
            raise ComparisonError(f"duplicate run id: {run_id}")
        run_ids.add(run_id)
        tool_id = entry["tool_id"]
        case_id = entry["case_id"]
        if tool_id not in tools or case_id not in cases:
            raise ComparisonError(f"run {run_id} references an unknown tool or case")
        repetition = _expect_integer(entry["repetition"], f"run {run_id} repetition", minimum=1, maximum=repetitions)
        sequence = _expect_integer(entry["sequence"], f"run {run_id} sequence", minimum=1, maximum=len(schedule))
        slot = (tool_id, case_id, repetition)
        if slot in seen_slots:
            raise ComparisonError(f"duplicate tool/case/repetition slot: {slot}")
        seen_slots.add(slot)
        if schedule_by_slot.get(slot) != sequence:
            raise ComparisonError(f"run {run_id} does not follow the committed randomized schedule")
        _expect_sha256(entry["source_state_sha256"], f"run {run_id} source_state_sha256")
        if entry["source_state_sha256"] != cases[case_id]["source_state_sha256"]:
            raise ComparisonError(f"run {run_id} is not bound to the oracle source state")
        if not isinstance(entry["collection_complete"], bool):
            raise ComparisonError(f"run {run_id} collection_complete must be boolean")
        for member in ("duration_ms", "analyst_actions", "external_script_lines"):
            _expect_integer(entry[member], f"run {run_id} {member}")
        failure = _load_failure(
            entry["failure"],
            entry["collection_complete"],
            path.parent,
            run_id,
            used_paths,
        )
        if entry["collection_complete"] and entry["result"] is None:
            raise ComparisonError(f"complete run {run_id} requires a retained result")
        statuses, result_provenance = _load_run_statuses(
            entry["result"],
            path.parent,
            adjudicator_ids,
            loaded["benchmark"],
            used_paths,
        )
        if entry["collection_complete"] and not statuses:
            raise ComparisonError(
                f"complete run {run_id} has no usable determined result rows"
            )
        if (
            tool_id == "automatestig"
            and entry["collection_complete"]
            and result_provenance != "native_xccdf"
        ):
            raise ComparisonError(
                f"complete AutomateSTIG run {run_id} must retain its native XCCDF result"
            )
        runs.append(
            {
                **entry,
                "failure": failure,
                "statuses": statuses,
                "result_provenance": result_provenance,
            }
        )
    if seen_slots != set(schedule):
        raise ComparisonError("runs do not cover every randomized tool/case/repetition slot")
    return {
        "path": path,
        "raw": raw,
        "manifest": manifest,
        "oracle": oracle,
        "cases": cases,
        "tools": tools,
        "deviations": loaded["deviations"],
        "runs": runs,
        "repetitions": repetitions,
    }


def _ratio(numerator, denominator):
    return None if denominator == 0 else numerator / denominator


def _median(values):
    return None if not values else statistics.median(values)


def _tool_metrics(tool_id, runs, cases):
    selected = [run for run in runs if run["tool_id"] == tool_id]
    metrics = {
        "attempts": len(selected),
        "complete_expected_attempts": 0,
        "complete_collections": 0,
        "usable_expected_result_runs": 0,
        "unexpected_complete_collections": 0,
        "failed_runs": 0,
        "expected_decisions": 0,
        "correct_decisions": 0,
        "false_passes": 0,
        "false_failures": 0,
        "status_mismatches": 0,
        "true_findings": 0,
        "emitted_findings": 0,
        "expected_findings": 0,
        "expected_compliant_rows": 0,
        "manual_tail": 0,
        "incomplete_determined_rows": 0,
        "unadjudicated_decisions": 0,
        "traceable_determined_rows": 0,
        "determined_rows": 0,
        "native_xccdf_runs": 0,
        "double_reviewed_normalized_runs": 0,
        "duration_ms_values": [],
        "analyst_action_values": [],
        "external_script_line_values": [],
    }
    for run in selected:
        case = cases[run["case_id"]]
        statuses = run["statuses"]
        determined_count = len(statuses)
        if run["failure"] is not None:
            metrics["failed_runs"] += 1
        metrics["determined_rows"] += determined_count
        metrics["traceable_determined_rows"] += determined_count
        if run["result_provenance"] == "native_xccdf":
            metrics["native_xccdf_runs"] += 1
        elif run["result_provenance"] == "double_reviewed_normalization":
            metrics["double_reviewed_normalized_runs"] += 1
        metrics["duration_ms_values"].append(run["duration_ms"])
        metrics["analyst_action_values"].append(run["analyst_actions"])
        metrics["external_script_line_values"].append(run["external_script_lines"])

        expected_complete = case["collection_expected"] == "complete"
        if expected_complete:
            metrics["complete_expected_attempts"] += 1
            expected = case["expected_status_by_vuln"]
            metrics["expected_decisions"] += len(expected)
            metrics["expected_findings"] += sum(
                status == "Finding" for status in expected.values()
            )
            metrics["expected_compliant_rows"] += sum(
                status == "NotAFinding" for status in expected.values()
            )
            if run["collection_complete"]:
                metrics["complete_collections"] += 1
                if set(statuses) & set(expected):
                    metrics["usable_expected_result_runs"] += 1
            else:
                metrics["manual_tail"] += len(expected)
        elif run["collection_complete"]:
            metrics["unexpected_complete_collections"] += 1

        if not run["collection_complete"] or not expected_complete:
            metrics["incomplete_determined_rows"] += determined_count
            metrics["false_passes"] += sum(
                status == "NotAFinding" for status in statuses.values()
            )
            continue

        expected = case["expected_status_by_vuln"]
        metrics["emitted_findings"] += sum(status == "Finding" for status in statuses.values())
        metrics["unadjudicated_decisions"] += len(set(statuses) - set(expected))
        for vuln, expected_status in expected.items():
            actual = statuses.get(vuln)
            if actual is None:
                metrics["manual_tail"] += 1
                continue
            if actual == expected_status:
                metrics["correct_decisions"] += 1
                if expected_status == "Finding":
                    metrics["true_findings"] += 1
                continue
            metrics["status_mismatches"] += 1
            if expected_status == "Finding":
                metrics["false_passes"] += 1
            elif actual == "Finding":
                metrics["false_failures"] += 1

    true_findings = metrics["true_findings"]
    metrics["collection_success"] = {
        "numerator": metrics["complete_collections"],
        "denominator": metrics["complete_expected_attempts"],
        "rate": _ratio(metrics["complete_collections"], metrics["complete_expected_attempts"]),
    }
    metrics["precision"] = {
        "numerator": true_findings,
        "denominator": metrics["emitted_findings"],
        "rate": _ratio(true_findings, metrics["emitted_findings"]),
    }
    metrics["recall"] = {
        "numerator": true_findings,
        "denominator": metrics["expected_findings"],
        "rate": _ratio(true_findings, metrics["expected_findings"]),
    }
    metrics["automation_depth"] = {
        "numerator": metrics["correct_decisions"],
        "denominator": metrics["expected_decisions"],
        "rate": _ratio(metrics["correct_decisions"], metrics["expected_decisions"]),
    }
    false_pass_denominator = (
        metrics["expected_findings"] + metrics["incomplete_determined_rows"]
    )
    metrics["false_pass_measure"] = {
        "numerator": metrics["false_passes"],
        "denominator": false_pass_denominator,
        "rate": _ratio(metrics["false_passes"], false_pass_denominator),
        "ground_truth_noncompliant_rows": metrics["expected_findings"],
        "unobservable_determined_rows": metrics["incomplete_determined_rows"],
    }
    metrics["false_failure_measure"] = {
        "numerator": metrics["false_failures"],
        "denominator": metrics["expected_compliant_rows"],
        "rate": _ratio(metrics["false_failures"], metrics["expected_compliant_rows"]),
    }
    metrics["manual_tail_measure"] = {
        "numerator": metrics["manual_tail"],
        "denominator": metrics["expected_decisions"],
        "rate": _ratio(metrics["manual_tail"], metrics["expected_decisions"]),
    }
    metrics["evidence_traceability"] = {
        "numerator": metrics["traceable_determined_rows"],
        "denominator": metrics["determined_rows"],
        "rate": _ratio(metrics["traceable_determined_rows"], metrics["determined_rows"]),
    }
    metrics["median_duration_ms"] = _median(metrics.pop("duration_ms_values"))
    metrics["median_analyst_actions"] = _median(metrics.pop("analyst_action_values"))
    metrics["median_external_script_lines"] = _median(metrics.pop("external_script_line_values"))
    return metrics


def _observed_deltas(automatestig, comparator):
    def rate_delta(name):
        left = automatestig[name]["rate"]
        right = comparator[name]["rate"]
        return None if left is None or right is None else left - right

    return {
        "false_passes": comparator["false_passes"] - automatestig["false_passes"],
        "false_failures": comparator["false_failures"] - automatestig["false_failures"],
        "collection_success_rate": rate_delta("collection_success"),
        "precision_rate": rate_delta("precision"),
        "recall_rate": rate_delta("recall"),
        "automation_depth_rate": rate_delta("automation_depth"),
        "manual_tail": comparator["manual_tail"] - automatestig["manual_tail"],
        "median_duration_ms": comparator["median_duration_ms"] - automatestig["median_duration_ms"],
        "median_analyst_actions": comparator["median_analyst_actions"] - automatestig["median_analyst_actions"],
        "median_external_script_lines": comparator["median_external_script_lines"] - automatestig["median_external_script_lines"],
        "median_setup_duration_ms": comparator["median_setup_duration_ms"] - automatestig["median_setup_duration_ms"],
        "median_setup_analyst_actions": comparator["median_setup_analyst_actions"] - automatestig["median_setup_analyst_actions"],
    }


def build_report(loaded):
    manifest = loaded["manifest"]
    tool_metrics = {
        tool_id: _tool_metrics(tool_id, loaded["runs"], loaded["cases"])
        for tool_id in loaded["tools"]
    }
    for tool_id, metrics in tool_metrics.items():
        trials = loaded["tools"][tool_id]["setup_trials"]
        metrics["median_setup_duration_ms"] = _median(
            [trial["duration_ms"] for trial in trials]
        )
        metrics["median_setup_analyst_actions"] = _median(
            [trial["analyst_actions"] for trial in trials]
        )
    sut = tool_metrics["automatestig"]
    safety_gate = (
        sut["false_passes"] == 0
        and sut["status_mismatches"] == 0
        and sut["incomplete_determined_rows"] == 0
        and sut["unexpected_complete_collections"] == 0
        and sut["unadjudicated_decisions"] == 0
    )
    blocking_deviations = [
        deviation["id"]
        for deviation in loaded["deviations"]
        if deviation["impact"] == "invalidates_claim"
    ]
    protocol_gate = not blocking_deviations
    usable_tool_ids = {
        tool_id
        for tool_id, metrics in tool_metrics.items()
        if metrics["complete_expected_attempts"] > 0
        and metrics["usable_expected_result_runs"]
        == metrics["complete_expected_attempts"]
    }
    comparator_ids = {
        tool_id for tool_id in loaded["tools"] if tool_id != "automatestig"
    }
    unusable_comparator_ids = sorted(comparator_ids - usable_tool_ids)
    comparator_results_gate = not unusable_comparator_ids
    sut_results_gate = "automatestig" in usable_tool_ids
    comparison_results_gate = comparator_results_gate and sut_results_gate
    comparisons = {}
    for tool_id in sorted(comparator_ids):
        comparable = sut_results_gate and tool_id in usable_tool_ids
        comparisons[tool_id] = {
            "comparable": comparable,
            "deltas": (
                _observed_deltas(sut, tool_metrics[tool_id]) if comparable else None
            ),
            "reason": (
                None
                if comparable
                else "usable oracle-covered results are missing for one or more expected-complete runs"
            ),
        }

    if blocking_deviations:
        claim_status = "protocol_deviation_blocks_claim"
    elif not comparison_results_gate:
        claim_status = "usable_tool_results_required"
    elif not safety_gate:
        claim_status = "automatestig_safety_gate_failed"
    else:
        claim_status = "independent_result_review_required"
    report = {
        "schema": "automatestig-scanner-comparison-report/v2",
        "comparison_id": manifest["comparison_id"],
        "manifest_sha256": _sha256(loaded["raw"]),
        "created_at": manifest["created_at"],
        "target": manifest["target"],
        "benchmark": manifest["benchmark"],
        "protocol": {
            "representative_authorized_device": True,
            "synthetic": False,
            "ground_truth_independent": True,
            "required_case_kinds": sorted(REQUIRED_CASE_KINDS),
            "repetitions": loaded["repetitions"],
            "randomization_algorithm": manifest["randomization"]["algorithm"],
            "tool_count": len(loaded["tools"]),
            "run_count": len(loaded["runs"]),
            "deviations": loaded["deviations"],
            "blocking_deviation_ids": blocking_deviations,
            "oracle": {
                "adjudicated_at": manifest["oracle"]["adjudicated_at"],
                "adjudicators": manifest["oracle"]["adjudicators"],
                "adjudication_basis_sha256": _sha256(
                    manifest["oracle"]["adjudication_basis"].encode("utf-8")
                ),
            },
        },
        "tools": {
            tool_id: {
                "identity": {
                    member: value
                    for member, value in loaded["tools"][tool_id].items()
                    if member != "setup_trials"
                },
                "metrics": metrics,
                "failures": [
                    {
                        "run_id": run["id"],
                        "case_id": run["case_id"],
                        "repetition": run["repetition"],
                        **run["failure"],
                    }
                    for run in loaded["runs"]
                    if run["tool_id"] == tool_id and run["failure"] is not None
                ],
                "cases": {
                    case_id: {
                        "kind": case["kind"],
                        "software_version": case["software_version"],
                        "metrics": _tool_metrics(
                            tool_id,
                            [
                                run
                                for run in loaded["runs"]
                                if run["case_id"] == case_id
                            ],
                            loaded["cases"],
                        ),
                    }
                    for case_id, case in loaded["cases"].items()
                },
            }
            for tool_id, metrics in tool_metrics.items()
        },
        "observed_advantage_automatestig_over_comparator": comparisons,
        "gates": {
            "protocol_gate_passed": protocol_gate,
            "automatestig_safety_gate_passed": safety_gate,
            "sut_results_gate_passed": sut_results_gate,
            "comparator_results_gate_passed": comparator_results_gate,
            "comparison_results_gate_passed": comparison_results_gate,
            "unusable_comparator_ids": unusable_comparator_ids,
            "technical_report_complete": comparison_results_gate,
            "superiority_claim_automatically_authorized": False,
            "superiority_claim_status": claim_status,
            "note": (
                "Observed deltas are target- and revision-specific measurements. "
                "The harness does not authorize a superiority claim; the cybersecurity "
                "SME and test owner must review variation, deviations, and retained raw artifacts."
            ),
        },
    }
    report["report_sha256"] = _sha256(_canonical_json(report))
    return report


def _format_ratio(value):
    if value["rate"] is None:
        return "n/a"
    return f"{value['numerator']}/{value['denominator']} ({value['rate']:.1%})"


def render_markdown(report):
    target = report["target"]
    benchmark = report["benchmark"]
    lines = [
        f"# Scanner comparison: {report['comparison_id']}",
        "",
        "> This is a measured, target-specific report—not an automatic authorization to claim product superiority.",
        "",
        f"Target: {target['family']} {target['model']} {target['software_version']} ({target['context']})  ",
        f"Benchmark: {benchmark['id']} {benchmark['release']}  ",
        f"Manifest SHA-256: `{report['manifest_sha256']}`  ",
        f"Report SHA-256: `{report['report_sha256']}`",
        "",
        "| Tool | False passes | False failures | Collection success | Precision | Recall | Automation depth | Manual tail | Median setup | Median actions | Median runtime |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for tool in report["tools"].values():
        identity = tool["identity"]
        metrics = tool["metrics"]
        lines.append(
            "| "
            + " | ".join(
                [
                    f"{identity['product']} {identity['version']}",
                    str(metrics["false_passes"]),
                    str(metrics["false_failures"]),
                    _format_ratio(metrics["collection_success"]),
                    _format_ratio(metrics["precision"]),
                    _format_ratio(metrics["recall"]),
                    _format_ratio(metrics["automation_depth"]),
                    str(metrics["manual_tail"]),
                    f"{metrics['median_setup_duration_ms']} ms",
                    str(metrics["median_analyst_actions"]),
                    f"{metrics['median_duration_ms']} ms",
                ]
            )
            + " |"
        )
    gate = report["gates"]
    lines.extend(
        [
            "",
            f"AutomateSTIG safety gate: **{'PASS' if gate['automatestig_safety_gate_passed'] else 'FAIL'}**",
            f"Usable comparison-results gate: **{'PASS' if gate['comparison_results_gate_passed'] else 'FAIL'}**",
            "",
            f"Claim status: **{gate['superiority_claim_status']}**. Retain the exact tool exports, manifest, normalization records, and report together.",
            "",
        ]
    )
    failures = [
        (tool["identity"]["id"], failure)
        for tool in report["tools"].values()
        for failure in tool["failures"]
    ]
    if failures:
        lines.extend(
            [
                "## Recorded run failures",
                "",
                "| Tool | Run | Case | Stage | Code | Detail | Evidence SHA-256 |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for tool_id, failure in failures:
            detail = failure["detail"].replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {tool_id} | {failure['run_id']} | {failure['case_id']} | "
                f"{failure['stage']} | {failure['code']} | {detail} | "
                f"`{failure['evidence_sha256']}` |"
            )
        lines.append("")
    return "\n".join(lines)


def _write_output(path, raw):
    destination = pathlib.Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(destination)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("--json-out", type=pathlib.Path)
    parser.add_argument("--markdown-out", type=pathlib.Path)
    parser.add_argument(
        "--prepare-schedule-out",
        type=pathlib.Path,
        help=(
            "expand a validated draft/v1 manifest with an empty runs array into a "
            "fillable randomized run sheet"
        ),
    )
    parser.add_argument(
        "--require-technical-gate",
        action="store_true",
        help=(
            "return non-zero when AutomateSTIG emits a false pass, status mismatch, "
            "or decision from incomplete evidence"
        ),
    )
    parser.add_argument(
        "--require-comparison-gate",
        action="store_true",
        help=(
            "return non-zero unless protocol, AutomateSTIG safety, and usable result "
            "gates pass for every declared tool"
        ),
    )
    arguments = parser.parse_args(argv)
    try:
        if arguments.prepare_schedule_out:
            if (
                arguments.json_out
                or arguments.markdown_out
                or arguments.require_technical_gate
                or arguments.require_comparison_gate
            ):
                raise ComparisonError("schedule preparation cannot be combined with report options")
            prepared = prepare_schedule(arguments.manifest)
            encoded = json.dumps(prepared, indent=2, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"
            _write_output(arguments.prepare_schedule_out, encoded)
            return 0
        report = build_report(load_manifest(arguments.manifest))
        encoded = json.dumps(report, indent=2, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"
        if arguments.json_out:
            _write_output(arguments.json_out, encoded)
        else:
            sys.stdout.buffer.write(encoded)
        if arguments.markdown_out:
            _write_output(arguments.markdown_out, render_markdown(report).encode("utf-8"))
        if arguments.require_technical_gate and not report["gates"]["automatestig_safety_gate_passed"]:
            print("AutomateSTIG safety gate failed", file=sys.stderr)
            return 2
        if arguments.require_comparison_gate and not (
            report["gates"]["protocol_gate_passed"]
            and report["gates"]["automatestig_safety_gate_passed"]
            and report["gates"]["comparison_results_gate_passed"]
        ):
            print("scanner comparison gate failed", file=sys.stderr)
            return 2
        return 0
    except ComparisonError as error:
        print(f"comparison rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
