#!/usr/bin/env python3
"""Require the published Linux CLI to be the exact live-tested binary."""

import argparse
import hashlib
import json
import pathlib
import re
import tarfile


SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_CLI_BYTES = 256 * 1024 * 1024


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json(path):
    return json.loads(
        path.read_bytes(),
        object_pairs_hook=unique_json_object,
    )


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_repo_reference(repo, reference, tag):
    if not isinstance(reference, str):
        raise ValueError("live evidence reference must be a string")
    relative = pathlib.PurePosixPath(reference)
    expected_parent = pathlib.PurePosixPath("release-evidence", "artifacts", tag)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.parent != expected_parent
    ):
        raise ValueError("live evidence reference escapes its tagged artifact directory")
    path = repo.joinpath(*relative.parts)
    if path.is_symlink() or not path.is_file():
        raise ValueError("live evidence reference must be a regular nonsymlink file")
    return path


def live_binary_digest(repo, tag):
    release_path = repo / "release-evidence" / f"{tag}.json"
    release = load_json(release_path)
    if (
        release.get("schema") != "automatestig-release-evidence/v1"
        or release.get("tag") != tag
    ):
        raise ValueError("release evidence identity does not match the tag")
    acceptance = release.get("acceptance")
    if not isinstance(acceptance, dict):
        raise ValueError("release evidence acceptance map is missing")
    digests = set()
    references = set()
    for gate in ("ontap", "freebsd", "cisco_ios_xe"):
        entry = acceptance.get(gate)
        if not isinstance(entry, dict):
            raise ValueError(f"release evidence is missing {gate}")
        reference = entry.get("evidence_reference")
        artifact = safe_repo_reference(repo, reference, tag)
        expected_artifact_sha = entry.get("evidence_sha256")
        if (
            not isinstance(expected_artifact_sha, str)
            or not SHA256.fullmatch(expected_artifact_sha)
            or sha256_file(artifact) != expected_artifact_sha
        ):
            raise ValueError(f"{gate} live evidence artifact digest mismatch")
        document = load_json(artifact)
        binary_sha256 = document.get("binary_sha256")
        if (
            document.get("schema") != "automatestig-live-device-acceptance/v1"
            or document.get("source_commit") != release.get("approved_commit")
            or not isinstance(binary_sha256, str)
            or not SHA256.fullmatch(binary_sha256)
        ):
            raise ValueError(f"{gate} live evidence lacks exact tested-binary provenance")
        references.add(reference)
        digests.add(binary_sha256)
    if len(references) != 1 or len(digests) != 1:
        raise ValueError("device gates do not share one exact live-tested binary artifact")
    return digests.pop()


def verified_archive(artifact_dir, tag):
    matches = list(
        artifact_dir.glob(
            f"automatestig-{tag}-x86_64-unknown-linux-gnu.tar.gz"
        )
    )
    if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file():
        raise ValueError("exactly one Linux x86_64 release archive is required")
    archive = matches[0]
    checksum = archive.with_name(archive.name + ".sha256")
    if checksum.is_symlink() or not checksum.is_file():
        raise ValueError("Linux x86_64 release archive checksum is missing")
    fields = checksum.read_text(encoding="utf-8").strip().split()
    if (
        len(fields) != 2
        or fields[1].lstrip("*") != archive.name
        or not SHA256.fullmatch(fields[0])
        or sha256_file(archive) != fields[0]
    ):
        raise ValueError("Linux x86_64 release archive checksum is invalid")
    return archive


def release_cli_digest(archive):
    with tarfile.open(archive, mode="r:gz") as package:
        normalized = {}
        for member in package.getmembers():
            path = pathlib.PurePosixPath(member.name)
            parts = tuple(part for part in path.parts if part not in ("", "."))
            if path.is_absolute() or ".." in parts or not parts:
                raise ValueError("release archive contains an unsafe member path")
            if parts in normalized:
                raise ValueError("release archive contains duplicate member paths")
            normalized[parts] = member
        member = normalized.get(("automatestig",))
        if (
            member is None
            or not member.isreg()
            or member.size <= 0
            or member.size > MAX_CLI_BYTES
        ):
            raise ValueError("release archive has no bounded regular CLI binary")
        stream = package.extractfile(member)
        if stream is None:
            raise ValueError("release CLI binary cannot be read")
        raw = stream.read(MAX_CLI_BYTES + 1)
        if len(raw) != member.size or len(raw) > MAX_CLI_BYTES:
            raise ValueError("release CLI binary length differs from its archive header")
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--artifact-dir", required=True)
    args = parser.parse_args()

    repo = pathlib.Path(args.repo_root).resolve()
    artifact_dir = pathlib.Path(args.artifact_dir).resolve()
    expected = live_binary_digest(repo, args.tag)
    archive = verified_archive(artifact_dir, args.tag)
    observed = release_cli_digest(archive)
    if observed != expected:
        raise SystemExit(
            "release Linux CLI differs from the exact binary exercised by "
            "protected live-device acceptance"
        )
    print(f"Release Linux CLI matches live-tested SHA-256 {expected}")


if __name__ == "__main__":
    main()
