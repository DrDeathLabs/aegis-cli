#!/usr/bin/env python3
"""Create or verify release checksums and a small artifact manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TAG_RE = re.compile(r"^v(?P<version>0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")


class ManifestError(ValueError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _asset(path: Path, kind: str) -> dict[str, object]:
    return {"name": path.name, "kind": kind, "bytes": path.stat().st_size, "sha256": _sha256(path)}


def create_manifest(
    artifact_dir: Path,
    release_tag: str,
    source_sha: str,
    version: str,
    test_summary_references: list[str],
) -> dict[str, object]:
    if not _TAG_RE.fullmatch(release_tag) or release_tag != f"v{version}":
        raise ManifestError("release tag and project version do not agree")
    if not _SHA_RE.fullmatch(source_sha):
        raise ManifestError("source SHA must be a full lowercase 40-character SHA")
    if not test_summary_references or any(not item.strip() for item in test_summary_references):
        raise ManifestError("at least one non-empty test summary reference is required")
    wheels = sorted(artifact_dir.glob(f"aegis_vulnerability_triage-{version}-*.whl"))
    sdists = sorted(artifact_dir.glob(f"aegis_vulnerability_triage-{version}.tar.gz"))
    sbom = artifact_dir / f"aegis-{release_tag}-sbom.cdx.json"
    if len(wheels) != 1 or len(sdists) != 1 or not sbom.is_file():
        raise ManifestError("expected exactly one wheel, one sdist, and the versioned CycloneDX SBOM")
    artifacts = [_asset(wheels[0], "wheel"), _asset(sdists[0], "sdist"), _asset(sbom, "cyclonedx-json-sbom")]
    sums_path = artifact_dir / "SHA256SUMS"
    manifest: dict[str, object] = {
        "schema": "aegis-release-manifest-v1",
        "version": version,
        "release_tag": release_tag,
        "source_sha": source_sha,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python_version": platform.python_version(),
        "test_summary_references": test_summary_references,
        "artifacts": artifacts,
        # SHA256SUMS includes the manifest itself.  Its own digest is not
        # embedded here, which avoids a circular hash dependency.
        "checksums": {"name": sums_path.name},
    }
    manifest_path = artifact_dir / "release_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    sums_items = [*artifacts, _asset(manifest_path, "release-manifest")]
    sums = "".join(f"{item['sha256']}  {item['name']}\n" for item in sums_items)
    sums_path.write_text(sums, encoding="ascii", newline="\n")
    return manifest


def verify_manifest(artifact_dir: Path, release_tag: str, source_sha: str) -> dict[str, object]:
    path = artifact_dir / "release_manifest.json"
    sums_path = artifact_dir / "SHA256SUMS"
    if not path.is_file() or not sums_path.is_file():
        raise ManifestError("release_manifest.json or SHA256SUMS is missing")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "aegis-release-manifest-v1":
        raise ManifestError("unknown release manifest schema")
    if manifest.get("release_tag") != release_tag or manifest.get("source_sha") != source_sha:
        raise ManifestError("manifest release tag/source SHA does not match this workflow")
    match = _TAG_RE.fullmatch(release_tag)
    if not match or manifest.get("version") != release_tag[1:]:
        raise ManifestError("manifest version does not match the release tag")
    if not isinstance(manifest.get("python_version"), str) or not manifest["python_version"]:
        raise ManifestError("manifest Python version is missing")
    references = manifest.get("test_summary_references")
    if not isinstance(references, list) or not references or any(
        not isinstance(item, str) or not item.strip() for item in references
    ):
        raise ManifestError("manifest test summary references are missing or invalid")
    wheels = sorted(artifact_dir.glob(f"aegis_vulnerability_triage-{release_tag[1:]}-*.whl"))
    sdist = artifact_dir / f"aegis_vulnerability_triage-{release_tag[1:]}.tar.gz"
    sbom = artifact_dir / f"aegis-{release_tag}-sbom.cdx.json"
    if len(wheels) != 1 or not sdist.is_file() or not sbom.is_file():
        raise ManifestError("release directory does not contain the expected wheel, sdist, and SBOM")
    expected_assets = {
        wheels[0].name: "wheel",
        sdist.name: "sdist",
        sbom.name: "cyclonedx-json-sbom",
    }
    declared_assets = manifest.get("artifacts")
    if not isinstance(declared_assets, list) or len(declared_assets) != len(expected_assets):
        raise ManifestError("manifest must declare exactly the expected release assets")
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("name"), str)
        or item.get("name") not in expected_assets
        or item.get("kind") != expected_assets.get(item.get("name"))
        for item in declared_assets
    ) or {item["name"] for item in declared_assets} != set(expected_assets):
        raise ManifestError("manifest release asset names or kinds do not match the candidate")
    expected_sums = []
    for item in declared_assets:
        name = item.get("name")
        if not isinstance(name, str) or Path(name).name != name:
            raise ManifestError("manifest contains an invalid artifact filename")
        artifact = artifact_dir / name
        if not artifact.is_file():
            raise ManifestError(f"release artifact is missing: {name}")
        digest = _sha256(artifact)
        size = artifact.stat().st_size
        if item.get("sha256") != digest or item.get("bytes") != size:
            raise ManifestError(f"release artifact hash/size mismatch: {name}")
        expected_sums.append(f"{digest}  {name}")
    if len(expected_sums) != 3:
        raise ManifestError("manifest must list exactly the wheel, sdist, and SBOM")
    manifest_path = artifact_dir / "release_manifest.json"
    expected_sums.append(f"{_sha256(manifest_path)}  {manifest_path.name}")
    if sums_path.read_text(encoding="ascii").splitlines() != expected_sums:
        raise ManifestError("SHA256SUMS does not exactly match manifest artifacts")
    checksums = manifest.get("checksums") or {}
    if checksums != {"name": sums_path.name}:
        raise ManifestError("manifest checksum-file reference is invalid")
    return {
        "verified": True,
        "release_tag": release_tag,
        "source_sha": source_sha,
        "artifact_count": 3,
        "checksummed_file_count": 4,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--test-summary-reference", action="append", default=[])
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args(argv)
    directory = args.artifact_dir.resolve()
    try:
        if args.verify_only:
            result = verify_manifest(directory, args.release_tag, args.source_sha)
        else:
            match = _TAG_RE.fullmatch(args.release_tag)
            if not match:
                raise ManifestError("release tag must be vMAJOR.MINOR.PATCH")
            version = args.release_tag[1:]
            references = list(args.test_summary_reference)
            if not references:
                server = os.environ.get("GITHUB_SERVER_URL")
                repository = os.environ.get("GITHUB_REPOSITORY")
                run_id = os.environ.get("GITHUB_RUN_ID")
                if server and repository and run_id:
                    references.append(f"{server.rstrip('/')}/{repository}/actions/runs/{run_id}")
            result = create_manifest(directory, args.release_tag, args.source_sha, version, references)
    except (OSError, json.JSONDecodeError, ManifestError) as exc:
        print(f"release manifest error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
