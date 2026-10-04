#!/usr/bin/env python3
"""Validate explicit release intent and source identity; never publishes."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory

_TAG_RE = re.compile(r"^v(?P<version>0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PLACEHOLDER_RE = re.compile(r"\b(?:TODO|TBD|placeholder|to be filled)\b", re.IGNORECASE)


class ReleaseGateError(ValueError):
    """A release-candidate validation error with a stable gate identifier."""

    def __init__(self, gate: str, message: str) -> None:
        super().__init__(message)
        self.gate = gate


def validate_candidate(
    *,
    release_tag: str,
    source_sha: str,
    confirmation: str,
    notes_reviewed: str,
    head_sha: str,
    tag_sha: str,
    project_version: str,
    notes_file: Path,
) -> dict[str, str]:
    if not isinstance(release_tag, str) or not _TAG_RE.fullmatch(release_tag):
        raise ReleaseGateError("release_tag_invalid", "release_tag must be a plain vMAJOR.MINOR.PATCH tag")
    if not isinstance(source_sha, str) or not _SHA_RE.fullmatch(source_sha):
        raise ReleaseGateError("source_sha_invalid", "source_sha must be a full lowercase 40-character SHA")
    if not isinstance(head_sha, str) or not _SHA_RE.fullmatch(head_sha):
        raise ReleaseGateError("head_sha_invalid", "checked-out HEAD must be a full lowercase 40-character SHA")
    if not isinstance(tag_sha, str) or not _SHA_RE.fullmatch(tag_sha):
        raise ReleaseGateError("tag_sha_invalid", "resolved tag target must be a full lowercase 40-character SHA")
    if release_tag != f"v{project_version}":
        raise ReleaseGateError("release_tag_version_mismatch", "release_tag does not agree with project version")
    if source_sha != head_sha:
        raise ReleaseGateError("source_sha_mismatch", "source_sha does not match checked-out HEAD")
    if tag_sha != source_sha:
        raise ReleaseGateError("tag_commit_mismatch", "release tag does not point to source_sha")
    if confirmation != "PUBLISH":
        raise ReleaseGateError("publish_confirmation_missing", "confirmation must be exactly PUBLISH")
    if notes_reviewed != "REVIEWED":
        raise ReleaseGateError("release_notes_not_reviewed", "notes_reviewed must be exactly REVIEWED")
    if not notes_file.is_file():
        raise ReleaseGateError("release_notes_missing", "versioned release notes file does not exist")
    notes = notes_file.read_text(encoding="utf-8").strip()
    if not notes or _PLACEHOLDER_RE.search(notes):
        raise ReleaseGateError("release_notes_incomplete", "release notes are empty or contain a placeholder")
    return {
        "release_tag": release_tag,
        "source_sha": source_sha,
        "project_version": project_version,
        "release_notes": str(notes_file),
        "publish_authorized": "true",
    }


def _resolve_tag(repo_root: Path, tag: str) -> str:
    if not _TAG_RE.fullmatch(tag):
        raise ReleaseGateError("release_tag_invalid", "release_tag must be a plain vMAJOR.MINOR.PATCH tag")
    result = subprocess.run(
        ["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ReleaseGateError("release_tag_missing", "release_tag does not resolve to a local commit")
    return result.stdout.strip().lower()


def _project_version(repo_root: Path) -> str:
    data = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _sha(repo_root: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", ref], cwd=repo_root, check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise ReleaseGateError("git_ref_unresolvable", f"could not resolve {ref}")
    return result.stdout.strip().lower()


def _self_test() -> int:
    with TemporaryDirectory(prefix="aegis-release-verifier-") as temp:
        notes = Path(temp) / "0.1.0.md"
        notes.write_text("# Aegis CLI 0.1.0\n\nReviewed release notes.\n", encoding="utf-8")
        valid = {
            "release_tag": "v0.1.0",
            "source_sha": "a" * 40,
            "confirmation": "PUBLISH",
            "notes_reviewed": "REVIEWED",
            "head_sha": "a" * 40,
            "tag_sha": "a" * 40,
            "project_version": "0.1.0",
            "notes_file": notes,
        }
        validate_candidate(**valid)
        failures = [
            ("wrong_confirmation", {"confirmation": "publish"}, "publish_confirmation_missing"),
            ("malformed_tag", {"release_tag": "v0.1.0;echo"}, "release_tag_invalid"),
            ("wrong_sha", {"source_sha": "b" * 40}, "source_sha_mismatch"),
            ("tag_source_mismatch", {"tag_sha": "b" * 40}, "tag_commit_mismatch"),
            ("version_mismatch", {"release_tag": "v0.2.0"}, "release_tag_version_mismatch"),
            ("notes_not_reviewed", {"notes_reviewed": ""}, "release_notes_not_reviewed"),
            ("missing_notes", {"notes_file": Path(temp) / "absent.md"}, "release_notes_missing"),
        ]
        checked: list[dict[str, str]] = []
        for case_name, change, expected_gate in failures:
            candidate = dict(valid)
            candidate.update(change)
            try:
                validate_candidate(**candidate)
            except ReleaseGateError as exc:
                if exc.gate != expected_gate:
                    raise RuntimeError(f"{case_name} expected {expected_gate}, got {exc.gate}") from exc
                checked.append({"case": case_name, "result": exc.gate})
            else:
                raise RuntimeError(f"{case_name} unexpectedly passed")
        print(json.dumps({"success_path": "passed", "failure_paths": checked}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--release-tag")
    parser.add_argument("--source-sha")
    parser.add_argument("--notes-reviewed")
    parser.add_argument("--confirmation")
    parser.add_argument("--notes-file", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    required = (args.release_tag, args.source_sha, args.notes_reviewed, args.confirmation, args.notes_file)
    if any(value is None for value in required):
        parser.error("release-tag, source-sha, notes-reviewed, confirmation, and notes-file are required")
    repo_root = args.repo_root.resolve()
    try:
        head = _sha(repo_root, "HEAD")
        tag = _resolve_tag(repo_root, args.release_tag)
        notes_file = args.notes_file if args.notes_file.is_absolute() else repo_root / args.notes_file
        result = validate_candidate(
            release_tag=args.release_tag,
            source_sha=args.source_sha.lower(),
            confirmation=args.confirmation,
            notes_reviewed=args.notes_reviewed,
            head_sha=head,
            tag_sha=tag,
            project_version=_project_version(repo_root),
            notes_file=notes_file,
        )
    except (OSError, KeyError, ReleaseGateError) as exc:
        gate = exc.gate if isinstance(exc, ReleaseGateError) else "release_validation_error"
        print(f"release gate {gate}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
