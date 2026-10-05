"""Command-facing lifecycle for the local vulnerability intelligence corpus."""

from __future__ import annotations

import json
import re
from typing import Any

from aegis.intelligence.artifact import read_artifact
from aegis.intelligence.corpus import build_corpus, load_training_rows
from aegis.intelligence.feeds import cached_feed_manifest, refresh_feeds
from aegis.intelligence.model import train_model
from aegis.intelligence.paths import corpus_path, data_dir, feed_dir, model_path

_NVD_CACHE_RE = re.compile(r"^nvd-20\d\d\.json\.gz$")


def status() -> dict[str, Any]:
    artifact, model_state = read_artifact(model_path())
    corpus_exists = corpus_path().is_file()
    corpus_state: dict[str, Any] = {"available": corpus_exists}
    if corpus_exists:
        try:
            import sqlite3

            with sqlite3.connect(corpus_path()) as conn:
                corpus_state["cve_records"] = conn.execute("SELECT COUNT(*) FROM cve_record").fetchone()[0]
                corpus_state["cwe_profiles"] = conn.execute("SELECT COUNT(*) FROM cwe_profile").fetchone()[0]
                meta = {row[0]: row[1] for row in conn.execute("SELECT key,value FROM corpus_meta")}
                corpus_state["built_at"] = meta.get("built_at")
        except Exception as exc:  # status is intentionally resilient to a damaged local cache
            corpus_state["error"] = type(exc).__name__
    if artifact and not artifact.get("model_eligible_for_inference", False):
        model_state = "held-out evaluation did not improve on the temporal prevalence baseline"
    return {
        "status": "active" if artifact and artifact.get("model_eligible_for_inference") else "unavailable",
        "data_directory": str(data_dir()),
        "corpus": corpus_state,
        "model": {
            "available": artifact is not None,
            "usable_for_inference": bool(artifact and artifact.get("model_eligible_for_inference")),
            "state": model_state,
            "version": artifact.get("model_version") if artifact else None,
            "sha256": artifact.get("model_hash") if artifact else None,
            "trained_at": artifact.get("trained_at") if artifact else None,
            "evaluation_quality": ((artifact or {}).get("evaluation") or {}).get("quality_status"),
        },
        "cached_feeds": cached_feed_manifest(),
        "network_used": False,
    }


def info() -> dict[str, Any]:
    artifact, model_state = read_artifact(model_path())
    if artifact is None:
        return {"available": False, "state": model_state, "network_used": False}
    evaluation = artifact.get("evaluation") or {}
    return {
        "available": True,
        "usable_for_inference": bool(artifact.get("model_eligible_for_inference")),
        "state": model_state,
        "model_version": artifact.get("model_version"),
        "model_hash": artifact.get("model_hash"),
        "model_type": artifact.get("model_type"),
        "trained_at": artifact.get("trained_at"),
        "software_version": artifact.get("software_version"),
        "feature_schema_version": artifact.get("feature_schema_version"),
        "feature_names": artifact.get("feature_names"),
        "training": artifact.get("training"),
        "evaluation": evaluation,
        "priority_authority": False,
        "network_used": False,
    }


def build() -> dict[str, Any]:
    result = build_corpus()
    result["network_used"] = False
    return result


def train(*, seed: int = 42) -> dict[str, Any]:
    rows, metadata = load_training_rows()
    return train_model(rows, metadata, seed=seed)


def refresh(*, start_year: int, end_year: int, force: bool = False, seed: int = 42) -> dict[str, Any]:
    feeds = refresh_feeds(start_year=start_year, end_year=end_year, force=force)
    corpus = build_corpus()
    trained = train(seed=seed)
    return {
        "status": "complete",
        "feeds": feeds,
        "corpus": corpus,
        "model": {key: value for key, value in trained.items() if key != "evaluation"},
        "evaluation": trained["evaluation"],
        "network_used": True,
    }


def reset() -> dict[str, Any]:
    """Remove only Aegis-owned model/corpus and recognized feed-cache files."""
    root = data_dir()
    targets = [model_path(), model_path().parent / "model-evaluation.json", corpus_path()]
    feed_root = feed_dir()
    if feed_root.is_dir() and not feed_root.is_symlink():
        for candidate in feed_root.iterdir():
            if candidate.is_file() and (
                _NVD_CACHE_RE.fullmatch(candidate.name)
                or candidate.name in {"epss-current.csv.gz", "kev.json"}
            ):
                targets.append(candidate)
    removed = []
    for path in targets:
        try:
            resolved = path.resolve(strict=False)
            if root.resolve() not in resolved.parents:
                continue
            if path.is_file() and not path.is_symlink():
                size = path.stat().st_size
                path.unlink()
                removed.append({"file": str(path.relative_to(root)), "bytes": size})
        except OSError:
            continue
    return {"status": "reset", "removed": removed, "bytes_removed": sum(row["bytes"] for row in removed)}


def evaluation_report() -> dict[str, Any] | None:
    path = model_path().parent / "model-evaluation.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
