"""Small atomic JSON/JSONL run store.

JSONL keeps the common import/normalize path streamable and makes a million
finding benchmark practical without requiring a server or a live database.
Each stage writes a versioned artifact in the run directory.
"""

from __future__ import annotations

import json
import hashlib
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator


class ResourceLimitExceeded(RuntimeError):
    """A hard run budget was exceeded after an atomic stage boundary."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_run_dir(base: str | Path = "artifacts/runs") -> Path:
    root = Path(base)
    root.mkdir(parents=True, exist_ok=True)
    run = root / f"run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    run.mkdir(parents=True)
    return run


def ensure_run_dir(path: str | Path) -> Path:
    run = Path(path).expanduser().resolve()
    run.mkdir(parents=True, exist_ok=True)
    # Vulnerability evidence can contain scanner proof and accidental
    # secrets.  Enforce a private directory on POSIX; Windows ACLs are
    # managed by the host and are reported as an explicit limitation.
    if os.name != "nt":
        run.chmod(0o700)
    return run


def atomic_write_text(path: str | Path, text: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return target


def write_json(path: str | Path, payload: Any) -> Path:
    return atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n")


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_jsonl(path: str | Path, records: Iterable[dict[str, Any]]) -> int:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    count = 0
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str) + "\n")
                count += 1
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return count


def iter_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"JSONL record at line {line_number} is not an object")
            yield value


def stage_path(run_dir: str | Path, stage: str) -> Path:
    return ensure_run_dir(run_dir) / f"{stage}.jsonl"


def run_metadata_path(run_dir: str | Path) -> Path:
    return ensure_run_dir(run_dir) / "run.json"


def load_run(run_dir: str | Path) -> dict[str, Any]:
    path = run_metadata_path(run_dir)
    if not path.exists():
        raise FileNotFoundError(f"Aegis run metadata not found: {path}")
    return read_json(path)


def save_run(run_dir: str | Path, metadata: dict[str, Any]) -> Path:
    metadata = dict(metadata)
    metadata.setdefault("updated_at", utc_now())
    return write_json(run_metadata_path(run_dir), metadata)


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_disk_bytes(run_dir: str | Path) -> int:
    """Return the private run footprint without following directory links."""
    root = ensure_run_dir(run_dir)
    total = 0
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            try:
                total += path.stat().st_size
            except OSError:
                continue
    return total


def _elapsed_seconds(metadata: dict[str, Any]) -> float:
    created = str(metadata.get("created_at") or "")
    try:
        started = datetime.fromisoformat(created.replace("Z", "+00:00"))
        return max(0.0, (datetime.now(timezone.utc) - started).total_seconds())
    except (TypeError, ValueError):
        return 0.0


def process_rss_mb() -> float | None:
    """Best-effort RSS measurement; resource policy treats it as advisory."""
    try:
        import psutil
        return round(psutil.Process().memory_info().rss / (1024 * 1024), 3)
    except Exception:
        return None


def enforce_run_limits(run_dir: str | Path, metadata: dict[str, Any], stage: str) -> dict[str, Any]:
    """Enforce disk/time budgets at atomic stage boundaries.

    RSS is measured and retained as an advisory signal because a process-wide
    kill at an arbitrary write point can corrupt the run; disk and wall-clock
    limits are hard and leave a terminal, inspectable run state.
    """
    run = ensure_run_dir(run_dir)
    limits = metadata.get("operational_budgets") or {}
    disk = run_disk_bytes(run)
    elapsed = _elapsed_seconds(metadata)
    rss = process_rss_mb()
    violations: list[str] = []
    max_disk = limits.get("max_run_disk_bytes")
    max_seconds = limits.get("max_run_seconds")
    if isinstance(max_disk, int) and disk > max_disk:
        violations.append(f"run disk budget exceeded: {disk} > {max_disk} bytes")
    if isinstance(max_seconds, (int, float)) and elapsed > max_seconds:
        violations.append(f"run wall-clock budget exceeded: {elapsed:.3f} > {max_seconds} seconds")
    resource = metadata.setdefault("resource_limits", {})
    resource.update({"disk_bytes": disk, "elapsed_seconds": round(elapsed, 3), "rss_mb": rss,
                     "rss_limit_mode": "advisory", "checked_after_stage": stage})
    if violations:
        metadata["status"] = "failed"
        metadata.setdefault("errors", []).append({"state": "resource_limit", "stage": stage, "reason": "; ".join(violations), "continued": False, "data_lost": False})
        metadata.setdefault("stages", {})[stage] = {"status": "failed", "resource_limit": True, "violations": violations}
        metadata["updated_at"] = utc_now()
        save_run(run, metadata)
        raise ResourceLimitExceeded("; ".join(violations))
    return resource


_STAGES = ("raw_records", "findings", "analyzed", "triaged", "correlated", "remediated")

_PIPELINE_STAGE_OUTPUTS = {
    "normalize": "findings",
    "analyze": "analyzed",
    "triage": "triaged",
    "correlate": "correlated",
    "remediation": "remediated",
}


def mark_stage_failed(run_dir: str | Path, metadata: dict[str, Any], stage: str, error: Exception) -> dict[str, Any]:
    """Persist a terminal stage failure and remove unusable downstream data."""
    run = ensure_run_dir(run_dir)
    stage_names = tuple(_PIPELINE_STAGE_OUTPUTS)
    if stage not in stage_names:
        return metadata
    stage_index = stage_names.index(stage)
    removed: list[str] = []
    for name in stage_names[stage_index:]:
        output_name = _PIPELINE_STAGE_OUTPUTS[name]
        output = stage_path(run, output_name)
        if output.exists():
            output.unlink()
            removed.append(output.name)
        metadata.setdefault("stages", {}).setdefault(name, {})["status"] = "stale"
    for artifact in (
        run / "correlation_groups.json", run / "remediation_actions.json",
        run / "remediation_actions.jsonl", run / "vulnerability_rollups.json",
        run / "longitudinal.json", run / "lineage_manifest.json",
    ):
        if artifact.exists():
            artifact.unlink()
            removed.append(artifact.name)
    reason = f"{type(error).__name__}: {error}"
    metadata.setdefault("errors", []).append({
        "state": "failed", "stage": stage, "reason": reason,
        "continued": False, "data_lost": False,
    })
    metadata["status"] = "failed"
    metadata.setdefault("stages", {})[stage] = {
        "status": "failed", "error": reason, "partial_artifacts_removed": sorted(set(removed)),
    }
    metadata["updated_at"] = utc_now()
    save_run(run, metadata)
    return metadata


def invalidate_downstream(run_dir: str | Path, metadata: dict[str, Any], stage: str) -> None:
    """Remove artifacts downstream of a rerun and mark their metadata stale."""
    if stage not in _STAGES:
        return
    start = _STAGES.index(stage) + 1
    for downstream in _STAGES[start:]:
        candidate = stage_path(run_dir, downstream)
        if candidate.exists():
            candidate.unlink()
        metadata.setdefault("stages", {}).setdefault(downstream, {})["status"] = "stale"
    for artifact in (Path(run_dir) / "correlation_groups.json", Path(run_dir) / "remediation_actions.json", Path(run_dir) / "remediation_actions.jsonl", Path(run_dir) / "vulnerability_rollups.json", Path(run_dir) / "longitudinal.json"):
        if artifact.exists():
            artifact.unlink()


def record_stage_lineage(metadata: dict[str, Any], stage: str, input_path: str | Path | None, output_path: str | Path) -> None:
    input_sha = file_sha256(input_path) if input_path and Path(input_path).exists() else None
    output_sha = file_sha256(output_path)
    metadata.setdefault("lineage", {})[stage] = {
        "input_sha256": input_sha, "output_sha256": output_sha,
        "schema_version": metadata.get("schema_version"),
    }


def write_lineage_manifest(run_dir: str | Path, metadata: dict[str, Any]) -> None:
    """Cache completed stage file fingerprints for bounded report/findings reads."""
    run = ensure_run_dir(run_dir)
    entries: dict[str, Any] = {}
    lineage_stage = {"raw_records": "ingest", "findings": "normalize", "analyzed": "analyze", "triaged": "triage", "correlated": "correlate", "remediated": "remediation"}
    for stage in _STAGES:
        path = stage_path(run, stage)
        if path.exists():
            stat = path.stat()
            line = (metadata.get("lineage") or {}).get(lineage_stage[stage], {})
            entries[stage] = {"path": path.name, "bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns,
                              "sha256": line.get("output_sha256")}
    write_json(run / "lineage_manifest.json", {"schema_version": metadata.get("schema_version"), "stages": entries})


def fast_stage_fingerprint(run_dir: str | Path, stage: str) -> str | None:
    """Validate a completed immutable artifact using size/mtime and return its cached hash."""
    run = ensure_run_dir(run_dir)
    manifest_path = run / "lineage_manifest.json"
    path = stage_path(run, stage)
    if not manifest_path.exists() or not path.exists():
        return None
    manifest = read_json(manifest_path)
    item = (manifest.get("stages") or {}).get(stage) or {}
    stat = path.stat()
    if item.get("bytes") != stat.st_size or item.get("mtime_ns") != stat.st_mtime_ns:
        return None
    return item.get("sha256")
