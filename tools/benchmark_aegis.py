"""Benchmark the real Aegis stages and persist measured results."""

from __future__ import annotations

import argparse
import json
import os
import threading
import sys
import time
from itertools import islice
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from aegis.analysis.council import analyze
from aegis.correlation import correlate
from aegis.ingest import ingest, normalize
from aegis.remediation import remediation
from aegis.triage.engine import triage
from aegis.reporting import iter_findings, report
from aegis.replay import export_corpus, validate_corpus


def _rss_mb() -> float | None:
    try:
        import psutil
        return round(psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024), 1)
    except Exception:
        return None


def _dir_bytes(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file()) if path.exists() else 0


def timed(label, function, *args, **kwargs):
    started = time.perf_counter()
    peak = [_rss_mb()]
    running = [True]
    def sample():
        while running[0]:
            current = _rss_mb()
            if current is not None:
                peak[0] = max(peak[0] or current, current)
            time.sleep(0.05)
    watcher = threading.Thread(target=sample, daemon=True)
    watcher.start()
    try:
        result = function(*args, **kwargs)
    finally:
        running[0] = False
        watcher.join(timeout=1)
    return result, {"stage": label, "seconds": round(time.perf_counter() - started, 3), "peak_rss_mb": peak[0]}


def benchmark(input_path: Path, run_dir: Path, result_path: Path) -> dict:
    measurements = []
    before_bytes = _dir_bytes(run_dir)
    metadata, timing = timed("ingest", ingest, [str(input_path)], run_dir=str(run_dir), provider="generic_json")
    timing["artifact_bytes_after"] = _dir_bytes(run_dir)
    measurements.append(timing)
    for label, function in (("normalize", normalize), ("analyze", analyze), ("triage", triage), ("correlate", correlate), ("remediation", remediation)):
        metadata, timing = timed(label, function, str(run_dir))
        timing["artifact_bytes_after"] = _dir_bytes(run_dir)
        measurements.append(timing)
    replay_path = run_dir / "replay.jsonl"
    _, timing = timed("report_json", report, str(run_dir), format_name="json", output=str(run_dir / "report.json"))
    timing["artifact_bytes_after"] = _dir_bytes(run_dir)
    measurements.append(timing)
    _, timing = timed("report_csv", report, str(run_dir), format_name="csv", output=str(run_dir / "report.csv"))
    timing["artifact_bytes_after"] = _dir_bytes(run_dir)
    measurements.append(timing)
    _, timing = timed("report_table", report, str(run_dir), format_name="table")
    timing["artifact_bytes_after"] = _dir_bytes(run_dir)
    measurements.append(timing)
    _, timing = timed("findings_limit", lambda: list(islice(iter_findings(str(run_dir)), 100)))
    timing["artifact_bytes_after"] = _dir_bytes(run_dir)
    measurements.append(timing)
    _, timing = timed("replay_export", export_corpus, run_dir / "remediated.jsonl", replay_path)
    timing["artifact_bytes_after"] = _dir_bytes(run_dir)
    measurements.append(timing)
    validation, timing = timed("replay_validate", validate_corpus, replay_path)
    timing["artifact_bytes_after"] = _dir_bytes(run_dir)
    measurements.append(timing)
    after_bytes = _dir_bytes(run_dir)
    result = {"input": str(input_path), "run_dir": str(run_dir), "records": metadata.get("raw_records", 0), "stages": measurements, "total_seconds": round(sum(item["seconds"] for item in measurements), 3), "artifact_bytes": after_bytes - before_bytes, "replay_valid": validation.get("valid"), "resource_limit_notes": "Measured wall clock and process RSS on the local host; no live provider call."}
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def completed_benchmark(input_path: Path, run_dir: Path, result_path: Path) -> dict:
    """Reconstruct accurate stage timings from a completed run's events."""
    events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if line]
    starts: dict[str, dict] = {}
    measurements = []
    for event in events:
        stage = event["event_type"].split(".", 1)[0]
        if event["event_type"].endswith(".started"):
            starts[stage] = event
        elif event["event_type"].endswith(".completed") and stage in starts:
            began = datetime.fromisoformat(starts[stage]["at"].replace("Z", "+00:00"))
            ended = datetime.fromisoformat(event["at"].replace("Z", "+00:00"))
            measurements.append({"stage": stage, "seconds": round((ended - began).total_seconds(), 3)})
    metadata = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    result = {"input": str(input_path), "run_dir": str(run_dir), "records": metadata.get("raw_records", 0),
              "stages": measurements, "total_seconds": round(sum(item["seconds"] for item in measurements), 3),
              "resumed_after_defect_fix": True, "resource_limit_notes": "Wall clock reconstructed from append-only stage events; local host only; no live provider call."}
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--completed-run", action="store_true", help="Read timings from an already completed run.")
    args = parser.parse_args()
    function = completed_benchmark if args.completed_run else benchmark
    print(json.dumps(function(args.input, args.run_dir, args.output), indent=2))
