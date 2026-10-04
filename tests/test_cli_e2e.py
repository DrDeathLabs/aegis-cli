from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def run_cli(*args, cwd: Path):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(cwd / "src")
    return subprocess.run([sys.executable, "-m", "aegis.cli", *args], cwd=cwd, env=env, text=True, capture_output=True, check=True)


def test_real_cli_path_from_ingest_to_export(local_tmp):
    root = Path(__file__).parents[1]
    run = local_tmp / "cli-run"
    fixture_dir = root / "fixtures" / "providers"
    for command in (("ingest", str(fixture_dir), "--run-dir", str(run)),
                    ("normalize", "--run-dir", str(run)), ("analyze", "--run-dir", str(run), "--backend", "mock"),
                    ("triage", "--run-dir", str(run)), ("correlate", "--run-dir", str(run)),
                    ("remediation", "--run-dir", str(run))):
        result = run_cli(*command, cwd=root)
        assert result.stdout.strip()
    analyzed = [json.loads(line) for line in (run / "analyzed.jsonl").read_text(encoding="utf-8").splitlines() if line]
    assert analyzed and all(row["analysis"]["model_observation"]["priority_authority"] is False for row in analyzed)
    table = run_cli("report", "--run-dir", str(run), "--format", "table", cwd=root).stdout
    assert "P0" in table and "Active findings" in table
    report_path = local_tmp / "report.json"
    run_cli("export", "json", "--run-dir", str(run), "--output", str(report_path), cwd=root)
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["summary"]["total_findings"] == 13
    assert payload["validation"]["reference_provider_live_validation"] is False
    assert set(payload["validation"]["provider_status"]) == {"tenable", "qualys", "rapid7", "defender", "crowdstrike", "nessus", "generic_json", "generic_csv"}
    replay_path = local_tmp / "replay.json"
    run_cli("replay-export", "--findings", str(run / "remediated.jsonl"), "--output", str(replay_path), cwd=root)
    replay = json.loads(run_cli("replay-validate", str(replay_path), cwd=root).stdout)
    assert replay["valid"] is True and replay["findings"] == 13
