from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from aegis.cli import main
from aegis.ingest import ingest, normalize
from aegis.ingest.pipeline import detect_provider
from aegis.providers import adapter_for
from aegis.storage import load_run, stage_path


def test_provider_detection_requires_complete_contract_shape(local_tmp: Path):
    cases = {
        "asset-definition": {"asset": {"id": "a1"}, "definition": {"id": "d1", "cve": "CVE-2026-1001"}},
        "crowdstrike-like": {"aid": "a1", "host_info": {"hostname": "host"}, "cve": {"id": "CVE-2026-1001"}},
        "defender-like": {"deviceId": "d1", "cveId": "CVE-2026-1001", "severity": "high"},
        "rapid7-like": {"assetId": "a1", "vulnId": "v1"},
    }
    for name, payload in cases.items():
        path = local_tmp / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        assert detect_provider(path) == "generic_json"


def test_generic_unknown_ancestry_is_opaque_and_selector_is_explicit(local_tmp: Path):
    path = local_tmp / "opaque.json"
    path.write_text(json.dumps({"metadata": {"data": {"items": [
        {"id": "opaque-1", "cve": "CVE-2026-2002", "hostname": "opaque.example"}
    ]}}}), encoding="utf-8")

    automatic = list(adapter_for("generic_json").records(path))
    assert automatic == [(json.loads(path.read_text(encoding="utf-8")), "")]
    run = local_tmp / "automatic-run"
    ingest([str(path)], run_dir=str(run), provider="generic_json")
    assert normalize(str(run))["normalized_findings"] == 0

    selected_run = local_tmp / "selected-run"
    selected = ingest(
        [str(path)], run_dir=str(selected_run), provider="generic_json",
        selectors=("/metadata/data/items",),
    )
    assert selected["raw_records"] == 1
    assert normalize(str(selected_run))["normalized_findings"] == 1


def test_cli_selector_is_available_on_real_ingest_path(local_tmp: Path):
    path = local_tmp / "selector.json"
    path.write_text(json.dumps({"metadata": {"data": {"items": [
        {"id": "selected-1", "cve": "CVE-2026-3003", "hostname": "selected.example"}
    ]}}}), encoding="utf-8")
    run = local_tmp / "cli-run"
    result = CliRunner().invoke(main, [
        "ingest", str(path), "--provider", "generic_json", "--selector", "/metadata/data/items",
        "--run-dir", str(run),
    ])
    assert result.exit_code == 0, result.output
    assert load_run(run)["selectors"] == ["/metadata/data/items"]


def test_unexpected_stage_failure_is_terminal_and_nonzero(local_tmp: Path):
    path = local_tmp / "valid.json"
    path.write_text(json.dumps({"findings": [{"id": "f1", "cve": "CVE-2026-4004", "hostname": "h.example"}]}), encoding="utf-8")
    run = local_tmp / "failed-run"
    ingest([str(path)], run_dir=str(run), provider="generic_json")
    stage_path(run, "raw_records").write_text("{not-json}\n", encoding="utf-8")

    result = CliRunner().invoke(main, ["normalize", "--run-dir", str(run)])
    assert result.exit_code != 0
    metadata = load_run(run)
    assert metadata["status"] == "failed"
    assert metadata["stages"]["normalize"]["status"] == "failed"
    assert metadata["errors"][-1]["stage"] == "normalize"
