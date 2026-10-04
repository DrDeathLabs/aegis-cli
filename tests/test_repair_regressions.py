from __future__ import annotations

import json
from pathlib import Path

from aegis.analysis.council import analyze
from aegis.correlation import correlate
from aegis.ingest import detect_provider, ingest, normalize
from aegis.remediation import remediation
from aegis.storage import iter_jsonl
from aegis.triage.engine import calculate_priority, triage


def _run_through_correlation(path: Path, run: Path) -> None:
    ingest([str(path)], run_dir=str(run))
    normalize(str(run))
    analyze(str(run))
    triage(str(run))
    correlate(str(run))


def test_strong_incident_evidence_cannot_be_neutralized_by_low_impact():
    finding = {
        "vulnerability": {
            "severity_normalized": "critical", "severity_original": "critical",
            "cvss_scores": [{"score": 9.8}], "exploited_in_wild": True,
            "exploit_available": True, "exploit_maturity": "weaponized",
            "kev": {"listed": True},
        },
        "asset": {"internet_exposed": True, "asset_criticality": "critical", "business_criticality": "critical"},
        "state": {"compensating_controls": ["none"]},
        "analysis": {"technical_impact": "low", "missing_evidence": []},
    }
    priority, drivers, guards, explanation = calculate_priority(finding)
    assert priority == "P0"
    assert "analysis_technical_impact=low" in drivers
    assert any(item["name"] == "incident_priority_guard" and item["triggered"] for item in guards)
    assert "incident guard" in explanation


def test_provider_detection_uses_schema_content_not_filename(local_tmp):
    cases = {
        "renamed-a.json": ({"rows": [{"plugin_id": "T-1", "plugin_name": "x", "cve": "CVE-2024-1"}]}, "tenable"),
        "renamed-b.json": ({"rows": [{"vulnerability_id": "R-1", "risk_score": 700, "cve": "CVE-2024-2"}]}, "rapid7"),
        "renamed-c.json": ({"rows": [{"vulnerabilityId": "M-1", "machineId": "m-1", "machineName": "host"}]}, "defender"),
        "renamed-d.json": ({"rows": [{"spotlight_id": "S-1", "falcon_rating": "critical", "cve": "CVE-2024-3"}]}, "crowdstrike"),
    }
    for filename, (payload, expected) in cases.items():
        path = local_tmp / filename
        path.write_text(json.dumps(payload), encoding="utf-8")
        assert detect_provider(path) == expected


def test_semantically_invalid_record_is_quarantined_with_provenance(local_tmp):
    path = local_tmp / "identity-missing.json"
    path.write_text(json.dumps({"findings": [{"title": "not enough identity", "hostname": "host", "severity": "high"}]}), encoding="utf-8")
    run = local_tmp / "identity-run"
    ingest([str(path)], run_dir=str(run), provider="generic_json")
    result = normalize(str(run))
    assert result["normalized_findings"] == 0
    assert result["normalize_accounting"]["quarantined"] == 1
    rows = list(iter_jsonl(run / "quarantined.jsonl"))
    assert rows[0]["source_path"] == str(path)
    assert rows[0]["record_pointer"] == "/findings/0"
    assert "missing required vulnerability identity" in rows[0]["reason"]
    assert rows[0]["continued"] is True


def test_cross_provider_same_asset_correlates_but_same_cve_other_asset_does_not(local_tmp):
    path = local_tmp / "records.json"
    path.write_text(json.dumps({"records": [
        {"plugin_id": "T-1", "plugin_name": "v", "cve": "CVE-2024-1000", "hostname": "shared.example", "ip": "192.0.2.10", "severity": "High"},
        {"QID": "Q-1", "CVE_ID": "CVE-2024-1000", "DNS": "shared.example", "IP": "192.0.2.10", "QDS": 90, "SEVERITY": 3},
        {"id": "G-1", "cve": "CVE-2024-1000", "hostname": "different.example", "severity": "High"},
    ]}), encoding="utf-8")
    # A single mixed file is genuinely ambiguous.  Explicit provider files
    # exercise the production detector and adapter boundary.
    tenable = local_tmp / "one.json"
    tenable.write_text(json.dumps({"vulnerabilities": [{"plugin_id": "T-1", "plugin_name": "v", "cve": "CVE-2024-1000", "hostname": "shared.example", "ip": "192.0.2.10", "severity": "High"}]}), encoding="utf-8")
    qualys = local_tmp / "two.json"
    qualys.write_text(json.dumps({"detections": [{"QID": "Q-1", "CVE_ID": "CVE-2024-1000", "DNS": "shared.example", "IP": "192.0.2.10", "QDS": 90, "SEVERITY": 3}]}), encoding="utf-8")
    generic = local_tmp / "three.json"
    generic.write_text(json.dumps({"records": [{"id": "G-1", "cve": "CVE-2024-1000", "hostname": "different.example", "severity": "High"}]}), encoding="utf-8")
    run = local_tmp / "correlation-run"
    ingest([str(tenable), str(qualys), str(generic)], run_dir=str(run))
    normalize(str(run)); analyze(str(run)); triage(str(run)); result = correlate(str(run))
    assert result["correlation"]["cross_provider_groups"] == 1
    groups = json.loads((run / "correlation_groups.json").read_text(encoding="utf-8"))
    assert sorted(item["count"] for item in groups) == [1, 2]
    shared = next(item for item in groups if item["count"] == 2)
    assert set(shared["providers"]) == {"tenable", "qualys"}


def test_explicit_shared_remediation_groups_without_generic_text_merge(local_tmp):
    path = local_tmp / "remediation.json"
    path.write_text(json.dumps({"records": [
        {"id": "A-1", "cve": "CVE-2024-2001", "hostname": "one.example", "solution": "Deploy security update KB12345", "severity": "High"},
        {"id": "A-2", "cve": "CVE-2024-2002", "hostname": "two.example", "solution": "Deploy security update KB12345", "severity": "High"},
        {"id": "A-3", "cve": "CVE-2024-2003", "hostname": "three.example", "solution": "Apply vendor update", "severity": "High"},
    ]}), encoding="utf-8")
    run = local_tmp / "remediation-run"
    _run_through_correlation(path, run)
    result = remediation(str(run))
    assert result["remediation_actions"] == 2
    actions = json.loads((run / "remediation_actions.json").read_text(encoding="utf-8"))
    explicit = next(action for action in actions if action["kind"] == "explicit_action")
    assert explicit["occurrence_count"] == 2
    assert explicit["grouping_evidence"]["key"] == "kb12345"
    assert all(action["occurrence_count"] == 1 for action in actions if action is not explicit)
