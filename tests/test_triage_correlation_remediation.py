from __future__ import annotations

from pathlib import Path

from aegis.ingest import ingest, normalize
from aegis.analysis.council import analyze
from aegis.triage.engine import calculate_priority, triage
from aegis.correlation import correlate
from aegis.remediation import remediation
from aegis.storage import iter_jsonl


def _finding(*, disposition="confirmed", active=False, internet=False, critical=False, controls=None):
    return {"title": "Remote code execution" if active else "Low configuration issue", "description": "RCE" if active else "configuration", "disposition": disposition,
            "vulnerability": {"severity_normalized": "critical" if active else "low", "severity_original": "Critical" if active else "Low", "exploited_in_wild": active, "exploit_available": active, "exploit_maturity": "functional" if active else None, "kev": {"listed": active}, "epss": .9 if active else None},
            "asset": {"internet_exposed": internet, "asset_criticality": "critical" if critical else "low", "business_criticality": "critical" if critical else "low"},
            "state": {"compensating_controls": controls or [], "recurrence": 1}, "analysis": {"technical_impact": "critical" if active else "low", "missing_evidence": []}, "evidence": {"basis": "scanner_and_source"}}


def test_priority_is_deterministic_and_disposition_is_separate():
    p0 = calculate_priority(_finding(active=True, internet=True, critical=True))
    assert p0[0] == "P0"
    false_positive = _finding(disposition="false_positive", active=True, internet=True, critical=True)
    assert calculate_priority(false_positive)[0] == "P0"
    accepted = _finding(disposition="accepted_risk", active=True, internet=True, critical=True)
    assert calculate_priority(accepted)[0] == "P0"
    unconfirmed = _finding(disposition="unconfirmed", active=True, internet=True, critical=True)
    assert calculate_priority(unconfirmed)[0] == "P0"


def test_fixture_pipeline_correlates_cross_provider_and_duplicate_rows(local_tmp):
    run = local_tmp / "run"
    ingest([str(Path(__file__).parents[1] / "fixtures/providers")], run_dir=str(run))
    normalize(str(run)); analyze(str(run)); triage(str(run)); result = correlate(str(run)); remediation_result = remediation(str(run))
    assert result["correlation"]["cross_provider_groups"] >= 1
    assert result["correlation"]["duplicates"] >= 2
    assert remediation_result["remediation_actions"] >= 1
    findings = list(iter_jsonl(run / "remediated.jsonl"))
    p0 = next(f for f in findings if f["priority"] == "P0")
    assert p0["remediation"]["action_id"]
    assert p0["triage"]["explanation"]
    closed = next(f for f in findings if f["source"] == "nessus")
    assert closed["disposition"] == "remediated" and closed["priority"] is None
    assert closed["triage"]["calculated_priority"] == "P3"
