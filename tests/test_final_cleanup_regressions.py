from __future__ import annotations

import json

import pytest

from aegis.analysis.council import analyze
from aegis.ingest import ingest, normalize
from aegis.providers import adapter_for
from aegis.storage import iter_jsonl
from aegis.triage.engine import calculate_priority, triage


def _active_finding(*, impact: str, internet: bool, criticality: str, controls: list[str], kev: bool,
                    exploited: bool) -> dict:
    scores = {"low": 2.0, "medium": 5.0, "high": 8.0, "critical": 9.8}
    return {
        "vulnerability": {
            "severity_normalized": impact,
            "severity_original": impact,
            "cvss_scores": [{"score": scores[impact]}],
            "exploited_in_wild": exploited,
            "exploit_available": False,
            "exploit_maturity": None,
            "kev": {"listed": kev},
            "epss": 0.01,
        },
        "asset": {
            "internet_exposed": internet,
            "asset_criticality": criticality,
            "business_criticality": criticality,
        },
        "state": {"compensating_controls": controls},
        "analysis": {"technical_impact": impact, "confidence": 1.0, "missing_evidence": []},
    }


@pytest.mark.parametrize("active_signal", ["kev", "exploited_in_wild"])
def test_active_exploitation_evidence_has_a_deterministic_p2_floor(active_signal):
    for impact in ("low", "medium", "high", "critical"):
        for internet in (False, True):
            for criticality in ("low", "medium", "high", "critical"):
                for controls in ([], ["strong network segmentation"]):
                    finding = _active_finding(
                        impact=impact, internet=internet, criticality=criticality,
                        controls=controls, kev=active_signal == "kev",
                        exploited=active_signal == "exploited_in_wild",
                    )
                    priority, _drivers, guards, _explanation = calculate_priority(finding)
                    active_guard = next(item for item in guards if item["name"] == "active_exploitation_guard")
                    assert active_guard["triggered"] is True
                    assert active_guard["minimum_priority"] == "P2"
                    assert priority in {"P0", "P1", "P2"}
                    minimum_guard = next(item for item in guards if item["name"] == "active_exploitation_minimum_guard")
                    if minimum_guard["triggered"]:
                        assert priority == "P2"
                    if priority in {"P0", "P1"}:
                        assert minimum_guard["triggered"] is False

    floor_priority, _drivers, floor_guards, _explanation = calculate_priority(
        _active_finding(impact="low", internet=False, criticality="low", controls=["strong"], kev=True, exploited=False)
    )
    assert floor_priority == "P2"
    assert any(item["name"] == "active_exploitation_minimum_guard" and item["triggered"] for item in floor_guards)


def test_poc_only_exploit_availability_does_not_promote_equivalent_cross_provider_findings():
    common = {
        "cve": "CVE-2024-9900",
        "hostname": "controlled.internal.example",
        "severity": "high",
        "cvss": 8.0,
        "exploit_maturity": "poc",
        "internet_exposed": False,
        "asset_criticality": "low",
        "business_criticality": "low",
        "compensating_controls": ["strong segmentation"],
    }
    records = {
        "generic_json": {"finding_id": "GEN-POC", "vulnerability": common["cve"], **common, "exploit_available": True},
        "tenable": {"finding_id": "TEN-POC", **common, "exploit_available": False},
    }
    normalized = {
        provider: adapter_for(provider).normalize(record, pointer=f"/{provider}", report_sha256="test")
        for provider, record in records.items()
    }
    results = {provider: calculate_priority(finding) for provider, finding in normalized.items()}

    assert results["generic_json"][0] == results["tenable"][0] == "P4"
    assert all(not any(item["name"] == "functional_exploit_guard" and item["triggered"] for item in result[2]) for result in results.values())
    assert normalized["generic_json"]["vulnerability"]["exploit_available"] is True
    assert normalized["tenable"]["vulnerability"]["exploit_available"] is False
    assert normalized["generic_json"]["vulnerability"]["exploit_maturity"] == "poc"
    assert normalized["tenable"]["vulnerability"]["exploit_maturity"] == "poc"


def test_effective_priority_is_null_for_every_non_active_disposition(local_tmp):
    dispositions = ("confirmed", "accepted_risk", "mitigated", "false_positive", "remediated", "unconfirmed")
    records = [{
        "finding_id": f"F-{index}", "cve": f"CVE-2024-{3000 + index}", "hostname": f"asset-{index}.example",
        "severity": "critical", "cvss": 9.8, "exploit_available": True, "exploit_maturity": "functional",
        "exploited_in_wild": True, "kev": True, "internet_exposed": True,
        "asset_criticality": "critical", "business_criticality": "critical", "disposition": disposition,
    } for index, disposition in enumerate(dispositions)]
    path = local_tmp / "disposition-semantics.json"
    path.write_text(json.dumps({"records": records}), encoding="utf-8")
    run = local_tmp / "disposition-semantics-run"
    ingest([str(path)], run_dir=str(run), provider="generic_json")
    normalize(str(run))
    analyze(str(run))
    triage(str(run))

    findings = {item["source_finding_id"]: item for item in iter_jsonl(run / "triaged.jsonl")}
    for index, disposition in enumerate(dispositions):
        finding = findings[f"F-{index}"]
        calculated = finding["triage"]["calculated_priority"]
        expected_effective = calculated if disposition == "confirmed" else None
        assert finding["calculated_priority"] == calculated
        assert finding["effective_priority"] == expected_effective
        assert finding["priority"] == expected_effective
        assert finding["triage"]["effective_priority"] == expected_effective
        assert finding["triage"]["active_queue"] is (disposition == "confirmed")
