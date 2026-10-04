from __future__ import annotations

import json

from aegis.analysis.council import analyze
from aegis.ingest import ingest, normalize
from aegis.providers import adapter_for
from aegis.remediation import remediation
from aegis.storage import iter_jsonl
from aegis.triage.engine import calculate_priority, triage
from aegis.correlation import correlate


def _run_all(paths, run, provider=None):
    ingest([str(path) for path in paths], run_dir=str(run), provider=provider)
    normalize(str(run))
    analyze(str(run))
    triage(str(run))
    correlate(str(run))
    remediation(str(run))


def _controlled_priority(*, controls=None, isolated=False, internet=False,
                         active=False, kev=False, epss=0.31, functional=False,
                         asset="high", business="medium"):
    return {
        "vulnerability": {
            "severity_normalized": "critical",
            "severity_original": "critical",
            "cvss_scores": [{"score": 9.8}],
            "exploited_in_wild": active,
            "exploit_available": functional,
            "exploit_maturity": "functional" if functional else "poc",
            "kev": {"listed": kev},
            "epss": epss,
        },
        "asset": {
            "internet_exposed": internet,
            "asset_criticality": asset,
            "business_criticality": business,
            "isolated": isolated,
            "network_zone": "isolated" if isolated else "internal",
        },
        "state": {"compensating_controls": controls or []},
        "analysis": {"technical_impact": "critical", "confidence": 1.0, "missing_evidence": []},
    }


def test_nessus_reporthost_context_propagates_with_item_precedence_and_provenance(local_tmp):
    path = local_tmp / "nested-context.nessus"
    path.write_text(
        '<?xml version="1.0"?><NessusClientData_v2><Report>'
        '<ReportHost name="host.example">'
        '<HostProperties>'
        '<tag name="host-ip">192.0.2.50</tag>'
        '<tag name="asset_criticality">high</tag>'
        '<tag name="business_criticality">medium</tag>'
        '<tag name="internet_exposed">false</tag>'
        '<tag name="network_zone">internal</tag>'
        '<tag name="compensating_control">strong</tag>'
        '</HostProperties>'
        '<ReportItem pluginID="N-HOST-1" pluginName="first" severity="2" />'
        '<ReportItem pluginID="N-HOST-2" pluginName="second" severity="2">'
        '<host-ip>198.51.100.50</host-ip><business_criticality>critical</business_criticality>'
        '<compensating_control>virtual patch</compensating_control>'
        '</ReportItem>'
        '</ReportHost></Report></NessusClientData_v2>',
        encoding="utf-8",
    )
    run = local_tmp / "nessus-context-run"
    ingest([str(path)], run_dir=str(run), provider="nessus")
    result = normalize(str(run))
    assert result["normalized_findings"] == 2
    findings = list(iter_jsonl(run / "findings.jsonl"))
    assert all(item["source_finding_id"] is None for item in findings)
    first, second = findings
    assert first["asset"]["hostname"] == "host.example"
    assert first["asset"]["ip_addresses"] == ["192.0.2.50"]
    assert first["asset"]["asset_criticality"] == "high"
    assert first["asset"]["business_criticality"] == "medium"
    assert first["asset"]["internet_exposed"] is False
    assert first["asset"]["network_zone"] == "internal"
    assert first["state"]["compensating_controls"] == ["strong"]
    assert second["asset"]["ip_addresses"] == ["198.51.100.50"]
    assert second["asset"]["business_criticality"] == "critical"
    assert second["state"]["compensating_controls"] == ["virtual patch"]
    host_evidence = first["source_metadata"]["provider_metadata"]["reporthost_context"]
    assert host_evidence["values"]["ip"] == "192.0.2.50"
    assert any("reporthost" in item.get("provenance", "").lower() for item in first["evidence"]["items"] if item["field"] == "ip")
    assert any("reportitem" not in item.get("provenance", "").lower() for item in second["evidence"]["items"] if item["field"] == "ip")


def test_crowdstrike_asset_and_business_criticality_are_independent():
    finding = adapter_for("crowdstrike").normalize(
        {"id": "C-OCC", "vulnerability_id": "C-VULN", "cve": "CVE-2024-1006",
         "aid": "device-6", "asset_criticality": "high",
         "business_criticality": "medium"},
        pointer="/0", report_sha256="test",
    )
    assert finding["asset"]["asset_criticality"] == "high"
    assert finding["asset"]["business_criticality"] == "medium"
    absent = adapter_for("crowdstrike").normalize(
        {"id": "C-ABSENT", "vulnerability_id": "C-VULN", "cve": "CVE-2024-1007",
         "aid": "device-7", "asset_criticality": "high"},
        pointer="/1", report_sha256="test",
    )
    assert absent["asset"]["business_criticality"] is None


def test_defender_recommendation_id_is_secondary_to_shared_action_token(local_tmp):
    defender = local_tmp / "defender.json"
    defender.write_text(json.dumps({"vulnerabilities": [{
        "id": "D-FIX", "vulnerabilityId": "D-VULN", "cveId": "CVE-2024-1234",
        "machineId": "machine-d", "remediation": "Apply FIX-G01",
        "recommendationId": "rec-defender-1",
    }]}), encoding="utf-8")
    generic = local_tmp / "generic.json"
    generic.write_text(json.dumps({"records": [{
        "finding_id": "G-FIX", "vulnerability": "CVE-2024-1234",
        "hostname": "host-g", "solution": "Apply FIX-G01",
    }]}), encoding="utf-8")
    run = local_tmp / "defender-remediation-run"
    _run_all([defender, generic], run)
    actions = json.loads((run / "remediation_actions.json").read_text(encoding="utf-8"))
    explicit = next(item for item in actions if item["kind"] == "explicit_action")
    assert explicit["occurrence_count"] == 2
    assert set(explicit["providers"]) == {"defender", "generic_json"}
    assert explicit["grouping_evidence"]["key"] == "fix-g01"
    assert explicit["grouping_evidence"]["remediation_ids"] == ["rec-defender-1"]


def test_records_need_vulnerability_and_target_identity(local_tmp):
    path = local_tmp / "invalid-targets.csv"
    path.write_text(
        "finding_id,cve_id,hostname,ip,severity\n"
        "ONLY-FINDING,, , ,high\n"
        "VALID-VULN-NO-TARGET,CVE-2024-1234,,,high\n"
        "VALID-NATIVE,,device.example,,high\n",
        encoding="utf-8",
    )
    run = local_tmp / "invalid-targets-run"
    ingest([str(path)], run_dir=str(run), provider="generic_csv")
    result = normalize(str(run))
    assert result["normalized_findings"] == 0
    assert result["normalize_accounting"]["quarantined"] == 3
    quarantine = list(iter_jsonl(run / "quarantined.jsonl"))
    assert len(quarantine) == 3
    assert all("target identity" in item["reason"] or "vulnerability identity" in item["reason"] for item in quarantine)
    assert all(item["original_record"] for item in quarantine)


def test_provider_native_resource_id_is_a_legitimate_target():
    finding = adapter_for("generic_json").normalize(
        {"finding_id": "RESOURCE-FINDING", "vulnerability_id": "VULN-RESOURCE",
         "resource_id": "resource-42"},
        pointer="/0", report_sha256="test",
    )
    assert finding["asset"]["asset_id"] == "resource-42"


def test_controls_and_isolation_are_part_of_tier_selection():
    no_control = _controlled_priority(controls=[])
    controlled = _controlled_priority(controls=["strong"], asset="high", business="medium")
    isolated = _controlled_priority(controls=[], isolated=True, asset="low", business="low")
    internet = _controlled_priority(controls=[], internet=True, asset="high", business="critical")
    poc_controlled = _controlled_priority(controls=["segmentation and virtual patch"], asset="high", business="medium")
    active_controlled = _controlled_priority(controls=["strong"], active=True, functional=True, internet=True, asset="critical", business="critical")
    kev_controlled = _controlled_priority(controls=["strong"], kev=True, internet=True, asset="critical", business="critical", functional=False)
    low_likelihood_isolated = _controlled_priority(controls=["strong"], isolated=True, epss=0.01, asset="critical", business="low")
    high_likelihood = _controlled_priority(controls=[], epss=0.9, asset="critical", business="critical")

    assert calculate_priority(no_control)[0] in {"P2", "P3"}
    assert calculate_priority(controlled)[0] == "P4"
    assert calculate_priority(controlled)[0] != calculate_priority(no_control)[0]
    assert calculate_priority(isolated)[0] == "P4"
    assert calculate_priority(isolated)[0] != calculate_priority(internet)[0]
    assert calculate_priority(poc_controlled)[0] == "P4"
    assert calculate_priority(active_controlled)[0] == "P0"
    assert calculate_priority(kev_controlled)[0] in {"P0", "P1"}
    assert calculate_priority(low_likelihood_isolated)[0] in {"P3", "P4"}
    assert calculate_priority(high_likelihood)[0] in {"P1", "P2"}
    guards = calculate_priority(controlled)[2]
    assert any(item["name"] == "control_deescalation_guard" and item["triggered"] for item in guards)
