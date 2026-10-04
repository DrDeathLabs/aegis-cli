from __future__ import annotations

import json

import pytest

from aegis.analysis.council import analyze
from aegis.correlation import correlate
from aegis.ingest import ingest, normalize
from aegis.providers import adapter_for
from aegis.remediation import _action_key, remediation
from aegis.storage import iter_jsonl
from aegis.triage.engine import calculate_priority, triage


def _priority_finding(
    *,
    severity="critical",
    score=9.8,
    epss=0.05,
    active=False,
    kev=False,
    functional=False,
    internet=False,
    asset="low",
    business="low",
    controls=None,
    isolated=None,
    network_zone=None,
):
    return {
        "vulnerability": {
            "severity_normalized": severity,
            "severity_original": severity,
            "cvss_scores": [{"score": score}],
            "exploited_in_wild": active,
            "exploit_available": functional,
            "exploit_maturity": "functional" if functional else "none",
            "kev": {"listed": kev},
            "epss": epss,
        },
        "asset": {
            "internet_exposed": internet,
            "asset_criticality": asset,
            "business_criticality": business,
            "isolated": isolated,
            "network_zone": network_zone,
        },
        "state": {"compensating_controls": controls or []},
        "analysis": {"technical_impact": severity, "confidence": 1.0, "missing_evidence": []},
    }


def test_calibration_keeps_cvss_secondary_to_likelihood_and_context():
    controlled = _priority_finding(controls=["strong"])
    isolated = _priority_finding(isolated=True, network_zone="isolated")
    high_cvss_without_context = _priority_finding(asset="high", business="medium", controls=[])
    medium_active_internet = _priority_finding(
        severity="medium", score=6.3, epss=0.22, active=True, internet=True
    )
    kev_critical_without_current_active = _priority_finding(
        active=False, kev=True, asset="critical", business="critical"
    )
    weak_controls = _priority_finding(
        severity="high", score=8.8, functional=True, internet=True,
        asset="critical", business="critical", controls=["monitoring only"],
    )
    strong_controls = _priority_finding(
        severity="high", score=8.8, functional=True, internet=True,
        asset="critical", business="critical", controls=["strong"],
    )

    assert calculate_priority(controlled)[0] == "P4"
    assert calculate_priority(isolated)[0] == "P4"
    assert calculate_priority(high_cvss_without_context)[0] == "P3"
    assert calculate_priority(medium_active_internet)[0] == "P1"
    assert calculate_priority(kev_critical_without_current_active)[0] == "P1"
    assert calculate_priority(weak_controls)[0] == "P1"
    # Functional exploit plus internet exposure is stronger evidence than a
    # generic control claim; controls must not neutralize that urgent path.
    assert calculate_priority(strong_controls)[0] == "P1"
    assert any(item["name"] == "control_effectiveness_guard" and item["triggered"] for item in calculate_priority(strong_controls)[2])
    assert any(item["name"] == "network_isolation_guard" and item["triggered"] for item in calculate_priority(isolated)[2])


def test_generic_json_vulnerability_aliases_are_validated_and_preserved(local_tmp):
    path = local_tmp / "generic-identities.json"
    path.write_text(json.dumps({"records": [
        {"finding_id": "G-CVE", "vulnerability": "CVE-2024-1234", "hostname": "cve.example"},
        {"finding_id": "G-VULN", "vulnerability_id": "VULN-42", "hostname": "native.example"},
        {"finding_id": "G-TEXT", "vulnerability": "arbitrary descriptive text", "hostname": "text.example"},
    ]}), encoding="utf-8")
    run = local_tmp / "generic-identities-run"
    ingest([str(path)], run_dir=str(run), provider="generic_json")
    result = normalize(str(run))
    assert result["normalized_findings"] == 2
    assert result["normalize_accounting"]["quarantined"] == 1
    findings = {item["source_finding_id"]: item for item in iter_jsonl(run / "findings.jsonl")}

    assert findings["G-CVE"]["vulnerability"]["cve"] == ["CVE-2024-1234"]
    assert findings["G-VULN"]["vulnerability"]["cve"] == []
    assert any(item["value"] == "VULN-42" for item in findings["G-VULN"]["vulnerability"]["provider_identifiers"])
    quarantine = list(iter_jsonl(run / "quarantined.jsonl"))
    text_record = next(item for item in quarantine if item["original_record"].get("finding_id") == "G-TEXT")
    assert "valid CVE or native identifier" in text_record["reason"] or "vulnerability identity" in text_record["reason"]


def test_generic_vulnerability_cve_restores_cross_provider_correlation(local_tmp):
    generic = local_tmp / "generic.json"
    generic.write_text(json.dumps({"records": [
        {"finding_id": "G-CROSS", "vulnerability": "CVE-2024-1234", "hostname": "shared.example", "ip": "192.0.2.10"},
    ]}), encoding="utf-8")
    tenable = local_tmp / "tenable.json"
    tenable.write_text(json.dumps({"vulnerabilities": [
        {"plugin_id": "T-CROSS", "plugin_name": "shared", "cve": "CVE-2024-1234", "hostname": "shared.example", "ip": "192.0.2.10"},
    ]}), encoding="utf-8")
    run = local_tmp / "generic-correlation-run"
    ingest([str(generic), str(tenable)], run_dir=str(run))
    normalize(str(run))
    analyze(str(run))
    triage(str(run))
    result = correlate(str(run))
    assert result["correlation"]["cross_provider_groups"] == 1
    groups = json.loads((run / "correlation_groups.json").read_text(encoding="utf-8"))
    group = next(item for item in groups if item["count"] == 2)
    assert set(group["providers"]) == {"generic_json", "tenable"}
    assert group["vulnerability_identity"] == "CVE-2024-1234"


def test_explicit_remediation_identity_precedes_package_inference():
    finding = {
        "asset": {"package": "openssl", "application": None, "service": "https", "fixed_version": "3.0.0"},
        "state": {"solution": "Apply FIX-G01", "remediation_id": None},
        "vulnerability": {"cve": ["CVE-2024-1234"], "identifiers": ["CVE-2024-1234"]},
        "correlation": {},
        "id": "f-explicit",
    }
    assert _action_key(finding) == ("explicit_action", "fix-g01")

    identified = dict(finding)
    identified["state"] = {"solution": "Upgrade package", "remediation_id": "REC-42"}
    assert _action_key(identified) == ("explicit_action", "remediation-id:rec-42")

    service_only = dict(finding)
    service_only["state"] = {"solution": "Apply vendor update", "remediation_id": None}
    service_only["asset"] = {"service": "https", "fixed_version": "3.0.0"}
    assert _action_key(service_only)[0] != "package_upgrade"

    package_fallback = dict(service_only)
    package_fallback["asset"] = {"package": "openssl", "fixed_version": "3.0.0"}
    assert _action_key(package_fallback) == ("package_upgrade", "openssl|3.0.0")


def test_shared_explicit_remediation_token_groups_across_provider_outputs(local_tmp):
    generic = local_tmp / "generic-remediation.json"
    generic.write_text(json.dumps({"records": [
        {"finding_id": "G-FIX", "vulnerability": "CVE-2024-1234", "hostname": "g.example", "package": "openssl", "fixed_version": "3.0.0", "solution": "Apply FIX-G01"},
    ]}), encoding="utf-8")
    tenable = local_tmp / "tenable-remediation.json"
    tenable.write_text(json.dumps({"vulnerabilities": [
        {"plugin_id": "T-FIX", "plugin_name": "other", "cve": "CVE-2024-5678", "hostname": "t.example", "package": "libssl", "fixed_version": "4.0.0", "solution": "Apply FIX-G01"},
    ]}), encoding="utf-8")
    run = local_tmp / "remediation-run"
    ingest([str(generic), str(tenable)], run_dir=str(run))
    normalize(str(run))
    analyze(str(run))
    triage(str(run))
    correlate(str(run))
    result = remediation(str(run))
    actions = json.loads((run / "remediation_actions.json").read_text(encoding="utf-8"))
    explicit = next(item for item in actions if item["kind"] == "explicit_action")
    assert result["remediation_actions"] == 1
    assert explicit["occurrence_count"] == 2
    assert set(explicit["providers"]) == {"generic_json", "tenable"}
    assert explicit["grouping_evidence"]["key"] == "fix-g01"
    assert explicit["grouping_evidence"]["packages"] == ["libssl", "openssl"]


def test_service_observations_are_not_package_grouping_evidence(local_tmp):
    path = local_tmp / "service-remediation.json"
    path.write_text(json.dumps({"records": [
        {"finding_id": "SERVICE-FIX", "vulnerability": "CVE-2024-1234", "hostname": "svc.example", "service": "https", "fixed_version": "3.0.0", "solution": "Apply vendor update"},
    ]}), encoding="utf-8")
    run = local_tmp / "service-remediation-run"
    ingest([str(path)], run_dir=str(run), provider="generic_json")
    normalize(str(run))
    analyze(str(run))
    triage(str(run))
    correlate(str(run))
    remediation(str(run))
    actions = json.loads((run / "remediation_actions.json").read_text(encoding="utf-8"))
    assert actions[0]["kind"] != "package_upgrade"
    assert actions[0]["grouping_evidence"]["packages"] == []


def test_nessus_plugin_only_is_valid_but_empty_or_marked_records_quarantine(local_tmp):
    path = local_tmp / "nessus-semantic.nessus"
    path.write_text(
        '<?xml version="1.0"?><NessusClientData_v2><Report><ReportHost name="host.example">'
        '<ReportItem pluginID="N-VALID" pluginName="Plugin-only detection" severity="2" port="443" protocol="tcp"><isValid>true</isValid><invalid_record_type>false</invalid_record_type><solution>Apply vendor update</solution></ReportItem>'
        '<ReportItem pluginID="" pluginName="No usable identity" severity="2" port="443" protocol="tcp"></ReportItem>'
        '<ReportItem pluginID="N-MARKED" pluginName="Malformed record" severity="2" port="443" protocol="tcp"></ReportItem>'
        '</ReportHost></Report></NessusClientData_v2>',
        encoding="utf-8",
    )
    run = local_tmp / "nessus-semantic-run"
    ingest([str(path)], run_dir=str(run))
    normalize_result = normalize(str(run))
    assert normalize_result["normalized_findings"] == 1
    assert normalize_result["normalize_accounting"]["quarantined"] == 2
    finding = next(iter_jsonl(run / "findings.jsonl"))
    assert finding["source_finding_id"] is None
    assert any(item["value"] == "N-VALID" for item in finding["vulnerability"]["provider_identifiers"])
    assert finding["vulnerability"]["cve"] == []
    quarantine = list(iter_jsonl(run / "quarantined.jsonl"))
    assert len(quarantine) == 2
    assert all(item["continued"] is True for item in quarantine)


@pytest.mark.parametrize(
    ("provider", "record", "expected_source_id", "secondary_id"),
    [
        ("tenable", {"finding_id": "T-FIND", "plugin_id": "T-PLUGIN", "cve": "CVE-2024-1001", "hostname": "h"}, "T-FIND", "T-PLUGIN"),
        ("qualys", {"SOURCE_FINDING_ID": "Q-FIND", "QID": "Q-1", "CVE_ID": "CVE-2024-1002", "HOSTNAME": "h"}, "Q-FIND", "Q-1"),
        ("rapid7", {"id": "R-OCC", "vulnerability_id": "R-VULN", "cve": "CVE-2024-1003", "hostname": "h"}, "R-OCC", "R-VULN"),
        ("nessus", {"source_finding_id": "N-FIND", "pluginID": "N-1", "cve": "CVE-2024-1004", "host": "h"}, "N-FIND", "N-1"),
        ("defender", {"id": "D-OCC", "vulnerabilityId": "D-VULN", "cveId": "CVE-2024-1005", "machineName": "h"}, "D-OCC", "D-VULN"),
        ("crowdstrike", {"id": "C-OCC", "vulnerability_id": "C-VULN", "spotlight_id": "spot-42", "cve": "CVE-2024-1006", "hostname": "h"}, "C-OCC", "C-VULN"),
    ],
)
def test_source_finding_identity_precedes_provider_vulnerability_ids(provider, record, expected_source_id, secondary_id):
    finding = adapter_for(provider).normalize(record, pointer="/0", report_sha256="test")
    assert finding["source_finding_id"] == expected_source_id
    source_identifiers = finding["source_metadata"]["provider_metadata"]["source_identifiers"]
    assert secondary_id in {str(value) for value in source_identifiers.values()}
    assert expected_source_id not in finding["vulnerability"]["identifiers"]
    assert all(item["value"] != expected_source_id for item in finding["vulnerability"]["provider_identifiers"])
    assert any(item["value"] == secondary_id for item in finding["vulnerability"]["provider_identifiers"])
    if provider == "crowdstrike":
        assert "spot-42" in {str(value) for value in source_identifiers.values()}
