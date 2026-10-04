from __future__ import annotations

import json

from aegis.analysis.council import analyze
from aegis.correlation import correlate
from aegis.ingest import ingest, normalize
from aegis.providers import adapter_for
from aegis.storage import iter_jsonl
from aegis.triage.engine import triage


def _record(**overrides):
    record = {
        "id": "R-OCCURRENCE-1",
        "vulnerability_id": "R-VULN-1",
        "cve": "CVE-2024-7001",
        "severity": "high",
    }
    record.update(overrides)
    return record


def test_rapid7_occurrence_id_stays_source_identity_and_not_asset_identity():
    record = _record(hostname="rapi.example")
    finding = adapter_for("rapid7").normalize(
        record, pointer="/vulnerabilities/0", report_sha256="rapid7-report",
    )

    assert finding["source_finding_id"] == "R-OCCURRENCE-1"
    assert finding["asset"]["asset_id"] is None
    assert finding["asset"]["hostname"] == "rapi.example"
    assert finding["vulnerability"]["identifiers"] == []
    assert any(item["value"] == "R-VULN-1" for item in finding["vulnerability"]["provider_identifiers"])
    assert all(item["value"] != "R-OCCURRENCE-1" for item in finding["vulnerability"]["provider_identifiers"])
    metadata = finding["source_metadata"]
    assert metadata["original_record"] == record
    assert metadata["record_pointer"] == "/vulnerabilities/0"
    assert metadata["report_sha256"] == "rapid7-report"
    assert metadata["provider_metadata"]["source_identifiers"]["id"] == "R-OCCURRENCE-1"
    assert metadata["provider_metadata"]["source_identifiers"]["vulnerability_id"] == "R-VULN-1"


def test_rapid7_legitimate_target_forms_are_accepted_without_occurrence_fallback():
    cases = [
        (_record(hostname="hostname-only.example"), None, "hostname-only.example"),
        (_record(asset={"id": "asset-native-7"}), "asset-native-7", None),
        (_record(ip="192.0.2.7"), None, None),
        (_record(asset_id="asset-direct-7"), "asset-direct-7", None),
    ]
    for record, expected_asset_id, expected_hostname in cases:
        finding = adapter_for("rapid7").normalize(record, pointer="/0", report_sha256="test")
        assert finding["source_finding_id"] == "R-OCCURRENCE-1"
        assert finding["asset"]["asset_id"] == expected_asset_id
        assert finding["asset"]["hostname"] == expected_hostname
        if expected_asset_id:
            assert expected_asset_id not in {"R-OCCURRENCE-1", "R-VULN-1"}


def test_rapid7_valid_vulnerability_without_target_is_quarantined_and_native_vulnerability_is_accepted(local_tmp):
    path = local_tmp / "rapid7-target-identity.json"
    path.write_text(json.dumps({"vulnerabilities": [
        _record(id="R-BAD-TARGET", vulnerability_id="R-VULN-BAD", cve="CVE-2024-7002"),
        _record(id="R-NATIVE-VULN", vulnerability_id="R-VULN-NATIVE", cve=None, hostname="native.example"),
        _record(id="R-NATIVE-ASSET", vulnerability_id="R-VULN-ASSET", cve=None, asset={"id": "asset-only"}),
    ]}), encoding="utf-8")
    run = local_tmp / "rapid7-target-identity-run"

    ingest([str(path)], run_dir=str(run), provider="rapid7")
    result = normalize(str(run))
    findings = list(iter_jsonl(run / "findings.jsonl"))
    quarantine = list(iter_jsonl(run / "quarantined.jsonl"))

    assert result["normalized_findings"] == 2
    assert result["normalize_accounting"]["quarantined"] == 1
    assert {finding["source_finding_id"] for finding in findings} == {"R-NATIVE-VULN", "R-NATIVE-ASSET"}
    native = next(f for f in findings if f["source_finding_id"] == "R-NATIVE-VULN")
    asset_only = next(f for f in findings if f["source_finding_id"] == "R-NATIVE-ASSET")
    assert native["vulnerability"]["cve"] == []
    assert any(item["value"] == "R-VULN-NATIVE" for item in native["vulnerability"]["provider_identifiers"])
    assert native["asset"]["hostname"] == "native.example"
    assert native["asset"]["asset_id"] is None
    assert asset_only["asset"]["asset_id"] == "asset-only"
    assert asset_only["asset"]["asset_id"] not in {"R-NATIVE-ASSET", "R-VULN-ASSET"}
    assert quarantine[0]["original_record"]["id"] == "R-BAD-TARGET"
    assert "missing required target identity" in quarantine[0]["reason"]


def test_rapid7_correlation_uses_real_target_observations_not_occurrence_ids(local_tmp):
    path = local_tmp / "rapid7-correlation.json"
    path.write_text(json.dumps({"vulnerabilities": [
        _record(id="R-SAME-A", hostname="shared-asset.example"),
        _record(id="R-SAME-B", hostname="shared-asset.example"),
        _record(id="R-DIFFERENT", hostname="different-asset.example"),
    ]}), encoding="utf-8")
    run = local_tmp / "rapid7-correlation-run"

    ingest([str(path)], run_dir=str(run), provider="rapid7")
    normalize(str(run))
    analyze(str(run))
    triage(str(run))
    result = correlate(str(run))
    findings = list(iter_jsonl(run / "correlated.jsonl"))
    groups = {finding["source_finding_id"]: finding["correlation"]["group_id"] for finding in findings}

    assert result["correlation"]["records"] == 3
    assert groups["R-SAME-A"] == groups["R-SAME-B"]
    assert groups["R-SAME-A"] != groups["R-DIFFERENT"]
    assert all(finding["asset"]["asset_id"] is None for finding in findings)
    assert all(finding["asset"]["hostname"] for finding in findings)
