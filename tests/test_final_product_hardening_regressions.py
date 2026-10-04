from __future__ import annotations

import json

from click.testing import CliRunner

from aegis.cli import main
from aegis.analysis.council import analyze
from aegis.correlation import correlate
from aegis.ingest import detect_provider, ingest, normalize
from aegis.providers import adapter_for
from aegis.remediation import remediation
from aegis.reporting import csv_text, html_text, payload
from aegis.providers.base import iter_json_records
from aegis.storage import iter_jsonl
from aegis.triage.engine import triage


def test_provider_identity_contracts_keep_occurrence_vulnerability_and_target_separate():
    cases = {
        "tenable": ({"id": "TEN-OCC", "pluginID": "TEN-PLUGIN", "cve": "CVE-2024-1001", "hostname": "ten.example"}, "TEN-OCC", "TEN-PLUGIN", "ten.example"),
        "qualys": ({"id": "Q-OCC", "QID": "Q-PLUGIN", "CVE_ID": "CVE-2024-1002", "HOSTNAME": "q.example"}, "Q-OCC", "Q-PLUGIN", "q.example"),
        "rapid7": ({"id": "R-OCC", "vulnerability_id": "R-VULN", "cve": "CVE-2024-1003", "hostname": "r.example"}, "R-OCC", "R-VULN", "r.example"),
        "defender": ({"id": "D-OCC", "vulnerabilityId": "D-VULN", "cveId": "CVE-2024-1004", "machineName": "d.example"}, "D-OCC", "D-VULN", "d.example"),
        "crowdstrike": ({"id": "C-OCC", "vulnerability_id": "C-VULN", "cve": "CVE-2024-1005", "aid": "cs-asset"}, "C-OCC", "C-VULN", "cs-asset"),
        "nessus": ({"id": "N-OCC", "pluginID": "N-PLUGIN", "cve": "CVE-2024-1006", "host": "n.example"}, "N-OCC", "N-PLUGIN", "n.example"),
        "generic_json": ({"id": "G-OCC", "vulnerability_id": "G-VULN", "cve": "CVE-2024-1007", "hostname": "g.example"}, "G-OCC", "G-VULN", "g.example"),
        "generic_csv": ({"id": "GC-OCC", "vulnerability_id": "GC-VULN", "cve": "CVE-2024-1008", "hostname": "gc.example"}, "GC-OCC", "GC-VULN", "gc.example"),
    }
    for provider, (record, occurrence, vulnerability, target) in cases.items():
        finding = adapter_for(provider).normalize(record, pointer="/0", report_sha256="audit")
        assert finding["source_finding_id"] == occurrence
        assert any(item["value"] == vulnerability and item["kind"] == "vulnerability" for item in finding["vulnerability"]["provider_identifiers"])
        asset = finding["asset"]
        assert target in {asset.get("asset_id"), asset.get("hostname"), *(asset.get("ip_addresses") or [])}
        assert asset.get("asset_id") != occurrence
        assert asset.get("asset_id") != vulnerability


def test_tenable_bare_uuid_cannot_become_asset_identity():
    record = {"uuid": "TEN-OCC-UUID", "pluginID": "TEN-PLUGIN", "cve": "CVE-2024-1010"}
    try:
        adapter_for("tenable").normalize(record, pointer="/0", report_sha256="audit")
    except ValueError as exc:
        assert "missing required target identity" in str(exc)
    else:
        raise AssertionError("occurrence UUID was accepted as a Tenable asset identity")


def test_generic_csv_native_vulnerability_and_extra_columns_are_preserved(local_tmp):
    path = local_tmp / "generic-native.csv"
    path.write_text(
        "finding_id,vulnerability_id,title,description,hostname\n"
        "G-CSV-NATIVE,VULN-CSV-1,Native issue,Details,asset.example,opaque-a,opaque-b\n",
        encoding="utf-8",
    )
    run = local_tmp / "generic-native-run"
    ingest([str(path)], run_dir=str(run), provider="generic_csv")
    result = normalize(str(run))
    assert result["normalized_findings"] == 1
    finding = next(iter_jsonl(run / "findings.jsonl"))
    assert finding["source_finding_id"] == "G-CSV-NATIVE"
    assert any(item["value"] == "VULN-CSV-1" for item in finding["vulnerability"]["provider_identifiers"])
    assert finding["title"] == "Native issue"
    assert finding["description"] == "Details"
    assert finding["source_metadata"]["original_record"]["_aegis_csv_extra_columns"] == ["opaque-a", "opaque-b"]
    assert any("extra columns" in warning for warning in finding["evidence"]["warnings"])


def test_provider_metadata_does_not_promote_asset_ids_to_vulnerability_identifiers():
    finding = adapter_for("crowdstrike").normalize(
        {"id": "CS-OCC", "vulnerability_id": "CS-VULN", "aid": "CS-ASSET", "hostname": "cs.example"},
        pointer="/0", report_sha256="audit",
    )
    assert finding["asset"]["asset_id"] == "CS-ASSET"
    assert "CS-ASSET" not in finding["source_metadata"]["provider_metadata"].get("source_identifiers", {}).values()
    assert "CS-ASSET" not in finding["vulnerability"]["identifiers"]


def test_secondary_provider_identifiers_are_mapped_metadata_not_false_unmapped_fields():
    finding = adapter_for("rapid7").normalize(
        {"id": "R-OCC", "vulnerability_id": "R-VULN", "cve": "CVE-2024-1114", "hostname": "r.example"},
        pointer="/0", report_sha256="audit",
    )
    assert "vulnerability_id" not in finding["source_metadata"]["unmapped_fields"]
    assert finding["source_metadata"]["provider_metadata"]["source_identifiers"]["vulnerability_id"] == "R-VULN"


def test_auto_detection_uses_schema_keys_not_field_values(local_tmp):
    json_path = local_tmp / "renamed-generic.json"
    json_path.write_text(json.dumps({"records": [{
        "id": "G-1", "cve": "CVE-2024-1111", "hostname": "asset.example",
        "description": "pluginId pluginName vprScore riskScore vulnerabilityId machineId",
    }]}), encoding="utf-8")
    csv_path = local_tmp / "renamed-generic.csv"
    csv_path.write_text(
        "finding_id,cve,hostname,description\n"
        "G-2,CVE-2024-1112,asset.example,pluginId pluginName vprScore riskScore\n",
        encoding="utf-8",
    )
    assert detect_provider(json_path) == "generic_json"
    assert detect_provider(csv_path) == "generic_csv"


def test_top_level_and_jsonl_scalar_records_are_quarantinable(local_tmp):
    scalar = local_tmp / "scalar.json"
    scalar.write_text("4", encoding="utf-8")
    records = list(iter_json_records(scalar))
    assert records == [({"_malformed": 4}, "")]

    jsonl = local_tmp / "scalar.jsonl"
    jsonl.write_text('4\n{"id":"G-1"}\n', encoding="utf-8")
    run = local_tmp / "scalar-run"
    ingest([str(jsonl)], run_dir=str(run), provider="generic_json")
    result = normalize(str(run))
    assert result["normalized_findings"] == 0
    assert result["normalize_accounting"]["quarantined"] == 2
    quarantined = list(iter_jsonl(run / "quarantined.jsonl"))
    assert {row["original_record"].get("_malformed") for row in quarantined} == {4, None}


def test_fully_malformed_ingest_fails_clearly_and_retains_run_metadata(local_tmp):
    path = local_tmp / "malformed.json"
    path.write_text('{"records":[', encoding="utf-8")
    run = local_tmp / "malformed-run"
    result = CliRunner().invoke(main, ["ingest", str(path), "--run-dir", str(run), "--provider", "generic_json"])
    assert result.exit_code != 0
    assert "ingest rejected" in result.output
    metadata = json.loads((run / "run.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "rejected"
    assert metadata["raw_records"] == 0


def test_nested_mappings_are_not_reported_as_unmapped_root_fields():
    finding = adapter_for("tenable").normalize(
        {"pluginID": "TEN-1", "cve": "CVE-2024-1113", "asset": {"uuid": "asset-1", "hostname": "nested.example", "opaque": "kept"}},
        pointer="/0", report_sha256="audit",
    )
    assert "asset" not in finding["source_metadata"]["unmapped_fields"]
    assert finding["source_metadata"]["original_record"]["asset"]["opaque"] == "kept"


def test_generic_asset_reference_is_a_target_when_no_hostname_or_ip_exists():
    finding = adapter_for("generic_json").normalize(
        {"finding_id": "GEN-ASSET-REF", "vulnerability_id": "GEN-VULN-1", "asset_ref": "resource-42"},
        pointer="/0", report_sha256="audit",
    )
    assert finding["asset"]["asset_id"] == "resource-42"
    assert finding["source_finding_id"] == "GEN-ASSET-REF"
    assert any(item["value"] == "GEN-VULN-1" for item in finding["vulnerability"]["provider_identifiers"])


def test_reports_preserve_calculated_and_effective_priority_for_every_finding(local_tmp):
    path = local_tmp / "report-fields.json"
    records = [
        {"finding_id": "REPORT-ACTIVE", "cve": "CVE-2024-1201", "hostname": "active.example", "severity": "high", "disposition": "confirmed"},
        {"finding_id": "REPORT-ACCEPTED", "cve": "CVE-2024-1202", "hostname": "accepted.example", "severity": "high", "disposition": "accepted_risk"},
    ]
    path.write_text(json.dumps({"records": records}), encoding="utf-8")
    run = local_tmp / "report-fields-run"
    ingest([str(path)], run_dir=str(run), provider="generic_json")
    normalize(str(run))
    analyze(str(run))
    triage(str(run))
    correlate(str(run))
    remediation(str(run))

    report_data = payload(run)
    assert report_data["summary"]["calculated_priority_counts"]
    assert report_data["summary"]["effective_priority_counts"]["P3"] == 1
    assert report_data["summary"]["effective_priority_counts"]["P4"] == 0
    csv_output = csv_text(report_data)
    assert "calculated_priority,effective_priority,priority" in csv_output.splitlines()[0]
    assert "correlation_group_id" in csv_output.splitlines()[0]
    assert "REPORT-ACCEPTED" in csv_output
    html_output = html_text(report_data)
    assert html_output.count("<tr>") == 3  # header plus both findings
    assert all(finding["id"] in html_output for finding in report_data["findings"])
