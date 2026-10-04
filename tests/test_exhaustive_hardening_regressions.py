from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aegis.analysis.council import analyze
from aegis.correlation import correlate
from aegis.ingest import detect_provider, ingest, normalize
from aegis.models import vulnerability_identity
from aegis.providers import adapter_for
from aegis.providers.api import PermanentProviderError, paginate_json
from aegis.providers.base import iter_csv_records, iter_json_records
from aegis.remediation import _action_key, remediation
from aegis.reporting import report
from aegis.replay import export_corpus, validate_corpus
from aegis.storage import iter_jsonl
from aegis.triage.engine import calculate_priority, triage


ROOT = Path(__file__).parents[1]
OFFICIAL = ROOT / "tests" / "fixtures" / "official_contracts"


def _run_all(path: Path, run: Path, provider: str = "auto") -> dict:
    imported = ingest([str(path)], run_dir=str(run), provider=provider)
    assert imported["raw_records"] >= 1
    normalize(str(run))
    analyze(str(run))
    triage(str(run))
    correlate(str(run))
    return remediation(str(run))


@pytest.mark.parametrize(
    ("filename", "provider"),
    [("defender_machines_vulnerabilities.json", "defender"), ("crowdstrike_spotlight.json", "crowdstrike"),
     ("tenable_vulnerability_export.json", "tenable"), ("rapid7_asset_vulnerability.json", "rapid7")],
)
def test_official_json_contracts_are_detected_and_preserve_native_context(filename, provider):
    path = OFFICIAL / filename
    assert detect_provider(path) == provider
    records = list(adapter_for(provider).records(path))
    finding = adapter_for(provider).normalize(records[0][0], pointer=records[0][1], report_sha256="official")
    assert finding["source"] == provider
    assert finding["source_metadata"]["provider_metadata"]["contract_version"]
    assert finding["vulnerability"]["cve"] or finding["vulnerability"]["provider_identifiers"]
    assert finding["asset"]["asset_id"] or finding["asset"]["hostname"] or finding["asset"]["ip_addresses"]


def test_official_provider_nested_fields_are_not_dropped(local_tmp):
    defender = adapter_for("defender").normalize({
        "id": "mde-occ", "cveId": "CVE-2024-1001", "machineId": "machine-1", "fixingKbId": "KB123456",
        "productName": "edge", "productVersion": "1.2.3", "productVendor": "microsoft", "severity": "Low",
    }, pointer="/value/0", report_sha256="x")
    metadata = defender["source_metadata"]["provider_metadata"]
    assert {metadata["fixingKbId"], metadata["productName"], metadata["productVersion"], metadata["productVendor"]} == {"KB123456", "edge", "1.2.3", "microsoft"}
    crowd = adapter_for("crowdstrike").normalize(json.loads((OFFICIAL / "crowdstrike_spotlight.json").read_text())["resources"][0], pointer="/resources/0", report_sha256="x")
    context = crowd["source_metadata"]["provider_metadata"]["documented_context"]
    assert context["cve"]["is_cisa_kev"] is True and context["exposure"]["internet_exposed"] is True
    assert crowd["vulnerability"]["kev"]["listed"] is True


def test_qualys_doctype_is_safe_and_one_finding_per_detection(local_tmp):
    path = OFFICIAL / "qualys_host_detection_doctype.xml"
    assert detect_provider(path) == "qualys"
    assert len(list(adapter_for("qualys").records(path))) == 2
    run = local_tmp / "qualys-official"
    _run_all(path, run, "qualys")
    findings = list(iter_jsonl(run / "findings.jsonl"))
    assert {item["source_finding_id"] for item in findings} == {None}
    assert {item["source_metadata"]["provider_metadata"]["qid"] for item in findings} == {"12345", "12346"}
    assert all(item["asset"]["ip_addresses"] == ["192.0.2.40"] for item in findings)
    assert all("<!DOCTYPE" not in json.dumps(item) for item in findings)


def test_nessus_reporthost_context_is_propagated_with_item_precedence():
    path = OFFICIAL / "nessus_reporthost_context.xml"
    record, pointer = next(adapter_for("nessus").records(path))
    finding = adapter_for("nessus").normalize(record, pointer=pointer, report_sha256="x")
    assert finding["asset"]["ip_addresses"] == ["192.0.2.50"]
    assert finding["asset"]["asset_criticality"] == "high"
    assert finding["asset"]["business_criticality"] == "critical"
    assert finding["asset"]["internet_exposed"] is False
    assert finding["asset"]["network_zone"] == "restricted"
    assert finding["state"]["compensating_controls"] == ["segmentation"]
    assert finding["source_metadata"]["provider_metadata"]["reporthost_context"]


def test_identity_separation_is_invariant_under_key_order_and_native_namespace():
    left = {"asset": {"id": "asset-1", "hostname": "same.example"}, "vulnerability": {"id": "vuln-1"}, "id": "occ-1"}
    right = {"id": "occ-1", "vulnerability": {"id": "vuln-1"}, "asset": {"hostname": "same.example", "id": "asset-1"}}
    a = adapter_for("generic_json").normalize(left, pointer="/records/0", report_sha256="x")
    b = adapter_for("generic_json").normalize(right, pointer="/records/0", report_sha256="x")
    assert a["source_finding_id"] == b["source_finding_id"] == "occ-1"
    assert a["asset"]["asset_id"] == b["asset"]["asset_id"] == "asset-1"
    assert vulnerability_identity(a) == vulnerability_identity(b) == "generic_json:vulnerability:VULN-1"
    assert "occ-1" not in a["vulnerability"]["identifiers"]


@pytest.mark.parametrize("raw", ["unknown", "999.999.999.999", "", "not-an-ip"])
def test_invalid_ip_never_enters_canonical_asset_or_correlation(raw):
    finding = adapter_for("generic_json").normalize({"id": "occ", "cve": "CVE-2024-1234", "ip": raw, "hostname": "valid.example"}, pointer="/0", report_sha256="x")
    assert raw not in finding["asset"]["ip_addresses"]


def test_parser_recovers_jsonl_and_retains_all_collections_and_duplicate_diagnostics(local_tmp):
    jsonl = local_tmp / "mixed.jsonl"
    jsonl.write_text('{"id":"a","cve":"CVE-2024-1001","hostname":"a.example"}\nnot json\n{"id":"b","cve":"CVE-2024-1002","hostname":"b.example"}\n', encoding="utf-8")
    rows = list(iter_json_records(jsonl))
    assert [pointer for _, pointer in rows] == ["/lines/1", "/lines/2", "/lines/3"]
    assert rows[1][0]["_malformed"] == "not json"
    multi = local_tmp / "multi.json"
    multi.write_text(json.dumps({"findings": [{"id": "a"}], "vulnerabilities": [{"id": "b"}]}), encoding="utf-8")
    assert [pointer for _, pointer in iter_json_records(multi)] == ["/findings/0", "/vulnerabilities/0"]
    duplicate = local_tmp / "duplicate.jsonl"
    duplicate.write_text('{"id":"first","id":"second","cve":"CVE-2024-1001","hostname":"x.example"}', encoding="utf-8")
    row = next(iter_json_records(duplicate))[0]
    assert row["_aegis_duplicate_keys"] == ["id"] and row["_aegis_original_pairs"]
    duplicate_csv = local_tmp / "duplicate.csv"
    duplicate_csv.write_text("id,id,cve,hostname\na,b,CVE-2024-1001,x.example\n", encoding="utf-8")
    csv_row = next(iter_csv_records(duplicate_csv))[0]
    assert csv_row["_aegis_duplicate_headers"] == ["id"] and csv_row["_aegis_csv_pairs"][0] == ["id", "a"]


def test_provider_detection_rejects_ambiguous_contracts(local_tmp):
    path = local_tmp / "ambiguous.json"
    path.write_text(json.dumps({"records": [{"assetId": "a", "vulnId": "v", "machineId": "m", "cveId": "CVE-2024-1001", "riskScore": 5}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="ambiguous provider schema"):
        detect_provider(path)


def test_directory_names_do_not_suppress_vulnerability_files(local_tmp):
    input_root = local_tmp / "directory-input"
    nested = input_root / "vendor" / "dist" / "build" / "migrations"
    nested.mkdir(parents=True, exist_ok=True)
    path = nested / "vulnerability.json"
    path.write_text(json.dumps({"records": [{"id": "nested", "cve": "CVE-2024-1234", "hostname": "nested.example"}]}), encoding="utf-8")
    run = local_tmp / "directory-run"
    assert ingest([str(input_root)], run_dir=str(run), provider="generic_json")["raw_records"] == 1


def _triage_finding(**overrides):
    finding = {"vulnerability": {"severity_normalized": "high", "severity_original": "high", "cvss_scores": [{"score": 8.0}], "kev": {"listed": False}, "exploit_available": False, "exploited_in_wild": False, "exploit_maturity": None, "epss": 0.01}, "asset": {"internet_exposed": False, "asset_criticality": "low", "business_criticality": "low", "isolated": False}, "state": {"compensating_controls": []}, "analysis": {"technical_impact": "high", "missing_evidence": []}}
    for section, values in overrides.items():
        finding[section].update(values)
    return finding


def test_triage_metamorphic_negation_and_keV_floor():
    base = calculate_priority(_triage_finding())[0]
    assert base in {"P3", "P4"}
    assert calculate_priority(_triage_finding(asset={"internet_exposed": True}))[0] in {"P2", "P3"}
    assert calculate_priority(_triage_finding(state={"compensating_controls": ["no firewall", "not segmented"]}))[0] == base
    for impact in ("low", "medium", "high", "critical"):
        priority = calculate_priority(_triage_finding(vulnerability={"severity_normalized": impact, "kev": {"listed": True}}))[0]
        assert priority in {"P0", "P1", "P2"}


def test_typed_bounds_and_xml_scalar_normalization():
    finding = adapter_for("generic_json").normalize({"id": "x", "cve": "CVE-2024-1001", "hostname": "x.example", "cvss": 2, "epss": "85%", "port": 99999, "kev": {"listed": "false"}}, pointer="/0", report_sha256="x")
    assert finding["vulnerability"]["kev"]["listed"] is False
    assert finding["vulnerability"]["epss"] == 0.85
    assert finding["asset"]["port"] is None
    assert finding["vulnerability"]["severity_normalized"] == "low"


def test_remediation_precedence_and_inactive_priority():
    finding = {"asset": {"package": "openssl", "fixed_version": "3.0.0", "service": "https", "hostname": "x.example"}, "state": {"solution": "Upgrade to 3.0.0; apply FIX-42", "remediation_id": "REC-1"}, "vulnerability": {"cve": ["CVE-2024-1"], "provider_identifiers": [{"provider": "rapid7", "kind": "vulnerability", "value": "R1"}]}, "correlation": {}, "id": "f"}
    assert _action_key(finding) == ("explicit_action", "fix-42")
    finding["state"] = {"solution": "Upgrade to 3.0.0", "remediation_id": "REC-1"}
    assert _action_key(finding) == ("explicit_action", "remediation-id:rec-1")
    finding["state"] = {"solution": "Upgrade to 3.0.0"}
    assert _action_key(finding)[0] != "package_upgrade" or _action_key(finding)[1] == "openssl|3.0.0"
    unrelated = {"asset": {"hostname": "y.example"}, "state": {"solution": "Upgrade the affected product to version 3.0.0"}, "vulnerability": {"cve": ["CVE-2024-2"]}, "correlation": {}, "id": "g"}
    assert _action_key(unrelated)[0] == "finding"


def test_report_redacts_raw_source_and_lineage_fails_closed(local_tmp):
    path = local_tmp / "sensitive.json"
    path.write_text(json.dumps({"records": [{"id": "s", "cve": "CVE-2024-1001", "hostname": "s.example", "api_key": "secret"}]}), encoding="utf-8")
    run = local_tmp / "sensitive-run"
    _run_all(path, run, "generic_json")
    output = Path(report(str(run), format_name="json"))
    rendered = json.loads(output.read_text(encoding="utf-8"))
    assert "secret" not in output.read_text(encoding="utf-8")
    marker = rendered["findings"][0]["source_metadata"]["original_record"]
    assert isinstance(marker, str) and marker.startswith("[REDACTED_SOURCE_RECORD sha256:")
    stale = run / "remediated.jsonl"
    stale.write_text(stale.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="stale"):
        report(str(run), format_name="json", output=str(local_tmp / "stale.json"))


def test_replay_is_streamed_and_semantically_validated(local_tmp):
    source = local_tmp / "canonical.jsonl"
    source.write_text(json.dumps(adapter_for("generic_json").normalize({"id": "x", "cve": "CVE-2024-1001", "hostname": "x.example"}, pointer="/0", report_sha256="x")) + "\n", encoding="utf-8")
    artifact = local_tmp / "replay.jsonl"
    export_corpus(source, artifact)
    assert validate_corpus(artifact)["valid"] is True
    content = artifact.read_text(encoding="utf-8").replace('"findings":1', '"findings":2')
    artifact.write_text(content, encoding="utf-8")
    assert validate_corpus(artifact)["valid"] is False


def test_pagination_permanent_error_is_not_retried():
    calls = []
    def request(_token):
        calls.append(1)
        raise PermanentProviderError("bad request")
    with pytest.raises(PermanentProviderError):
        list(paginate_json(request, retries=4))
    assert len(calls) == 1


def test_invalid_replay_cli_returns_nonzero(local_tmp):
    artifact = local_tmp / "invalid.jsonl"
    artifact.write_text('{"kind":"header","format":"wrong"}\n', encoding="utf-8")
    result = subprocess.run([sys.executable, "-m", "aegis.cli", "replay-validate", str(artifact)], cwd=ROOT, text=True, capture_output=True)
    assert result.returncode != 0
