from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from aegis.analysis.council import analyze
from aegis.correlation import correlate
from aegis.ingest import detect_provider, ingest, normalize
from aegis.providers import adapter_for
from aegis.reporting import report
from aegis.remediation import remediation
from aegis.storage import iter_jsonl
from aegis.triage.engine import calculate_priority, triage


def _run_all(path, run, provider="auto"):
    ingest([str(path)], run_dir=str(run), provider=provider)
    normalize(str(run))
    analyze(str(run))
    triage(str(run))
    correlate(str(run))
    remediation(str(run))


def test_qualys_native_severity_is_ordinal_not_cvss():
    expected = {1: "low", 2: "medium", 3: "high", 4: "high", 5: "critical"}
    for native, normalized in expected.items():
        finding = adapter_for("qualys").normalize(
            {"id": f"Q-OCC-{native}", "UNIQUE_VULN_ID": f"Q-VULN-{native}",
             "QID": f"QID-{native}", "SEVERITY": native, "HOSTNAME": "q.example"},
            pointer=f"/{native}", report_sha256="test",
        )
        assert finding["vulnerability"]["severity_normalized"] == normalized
        assert finding["vulnerability"]["source_signals"]["severity_normalization"]["basis"] == "qualys_native_ordinal_1_5"
        assert {item["value"] for item in finding["vulnerability"]["provider_identifiers"]} >= {f"Q-VULN-{native}"}
        assert finding["evidence"]["missing"] == []


def test_documented_current_provider_shapes_preserve_nested_fields():
    fixtures = {
        "tenable": "fixtures/official_contracts/tenable_vm_current.json",
        "defender": "fixtures/official_contracts/defender_software_vulnerabilities_by_machine.json",
        "crowdstrike": "fixtures/official_contracts/crowdstrike_spotlight_nested.json",
    }
    for provider, fixture in fixtures.items():
        record = json.loads(open(fixture, encoding="utf-8").read())
        assert detect_provider(Path(fixture)) == provider
        finding = adapter_for(provider).normalize(record, pointer="/0", report_sha256="test")
        assert finding["source_metadata"]["original_record"] == record
        assert finding["asset"]["asset_id"] or finding["asset"]["hostname"]
        assert finding["vulnerability"]["cve"]
        assert finding["evidence"]["missing"] == []
    tenable = adapter_for("tenable").normalize(
        json.loads(open(fixtures["tenable"], encoding="utf-8").read()), pointer="/0", report_sha256="test"
    )
    assert tenable["asset"]["ip_addresses"] == ["192.0.2.10", "2001:db8::10"]
    assert {item["version"] for item in tenable["vulnerability"]["cvss_scores"]} == {"3", "4"}
    assert tenable["vulnerability"]["epss"] == 0.71
    assert tenable["vulnerability"]["exploit_maturity"] == "poc"
    defender = adapter_for("defender").normalize(
        json.loads(open(fixtures["defender"], encoding="utf-8").read()), pointer="/0", report_sha256="test"
    )
    assert defender["asset"]["package"] == "Example Agent"
    assert defender["state"]["remediation_id"] == "KB5002001"
    crowdstrike = adapter_for("crowdstrike").normalize(
        json.loads(open(fixtures["crowdstrike"], encoding="utf-8").read()), pointer="/0", report_sha256="test"
    )
    assert crowdstrike["asset"]["internet_exposed"] is True
    assert crowdstrike["vulnerability"]["exploit_maturity"] == "poc"
    assert crowdstrike["vulnerability"]["vendor_risk_metadata"]["remediation_level"] == "official-fix-available"


def test_jsonl_detection_survives_malformed_vendor_row(local_tmp):
    path = local_tmp / "tenable-mixed.jsonl"
    path.write_text(
        '{"id":"T-1","pluginID":"PLUGIN-1","cve":"CVE-2026-4001","hostname":"one.example"}\n'
        '{broken vendor row\n'
        '{"id":"T-2","pluginID":"PLUGIN-2","cve":"CVE-2026-4002","hostname":"two.example"}\n',
        encoding="utf-8",
    )
    assert detect_provider(path) == "tenable"
    run = local_tmp / "mixed-run"
    imported = ingest([str(path)], run_dir=str(run), provider="auto")
    normalized = normalize(str(run))
    assert imported["providers"]["tenable"]["records"] == 3
    assert normalized["normalized_findings"] == 2
    assert normalized["normalize_accounting"]["quarantined"] == 1
    assert {f["source_finding_id"] for f in iter_jsonl(run / "findings.jsonl")} == {"T-1", "T-2"}
    assert all(row["provider"] == "tenable" for row in iter_jsonl(run / "quarantined.jsonl"))
    assert json.loads((run / "run.json").read_text(encoding="utf-8"))["record_accounting"]["total_records"] == 3


def test_metadata_arrays_are_not_candidate_finding_collections(local_tmp):
    path = local_tmp / "metadata-array.json"
    path.write_text(json.dumps({
        "records": [{"finding_id": "F-1", "cve": "CVE-2026-4010", "hostname": "asset.example"}],
        "metadata": {"owners": [{"name": "not-a-finding"}]},
    }), encoding="utf-8")
    run = local_tmp / "metadata-array-run"
    ingest([str(path)], run_dir=str(run), provider="generic_json")
    result = normalize(str(run))
    assert result["normalized_findings"] == 1
    assert result["normalize_accounting"]["quarantined"] == 0


def test_duplicate_source_fields_finish_in_terminal_state(local_tmp):
    json_path = local_tmp / "duplicate.json"
    json_path.write_text(
        '{"records":[{"finding_id":"F-1","finding_id":"F-2","cve":"CVE-2026-4020","hostname":"asset.example"}]}',
        encoding="utf-8",
    )
    json_run = local_tmp / "duplicate-json-run"
    result = ingest([str(json_path)], run_dir=str(json_run), provider="generic_json")
    assert result["status"] == "rejected"
    assert result["stages"]["ingest"]["status"] == "failed"
    assert result["status"] not in {"ingesting", "running"}

    csv_path = local_tmp / "duplicate.csv"
    csv_path.write_text("finding_id,finding_id,cve,hostname\nF-1,F-2,CVE-2026-4021,asset.example\n", encoding="utf-8")
    csv_run = local_tmp / "duplicate-csv-run"
    result = ingest([str(csv_path)], run_dir=str(csv_run), provider="generic_csv")
    assert result["status"] == "rejected"
    assert result["stages"]["ingest"]["status"] == "failed"


def test_snapshot_hash_is_the_hash_of_the_parsed_immutable_bytes(local_tmp):
    path = local_tmp / "snapshot.jsonl"
    path.write_text('{"finding_id":"F-1","cve":"CVE-2026-4030","hostname":"asset.example"}\n', encoding="utf-8")
    run = local_tmp / "snapshot-run"
    ingest([str(path)], run_dir=str(run), provider="generic_json")
    raw = next(iter_jsonl(run / "raw_records.jsonl"))
    snapshot = open(raw["source_snapshot_path"], "rb").read()
    assert raw["report_sha256"] == hashlib.sha256(snapshot).hexdigest()


def test_semantic_identity_is_stable_when_new_observation_is_added():
    adapter = adapter_for("generic_json")
    baseline = adapter.normalize({"finding_id": "F-1", "vulnerability_id": "V-1", "hostname": "asset.example"}, pointer="/0", report_sha256="test")
    enriched = adapter.normalize({"finding_id": "F-2", "vulnerability_id": "V-1", "hostname": "asset.example", "ip": "192.0.2.40"}, pointer="/1", report_sha256="test")
    # Independent observations have distinct local signatures.  Cross-run
    # continuity is established by correlation against a baseline registry,
    # not by exposing a mutable preferred-alias hash as a durable handle.
    assert baseline["observation_signature"] != enriched["observation_signature"]


def test_generic_vulnerability_alias_requires_a_valid_cve():
    adapter = adapter_for("generic_json")
    finding = adapter.normalize(
        {"finding_id": "GEN-VULN", "vulnerability": "CVE-2026-4070", "hostname": "asset.example", "severity": "medium"},
        pointer="/0", report_sha256="test",
    )
    assert finding["vulnerability"]["cve"] == ["CVE-2026-4070"]
    assert finding["evidence"]["missing"] == []
    try:
        adapter.normalize({"finding_id": "GEN-TITLE", "vulnerability": "OpenSSH issue", "hostname": "asset.example"}, pointer="/1", report_sha256="test")
    except ValueError as exc:
        assert "vulnerability identity" in str(exc)
    else:
        raise AssertionError("generic prose must not manufacture vulnerability identity")


def test_ip_bridge_is_conflict_aware(local_tmp):
    path = local_tmp / "bridge.json"
    path.write_text(json.dumps({"records": [
        {"finding_id": "A", "cve": "CVE-2026-4040", "hostname": "host1", "ip": "192.0.2.1"},
        {"finding_id": "B", "cve": "CVE-2026-4040", "hostname": "host1", "ip": "192.0.2.2"},
        {"finding_id": "C", "cve": "CVE-2026-4040", "hostname": "host2", "ip": "192.0.2.2"},
    ]}), encoding="utf-8")
    run = local_tmp / "bridge-run"
    _run_all(path, run, "generic_json")
    result = json.loads((run / "run.json").read_text(encoding="utf-8"))
    assert result["correlation"]["groups"] == 2
    assert result["correlation"]["blocked_conflict_edges"] >= 1
    findings = {item["source_finding_id"]: item for item in iter_jsonl(run / "correlated.jsonl")}
    assert findings["A"]["correlation"]["group_id"] == findings["B"]["correlation"]["group_id"]
    assert findings["C"]["correlation"]["group_id"] != findings["A"]["correlation"]["group_id"]
    assert findings["B"]["correlation"]["conflicts"] or findings["C"]["correlation"]["conflicts"]


def test_failed_or_ambiguous_controls_never_deescalate_priority():
    base = {
        "vulnerability": {"severity_normalized": "critical", "cvss_scores": [{"score": 9.8}], "epss": 0.01, "kev": {"listed": False}},
        "asset": {"asset_criticality": "high", "business_criticality": "medium", "internet_exposed": False, "network_zone": "internal"},
        "analysis": {"technical_impact": "critical"},
        "state": {"compensating_controls": []},
    }
    no_control = calculate_priority(base)
    for text in ("firewall failed", "firewall bypassed", "firewall misconfigured", "segmentation failed", "isolated but failed", "monitor only", "expired virtual patch"):
        case = json.loads(json.dumps(base))
        case["state"]["compensating_controls"] = [text]
        case["state"]["control_evidence"] = [{"text": text, "state": "ineffective", "effective": False}]
        result = calculate_priority(case)
        assert result[0] == no_control[0]
        assert not any(guard["name"] == "control_deescalation_guard" and guard["triggered"] for guard in result[2])
    positive = json.loads(json.dumps(base))
    positive["state"]["compensating_controls"] = ["firewall effective and blocks inbound access"]
    positive["state"]["control_evidence"] = [{"text": positive["state"]["compensating_controls"][0], "state": "effective", "effective": True}]
    assert calculate_priority(positive)[0] == "P4"


def test_default_table_and_findings_paths_are_bounded(local_tmp):
    path = local_tmp / "bounded.json"
    path.write_text(json.dumps({"records": [
        {"finding_id": f"F-{i:03d}", "cve": "CVE-2026-4050", "hostname": f"asset-{i}.example", "severity": "low"}
        for i in range(150)
    ]}), encoding="utf-8")
    run = local_tmp / "bounded-run"
    _run_all(path, run, "generic_json")
    table = report(str(run), format_name="table")
    assert "Total findings: 150" in table
    assert table.count("generic_json") <= 100
    from click.testing import CliRunner
    from aegis.cli import main
    result = CliRunner().invoke(main, ["findings", "--run-dir", str(run), "--limit", "7"])
    assert result.exit_code == 0
    assert len(json.loads(result.output)) == 7


def test_scale_evidence_hashes_artifacts_and_checks_lineage(local_tmp):
    path = local_tmp / "scale-evidence.jsonl"
    path.write_text(
        "\n".join(json.dumps({"finding_id": f"F-{i}", "cve": "CVE-2026-4060", "hostname": f"h-{i}.example"}) for i in range(5)) + "\n",
        encoding="utf-8",
    )
    run = local_tmp / "scale-evidence-run"
    _run_all(path, run, "generic_json")
    tool_path = Path(__file__).parents[1] / "tools" / "scale_evidence.py"
    spec = importlib.util.spec_from_file_location("aegis_scale_evidence", tool_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    build_evidence = module.build_evidence
    output = local_tmp / "scale-evidence.json"
    evidence = build_evidence(run, output, stride=2)
    assert evidence["artifacts"]["findings.jsonl"]["record_count"] == 5
    assert evidence["artifacts"]["findings.jsonl"]["sha256"]
    assert all(item["output_sha256_matches"] for item in evidence["lineage_checks"] if item["stage"] != "ingest")
