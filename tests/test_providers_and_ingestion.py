from __future__ import annotations

from pathlib import Path

import pytest

from aegis.ingest import detect_provider, ingest, normalize
from aegis.providers import available_adapters
from aegis.providers.base import iter_xml_records
from aegis.storage import iter_jsonl


ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "fixtures" / "providers"


def test_all_day_one_adapters_and_auto_detection():
    expected = {"tenable", "qualys", "rapid7", "defender", "crowdstrike", "nessus", "generic_json", "generic_csv"}
    assert set(available_adapters()) == expected
    assert detect_provider(FIXTURES / "tenable.json") == "tenable"
    assert detect_provider(FIXTURES / "qualys.json") == "qualys"
    assert detect_provider(FIXTURES / "rapid7.json") == "rapid7"
    assert detect_provider(FIXTURES / "defender.json") == "defender"
    assert detect_provider(FIXTURES / "crowdstrike.json") == "crowdstrike"
    assert detect_provider(FIXTURES / "generic.json") == "generic_json"
    assert detect_provider(FIXTURES / "generic.csv") == "generic_csv"
    assert detect_provider(FIXTURES / "nessus.nessus") == "nessus"


def test_fixture_directory_is_lossless_and_normalizes_to_canonical_model(local_tmp):
    run = local_tmp / "run"
    imported = ingest([str(FIXTURES)], run_dir=str(run))
    assert imported["raw_records"] == 13
    assert set(imported["providers"]) == expected_providers()
    normalized = normalize(str(run))
    assert normalized["normalized_findings"] == 13
    findings = list(iter_jsonl(run / "findings.jsonl"))
    assert {finding["source"] for finding in findings} == expected_providers()
    assert all(finding["source_metadata"]["original_record"] for finding in findings)
    generic = next(f for f in findings if f["source"] == "generic_json" and f["source_finding_id"] == "G-7007")
    assert "custom_owner_note" in generic["source_metadata"]["unmapped_fields"]
    generic_csv = next(f for f in findings if f["source"] == "generic_csv")
    assert generic_csv["source_finding_id"] == "G-CSV-9009"
    assert generic_csv["disposition"] == "confirmed"
    tenable = next(f for f in findings if f["source"] == "tenable")
    assert any(item["value"] == "T-1001" for item in tenable["vulnerability"]["provider_identifiers"])
    qualys = next(f for f in findings if f["source"] == "qualys")
    assert tenable["vulnerability"]["vendor_risk_score"] == 9.9
    assert qualys["vulnerability"]["vendor_risk_score"] == 95.0
    assert tenable["vulnerability"]["source_signals"]["vendor_risk_score"]["original"] == 9.9
    nessus = next(f for f in findings if f["source"] == "nessus")
    assert nessus["asset"]["hostname"] == "legacy-6.example"
    assert imported["record_accounting"]["unexplained"] == 0
    assert normalized["normalize_record_accounting"]["unexplained"] == 0


def expected_providers():
    return {"tenable", "qualys", "rapid7", "defender", "crowdstrike", "nessus", "generic_json", "generic_csv"}


def test_malformed_record_is_quarantined_and_xxe_is_rejected(local_tmp):
    bad_json = local_tmp / "bad.json"
    bad_json.write_text('{"findings":[{"title":"ok","cve":"CVE-2024-0001"}, 4]}', encoding="utf-8")
    run = local_tmp / "bad-run"
    imported = ingest([str(bad_json)], run_dir=str(run), provider="generic_json")
    assert imported["raw_records"] == 2
    normalized = normalize(str(run))
    # The CVE-bearing record still lacks a target, so the third repair's
    # canonical contract quarantines both malformed inputs.
    assert normalized["normalize_record_accounting"]["malformed"] == 2
    assert normalized["normalized_findings"] == 0
    assert normalized["normalize_accounting"]["quarantined"] == 2
    assert (run / "quarantined.jsonl").exists()
    xxe = local_tmp / "unsafe.xml"
    xxe.write_text('<!DOCTYPE x [<!ENTITY e "bad">]><root>&e;</root>', encoding="utf-8")
    with pytest.raises(ValueError, match="DOCTYPE/ENTITY"):
        list(iter_xml_records(xxe))
