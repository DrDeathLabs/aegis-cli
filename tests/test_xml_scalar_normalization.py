from __future__ import annotations

from aegis.analysis.council import analyze
from aegis.ingest import ingest, normalize
from aegis.providers.base import normalize_xml_leaf_scalars
from aegis.providers.nessus import NessusAdapter
from aegis.storage import iter_jsonl


def test_xml_leaf_scalar_normalizer_unwraps_text_but_preserves_attributes():
    value = normalize_xml_leaf_scalars({
        "kev": {"#text": "true"},
        "disposition": {"#text": "accepted_risk"},
        "source_finding_id": {"#text": "F-1"},
        "nested": [{"#text": "one"}, {"#text": "two"}],
        "attribute_leaf": {"@name": "kind", "#text": "value"},
    })
    assert value == {
        "kev": "true",
        "disposition": "accepted_risk",
        "source_finding_id": "F-1",
        "nested": ["one", "two"],
        "attribute_leaf": {"@name": "kind", "#text": "value"},
    }


def test_nessus_xml_scalars_map_all_dispositions_and_preserve_identifiers(local_tmp):
    dispositions = (
        "confirmed", "unconfirmed", "false_positive", "mitigated",
        "accepted_risk", "remediated",
    )
    items = []
    for index, disposition in enumerate(dispositions):
        kev = "true" if index % 2 == 0 else "false"
        items.append(
            f'<ReportItem pluginID="PLUGIN-{index}" pluginName="scalar-{index}" severity="2">'
            f'<source_finding_id>FINDING-{index}</source_finding_id>'
            f'<cve>CVE-2024-{1000 + index}</cve>'
            f'<kev>{kev}</kev>'
            f'<disposition>{disposition}</disposition>'
            f'<case_id>CASE-{index}</case_id>'
            f'<submission_id>SUBMISSION-{index}</submission_id>'
            f'<opaque_extra_field>opaque-{index}</opaque_extra_field>'
            '<host>asset.example</host>'
            '</ReportItem>'
        )
    path = local_tmp / "nessus-scalars.nessus"
    path.write_text(
        '<?xml version="1.0"?><NessusClientData_v2><Report><ReportHost name="asset.example">'
        + "".join(items)
        + "</ReportHost></Report></NessusClientData_v2>",
        encoding="utf-8",
    )

    parsed = list(NessusAdapter().records(path))
    assert len(parsed) == len(dispositions)
    assert all(isinstance(record[0]["kev"], str) for record in parsed)
    assert all(isinstance(record[0]["source_finding_id"], str) for record in parsed)
    assert all(isinstance(record[0]["cve"], str) for record in parsed)
    assert all(isinstance(record[0]["case_id"], str) for record in parsed)
    assert all(isinstance(record[0]["submission_id"], str) for record in parsed)

    run = local_tmp / "nessus-scalars-run"
    ingest([str(path)], run_dir=str(run), provider="nessus")
    result = normalize(str(run))
    assert result["normalized_findings"] == len(dispositions)
    analyze(str(run))

    findings = {item["source_finding_id"]: item for item in iter_jsonl(run / "analyzed.jsonl")}
    assert set(findings) == {f"FINDING-{index}" for index in range(len(dispositions))}
    for index, disposition in enumerate(dispositions):
        finding = findings[f"FINDING-{index}"]
        original = finding["source_metadata"]["original_record"]
        assert finding["vulnerability"]["cve"] == [f"CVE-2024-{1000 + index}"]
        assert finding["vulnerability"]["kev"]["listed"] is (index % 2 == 0)
        assert finding["state"]["status"] == disposition
        assert finding["disposition"] == disposition
        assert original["case_id"] == f"CASE-{index}"
        assert original["submission_id"] == f"SUBMISSION-{index}"
        assert original["opaque_extra_field"] == f"opaque-{index}"
        assert "#text" not in str(original)


def test_empty_nessus_report_item_is_quarantined_for_missing_identity(local_tmp):
    path = local_tmp / "empty-report-item.nessus"
    path.write_text(
        '<?xml version="1.0"?><NessusClientData_v2><Report><ReportHost name="asset.example">'
        '<ReportItem />'
        '</ReportHost></Report></NessusClientData_v2>',
        encoding="utf-8",
    )
    run = local_tmp / "empty-report-item-run"
    ingest([str(path)], run_dir=str(run), provider="nessus")
    normalize(str(run))
    assert list(iter_jsonl(run / "findings.jsonl")) == []
    quarantine = list(iter_jsonl(run / "quarantined.jsonl"))
    assert len(quarantine) == 1
    assert "vulnerability identity" in quarantine[0]["reason"]
