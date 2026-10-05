from __future__ import annotations

import gzip
import json
import math
from pathlib import Path

import pytest

from aegis.intelligence.artifact import ARTIFACT_SCHEMA_VERSION, read_artifact, seal_artifact, write_artifact
from aegis.intelligence.corpus import CorpusError, _stream_nvd, build_corpus, load_training_rows, profile_for_cwe
from aegis.intelligence.features import extract_features, feature_names
from aegis.intelligence.inference import enrich_finding, load_active_model
from aegis.intelligence.model import train_model
from aegis.cli import main


def _finding(**overrides):
    finding = {
        "source": "tenable",
        "vulnerability": {
            "cve": ["CVE-2024-12345"],
            "cwe": ["CWE-79"],
            "cvss_scores": [{"score": 9.8, "version": "3.1"}],
            "cvss_vectors": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
            "epss": 0.03,
            "kev": {"listed": False},
            "exploit_available": False,
            "exploit_maturity": "none",
        },
        "asset": {"business_criticality": "high", "internet_exposed": True},
        "state": {"compensating_controls": []},
    }
    finding.update(overrides)
    return finding


def _nvd_item(cve_id: str, published: str, cwe: str, score: float, vector: str):
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": published,
            "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": score, "vectorString": vector, "attackVector": "NETWORK",
                "attackComplexity": "LOW", "privilegesRequired": "NONE", "userInteraction": "NONE",
                "confidentialityImpact": "HIGH", "integrityImpact": "HIGH", "availabilityImpact": "HIGH",
            }}]},
        }
    }


def _write_feed_set(root: Path, nvd_items: list[dict], epss_rows: list[tuple[str, float]], kev_items=None):
    feed_dir = root / "feeds"
    feed_dir.mkdir(parents=True)
    with gzip.open(feed_dir / "nvd-2024.json.gz", "wt", encoding="utf-8") as handle:
        json.dump({"format": "NVD_CVE", "vulnerabilities": nvd_items, "timestamp": "test"}, handle)
    with gzip.open(feed_dir / "epss-current.csv.gz", "wt", encoding="utf-8", newline="") as handle:
        handle.write("# public synthetic fixture for parser regression\ncve,epss,percentile\n")
        for cve, score in epss_rows:
            handle.write(f"{cve},{score},0.8\n")
    (feed_dir / "kev.json").write_text(json.dumps({"vulnerabilities": kev_items or []}), encoding="utf-8")


def _training_rows(count: int = 1200):
    rows = []
    vectors = [
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N",
    ]
    for index in range(count):
        year = 2012 + index // 100
        score = (4.0, 6.0, 8.0, 9.2)[index % 4]
        vector = vectors[index % len(vectors)]
        high = (score >= 8 and index % 3 == 0) or index % 17 == 0
        month = (index % 12) + 1
        rows.append({
            "cve_id": f"CVE-{year}-{index + 1000:04d}",
            "published": f"{year:04d}-{month:02d}-15T00:00:00.000Z",
            "cvss_score": score,
            "cvss_vector": vector,
            "cwes": [f"CWE-{(79, 89, 125)[index % 3]}"],
            "epss": 0.2 if high else 0.001 + (index % 4) * 0.001,
            "attributes": {},
        })
    return rows


def _scoring_artifact():
    names = feature_names(["CWE-79"])
    means = [0.0] * len(names)
    scales = [1.0] * len(names)
    coefficients = [0.0] * len(names)
    coefficients[names.index("cvss_base_score")] = 0.8
    payload = {
        "model_version": "test-v1", "model_type": "binary_logistic_regression",
        "trained_at": "2026-10-04T00:00:00Z", "software_version": "0.1.0",
        "feature_schema_version": "aegis-vulnerability-features-v1", "feature_names": names,
        "cwe_categories": ["CWE-79"], "means": means, "scales": scales,
        "coefficients": coefficients, "intercept": -5.0,
        "calibration": {"method": "identity", "slope": 1.0, "intercept": 0.0},
        "model_eligible_for_inference": True,
        "training": {"seed": 42}, "evaluation": {"quality_status": "test"},
    }
    return seal_artifact(payload)


def test_feature_extraction_is_provider_and_enterprise_context_independent():
    original = _finding()
    other = _finding(source="crowdstrike", asset={"business_criticality": "low", "internet_exposed": False},
                     vulnerability={**_finding()["vulnerability"], "epss": 0.99,
                                    "kev": {"listed": True}, "exploit_available": True,
                                    "exploited_in_wild": True})
    left, _ = extract_features(original, ["CWE-79"])
    right, _ = extract_features(other, ["CWE-79"])
    assert left == right


def test_model_prediction_is_independent_of_provider_epss_kev_and_asset_context(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))
    artifact = write_artifact(tmp_path / "vulnerability-model.json", _scoring_artifact())
    loaded, state = load_active_model()
    assert state == "active"
    base = enrich_finding(_finding(), loaded)
    changed = enrich_finding(_finding(
        source="rapid7", asset={"business_criticality": "critical", "internet_exposed": False,
                                 "asset_criticality": "critical"},
        vulnerability={**_finding()["vulnerability"], "epss": 0.9,
                       "kev": {"listed": True}, "exploit_available": True,
                       "exploited_in_wild": True},
        state={"compensating_controls": ["isolated"], "recurrence": 12},
    ), loaded)
    assert base["prediction"]["elevated_epss_band_probability"] == changed["prediction"]["elevated_epss_band_probability"]
    assert base["risk_band"] == changed["risk_band"]
    assert base["model_used"] and changed["model_used"]
    assert changed["public_signals"]["observed_kev_listed"] is True
    assert changed["public_signals"]["observed_epss"] == 0.9
    assert changed["enterprise_context"]["business_criticality"] == "critical"
    assert changed["source_features"]["cve"] == ["CVE-2024-12345"]
    assert "vulnerability.cve" in changed["feature_provenance"]
    assert 0.0 <= changed["confidence"] <= 1.0
    assert changed["priority_authority"] is False
    assert "priority" not in changed
    assert artifact["model_hash"] == base["model_hash"]


def test_model_absence_and_invalid_cve_degrade_without_failing():
    missing = enrich_finding(_finding(), None, unavailable_reason="model is missing")
    assert missing["model_used"] is False
    assert missing["status"] == "model is missing"
    assert missing["prediction"] is None
    no_cve = enrich_finding(_finding(vulnerability={"cve": [], "cwe": ["CWE-79"]}), _scoring_artifact())
    assert no_cve["model_used"] is False
    assert no_cve["status"] == "exactly_one_valid_cve_required_for_public_vulnerability_model"


def test_multiple_cves_are_not_silently_collapsed_to_one_model_prediction():
    finding = _finding()
    finding["vulnerability"]["cve"].append("CVE-2024-10001")
    result = enrich_finding(finding, _scoring_artifact())

    assert result["model_used"] is False
    assert result["status"] == "exactly_one_valid_cve_required_for_public_vulnerability_model"
    assert "single_valid_cve" in result["missing_features"]


def test_json_model_hash_schema_and_corrupt_handling(tmp_path):
    path = tmp_path / "model.json"
    artifact = write_artifact(path, _scoring_artifact())
    loaded, reason = read_artifact(path)
    assert loaded and reason == "valid"
    corrupted = dict(artifact)
    corrupted["coefficients"] = list(artifact["coefficients"])
    corrupted["coefficients"][0] = math.nan
    path.write_text(json.dumps(corrupted), encoding="utf-8")
    loaded, reason = read_artifact(path)
    assert loaded is None and "non-finite" in reason
    path.write_text(json.dumps({**artifact, "schema_version": "future-v9"}), encoding="utf-8")
    loaded, reason = read_artifact(path)
    assert loaded is None and "unsupported" in reason
    assert ARTIFACT_SCHEMA_VERSION == "aegis-ml-artifact-v1"


def test_temporal_training_reproducibility_and_evaluation_report(tmp_path):
    rows = _training_rows()
    first = train_model(rows, {"corpus_sha256": "fixture-hash"}, seed=77, output=tmp_path / "model-a.json")
    second = train_model(rows, {"corpus_sha256": "fixture-hash"}, seed=77, output=tmp_path / "model-b.json")
    artifact_a, reason_a = read_artifact(tmp_path / "model-a.json")
    artifact_b, reason_b = read_artifact(tmp_path / "model-b.json")
    assert reason_a == reason_b == "valid"
    assert artifact_a["coefficients"] == pytest.approx(artifact_b["coefficients"], abs=1e-10)
    assert artifact_a["intercept"] == pytest.approx(artifact_b["intercept"], abs=1e-10)
    assert first["evaluation"]["split_method"].startswith("chronological")
    assert first["evaluation"]["class_balance"]["test"]["n"] == second["test_rows"]
    assert first["evaluation"]["metrics"]["model"]["brier_score"] >= 0
    assert first["evaluation"]["metrics"]["model"]["average_precision_pr_auc"] >= 0
    metrics = first["evaluation"]["metrics"]["model"]
    assert metrics["observed_prevalence"] == metrics["positive_count"] / metrics["n"]
    assert 0 <= metrics["precision_at_threshold"] <= 1
    assert 0 <= metrics["recall_at_threshold"] <= 1
    assert 0 <= metrics["f1_at_threshold"] <= 1
    assert len(metrics["confusion_matrix_at_threshold"]) == 2
    assert first["evaluation"]["quality_status"] in {
        "better_than_temporal_prevalence_baseline", "not_better_than_temporal_prevalence_baseline",
    }
    assert first["evaluation"]["target"].startswith("current EPSS score")
    assert (tmp_path / "model-evaluation.json").is_file()


def test_streaming_nvd_parser_yields_records_without_loading_array(tmp_path):
    path = tmp_path / "nvd-2024.json.gz"
    records = [_nvd_item(f"CVE-2024-{index + 1000}", "2024-01-01T00:00:00.000Z", "CWE-79", 8.8,
                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") for index in range(10)]
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump({"format": "NVD_CVE", "timestamp": "t", "vulnerabilities": records, "tail": {"ok": True}}, handle)
    assert len(list(_stream_nvd(path))) == 10


def test_corpus_build_profiles_and_feed_lineage(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "data"))
    cves = ["CVE-2024-1001", "CVE-2024-1002", "CVE-2024-1003"]
    records = [_nvd_item(cve, f"2024-01-0{index + 1}T00:00:00.000Z", "CWE-79", 8.8,
                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") for index, cve in enumerate(cves)]
    _write_feed_set(tmp_path / "data", records, list(zip(cves, [0.01, 0.2, 0.4])),
                    [{"cveID": cves[1], "knownRansomwareCampaignUse": "Known", "dateAdded": "2024-02-01"}])
    result = build_corpus()
    assert result["cve_records"] == 3
    assert result["cwe_profiles"] == 1
    assert len(result["feed_manifest"]) == 3
    rows, metadata = load_training_rows()
    assert len(rows) == 3 and metadata["corpus_sha256"] == result["corpus_sha256"]
    profile = profile_for_cwe("CWE-79")
    assert profile["cve_count"] == 3
    assert profile["kev_rate"] == pytest.approx(1 / 3)
    assert profile["high_epss_rate"] == pytest.approx(2 / 3)


def test_nvd_stream_parser_rejects_truncated_or_malformed_feed(tmp_path):
    path = tmp_path / "bad.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write('{"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}')
    with pytest.raises(CorpusError):
        list(_stream_nvd(path))


def test_real_cli_council_ml_evidence_does_not_change_deterministic_priority(tmp_path, monkeypatch):
    from click.testing import CliRunner
    import aegis.intelligence.feeds as feeds

    monkeypatch.setattr(feeds, "urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("normal Aegis processing must not access the network")))
    fixture = Path(__file__).parents[1] / "fixtures" / "providers" / "tenable.json"
    runner = CliRunner()

    unavailable_dir = tmp_path / "without-model"
    monkeypatch.setenv("AEGIS_DATA_DIR", str(unavailable_dir))
    no_model_run = tmp_path / "run-without-model"
    no_model = runner.invoke(main, ["run-all", str(fixture), "--provider", "tenable", "--run-dir", str(no_model_run)])
    assert no_model.exit_code == 0, no_model.output
    no_model_findings = [json.loads(line) for line in (no_model_run / "triaged.jsonl").read_text(encoding="utf-8").splitlines()]

    active_dir = tmp_path / "with-model"
    active_dir.mkdir()
    write_artifact(active_dir / "vulnerability-model.json", _scoring_artifact())
    monkeypatch.setenv("AEGIS_DATA_DIR", str(active_dir))
    model_run = tmp_path / "run-with-model"
    with_model = runner.invoke(main, ["run-all", str(fixture), "--provider", "tenable", "--run-dir", str(model_run)])
    assert with_model.exit_code == 0, with_model.output
    findings = [json.loads(line) for line in (model_run / "triaged.jsonl").read_text(encoding="utf-8").splitlines()]
    analyzed = [json.loads(line) for line in (model_run / "analyzed.jsonl").read_text(encoding="utf-8").splitlines()]

    assert [row["priority"] for row in findings] == [row["priority"] for row in no_model_findings]
    assert findings[0]["ml"]["model_used"] is True
    assert findings[0]["analysis"]["ml_review"]["priority_authority"] is False
    assert any(item["role"] == "ML Vulnerability Intelligence Reviewer" for item in analyzed[0]["analysis"]["council"])
    report_path = tmp_path / "model-report.json"
    report = runner.invoke(main, ["report", "--run-dir", str(model_run), "--format", "json", "--output", str(report_path)])
    assert report.exit_code == 0, report.output
    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_payload["findings"][0]["ml"]["model_hash"] == findings[0]["ml"]["model_hash"]


def test_model_lifecycle_cli_is_offline_and_status_is_safe(tmp_path, monkeypatch):
    from click.testing import CliRunner
    import aegis.intelligence.feeds as feeds

    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "aegis-data"))
    monkeypatch.setattr(feeds, "urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("status cannot make requests")))
    runner = CliRunner()
    result = runner.invoke(main, ["model", "status"])
    assert result.exit_code == 0
    assert json.loads(result.output)["network_used"] is False
    assert "model is missing" in json.loads(result.output)["model"]["state"]
    path_result = runner.invoke(main, ["model", "path"])
    assert path_result.exit_code == 0
    assert json.loads(path_result.output)["data_directory"] == str(tmp_path / "aegis-data")


def test_model_reset_removes_only_recognized_model_and_feed_artifacts(tmp_path, monkeypatch):
    from aegis.intelligence.service import reset

    root = tmp_path / "aegis-data"
    feeds = root / "feeds"
    feeds.mkdir(parents=True)
    recognized = [
        root / "vulnerability-model.json",
        root / "model-evaluation.json",
        root / "vulnerability-corpus.sqlite3",
        feeds / "nvd-2024.json.gz",
        feeds / "epss-current.csv.gz",
        feeds / "kev.json",
    ]
    unrelated = feeds / "operator-notes.txt"
    for path in [*recognized, unrelated]:
        path.write_text("test data", encoding="utf-8")
    monkeypatch.setenv("AEGIS_DATA_DIR", str(root))

    result = reset()

    assert result["status"] == "reset"
    assert result["bytes_removed"] == sum(len("test data") for _ in recognized)
    assert all(not path.exists() for path in recognized)
    assert unrelated.read_text(encoding="utf-8") == "test data"
