from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from aegis.analysis.budget import LLMBudget
from aegis.analysis.council import _analysis_for
from aegis.analysis.llm import ChatMessage, ModelResponse
from aegis.analysis.schemas import MockModelResponse
from aegis.analysis.structured import chat_structured
from aegis.cli import main
from aegis.correlation import _asset_descriptor
from aegis.ingest import detect_provider, ingest, normalize
from aegis.models import reconcile_semantic_identity
from aegis.providers import adapter_for
from aegis.providers.base import iter_json_records
from aegis.reporting import iter_findings, report
from aegis.remediation import _action_key
from aegis.storage import ResourceLimitExceeded, enforce_run_limits


def _generic(record: dict) -> dict:
    return adapter_for("generic_json").normalize(record, pointer="/0", report_sha256="test")


def test_semantic_reconciliation_survives_nonconflicting_alias_arrival_orders():
    cases = [
        ({"hostname": "host.example"}, {"hostname": "host.example", "ip": "192.0.2.10"}),
        ({"hostname": "host.example"}, {"hostname": "host.example", "asset_id": "asset-1"}),
        ({"ip": "192.0.2.10"}, {"ip": "192.0.2.10", "hostname": "host.example"}),
    ]
    for before_target, after_target in cases:
        left = _generic({"finding_id": "occ-a", "vulnerability_id": "native-1", **before_target})
        right = _generic({"finding_id": "occ-b", "vulnerability_id": "native-1", **after_target})
        assert reconcile_semantic_identity(left, right)
        assert left["identity"]["semantic_aliases"]
    native_only = _generic({"finding_id": "occ-a", "vulnerability_id": "native-2", "hostname": "h.example"})
    native_cve = _generic({"finding_id": "occ-b", "vulnerability_id": "native-2", "vulnerability": "CVE-2026-9001", "hostname": "h.example"})
    assert reconcile_semantic_identity(native_only, native_cve)
    assert reconcile_semantic_identity(
        _generic({"finding_id": "a", "vulnerability": "CVE-2026-9002", "hostname": "h.example"}),
        _generic({"hostname": "h.example", "vulnerability": "CVE-2026-9002", "finding_id": "b"}),
    )


def test_provider_local_asset_ids_are_namespaced_for_group_identity():
    left = {"source": "generic_json", "asset": {"asset_id": "same"}}
    right = {"source": "rapid7", "asset": {"asset_id": "same"}}
    assert _asset_descriptor(left)["stable_anchor"] != _asset_descriptor(right)["stable_anchor"]


def test_remediation_does_not_trust_a_collision_only_correlation_id():
    base = {"correlation": {"group_id": "g-collision"}, "state": {"solution": "Replace the vulnerable library with the vendor-supported release for this host"}, "vulnerability": {"cve": ["CVE-2026-9010"]}}
    left = {**base, "id": "left", "asset": {"hostname": "one.example"}}
    right = {**base, "id": "right", "asset": {"hostname": "two.example"}}
    assert _action_key(left) != _action_key(right)


def test_nested_vendor_like_metadata_stays_generic_and_key_order_independent(local_tmp: Path):
    records = {"records": [{"finding_id": "g-1", "cve": "CVE-2026-9011", "hostname": "h.example", "metadata": {
        "aid": "not-a-crowdstrike-row", "deviceId": "not-defender", "cveId": "not-cve", "asset": {}, "definition": {},
    }}]}
    first = local_tmp / "first.json"
    second = local_tmp / "second.json"
    first.write_text(json.dumps(records), encoding="utf-8")
    second.write_text(json.dumps({"records": [dict(reversed(list(records["records"][0].items())))]}), encoding="utf-8")
    assert detect_provider(first) == "generic_json"
    assert detect_provider(second) == "generic_json"


def test_unknown_nested_arrays_are_opaque_until_explicit_selector(local_tmp: Path):
    path = local_tmp / "collections.json"
    path.write_text(json.dumps({"findings": [{"id": "f"}], "metadata": {
        "data": [{"id": "m1"}], "items": [{"id": "m2"}], "values": [{"id": "m3"}],
        "owners": [{"id": "m4"}], "contacts": [{"id": "m5"}], "history": [{"id": "m6"}], "audit": [{"id": "m7"}],
    }}), encoding="utf-8")
    assert [pointer for _, pointer in iter_json_records(path)] == ["/findings/0"]
    assert [pointer for _, pointer in iter_json_records(path, selectors=("/metadata/items",))] == ["/findings/0", "/metadata/items/0"]


def test_run_all_stops_nonzero_on_rejected_zero_finding_run(local_tmp: Path):
    path = local_tmp / "rejected.json"
    path.write_text(json.dumps({"records": [{"title": "not an identity"}]}), encoding="utf-8")
    run = local_tmp / "run"
    result = CliRunner().invoke(main, ["run-all", str(path), "--provider", "generic_json", "--run-dir", str(run)])
    assert result.exit_code != 0
    metadata = json.loads((run / "run.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "rejected"
    assert "analyze" not in metadata.get("stages", {})


def test_remediation_evidence_is_consistent_for_council():
    finding = _generic({"id": "occ", "cve": "CVE-2026-9012", "hostname": "h.example", "fixed_version": "9.9.9"})
    analysis = _analysis_for(finding)
    assert analysis["remediation"]["fixed_version"] == "9.9.9"
    role = next(item for item in analysis["council"] if item["role"] == "Remediation Expert")
    assert role["conclusion"] == "remediation=available"


class _CountingBackend:
    def __init__(self, responses: list[str], raises: bool = False):
        self.responses = responses
        self.calls = 0
        self.raises = raises

    def chat(self, messages, *, model):
        self.calls += 1
        if self.raises:
            raise RuntimeError("backend failure")
        return ModelResponse(self.responses[min(self.calls - 1, len(self.responses) - 1)], {})


def test_model_call_accounting_is_exact_and_never_negative():
    valid = json.dumps({"conclusion": "ok", "confidence": 0.8, "rationale": "evidence"})
    denied_backend = _CountingBackend([valid])
    denied = chat_structured(denied_backend, [ChatMessage("user", "x")], MockModelResponse, model="m", call_permit=LLMBudget(0).take)
    assert denied.llm_calls == 0 and denied_backend.calls == 0
    retry_backend = _CountingBackend(["not-json", valid])
    retry = chat_structured(retry_backend, [ChatMessage("user", "x")], MockModelResponse, model="m", max_repair_retries=1, call_permit=LLMBudget(2).take)
    assert retry.llm_calls == retry_backend.calls == 2
    exception_backend = _CountingBackend([valid], raises=True)
    with pytest.raises(RuntimeError):
        chat_structured(exception_backend, [ChatMessage("user", "x")], MockModelResponse, model="m", call_permit=LLMBudget(1).take)
    assert exception_backend.calls == 1


def test_shareable_report_omits_machine_paths_and_keeps_internal_provenance(local_tmp: Path):
    path = local_tmp / "path.json"
    path.write_text(json.dumps({"records": [{"id": "p", "cve": "CVE-2026-9013", "hostname": "h.example"}]}), encoding="utf-8")
    run = local_tmp / "run"
    ingest([str(path)], run_dir=str(run), provider="generic_json")
    normalize(str(run))
    from aegis.analysis.council import analyze
    from aegis.triage.engine import triage
    from aegis.correlation import correlate
    from aegis.remediation import remediation
    analyze(str(run)); triage(str(run)); correlate(str(run)); remediation(str(run))
    rendered = Path(report(str(run), format_name="json")).read_text(encoding="utf-8")
    assert str(run) not in rendered
    assert str(path) not in rendered
    assert "source_snapshot_path" not in rendered


def test_resource_limit_is_terminal_and_inspectable(local_tmp: Path):
    run = local_tmp / "budget-run"
    run.mkdir(exist_ok=True)
    (run / "payload.bin").write_bytes(b"x" * 16)
    metadata = {"created_at": "2020-01-01T00:00:00Z", "operational_budgets": {"max_run_disk_bytes": 1, "max_run_seconds": 999999}, "stages": {}}
    with pytest.raises(ResourceLimitExceeded):
        enforce_run_limits(run, metadata, "normalize")
    stored = json.loads((run / "run.json").read_text(encoding="utf-8"))
    assert stored["status"] == "failed" and stored["stages"]["normalize"]["status"] == "failed"


def test_completed_lineage_manifest_makes_findings_limit_independent_of_rehash(local_tmp: Path, monkeypatch):
    path = local_tmp / "fast.json"
    path.write_text(json.dumps({"records": [{"id": "f", "cve": "CVE-2026-9014", "hostname": "h.example"}]}), encoding="utf-8")
    run = local_tmp / "run"
    result = CliRunner().invoke(main, ["run-all", str(path), "--provider", "generic_json", "--run-dir", str(run)])
    assert result.exit_code == 0 and (run / "lineage_manifest.json").exists()
    import aegis.reporting as reporting
    monkeypatch.setattr(reporting, "file_sha256", lambda _: (_ for _ in ()).throw(AssertionError("unexpected full rehash")))
    assert len(list(iter_findings(run))) == 1


def test_scale_evidence_contains_compact_chunk_and_lineage_proof(local_tmp: Path):
    path = local_tmp / "scale.jsonl"
    path.write_text(json.dumps({"id": "one"}) + "\n", encoding="utf-8")
    tool_path = Path(__file__).parents[1] / "tools" / "scale_evidence.py"
    import importlib.util
    spec = importlib.util.spec_from_file_location("scale_evidence_arch", tool_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    output = local_tmp / "evidence.json"
    evidence = module.build_evidence(local_tmp, output, stride=1)
    entry = evidence["artifacts"]["scale.jsonl"]
    assert entry["chunk_merkle_root"] and entry["chunk_count"] == 1
    assert evidence["tool_version"] == "aegis-scale-evidence-v2"
