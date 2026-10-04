from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.analysis.council import analyze
from aegis.correlation import correlate
from aegis.ingest import detect_provider
from aegis.models import reconcile_semantic_identity
from aegis.providers import adapter_for
from aegis.providers.base import iter_json_records
from aegis.remediation import _action_key, remediation
from aegis.storage import iter_jsonl
from aegis.triage.engine import triage
from aegis.ingest import ingest, normalize


def _finding(record: dict, provider: str = "generic_json") -> dict:
    return adapter_for(provider).normalize(record, pointer="/0", report_sha256="test")


def _run_identity_case(local_tmp: Path, name: str, baseline_record: dict, current_record: dict,
                       baseline_provider: str = "generic_json", current_provider: str = "generic_json") -> tuple[Path, Path]:
    baseline = local_tmp / f"{name}-baseline"
    current = local_tmp / f"{name}-current"
    baseline_path = baseline.with_suffix(".json")
    current_path = current.with_suffix(".json")
    baseline_path.write_text(json.dumps({"records": [baseline_record]}), encoding="utf-8")
    current_path.write_text(json.dumps({"records": [current_record]}), encoding="utf-8")
    ingest([str(baseline_path)], run_dir=str(baseline), provider=baseline_provider)
    normalize(str(baseline)); analyze(str(baseline)); triage(str(baseline)); correlate(str(baseline)); remediation(str(baseline))
    ingest([str(current_path)], run_dir=str(current), provider=current_provider)
    normalize(str(current)); analyze(str(current)); triage(str(current)); correlate(str(current), baseline_run_dir=str(baseline)); remediation(str(current))
    return baseline, current


def _identity_outputs(run: Path) -> tuple[dict, dict, dict, dict]:
    finding = next(iter_jsonl(run / "correlated.jsonl"))
    longitudinal = json.loads((run / "longitudinal.json").read_text(encoding="utf-8"))
    group = json.loads((run / "correlation_groups.json").read_text(encoding="utf-8"))[0]
    action = json.loads((run / "remediation_actions.json").read_text(encoding="utf-8"))[0]
    return finding, longitudinal, group, action


def test_semantic_entity_id_survives_nonconflicting_enrichment_and_native_cve_arrival():
    base = _finding({"finding_id": "occ-a", "cve": "CVE-2026-9101", "hostname": "host.example"})
    enriched = _finding({
        "finding_id": "occ-b", "cve": "CVE-2026-9101", "hostname": "host.example",
        "ip": "192.0.2.91", "asset_id": "provider-asset-91",
    })
    assert base["observation_signature"] != enriched["observation_signature"]
    assert reconcile_semantic_identity(base, enriched)
    assert base["semantic_entity_id"] == enriched["semantic_entity_id"]

    native = _finding({"finding_id": "occ-c", "vulnerability_id": "NATIVE-9101", "hostname": "host.example"})
    native_with_cve = _finding({
        "finding_id": "occ-d", "vulnerability_id": "NATIVE-9101",
        "vulnerability": "CVE-2026-9101", "hostname": "host.example",
    })
    assert reconcile_semantic_identity(native, native_with_cve)
    assert native["semantic_entity_id"] == native_with_cve["semantic_entity_id"]
    assert reconcile_semantic_identity(base, _finding({
        "id": "rapid-occ-9101", "cve": "CVE-2026-9101", "hostname": "host.example",
    }, "rapid7"))


def test_group_and_action_keys_do_not_change_when_observations_are_added():
    before = _finding({"finding_id": "occ-e", "cve": "CVE-2026-9102", "hostname": "host.example", "solution": "Apply ACTION-9102"})
    after = _finding({
        "finding_id": "occ-f", "cve": "CVE-2026-9102", "hostname": "host.example",
        "ip": "192.0.2.92", "asset_id": "asset-92", "solution": "Apply ACTION-9102",
    })
    before["correlation"]["group_id"] = "CG-stable"
    after["correlation"]["group_id"] = "CG-stable"
    assert before["observation_signature"] != after["observation_signature"]
    assert reconcile_semantic_identity(before, after)
    assert before["semantic_entity_id"] == after["semantic_entity_id"]
    assert _action_key(before) == _action_key(after)


@pytest.mark.parametrize(
    ("name", "baseline", "current", "baseline_provider", "current_provider"),
    [
        ("hostname-ip", {"finding_id": "b-1", "cve": "CVE-2026-9301", "hostname": "host.example"}, {"finding_id": "c-1", "cve": "CVE-2026-9301", "hostname": "host.example", "ip": "192.0.2.1"}, "generic_json", "generic_json"),
        ("hostname-asset", {"finding_id": "b-2", "cve": "CVE-2026-9302", "hostname": "host.example"}, {"finding_id": "c-2", "cve": "CVE-2026-9302", "hostname": "host.example", "asset_id": "asset-2"}, "generic_json", "generic_json"),
        ("ip-hostname", {"finding_id": "b-3", "cve": "CVE-2026-9303", "ip": "192.0.2.3"}, {"finding_id": "c-3", "cve": "CVE-2026-9303", "ip": "192.0.2.3", "hostname": "host.example"}, "generic_json", "generic_json"),
        ("hostname-fqdn", {"finding_id": "b-4", "cve": "CVE-2026-9304", "hostname": "host"}, {"finding_id": "c-4", "cve": "CVE-2026-9304", "hostname": "host", "fqdn": "host.example"}, "generic_json", "generic_json"),
        ("asset-hostname", {"finding_id": "b-5", "cve": "CVE-2026-9305", "asset_id": "asset-5"}, {"finding_id": "c-5", "cve": "CVE-2026-9305", "asset_id": "asset-5", "hostname": "host.example"}, "generic_json", "generic_json"),
        ("native-cve", {"finding_id": "b-6", "vulnerability_id": "NATIVE-9306", "hostname": "host.example"}, {"finding_id": "c-6", "vulnerability_id": "NATIVE-9306", "cve": "CVE-2026-9306", "hostname": "host.example"}, "generic_json", "generic_json"),
        ("cve-native", {"finding_id": "b-7", "cve": "CVE-2026-9307", "hostname": "host.example"}, {"finding_id": "c-7", "cve": "CVE-2026-9307", "vulnerability_id": "NATIVE-9307", "hostname": "host.example"}, "generic_json", "generic_json"),
        ("cross-provider-hostname", {"finding_id": "b-8", "cve": "CVE-2026-9308", "hostname": "host.example"}, {"id": "c-8", "vulnId": "R-9308", "cve": "CVE-2026-9308", "hostName": "host.example"}, "generic_json", "rapid7"),
        ("cross-provider-ip", {"finding_id": "b-9", "cve": "CVE-2026-9309", "ip": "192.0.2.9"}, {"id": "c-9", "vulnId": "R-9309", "cve": "CVE-2026-9309", "ip": "192.0.2.9"}, "generic_json", "rapid7"),
        ("alias-order", {"finding_id": "b-10", "cve": "CVE-2026-9310", "hostname": "host.example", "ip": "192.0.2.10", "asset_id": "asset-10"}, {"asset_id": "asset-10", "ip": "192.0.2.10", "hostname": "host.example", "cve": "CVE-2026-9310", "finding_id": "c-10"}, "generic_json", "generic_json"),
    ],
)
def test_frozen_identity_enrichment_inherits_durable_entity_group_and_fallback_action(
    local_tmp: Path, name: str, baseline: dict, current: dict, baseline_provider: str, current_provider: str,
):
    baseline_run, current_run = _run_identity_case(local_tmp, name, baseline, current, baseline_provider, current_provider)
    baseline_finding, _, baseline_group, baseline_action = _identity_outputs(baseline_run)
    current_finding, longitudinal, current_group, current_action = _identity_outputs(current_run)
    assert baseline_finding["semantic_entity_id"] == current_finding["semantic_entity_id"]
    assert longitudinal["current_semantic_entities"] == 1
    assert longitudinal["baseline_semantic_entities"] == 1
    assert longitudinal["recurring_semantic_findings"] == 1
    assert longitudinal["new_semantic_findings"] == 0
    assert longitudinal["stale_semantic_findings"] == 0
    assert current_group["group_id"] == baseline_group["group_id"]
    assert current_action["action_id"] == baseline_action["action_id"]
    assert current_finding["identity"]["reconciliation"]["state"] == "reconciled"


def test_conflicting_target_evidence_does_not_inherit_baseline_handle(local_tmp: Path):
    baseline_run, current_run = _run_identity_case(
        local_tmp, "conflict",
        {"finding_id": "b-conflict", "cve": "CVE-2026-9320", "hostname": "one.example", "ip": "192.0.2.20"},
        {"finding_id": "c-conflict", "cve": "CVE-2026-9320", "hostname": "two.example", "ip": "192.0.2.20"},
    )
    baseline_finding, _, baseline_group, _ = _identity_outputs(baseline_run)
    current_finding, longitudinal, current_group, _ = _identity_outputs(current_run)
    assert current_finding["semantic_entity_id"] != baseline_finding["semantic_entity_id"]
    assert current_finding["identity"]["reconciliation"]["state"] == "conflict"
    assert longitudinal["recurring_semantic_findings"] == 0
    assert longitudinal["new_semantic_findings"] == 1
    assert longitudinal["stale_semantic_findings"] == 1
    assert current_group["group_id"] != baseline_group["group_id"]


def test_generated_vendor_like_negative_records_remain_generic(local_tmp: Path):
    negatives = [
        {"aid": "not-crowd", "cve": "CVE-2026-9201", "hostname": "host.example"},
        {"deviceId": "not-defender", "cveId": "CVE-2026-9202", "hostname": "host.example"},
        {"asset": {"id": "not-tenable"}, "definition": {"id": "not-a-plugin"}, "cve": "CVE-2026-9203", "hostname": "host.example"},
        {"metadata": {"aid": "opaque", "deviceId": "opaque", "cveId": "opaque", "asset": {}, "definition": {}}},
    ]
    for index, record in enumerate(negatives):
        path = local_tmp / f"negative-{index}.json"
        path.write_text(json.dumps({"records": [record]}), encoding="utf-8")
        assert detect_provider(path) == "generic_json"


def test_unknown_collection_ancestry_is_opaque_but_explicit_selector_is_honored(local_tmp: Path):
    path = local_tmp / "collections.json"
    path.write_text(json.dumps({
        "findings": [{"id": "f-1"}],
        "metadata": {"data": {"items": [{"id": "metadata-item"}]}},
        "audit": {"history": {"values": [{"id": "audit-item"}]}},
    }), encoding="utf-8")
    assert [pointer for _, pointer in iter_json_records(path)] == ["/findings/0"]
    assert [pointer for _, pointer in iter_json_records(path, selectors=("/metadata/data/items",))] == [
        "/findings/0", "/metadata/data/items/0",
    ]


def test_provider_diagnostics_are_recomputed_after_nested_mapping():
    fixture_root = Path(__file__).parents[1] / "fixtures" / "official_contracts"
    for provider, filename in (
        ("tenable", "tenable_vm_current.json"),
        ("defender", "defender_software_vulnerabilities_by_machine.json"),
        ("crowdstrike", "crowdstrike_spotlight_nested.json"),
    ):
        record = json.loads((fixture_root / filename).read_text(encoding="utf-8"))
        finding = _finding(record, provider)
        warnings = set(finding["evidence"]["warnings"])
        assert "required vulnerability identity is missing" not in warnings
        assert "asset identity is missing" not in warnings
        assert "title and vulnerability identifier are missing" not in warnings
        assert finding["evidence"]["mapping_confidence"] == 1.0
