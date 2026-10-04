from __future__ import annotations

import json
from pathlib import Path

from aegis.triage.engine import calculate_priority


def finding_from_case(case):
    evidence = case["evidence"]
    return {
        "title": "Remote code execution" if evidence["technical_impact"] == "critical" else "Synthetic evidence case",
        "description": "evidence",
        "disposition": case["expected"]["disposition"],
        "vulnerability": {"severity_normalized": evidence["technical_impact"], "severity_original": evidence["technical_impact"], "exploited_in_wild": evidence.get("active", False), "exploit_available": evidence.get("functional", False), "exploit_maturity": "functional" if evidence.get("functional") else None, "kev": {"listed": evidence.get("active", False)}, "epss": evidence.get("epss")},
        "asset": {"internet_exposed": evidence.get("internet", False), "asset_criticality": "critical" if evidence.get("critical_asset") else "low", "business_criticality": "critical" if evidence.get("critical_asset") else "low"},
        "state": {"compensating_controls": evidence.get("controls", []), "recurrence": 1},
        "analysis": {"technical_impact": evidence["technical_impact"], "missing_evidence": evidence.get("missing", [])},
        "evidence": {"basis": "report_only"},
    }


def test_curated_golden_corpus_matches_expected_rules():
    cases = json.loads((Path(__file__).parents[1] / "fixtures/golden/golden.json").read_text(encoding="utf-8"))
    observed = {case["case_id"]: calculate_priority(finding_from_case(case))[0] for case in cases}
    assert set(observed.values()) == {"P0", "P1", "P2", "P3", "P4"}
    for case in cases:
        calculated = observed[case["case_id"]]
        expected = case["expected"]
        assert calculated == expected["calculated_priority"], case["case_id"]
        effective = None if expected["disposition"] != "confirmed" else calculated
        assert effective == expected["priority"], case["case_id"]
