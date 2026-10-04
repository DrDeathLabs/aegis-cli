"""Deterministic remediation-action grouping over correlated findings."""

from __future__ import annotations

from collections import Counter
import re
from typing import Any

from aegis.models import stable_id, vulnerability_identity
from aegis.remediation_evidence import remediation_evidence
from aegis.storage import ensure_run_dir, iter_jsonl, load_run, save_run, stage_path, utc_now, write_jsonl, write_json, invalidate_downstream, record_stage_lineage, enforce_run_limits, write_lineage_manifest
from aegis.observability.events import EventSink


_ACTION_TOKEN_RE = re.compile(r"\b(?:KB|MS)\d{3,}\b|\b(?:FIX|PATCH|ACTION|CHANGE|BULLETIN|ADVISORY|REMEDIATION)[-_][A-Z0-9][A-Z0-9_-]*\b", re.I)
_VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,3}\b")
_GENERIC_SOLUTION_RE = re.compile(r"^(?:apply|install|upgrade|update|patch|fix|remediate)\b(?:\s+(?:the|a|an|vendor|affected|available|latest|security|software|package|product|service|version|to)\b.*)?$", re.I)


def _normalized_solution(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _explicit_action(finding: dict[str, Any]) -> str | None:
    state = finding.get("state") or {}
    solution = _normalized_solution(state.get("solution"))
    match = _ACTION_TOKEN_RE.search(solution)
    if match:
        return match.group(0).lower()
    action_id = _normalized_solution(state.get("remediation_action_id"))
    if action_id and action_id not in {"none", "null", "unknown", "n/a", "na", "placeholder", "0", "-"}:
        return f"action-id:{action_id}"
    remediation_id = _normalized_solution(state.get("remediation_id"))
    if remediation_id and remediation_id not in {"none", "null", "unknown", "n/a", "na", "placeholder", "0", "-"}:
        return f"remediation-id:{remediation_id}"
    return None


def _action_key(finding: dict[str, Any]) -> tuple[str, str]:
    asset = finding.get("asset") or {}
    evidence = remediation_evidence(finding)
    package = str(evidence.get("package") or "").strip().lower()
    fixed = str(evidence.get("fixed_version") or "").strip().lower()
    solution = _normalized_solution(evidence.get("solution"))
    action_key = _explicit_action(finding)
    if action_key:
        # Explicit patch/update identifiers are stronger evidence of a shared
        # action than free-text similarity and can span different providers,
        # assets, and vulnerability identifiers.
        return "explicit_action", action_key
    if package and fixed:
        return "package_upgrade", f"{package}|{fixed}"
    correlation_group = str((finding.get("correlation") or {}).get("group_id") or "").strip()
    entity_id = str(finding.get("semantic_entity_id") or (finding.get("identity") or {}).get("semantic_entity_id") or "").strip()
    target_value = next(
        (
            str(asset.get(field)).strip().lower()
            for field in ("fqdn", "hostname", "asset_id")
            if str(asset.get(field) or "").strip()
        ),
        next((str(value).strip().lower() for value in (asset.get("ip_addresses") or []) if str(value).strip()), "unknown-target"),
    )
    # The durable semantic entity is stable under non-conflicting identity
    # enrichment.  Synthetic/legacy findings without one still receive a
    # target-specific fallback so a correlation-ID collision cannot merge
    # unrelated actions.
    action_target = f"entity:{entity_id}" if entity_id else f"target:{stable_id(target_value, length=16)}"
    if correlation_group and solution:
        return "correlated_solution", f"{correlation_group}|{action_target}|solution:{solution}"
    if package and solution and len(solution) >= 12 and not re.fullmatch(r"(?:apply|install|upgrade|update|patch)\b.*", solution):
        return "targeted_solution", f"{package}|{solution}"
    if solution and len(solution) >= 20 and not _VERSION_RE.fullmatch(solution) and not _GENERIC_SOLUTION_RE.fullmatch(solution):
        # Exact, sufficiently specific prose is a last-resort evidence key;
        # a bare version string or generic update sentence is never shared.
        return "specific_solution", solution
    if fixed:
        # A fixed version without a package/product is not enough to prove a
        # shared action across unrelated vulnerabilities.
        return "fixed_version", f"{fixed}|{vulnerability_identity(finding)}"
    return "finding", str(correlation_group or finding["id"])


def remediation(run_dir: str) -> dict[str, Any]:
    run = ensure_run_dir(run_dir)
    metadata = load_run(run)
    invalidate_downstream(run, metadata, "remediation")
    events = EventSink(run / "events.jsonl")
    events.emit("remediation.started", run_id=str(metadata.get("run_id") or run.name))
    source = stage_path(run, "correlated")
    if not source.exists():
        raise FileNotFoundError(f"correlated stage not found: {source}")
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in iter_jsonl(source):
        disposition = finding.get("disposition")
        if disposition in {"false_positive", "remediated", "unconfirmed"}:
            continue
        key = _action_key(finding)
        action = groups.setdefault(key, {
            "action_id": "RA-" + stable_id(*key, length=12).upper(), "kind": key[0], "target": key[1],
            "action": remediation_evidence(finding).get("solution") or (f"Upgrade {key[1]}" if key[0] in {"package_upgrade", "fixed_version"} else "Investigate and remediate the finding"),
            "finding_ids": [], "asset_ids": [], "asset_observations": [], "identifiers": [], "providers": set(),
            "correlation_groups": set(), "priority_distribution": Counter(),
            "highest_priority": None, "active_highest_priority": None, "dispositions": Counter(), "evidence_references": [],
            "evidence_reference_count": 0, "conflicts": [],
            "grouping_evidence": {"kind": key[0], "key": key[1], "solutions": set(), "source_solutions": set(), "remediation_action_ids": set(), "remediation_ids": set(), "fixed_versions": set(), "packages": set()},
        })
        action["finding_ids"].append(finding["id"])
        action["providers"].add(str(finding.get("source") or "unknown"))
        if (finding.get("correlation") or {}).get("group_id"):
            action["correlation_groups"].add(finding["correlation"]["group_id"])
        asset = finding.get("asset") or {}
        if asset.get("asset_id"):
            action["asset_ids"].append(asset["asset_id"])
        for value in [asset.get("fqdn"), asset.get("hostname"), *(asset.get("ip_addresses") or [])]:
            if str(value or "").strip():
                action["asset_observations"].append(str(value).strip().lower())
        canonical_asset = next((str(asset.get(key)).strip().lower() for key in ("fqdn", "hostname", "asset_id") if str(asset.get(key) or "").strip()), None)
        if not canonical_asset:
            canonical_asset = next((str(value).strip().lower() for value in (asset.get("ip_addresses") or []) if str(value).strip()), None)
        if canonical_asset:
            action.setdefault("canonical_assets", set()).add(canonical_asset)
        vuln = finding.get("vulnerability") or {}
        # Keep global and provider-native vulnerability identities as
        # independent evidence.  A CVE must not hide a native ID that is
        # needed to explain how a provider mapped the occurrence.
        action["identifiers"].extend(vuln.get("cve") or [])
        action["identifiers"].extend(vuln.get("identifiers") or [])
        action["identifiers"].extend(
            f"{item.get('provider')}:{item.get('kind')}:{item.get('value')}"
            for item in (vuln.get("provider_identifiers") or [])
            if isinstance(item, dict) and item.get("provider") and item.get("kind") and item.get("value")
        )
        grouping = action["grouping_evidence"]
        evidence = remediation_evidence(finding)
        if evidence.get("solution"):
            grouping["solutions"].add(_normalized_solution(evidence["solution"]))
            grouping["source_solutions"].add(str(evidence["solution"]).strip())
        if (finding.get("state") or {}).get("remediation_action_id"):
            grouping["remediation_action_ids"].add(str(finding["state"]["remediation_action_id"]).strip())
        if (finding.get("state") or {}).get("remediation_id"):
            grouping["remediation_ids"].add(str(finding["state"]["remediation_id"]).strip())
        if evidence.get("fixed_version"):
            grouping["fixed_versions"].add(str(evidence["fixed_version"]).strip())
        # A listening service is an asset observation, not a software package.
        # Keep it in the canonical asset record, but never let names such as
        # https/ssh/smb become package evidence for action grouping.
        if asset.get("package") or asset.get("application"):
            grouping["packages"].add(str(asset.get("package") or asset.get("application")).strip())
        calculated_priority = (finding.get("triage") or {}).get("calculated_priority") or finding.get("calculated_priority") or finding.get("priority")
        if calculated_priority:
            action["priority_distribution"][calculated_priority] += 1
            if finding.get("active_queue", (finding.get("triage") or {}).get("active_queue", finding.get("disposition") == "confirmed")):
                action.setdefault("active_priority_distribution", Counter())[calculated_priority] += 1
        action["dispositions"][finding.get("disposition", "confirmed")] += 1
        action["evidence_reference_count"] += 1
        # Finding IDs provide exact action resolution. Keep only a bounded
        # evidence sample here so a shared fix cannot duplicate a full triage
        # object a million times in memory; the individual finding retains its
        # complete drivers, guards, and provenance.
        if len(action["evidence_references"]) < 25:
            triage = finding.get("triage") or {}
            action["evidence_references"].append({"finding_id": finding["id"], "source": finding.get("source"), "group_id": (finding.get("correlation") or {}).get("group_id"), "priority": finding.get("effective_priority", finding.get("priority")), "calculated_priority": triage.get("calculated_priority"), "drivers": triage.get("drivers", [])})
        action["conflicts"].extend((finding.get("evidence") or {}).get("conflicts") or [])
    rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
    actions = []
    for action in groups.values():
        action["finding_ids"] = sorted(set(action["finding_ids"]))
        action["asset_ids"] = sorted(set(action["asset_ids"]))
        action["asset_observations"] = sorted(set(action["asset_observations"]))
        action["canonical_assets"] = sorted(action.get("canonical_assets", set()))
        action["identifiers"] = sorted(set(action["identifiers"]))
        action["providers"] = sorted(action["providers"])
        action["correlation_groups"] = sorted(action["correlation_groups"])
        action["priority_distribution"] = dict(action["priority_distribution"])
        action["active_priority_distribution"] = dict(action.get("active_priority_distribution", {}))
        action["dispositions"] = dict(action["dispositions"])
        action["grouping_evidence"]["solutions"] = sorted(action["grouping_evidence"]["solutions"])
        action["grouping_evidence"]["source_solutions"] = sorted(action["grouping_evidence"]["source_solutions"])
        action["grouping_evidence"]["remediation_action_ids"] = sorted(action["grouping_evidence"]["remediation_action_ids"])
        action["grouping_evidence"]["remediation_ids"] = sorted(action["grouping_evidence"]["remediation_ids"])
        action["grouping_evidence"]["fixed_versions"] = sorted(action["grouping_evidence"]["fixed_versions"])
        action["grouping_evidence"]["packages"] = sorted(action["grouping_evidence"]["packages"])
        action["highest_priority"] = min(action["active_priority_distribution"], key=rank.get) if action["active_priority_distribution"] else None
        action["historical_highest_priority"] = min(action["priority_distribution"], key=rank.get) if action["priority_distribution"] else None
        action["occurrence_count"] = len(action["finding_ids"])
        action["asset_count"] = len(action["canonical_assets"])
        action["conflicts"] = sorted(set(action["conflicts"]))
        actions.append(action)
    actions.sort(key=lambda item: (rank.get(item["highest_priority"], 9), item["action_id"]))
    write_json(run / "remediation_actions.json", actions)
    # The JSON array is retained for small API consumers; the JSONL mirror is
    # the bounded report/export and downstream integration contract.
    write_jsonl(run / "remediation_actions.jsonl", actions)
    action_by_finding = {finding_id: action["action_id"] for action in actions for finding_id in action["finding_ids"]}
    action_by_id = {action["action_id"]: action for action in actions}
    target = stage_path(run, "remediated")
    def records():
        for finding in iter_jsonl(source):
            finding["remediation"]["action_id"] = action_by_finding.get(finding["id"])
            action = action_by_id.get(action_by_finding.get(finding["id"]))
            finding["remediation"]["action"] = action["action"] if action else None
            finding["remediation"]["target"] = action["target"] if action else None
            yield finding
    count = write_jsonl(target, records())
    record_stage_lineage(metadata, "remediation", source, target)
    enforce_run_limits(run, metadata, "remediation")
    metadata["remediation_actions"] = len(actions)
    metadata["remediation_occurrences"] = sum(item["occurrence_count"] for item in actions)
    metadata["stages"]["remediation"] = {"status": "complete", "findings": count, "actions": len(actions)}
    metadata["updated_at"] = utc_now()
    save_run(run, metadata)
    write_lineage_manifest(run, metadata)
    events.emit("remediation.completed", run_id=str(metadata.get("run_id") or run.name), payload={"actions": len(actions), "findings": count})
    return metadata
