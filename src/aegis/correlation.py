"""Scalable deterministic finding correlation."""

from __future__ import annotations

import hashlib
import json
import ipaddress
from collections import Counter
from pathlib import Path
from typing import Any

from aegis.models import durable_semantic_entity_id, observation_signature, semantic_identity_aliases, set_semantic_entity_id, stable_id, vulnerability_identity
from aegis.storage import ensure_run_dir, iter_jsonl, load_run, save_run, stage_path, utc_now, write_jsonl, write_json, invalidate_downstream, record_stage_lineage, enforce_run_limits, write_lineage_manifest
from aegis.observability.events import EventSink


def _fingerprint(finding: dict[str, Any]) -> str:
    record = (finding.get("source_metadata") or {}).get("original_record")
    encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256((finding.get("source", "") + "|" + encoded).encode("utf-8")).hexdigest()


def _asset_tokens(finding: dict[str, Any]) -> tuple[str, ...]:
    """Return strong, normalized asset observations for conservative blocking.

    Provider-local asset IDs are namespaced so equal opaque IDs from two
    products cannot create a false cross-provider merge.  Hostnames/FQDNs and
    IP addresses are global observations and allow an asset to be represented
    differently by providers when one of those observations is shared.
    """
    asset = finding.get("asset") or {}
    source = str(finding.get("source") or "unknown").strip().lower()
    tokens: set[str] = set()
    asset_id = str(asset.get("asset_id") or "").strip().lower()
    if asset_id:
        tokens.add(f"asset-id:{source}:{asset_id}")
    for field in ("fqdn", "hostname"):
        value = str(asset.get(field) or "").strip().lower().rstrip(".")
        if value:
            tokens.add(f"asset-name:{value}")
    for value in asset.get("ip_addresses") or []:
        try:
            text = str(ipaddress.ip_address(str(value).strip())).lower()
        except ValueError:
            continue
        tokens.add(f"asset-ip:{text}")
    return tuple(sorted(tokens))


def _asset_descriptor(finding: dict[str, Any]) -> dict[str, set[str] | tuple[str, ...] | str | None]:
    asset = finding.get("asset") or {}
    hostnames = {str(asset.get(field)).strip().lower().rstrip(".") for field in ("fqdn", "hostname") if str(asset.get(field) or "").strip()}
    ips = set()
    for value in asset.get("ip_addresses") or []:
        try:
            ips.add(str(ipaddress.ip_address(str(value).strip())).lower())
        except ValueError:
            continue
    asset_ids = {str(asset.get("asset_id")).strip().lower()} if str(asset.get("asset_id") or "").strip() else set()
    source = str(finding.get("source") or "unknown").strip().lower()
    occurrence = str((finding.get("identity") or {}).get("source_occurrence_id") or finding.get("source_finding_id") or "").strip().lower()
    stable_candidates = ([f"occurrence:{source}:{occurrence}"] if occurrence else []) or sorted(
        [f"asset-name:{value}" for value in hostnames]
        or [f"asset-ip:{value}" for value in ips]
        or [f"asset-id:{source}:{value}" for value in asset_ids]
    )
    stable_anchor = stable_candidates[0] if stable_candidates else None
    return {
        "tokens": _asset_tokens(finding), "hostnames": hostnames, "ips": ips,
        "asset_ids": asset_ids, "stable_anchor": stable_anchor,
    }


def _load_entity_registry(path: Path) -> dict[str, Any]:
    """Load the durable entity registry represented by a completed baseline.

    A correlated stage is the persisted registry boundary for this file-based
    application.  The registry is intentionally built only when a baseline is
    supplied; independent runs retain their own seed handles and do not incur a
    million-record cross-run index that the caller did not request.
    """
    entries: dict[str, dict[str, Any]] = {}
    alias_owners: dict[str, set[str]] = {}
    for finding in iter_jsonl(path):
        entity_id = str(
            finding.get("semantic_entity_id")
            or (finding.get("identity") or {}).get("semantic_entity_id")
            or durable_semantic_entity_id(finding)
        ).strip()
        aliases = set(finding.get("semantic_identity_aliases") or semantic_identity_aliases(finding))
        descriptor = _asset_descriptor(finding)
        entry = entries.setdefault(entity_id, {
            "aliases": set(), "hostnames": set(), "ips": set(), "asset_ids_by_source": {},
            "sources": set(), "finding_ids": [],
        })
        entry["aliases"].update(aliases)
        entry["hostnames"].update(descriptor.get("hostnames", set()))
        entry["ips"].update(descriptor.get("ips", set()))
        source = str(finding.get("source") or "unknown").strip().lower()
        entry["sources"].add(source)
        entry["asset_ids_by_source"].setdefault(source, set()).update(descriptor.get("asset_ids", set()))
        entry["finding_ids"].append(str(finding.get("id") or ""))
        for alias in aliases:
            alias_owners.setdefault(alias, set()).add(entity_id)
    return {"entries": entries, "alias_owners": alias_owners}


def _baseline_target_conflicts(entry: dict[str, Any], finding: dict[str, Any]) -> bool:
    """Return whether current target evidence contradicts the baseline entity."""
    descriptor = _asset_descriptor(finding)
    if entry.get("hostnames") and descriptor.get("hostnames") and entry["hostnames"].isdisjoint(descriptor["hostnames"]):
        return True
    if entry.get("ips") and descriptor.get("ips") and entry["ips"].isdisjoint(descriptor["ips"]):
        return True
    source = str(finding.get("source") or "unknown").strip().lower()
    baseline_ids = set((entry.get("asset_ids_by_source") or {}).get(source, set()))
    current_ids = set(descriptor.get("asset_ids", set()))
    return bool(baseline_ids and current_ids and baseline_ids.isdisjoint(current_ids))


def _reconcile_finding_to_baseline(finding: dict[str, Any], registry: dict[str, Any]) -> tuple[str, bool]:
    """Inherit exactly one compatible baseline handle, or retain the seed."""
    aliases = set(finding.get("semantic_identity_aliases") or semantic_identity_aliases(finding))
    candidates = {
        entity_id
        for alias in aliases
        for entity_id in registry.get("alias_owners", {}).get(alias, set())
    }
    seed = str(
        finding.get("semantic_entity_id")
        or (finding.get("identity") or {}).get("semantic_entity_id")
        or durable_semantic_entity_id(finding)
    ).strip()
    if len(candidates) != 1:
        reconciliation = (finding.setdefault("identity", {}).setdefault("reconciliation", {}))
        reconciliation["state"] = "ambiguous" if len(candidates) > 1 else "unreconciled"
        reconciliation["candidate_entity_ids"] = sorted(candidates)
        return seed, False
    entity_id = next(iter(candidates))
    entry = registry["entries"][entity_id]
    shared = aliases & set(entry.get("aliases", set()))
    if not shared or _baseline_target_conflicts(entry, finding):
        reconciliation = (finding.setdefault("identity", {}).setdefault("reconciliation", {}))
        reconciliation["state"] = "conflict"
        reconciliation["candidate_entity_ids"] = [entity_id]
        return seed, False
    set_semantic_entity_id(finding, entity_id, matched_aliases=shared)
    reconciliation = finding.setdefault("identity", {}).setdefault("reconciliation", {})
    reconciliation["baseline_entity_id"] = entity_id
    reconciliation["observation_signature"] = observation_signature(finding)
    return entity_id, True


def _merge_asset_descriptors(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return {
        "tokens": tuple(sorted(set(left.get("tokens", ())) | set(right.get("tokens", ())))),
        "hostnames": set(left.get("hostnames", set())) | set(right.get("hostnames", set())),
        "ips": set(left.get("ips", set())) | set(right.get("ips", set())),
        "asset_ids": set(left.get("asset_ids", set())) | set(right.get("asset_ids", set())),
        "stable_anchors": set(left.get("stable_anchors", set())) | set(right.get("stable_anchors", set())) | ({left["stable_anchor"]} if left.get("stable_anchor") else set()) | ({right["stable_anchor"]} if right.get("stable_anchor") else set()),
    }


def _compatible_token_merge(descriptor: dict[str, Any], aggregate: dict[str, Any], token: str) -> bool:
    """Block an IP bridge when its hostname contradicts the existing group."""
    if token.startswith("asset-ip:"):
        incoming_hosts = set(descriptor.get("hostnames", set()))
        group_hosts = set(aggregate.get("hostnames", set()))
        if incoming_hosts and group_hosts and incoming_hosts.isdisjoint(group_hosts):
            return False
    return True


def _group_key(finding: dict[str, Any]) -> str:
    """Expose a readable blocking key for diagnostics and compatibility."""
    vuln = vulnerability_identity(finding)
    tokens = _asset_tokens(finding)
    return f"{vuln}|{','.join(tokens) if tokens else 'unknown-asset'}"


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, value: str) -> None:
        self.parent.setdefault(value, value)

    def find(self, value: str) -> str:
        parent = self.parent.setdefault(value, value)
        while parent != self.parent[parent]:
            self.parent[parent] = self.parent[self.parent[parent]]
            parent = self.parent[parent]
        root = parent
        parent = value
        while self.parent[parent] != parent:
            next_parent = self.parent[parent]
            self.parent[parent] = root
            parent = next_parent
        return root

    def union(self, left: str, right: str) -> str:
        left_root, right_root = self.find(left), self.find(right)
        if left_root == right_root:
            return left_root
        root, child = min(left_root, right_root), max(left_root, right_root)
        self.parent[child] = root
        return root


def correlate(run_dir: str, *, baseline_run_dir: str | None = None) -> dict[str, Any]:
    run = ensure_run_dir(run_dir)
    metadata = load_run(run)
    invalidate_downstream(run, metadata, "correlate")
    events = EventSink(run / "events.jsonl")
    events.emit("correlate.started", run_id=str(metadata.get("run_id") or run.name))
    source = stage_path(run, "triaged")
    if not source.exists():
        raise FileNotFoundError(f"triaged stage not found: {source}")
    baseline = Path(baseline_run_dir).expanduser().resolve() if baseline_run_dir else None
    baseline_registry: dict[str, Any] | None = None
    if baseline is not None:
        baseline_stage = stage_path(baseline, "correlated")
        if not baseline_stage.exists():
            raise FileNotFoundError(f"baseline correlated stage not found: {baseline_stage}")
        baseline_registry = _load_entity_registry(baseline_stage)
    union_find = _UnionFind()
    token_owners: dict[tuple[str, str], str] = {}
    descriptors: dict[str, dict[str, Any]] = {}
    aggregates: dict[str, dict[str, Any]] = {}
    reconciled_by_finding: dict[str, bool] = {}
    reconciliation_by_finding: dict[str, dict[str, Any]] = {}
    blocked_conflicts: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for finding in iter_jsonl(source):
        finding_id = str(finding["id"])
        union_find.add(finding_id)
        if baseline_registry is not None:
            _, reconciled = _reconcile_finding_to_baseline(finding, baseline_registry)
            reconciled_by_finding[finding_id] = reconciled
            reconciliation_by_finding[finding_id] = dict((finding.get("identity") or {}).get("reconciliation") or {})
        vulnerability_key = vulnerability_identity(finding)
        tokens = _asset_tokens(finding)
        descriptors[finding_id] = {
            "vulnerability": vulnerability_key,
            "tokens": tokens,
            "asset_descriptor": _asset_descriptor(finding),
            "source": finding.get("source"),
            "source_finding_id": finding.get("source_finding_id"),
            "fingerprint": _fingerprint(finding),
            "semantic_entity_id": durable_semantic_entity_id(finding),
            "semantic_aliases": set(semantic_identity_aliases(finding)),
            "observation_signature": observation_signature(finding),
            "reconciled": reconciled_by_finding.get(finding_id, False),
        }
        # An unknown asset must not merge every occurrence of a vulnerability.
        # Each strong token is indexed independently so host-only, IP-only, and
        # provider-specific-ID representations can correlate when evidence
        # overlaps without introducing CVE-only merges.
        for token in tokens:
            index_key = (vulnerability_key, token)
            owner = token_owners.get(index_key)
            if owner is not None:
                owner_root = union_find.find(owner)
                incoming = descriptors[finding_id]["asset_descriptor"]
                aggregate = aggregates.get(owner_root, incoming)
                if _compatible_token_merge(incoming, aggregate, token):
                    left_root, right_root = owner_root, union_find.find(finding_id)
                    merged_root = union_find.union(finding_id, owner)
                    aggregates[merged_root] = _merge_asset_descriptors(
                        aggregates.get(left_root, incoming),
                        aggregates.get(right_root, incoming),
                    )
                    if left_root != merged_root:
                        aggregates.pop(left_root, None)
                    if right_root != merged_root:
                        aggregates.pop(right_root, None)
                else:
                    blocked_conflicts.append({
                        "left_finding_id": owner,
                        "right_finding_id": finding_id,
                        "token": token,
                        "reason": "shared asset token conflicts with stronger hostname evidence",
                    })
            else:
                token_owners[index_key] = finding_id
        root = union_find.find(finding_id)
        aggregates.setdefault(root, _merge_asset_descriptors(
            {"tokens": (), "hostnames": set(), "ips": set(), "asset_ids": set(), "stable_anchors": set()},
            descriptors[finding_id]["asset_descriptor"],
        ))
        counts["records"] += 1

    groups: dict[str, dict[str, Any]] = {}
    priority_rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
    for finding_id, descriptor in descriptors.items():
        root = union_find.find(finding_id)
        group = groups.setdefault(root, {"members": [], "sources": set(), "severities": set(), "priorities": Counter(), "exact_keys": Counter(), "asset_tokens": set(), "stable_anchors": set(), "vulnerability": descriptor["vulnerability"]})
        group["members"].append(finding_id)
        group["sources"].add(descriptor["source"])
        group["asset_tokens"].update(descriptor["tokens"])
        asset_descriptor = descriptor["asset_descriptor"]
        if asset_descriptor.get("stable_anchor"):
            group["stable_anchors"].add(asset_descriptor["stable_anchor"])
        group["exact_keys"][f"{descriptor['source']}|{descriptor['source_finding_id']}|{descriptor['fingerprint']}"] += 1

    relation_by_id: dict[str, str | None] = {}
    group_summaries: dict[str, dict[str, Any]] = {}
    for root, group in groups.items():
        members = group["members"]
        # Read the source order only for canonical tie-breaking and exact-copy
        # ownership; both are deterministic because the stage is deterministic.
        # The priority is not in the compact descriptor, so select a stable
        # lexical member here and refine it in the second pass.
        canonical_id = min(members)
        group_summaries[root] = {"canonical_id": canonical_id, "canonical_priority": "P4", "count": len(members), "sources": group["sources"], "severities": group["severities"], "priorities": group["priorities"], "asset_tokens": group["asset_tokens"], "stable_anchors": group["stable_anchors"], "exact_keys": group["exact_keys"], "vulnerability": group["vulnerability"]}

    # The second pass enriches group statistics and selects the highest-priority
    # canonical member without retaining complete findings in memory.
    for finding in iter_jsonl(source):
        root = union_find.find(str(finding["id"]))
        group = group_summaries[root]
        group["sources"].add(finding.get("source"))
        group["severities"].add(str((finding.get("vulnerability") or {}).get("severity_normalized") or "unknown"))
        priority = finding.get("priority") or (finding.get("triage") or {}).get("calculated_priority") or "P4"
        group["priorities"][priority] += 1
        current = group["canonical_id"]
        if (priority_rank.get(priority, 9), str(finding["id"])) < (priority_rank.get(group.get("canonical_priority", "P4"), 9), str(current)):
            group["canonical_id"] = finding["id"]
            group["canonical_priority"] = priority

    def _preferred_common_alias(aliases: set[str]) -> str | None:
        def rank(alias: str) -> tuple[int, str]:
            if "|target:fqdn:" in alias:
                return (0, alias)
            if "|target:hostname:" in alias:
                return (1, alias)
            if "|target:ip:" in alias:
                return (2, alias)
            return (3, alias)
        return min(aliases, key=rank) if aliases else None

    for root, group in group_summaries.items():
        member_descriptors = [descriptors[finding_id] for finding_id in groups[root]["members"]]
        entity_ids = sorted({str(item["semantic_entity_id"]) for item in member_descriptors if item.get("semantic_entity_id")})
        reconciled_entity_ids = sorted({
            str(item["semantic_entity_id"])
            for item in member_descriptors
            if item.get("reconciled") and item.get("semantic_entity_id")
        })
        stable_entity_id = (
            reconciled_entity_ids[0] if len(reconciled_entity_ids) == 1
            else entity_ids[0] if len(entity_ids) == 1
            else None
        )
        group["stable_entity_id"] = stable_entity_id
        common_aliases = set(member_descriptors[0].get("semantic_aliases", set())) if member_descriptors else set()
        for item in member_descriptors[1:]:
            common_aliases &= set(item.get("semantic_aliases", set()))
        common_alias = _preferred_common_alias(common_aliases)
        if stable_entity_id:
            stable_basis = ("entity", stable_entity_id)
        elif len(group["sources"]) > 1 and common_alias:
            stable_basis = ("global-alias", common_alias)
        else:
            stable_basis = tuple(sorted(group["stable_anchors"])) or tuple(sorted(group["asset_tokens"])) or tuple(sorted(group["members"]))
        # A reconciled entity handle is the durable group anchor.  Do not add
        # the current preferred vulnerability alias to this hash: native-ID to
        # CVE enrichment must not rotate an otherwise unchanged group.
        group["stable_group_id"] = (
            "g-" + stable_id("entity-group", stable_entity_id)
            if stable_entity_id
            else "g-" + stable_id(group["vulnerability"], stable_basis)
        )
        for finding_id in groups[root]["members"]:
            descriptor = descriptors[finding_id]
            if stable_entity_id:
                descriptor["semantic_entity_id"] = stable_entity_id
            exact_key = f"{descriptor['source']}|{descriptor['source_finding_id']}|{descriptor['fingerprint']}"
            if finding_id == group["canonical_id"]:
                relation_by_id[finding_id] = None
            elif group["exact_keys"][exact_key] > 1:
                relation_by_id[finding_id] = "duplicate"
            elif len(group["sources"]) > 1:
                relation_by_id[finding_id] = "cross_provider_duplicate"
            else:
                relation_by_id[finding_id] = "related"
        group["duplicate_count"] = sum(1 for finding_id in groups[root]["members"] if relation_by_id.get(finding_id) == "duplicate")
        group["cross_provider_duplicate_count"] = sum(1 for finding_id in groups[root]["members"] if relation_by_id.get(finding_id) == "cross_provider_duplicate")
        group["related_count"] = sum(1 for finding_id in groups[root]["members"] if relation_by_id.get(finding_id) == "related")
        group["exact_duplicate_group"] = group["duplicate_count"] > 0
        group["cross_provider_duplicate_group"] = group["cross_provider_duplicate_count"] > 0

    target = stage_path(run, "correlated")
    stats = {
        "records": counts["records"], "groups": len(groups),
        "duplicates": sum(group["duplicate_count"] for group in group_summaries.values()),
        "exact_duplicate_groups": sum(1 for group in group_summaries.values() if group["exact_duplicate_group"]),
        "related": sum(group["related_count"] for group in group_summaries.values()),
        "cross_provider_groups": sum(1 for group in group_summaries.values() if len(group["sources"]) > 1),
        "cross_provider_duplicate_groups": sum(1 for group in group_summaries.values() if group["cross_provider_duplicate_group"]),
        "cross_provider_duplicate_records": sum(group["cross_provider_duplicate_count"] for group in group_summaries.values()),
        "conflicting_groups": sum(1 for group in group_summaries.values() if len(group["severities"]) > 1),
        "blocked_conflict_edges": len(blocked_conflicts),
    }

    def records():
        conflicts_by_id: dict[str, list[dict[str, Any]]] = {}
        for conflict in blocked_conflicts:
            conflicts_by_id.setdefault(conflict["left_finding_id"], []).append(conflict)
            conflicts_by_id.setdefault(conflict["right_finding_id"], []).append(conflict)
        for finding in iter_jsonl(source):
            root = union_find.find(str(finding["id"]))
            group = group_summaries[root]
            final_entity_id = descriptors[str(finding["id"])]["semantic_entity_id"]
            current_entity_id = str(
                finding.get("semantic_entity_id")
                or (finding.get("identity") or {}).get("semantic_entity_id")
                or ""
            ).strip()
            if final_entity_id and final_entity_id != current_entity_id:
                matched = set(finding.get("semantic_identity_aliases") or semantic_identity_aliases(finding))
                set_semantic_entity_id(finding, final_entity_id, matched_aliases=matched if reconciled_by_finding.get(str(finding["id"])) else None)
            if str(finding["id"]) in reconciliation_by_finding:
                finding.setdefault("identity", {})["reconciliation"] = dict(reconciliation_by_finding[str(finding["id"])])
            relation = relation_by_id.get(finding["id"], "related")
            finding["correlation"] = {
                "group_id": group["stable_group_id"], "canonical_id": group["canonical_id"],
                "relations": ([] if relation is None else [{"type": relation, "canonical_id": group["canonical_id"]}]),
                "duplicate_count": group["duplicate_count"],
                "related_count": group["related_count"],
                "cross_provider_duplicate_count": group["cross_provider_duplicate_count"],
                "recurrence_count": group["count"], "providers": sorted(group["sources"]),
                "conflicting_severities": sorted(group["severities"]) if len(group["severities"]) > 1 else [],
                "priority_distribution": dict(group["priorities"]),
                "conflicts": conflicts_by_id.get(finding["id"], []),
                "aggregation_basis": "normalized vulnerability identity plus overlapping strong asset observations",
            }
            yield finding

    write_jsonl(target, records())
    record_stage_lineage(metadata, "correlate", source, target)
    enforce_run_limits(run, metadata, "correlate")
    group_summary = []
    for root, group in group_summaries.items():
        group_summary.append({
            "group_id": group["stable_group_id"], "canonical_id": group["canonical_id"],
            "semantic_entity_id": group.get("stable_entity_id"),
            "count": group["count"], "providers": sorted(group["sources"]),
            "conflicting_severities": sorted(group["severities"]) if len(group["severities"]) > 1 else [],
            "priority_distribution": dict(group["priorities"]),
            "duplicate_count": group["duplicate_count"],
            "cross_provider_duplicate_count": group["cross_provider_duplicate_count"],
            "related_count": group["related_count"],
            "vulnerability_identity": groups[root]["vulnerability"],
            "asset_observations": sorted(group["asset_tokens"]),
            "stable_anchors": sorted(group["stable_anchors"]),
            "conflicts": [conflict for conflict in blocked_conflicts if any(member in {conflict["left_finding_id"], conflict["right_finding_id"]} for member in groups[root]["members"])],
            "aggregation_basis": "normalized vulnerability identity plus overlapping strong asset observations",
        })
    write_json(run / "correlation_groups.json", group_summary)
    # A rollup is deliberately separate from the blocking groups: two
    # different assets with the same vulnerability must remain separate
    # finding groups, while remediation planning still needs a stable view
    # of the vulnerability's enterprise prevalence.
    rollups: dict[str, dict[str, Any]] = {}
    for item in group_summary:
        vulnerability = item["vulnerability_identity"]
        if vulnerability == "unknown-vulnerability":
            continue
        rollup = rollups.setdefault(vulnerability, {"vulnerability_identity": vulnerability, "group_ids": [], "finding_count": 0, "asset_observations": set(), "providers": set()})
        rollup["group_ids"].append(item["group_id"])
        rollup["finding_count"] += item["count"]
        rollup["asset_observations"].update(item["asset_observations"])
        rollup["providers"].update(item["providers"])
    rollup_output = []
    for vulnerability, item in sorted(rollups.items()):
        rollup_output.append({
            "rollup_id": "vr-" + stable_id(vulnerability, length=16),
            "vulnerability_identity": vulnerability,
            "group_ids": sorted(item["group_ids"]), "finding_count": item["finding_count"],
            "asset_count": len(item["asset_observations"]),
            "asset_observations": sorted(item["asset_observations"]),
            "providers": sorted(item["providers"]),
            "aggregation_basis": "same canonical vulnerability across separate target groups",
        })
    write_json(run / "vulnerability_rollups.json", rollup_output)
    def _semantic_entities(path: Path) -> dict[str, set[str]]:
        entities: dict[str, set[str]] = {}
        for finding in iter_jsonl(path):
            aliases = set(finding.get("semantic_identity_aliases") or semantic_identity_aliases(finding))
            entity_id = str(finding.get("semantic_entity_id") or (finding.get("identity") or {}).get("semantic_entity_id") or durable_semantic_entity_id(finding))
            entities[entity_id] = entities.get(entity_id, set()) | aliases
        return entities

    # Longitudinal comparison must use the reconciled correlated output.  The
    # triaged input still contains an independent-run seed handle and would
    # incorrectly report a new entity even after baseline reconciliation.
    current_entities = _semantic_entities(target)
    baseline_entities: dict[str, set[str]] = {}
    if baseline:
        baseline_stage = stage_path(baseline, "correlated")
        baseline_entities = _semantic_entities(baseline_stage)
    longitudinal_status = "not_compared"
    stale_keys: list[str] = []
    recurring_entities = new_entities = stale_entities = None
    if baseline is not None:
        longitudinal_status = "compared"
        matched_current: set[str] = set()
        matched_baseline: set[str] = set()
        for current_id, aliases in current_entities.items():
            matches = {baseline_id for baseline_id in baseline_entities if current_id == baseline_id}
            if matches:
                matched_current.add(current_id)
                matched_baseline.update(matches)
        recurring_entities = len(matched_current)
        new_entities = len(current_entities) - recurring_entities
        stale_entities = len(baseline_entities) - len(matched_baseline)
        stale_keys = sorted(set(baseline_entities) - matched_baseline)
    write_json(run / "longitudinal.json", {
        "status": longitudinal_status, "baseline_run_dir": str(baseline) if baseline else None,
        "current_semantic_entities": len(current_entities), "baseline_semantic_entities": len(baseline_entities) if baseline is not None else None,
        "current_semantic_findings": len(current_entities), "baseline_semantic_findings": len(baseline_entities) if baseline is not None else None,
        "recurring_semantic_findings": recurring_entities,
        "new_semantic_findings": new_entities,
        "stale_semantic_findings": stale_entities,
        "entity_count_invariants": {"new_plus_recurring_equals_current": (new_entities + recurring_entities == len(current_entities)) if baseline is not None else None, "stale_plus_recurring_not_above_baseline": (stale_entities + recurring_entities <= len(baseline_entities)) if baseline is not None else None},
        "stale_keys": stale_keys,
        "identity_basis": "durable semantic entity handles reconciled by shared global vulnerability-target aliases; enrichment observations do not create a new entity",
    })
    metadata["correlation"] = stats
    metadata["vulnerability_rollups"] = len(rollup_output)
    metadata["longitudinal"] = {"status": longitudinal_status, "stale": len(stale_keys)}
    metadata["stages"]["correlate"] = {"status": "complete", **stats}
    metadata["updated_at"] = utc_now()
    save_run(run, metadata)
    write_lineage_manifest(run, metadata)
    events.emit("correlate.completed", run_id=str(metadata.get("run_id") or run.name), payload=stats)
    return metadata
