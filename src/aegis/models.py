"""Provider-independent Aegis canonical model.

The model intentionally keeps source signals separate.  Aegis never turns CVSS,
EPSS, KEV, provider risk, exposure, and business criticality into one opaque
number; deterministic triage consumes the structured evidence and records its
drivers and guards.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

DISPOSITIONS = (
    "confirmed", "unconfirmed", "false_positive", "mitigated",
    "accepted_risk", "remediated",
)
PRIORITIES = ("P0", "P1", "P2", "P3", "P4")
SCHEMA_VERSION = "aegis-finding-v1"


def stable_id(*parts: Any, length: int = 24) -> str:
    encoded = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:length]


def finding_id(provider: str, source_record_id: str | None, report_sha256: str, record_pointer: str) -> str:
    return "f-" + stable_id(provider, source_record_id, report_sha256, record_pointer)


def empty_finding(
    *, provider: str, source_type: str, source_record_id: str | None, report_sha256: str,
    record_pointer: str, original_record: Any, title: str = "Imported vulnerability finding",
) -> dict[str, Any]:
    """Return a complete, JSON-safe canonical finding skeleton."""
    return {
        "schema_version": SCHEMA_VERSION,
        "id": finding_id(provider, source_record_id, report_sha256, record_pointer),
        "import_instance_id": finding_id(provider, source_record_id, report_sha256, record_pointer),
        "semantic_finding_key": None,
        "semantic_entity_id": None,
        "observation_signature": None,
        "semantic_identity_aliases": [],
        "identity": {
            "import_instance_id": finding_id(provider, source_record_id, report_sha256, record_pointer),
            "source_occurrence_id": source_record_id,
            "provider_vulnerability_ids": [],
            "target_observations": [],
            "semantic_aliases": [],
            "semantic_entity_id": None,
            "observation_signature": None,
            "reconciliation": {"state": "unreconciled", "matched_aliases": [], "merged_entity_ids": []},
        },
        "source": provider,
        "source_type": source_type,
        "source_finding_id": source_record_id,
        "finding_type": "vulnerability",
        "title": title,
        "description": "",
        "vulnerability": {
            "identifiers": [], "cve": [], "cwe": [], "cvss_versions": [],
            "cvss_scores": [], "cvss_vectors": [], "severity_original": None,
            "provider_identifiers": [],
            "exploit_available": None, "exploit_maturity": None,
            "exploited_in_wild": None, "kev": {"listed": False, "source": "unknown"},
            "epss": None, "vendor_risk_score": None, "vendor_risk_metadata": {},
            "source_signals": {},
            "technical_impact": None,
        },
        "asset": {
            "asset_id": None, "hostname": None, "fqdn": None, "ip_addresses": [],
            "operating_system": None, "application": None, "package": None,
            "installed_version": None, "fixed_version": None, "port": None,
            "protocol": None, "service": None, "environment": None,
            "network_zone": None, "isolation": None, "isolated": None,
            "internet_exposed": None, "asset_criticality": None,
            "business_criticality": None, "data_sensitivity": None, "owner": None,
            "tags": [],
            "invalid_ip_observations": [],
        },
        "state": {
            "first_seen": None, "last_seen": None, "recurrence": 1, "prevalence": None,
            "status": None, "patch_available": None, "solution": None,
            "remediation_action_id": None, "remediation_id": None,
            "compensating_controls": [],
            "control_evidence": [],
        },
        "evidence": {
            "basis": "report_only", "items": [], "conflicts": [],
            "missing": [], "warnings": [], "mapping_confidence": 0.0,
        },
        "analysis": {
            "exploitability": None, "exposure": None, "threat": None,
            "technical_impact": None, "business_impact": None, "prevalence": None,
            "remediation": None, "confidence": 0.0, "conflicts": [],
            "missing_evidence": [], "council": [],
        },
        "disposition": "confirmed",
        "calculated_priority": None,
        "effective_priority": None,
        "priority": None,
        "triage": {},
        "correlation": {
            "group_id": None, "canonical_id": None, "relations": [],
            "duplicate_count": 0, "related_count": 0, "recurrence_count": 1,
        },
        "remediation": {"action_id": None, "action": None, "target": None},
        "source_metadata": {
            "provider": provider, "source_type": source_type,
            "report_sha256": report_sha256, "record_pointer": record_pointer,
            "original_record": original_record, "provider_metadata": {},
            "unmapped_fields": [], "mapping_version": None,
            "normalization_version": SCHEMA_VERSION,
            "ingested_at": None,
            "semantic_finding_key": None,
            "observation_signature": None,
        },
    }


def json_safe(value: Any) -> Any:
    """Convert common non-JSON values without dropping evidence."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    return str(value)


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return "; ".join(normalize_text(v) for v in value if normalize_text(v))
    if isinstance(value, dict):
        for key in ("text", "#text", "@value", "value", "name", "id", "message", "title"):
            if key in value and normalize_text(value[key]):
                return normalize_text(value[key])
    return ""


def as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    return [value]


def put_signal(finding: dict[str, Any], key: str, value: Any, source: str, original: Any = None) -> None:
    finding["vulnerability"][key] = value
    finding["vulnerability"].setdefault("source_signals", {})[key] = {
        "value": value, "source": source, "original": original if original is not None else value,
    }


def add_evidence(finding: dict[str, Any], *, field: str, value: Any, source: str,
                 pointer: str, confidence: float = 1.0) -> None:
    finding["evidence"]["items"].append({
        "field": field, "value": json_safe(value), "source": source,
        "confidence": max(0.0, min(1.0, float(confidence))), "provenance": pointer,
    })


def asset_identity(asset: dict[str, Any]) -> str:
    """Stable identity using the strongest available asset evidence."""
    keys = (
        asset.get("asset_id"), asset.get("fqdn"), asset.get("hostname"),
        *(sorted(str(ip).lower() for ip in asset.get("ip_addresses") or [])),
    )
    values = [str(k).strip().lower() for k in keys if k not in (None, "")]
    return values[0] if values else "unknown-asset"


def vulnerability_identity(finding: dict[str, Any]) -> str:
    vuln = finding.get("vulnerability") or {}
    cves = sorted(str(v).upper() for v in vuln.get("cve") or [] if v)
    native = []
    for item in vuln.get("provider_identifiers") or []:
        if isinstance(item, dict) and item.get("provider") and item.get("kind") == "vulnerability" and item.get("value"):
            native.append(f"{item['provider'].lower()}:vulnerability:{str(item['value']).strip().upper()}")
    return ",".join(cves or sorted(native)) or "unknown-vulnerability"


def _semantic_vulnerability_aliases(finding: dict[str, Any]) -> set[str]:
    vuln = finding.get("vulnerability") or {}
    aliases: set[str] = {
        f"cve:{str(value).strip().upper()}"
        for value in vuln.get("cve") or []
        if str(value).strip()
    }
    for item in vuln.get("provider_identifiers") or []:
        if isinstance(item, dict) and item.get("provider") and item.get("kind") == "vulnerability" and item.get("value"):
            aliases.add(
                f"{str(item['provider']).strip().lower()}:{str(item['kind']).strip().lower()}:{str(item['value']).strip().upper()}"
            )
    return aliases


def _semantic_target_aliases(finding: dict[str, Any]) -> set[str]:
    """Return global target aliases plus namespaced opaque asset aliases."""
    provider = str(finding.get("source") or "unknown").strip().lower()
    asset = finding.get("asset") or {}
    aliases: set[str] = set()
    for field in ("fqdn", "hostname"):
        value = str(asset.get(field) or "").strip().lower().rstrip(".")
        if value:
            aliases.add(f"{field}:{value}")
    asset_id = str(asset.get("asset_id") or "").strip()
    if asset_id:
        aliases.add(f"asset-id:{provider}:{asset_id.lower()}")
    for value in asset.get("ip_addresses") or []:
        text = str(value).strip().lower()
        if text:
            aliases.add(f"ip:{text}")
    return aliases


def semantic_identity_aliases(finding: dict[str, Any]) -> list[str]:
    """Return provider-independent vulnerability-on-target aliases.

    CVE, hostname/FQDN, and canonical IP observations are global evidence and
    therefore deliberately do not carry a provider prefix. Provider-native
    vulnerability and asset IDs retain their provider namespace. The aliases
    are pairwise so a CVE-only or target-only observation cannot merge records
    from different entities.
    """
    vulnerability_aliases = _semantic_vulnerability_aliases(finding)
    target_aliases = _semantic_target_aliases(finding)
    return sorted(
        f"vulnerability:{vulnerability}|target:{target}"
        for vulnerability in sorted(vulnerability_aliases)
        for target in sorted(target_aliases)
    )


def observation_signature(finding: dict[str, Any]) -> str:
    """Return the deterministic, observation-local identity signature.

    This signature describes the aliases visible in one observation.  It is
    deliberately allowed to change when a provider supplies additional
    identity evidence.  It is never the cross-run semantic entity handle;
    correlation must reconcile that handle against a baseline registry first.
    """
    aliases = sorted(set(finding.get("semantic_identity_aliases") or semantic_identity_aliases(finding)))
    if aliases:
        return "obs-" + stable_id("observation", aliases, length=24)
    provider = str(finding.get("source") or "unknown").strip().lower()
    occurrence = _source_occurrence_id(finding)
    return "obs-" + stable_id("observation", provider, occurrence or finding.get("id"), length=24)


def _source_occurrence_id(finding: dict[str, Any]) -> str | None:
    identity = finding.get("identity") or {}
    value = identity.get("source_occurrence_id") or finding.get("source_finding_id")
    text = str(value or "").strip()
    return text or None


def durable_semantic_entity_id(finding: dict[str, Any]) -> str:
    """Return an independent-run entity handle for one imported observation.

    A provider occurrence is retained as immutable evidence, but it is not a
    guaranteed cross-run entity key: providers commonly issue a new occurrence
    ID when an existing finding is enriched.  The handle returned here is a
    seed for an independent run.  Cross-run continuity is established only by
    ``correlate(..., baseline_run_dir=...)``, which inherits a prior handle
    after checking alias overlap and target conflicts.
    """
    existing = str(finding.get("semantic_entity_id") or (finding.get("identity") or {}).get("semantic_entity_id") or "").strip()
    if existing:
        return existing
    return "se-" + stable_id("independent-run", observation_signature(finding), length=24)


def set_semantic_entity_id(finding: dict[str, Any], entity_id: str, *, matched_aliases: set[str] | None = None, merged_entity_ids: set[str] | None = None) -> None:
    entity_id = str(entity_id)
    finding["semantic_entity_id"] = entity_id
    finding["semantic_finding_key"] = entity_id
    identity = finding.setdefault("identity", {})
    identity["semantic_entity_id"] = entity_id
    signature = observation_signature(finding)
    finding["observation_signature"] = signature
    identity["observation_signature"] = signature
    aliases = finding.get("semantic_identity_aliases") or semantic_identity_aliases(finding)
    identity["semantic_aliases"] = sorted(set(aliases))
    finding["semantic_identity_aliases"] = sorted(set(aliases))
    reconciliation = identity.setdefault("reconciliation", {})
    reconciliation["state"] = "reconciled" if matched_aliases else reconciliation.get("state", "unreconciled")
    if matched_aliases:
        reconciliation["matched_aliases"] = sorted(set(matched_aliases))
    if merged_entity_ids:
        reconciliation["merged_entity_ids"] = sorted(set(merged_entity_ids))
    source_metadata = finding.setdefault("source_metadata", {})
    source_metadata["semantic_finding_key"] = entity_id
    source_metadata["semantic_entity_id"] = entity_id
    source_metadata["observation_signature"] = signature


def conflicting_semantic_identity(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Return whether strong target evidence contradicts across observations."""
    def target(finding: dict[str, Any]) -> tuple[set[str], set[str], set[str], str]:
        asset = finding.get("asset") or {}
        names = {
            str(asset.get(field)).strip().lower().rstrip(".")
            for field in ("fqdn", "hostname")
            if str(asset.get(field) or "").strip()
        }
        ips = {str(value).strip().lower() for value in asset.get("ip_addresses") or [] if str(value).strip()}
        asset_ids = {str(asset.get("asset_id")).strip().lower()} if str(asset.get("asset_id") or "").strip() else set()
        source = str(finding.get("source") or "unknown").strip().lower()
        return names, ips, asset_ids, source

    left_names, left_ips, left_ids, left_source = target(left)
    right_names, right_ips, right_ids, right_source = target(right)
    if left_names and right_names and left_names.isdisjoint(right_names):
        return True
    if left_ips and right_ips and left_ips.isdisjoint(right_ips):
        return True
    return left_source == right_source and bool(left_ids and right_ids and left_ids.isdisjoint(right_ids))


def reconcile_semantic_identity(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Return whether two observations can be the same semantic finding.

    The relation is intentionally conservative: a shared semantic alias is
    sufficient, while a CVE-only or vulnerability-only match is not.  This
    keeps same-vulnerability/many-asset findings separate and lets callers
    record ambiguous/conflicting relations instead of silently merging them.
    """
    left_aliases = set(left.get("semantic_identity_aliases") or semantic_identity_aliases(left))
    right_aliases = set(right.get("semantic_identity_aliases") or semantic_identity_aliases(right))
    shared = left_aliases & right_aliases
    if not shared or conflicting_semantic_identity(left, right):
        return False
    left_id = durable_semantic_entity_id(left)
    right_id = durable_semantic_entity_id(right)
    # Preserve an existing left-side entity handle when reconciling a later
    # observation. If neither side has a persisted handle, choose the stable
    # global alias so key order and provider order do not affect the merge.
    entity_id = str(left.get("semantic_entity_id") or (left.get("identity") or {}).get("semantic_entity_id") or "").strip()
    if not entity_id:
        entity_id = "se-" + stable_id("global", min(shared), length=24)
    merged_ids = {left_id, right_id} - {entity_id}
    merged_aliases = left_aliases | right_aliases
    for item in (left, right):
        item["semantic_identity_aliases"] = sorted(merged_aliases)
        set_semantic_entity_id(item, entity_id, matched_aliases=shared, merged_entity_ids=merged_ids)
    return True
