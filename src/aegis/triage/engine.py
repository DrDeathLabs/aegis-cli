"""Deterministic P0-P4 engine with explicit evidence drivers and guards."""

from __future__ import annotations

from collections import Counter
from typing import Any

from aegis.storage import ensure_run_dir, iter_jsonl, load_run, save_run, stage_path, utc_now, write_jsonl, invalidate_downstream, record_stage_lineage, enforce_run_limits, write_lineage_manifest
from aegis.observability.events import EventSink

PRIORITIES = ("P0", "P1", "P2", "P3", "P4")
_RANK = {priority: index for index, priority in enumerate(PRIORITIES)}
_IMPACT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}
_CRITICALITY = {"critical": 3, "high": 2, "medium": 1, "low": 0}
TRIAGE_VERSION = "aegis-deterministic-triage-v2"
_MATURE_EXPLOIT_MATURITIES = {
    "functional", "weaponized", "mature", "public", "in_the_wild", "reliable",
    "public_exploit", "active_exploitation", "functional_exploit", "weaponized_exploit",
}


def _bool(value: Any) -> bool:
    return value is True or str(value).lower() in {"true", "yes", "1", "active", "listed"}


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


_CONTROL_NEGATIONS = (
    "failed", "failure", "bypassed", "misconfigured", "degraded", "expired",
    "unavailable", "monitor only", "audit only", "disabled", "ineffective",
    "unsegmented", "unisolated", "not ", "without ", "no ",
)
_CONTROL_POSITIVE = (
    "effective", "strong", "blocks", "block ", "deny", "prevents", "contained",
    "segmented", "isolated", "air gap", "air-gapped", "virtual patch", "mitigat",
    "compensat",
)


def _control_state(value: Any) -> str:
    text = _lower(value)
    if not text:
        return "unknown"
    if any(term in text for term in _CONTROL_NEGATIONS):
        return "ineffective"
    if any(term in text for term in _CONTROL_POSITIVE):
        return "effective"
    return "unknown"


def _strong_control(controls: list[str], evidence: list[dict[str, Any]] | None = None) -> bool:
    """Return true only for explicit positive control evidence.

    Security-control nouns by themselves are not proof of mitigation.  The
    normalized evidence list is preferred because it preserves the original
    text and an explicit state; the fallback keeps older in-memory callers
    safe while applying the same negation-first rule.
    """
    candidates: list[Any] = evidence if evidence else controls
    for candidate in candidates:
        if isinstance(candidate, dict):
            if candidate.get("state") == "effective" and candidate.get("effective") is True:
                return True
            value = candidate.get("text")
        else:
            value = candidate
        if _control_state(value) == "effective":
            return True
    return False


def _isolated(asset: dict[str, Any]) -> bool:
    if _bool(asset.get("isolated")):
        return True
    values = (_lower(asset.get("isolation")), _lower(asset.get("network_zone")))
    isolation_terms = ("isolated", "air-gapped", "airgapped", "segmented", "restricted", "quarantined")
    return any(
        _control_state(value) == "effective"
        and (value in isolation_terms or any(term in value for term in isolation_terms))
        for value in values if value
    )


def _impact(finding: dict[str, Any]) -> tuple[str, int]:
    analysis = finding.get("analysis") or {}
    vuln = finding.get("vulnerability") or {}
    analysis_value = _lower(analysis.get("technical_impact"))
    severity = _lower(vuln.get("severity_normalized"))
    score_rank = 0
    for item in vuln.get("cvss_scores") or []:
        if not isinstance(item, dict):
            continue
        try:
            score = float(item.get("score"))
        except (TypeError, ValueError):
            continue
        score_rank = max(score_rank, 4 if score >= 9 else 3 if score >= 7 else 2 if score >= 4 else 1 if score > 0 else 0)
    evidence_rank = max(_IMPACT.get(severity, 0), score_rank)
    analysis_rank = _IMPACT.get(analysis_value, 0)
    rank = max(analysis_rank, evidence_rank)
    if rank <= 0:
        return "unknown", 0
    name = next(label for label, value in _IMPACT.items() if value == rank)
    return name, rank


def calculate_priority(finding: dict[str, Any]) -> tuple[str, list[str], list[dict[str, Any]], str]:
    vuln = finding.get("vulnerability") or {}
    asset = finding.get("asset") or {}
    state = finding.get("state") or {}
    analysis = finding.get("analysis") or {}
    impact_name, impact_rank = _impact(finding)
    kev = vuln.get("kev") or {}
    kev_listed = _bool(kev.get("listed"))
    active = _bool(vuln.get("exploited_in_wild")) or kev_listed
    exploit_maturity = _lower(vuln.get("exploit_maturity"))
    # PoC evidence is useful context but is not equivalent to a mature,
    # reliable exploit. exploit_available establishes existence only; when
    # explicit maturity is present it is the stronger semantic signal.
    exploit_exists = _bool(vuln.get("exploit_available"))
    mature_exploit = exploit_maturity in _MATURE_EXPLOIT_MATURITIES
    epss = vuln.get("epss")
    try:
        epss_value = float(epss) if epss is not None else None
    except (TypeError, ValueError):
        epss_value = None
    internet = _bool(asset.get("internet_exposed"))
    asset_criticality = _lower(asset.get("asset_criticality"))
    business_criticality = _lower(asset.get("business_criticality"))
    criticality_rank = max(_CRITICALITY.get(asset_criticality, 0), _CRITICALITY.get(business_criticality, 0))
    critical_asset = criticality_rank >= 2
    critical_consequence = criticality_rank >= 3
    criticality_label = next((label for label, value in _CRITICALITY.items() if value == criticality_rank), "unknown")
    controls = [str(item) for item in state.get("compensating_controls") or []
                if str(item).strip().lower() not in {"none", "no", "false", "n/a", "na", "unknown"}]
    control_evidence = state.get("control_evidence") or []
    strong_controls = _strong_control(controls, control_evidence)
    isolated = _isolated(asset)
    drivers: list[str] = [f"technical_impact={impact_name}"]
    analysis_impact = _lower(analysis.get("technical_impact"))
    if analysis_impact and analysis_impact != impact_name:
        drivers.append(f"analysis_technical_impact={analysis_impact}")
    if impact_rank > _IMPACT.get(analysis_impact, 0):
        drivers.append("technical_impact_floor=source severity/CVSS evidence")
    if vuln.get("severity_original") is not None:
        drivers.append(f"source_severity={vuln.get('severity_original')}")
    if kev_listed:
        drivers.append("CISA_KEV=true")
    if vuln.get("exploited_in_wild") is True:
        drivers.append("exploited_in_wild=true")
    if vuln.get("exploit_available") is True:
        drivers.append("exploit_available=true")
    if exploit_maturity:
        drivers.append(f"exploit_maturity={exploit_maturity}")
    if epss_value is not None:
        drivers.append(f"EPSS={epss_value:g}")
    if internet:
        drivers.append("internet_exposed=true")
    if critical_asset:
        drivers.append(f"critical_asset={criticality_label}")
    if critical_consequence:
        drivers.append("critical_business_or_asset_consequence=true")
    if controls:
        drivers.append("compensating_controls=" + ", ".join(controls[:3]))
    if strong_controls:
        drivers.append("strong_compensating_controls=true")
    if isolated:
        drivers.append("network_isolation=true")
    if asset.get("network_zone"):
        drivers.append(f"network_zone={asset['network_zone']}")
    confidence = analysis.get("confidence")
    if confidence is not None:
        drivers.append(f"analysis_confidence={confidence:g}" if isinstance(confidence, (int, float)) else f"analysis_confidence={confidence}")
    if analysis.get("conflicts"):
        drivers.append("conflicting_analysis=true")
    if state.get("recurrence", 1) > 1:
        drivers.append(f"recurrence={state.get('recurrence')}")
    if state.get("prevalence") is not None:
        drivers.append(f"prevalence={state.get('prevalence')}")
    if asset.get("data_sensitivity"):
        drivers.append(f"data_sensitivity={asset.get('data_sensitivity')} (context; no standalone tier promotion)")
    if asset.get("environment"):
        drivers.append(f"environment={asset.get('environment')} (context; no standalone tier promotion)")
    if state.get("patch_available") is not None:
        drivers.append(f"patch_available={state.get('patch_available')} (remediation planning context)")
    if vuln.get("vendor_risk_score") is not None:
        drivers.append(f"vendor_risk_score={vuln.get('vendor_risk_score')} (provider context; no standalone tier promotion)")
    guards: list[dict[str, Any]] = []
    # A strong independent incident signal cannot be neutralized by a weak
    # prose impact observation.  The source severity/CVSS floor above makes
    # the impact gate evidence-based rather than dependent on prose analysis.
    # Incident evidence is allowed to override controls. Controls remain
    # visible in the explanation, but cannot turn an active, internet-facing,
    # critical-consequence incident into a lower tier.
    p0 = impact_rank >= 4 and active and internet and critical_consequence
    active_urgent = active and impact_rank >= 2 and (internet or critical_asset)
    exploit_urgent = mature_exploit and impact_rank >= 3 and (internet or critical_consequence)
    epss_urgent = epss_value is not None and epss_value >= 0.85 and impact_rank >= 3 and (internet or critical_consequence)
    p1 = active_urgent or exploit_urgent or epss_urgent
    p2 = (
        (active and impact_rank >= 1 and (internet or critical_asset or (epss_value is not None and epss_value >= 0.5)))
        or (mature_exploit and impact_rank >= 2 and (internet or critical_asset))
        or (epss_value is not None and epss_value >= 0.5 and impact_rank >= 3)
        or (impact_rank >= 3 and (internet or critical_consequence))
        or (impact_rank >= 2 and (internet or critical_asset) and (mature_exploit or (epss_value is not None and epss_value >= 0.2)))
    )
    guards.append({"name": "internet_critical_asset_guard", "triggered": internet and critical_asset, "reason": "internet exposure and critical asset context" if internet and critical_asset else "internet/critical-asset combination not established"})
    guards.append({"name": "functional_exploit_guard", "triggered": mature_exploit, "reason": "explicit mature/reliable exploit maturity" if mature_exploit else "exploit maturity is not mature; exploit_available establishes existence only" if exploit_exists else "mature exploit not established"})
    guards.append({"name": "incident_priority_guard", "triggered": p0, "reason": "critical impact, active exploitation/KEV, internet exposure, and critical consequence; strong controls do not neutralize incident evidence" if p0 else "incident guard combination not established"})
    guards.append({"name": "control_effectiveness_guard", "triggered": strong_controls, "reason": "strong compensating control evidence" if strong_controls else "strong compensating control not established"})
    guards.append({"name": "network_isolation_guard", "triggered": isolated, "reason": "isolated or segmented network placement" if isolated else "isolated network placement not established"})
    guards.append({"name": "mitigation_reduction_guard", "triggered": bool(controls), "reason": "compensating controls recorded" if controls else "no compensating controls recorded"})
    active_floor_applied = False
    if p0:
        priority = "P0"
    elif p1:
        priority = "P1"
    elif p2:
        priority = "P2"
    elif impact_rank >= 2:
        priority = "P3"
    else:
        priority = "P4"
    if active and _RANK.get(priority, 9) > _RANK["P2"]:
        priority = "P2"
        active_floor_applied = True
    guards.insert(0, {
        "name": "active_exploitation_guard", "triggered": active,
        "minimum_priority": "P2" if active else None,
        "reason": "KEV or exploited-in-wild evidence; final priority cannot be lower than P2" if active else "no active exploitation evidence",
    })
    guards.insert(1, {
        "name": "active_exploitation_minimum_guard", "triggered": active_floor_applied,
        "minimum_priority": "P2" if active else None,
        "reason": "active exploitation/KEV floor enforced" if active_floor_applied else "active exploitation/KEV floor not needed" if active else "no active exploitation/KEV floor applies",
    })
    # Mitigation and isolation participate in tier selection, rather than
    # blindly lowering an already selected tier. The de-escalation gate is
    # closed by active/KEV evidence, meaningful external exposure, mature
    # exploit evidence, or high EPSS. Critical consequence remains a reason
    # to retain a monitored P3 instead of forcing every case to P4.
    strong_evidence_override = active or internet or mature_exploit or (epss_value is not None and epss_value >= 0.5)
    low_likelihood = epss_value is None or epss_value < 0.5
    control_deescalation_eligible = strong_controls and not strong_evidence_override and low_likelihood
    isolation_deescalation_eligible = isolated and not strong_evidence_override and low_likelihood
    guards.append({"name": "control_deescalation_guard", "triggered": control_deescalation_eligible,
                   "reason": "strong controls materially reduce a non-urgent, low-likelihood finding" if control_deescalation_eligible else "strong evidence or insufficient control/de-escalation conditions"})
    guards.append({"name": "isolation_deescalation_guard", "triggered": isolation_deescalation_eligible,
                   "reason": "isolation materially reduces a non-urgent, low-likelihood finding" if isolation_deescalation_eligible else "strong evidence or insufficient isolation/de-escalation conditions"})
    compensated = control_deescalation_eligible or isolation_deescalation_eligible
    if compensated and priority not in {"P0", "P1"}:
        if not critical_consequence:
            priority = "P4"
            reason = "selected P4 because low likelihood and internal/controlled or isolated placement support backlog treatment"
        else:
            priority = "P3"
            reason = "retained P3 because critical business/asset consequence warrants monitored remediation despite controls/isolation"
        guards.append({"name": "mitigation_selection_applied", "triggered": True, "reason": reason})
    else:
        guards.append({"name": "mitigation_selection_applied", "triggered": False,
                       "reason": "no eligible de-escalation; stronger exploitation, exposure, likelihood, or consequence evidence governs"})
    # Compatibility guard names remain explicit for consumers of earlier
    # schemas, but no post-tier one-step reduction is performed.
    guards.append({"name": "mitigation_reduction_applied", "triggered": False, "reason": "no generic post-tier reduction; mitigation was part of tier selection"})
    guards.append({"name": "isolation_reduction_applied", "triggered": False, "reason": "no generic post-tier reduction; isolation was part of tier selection"})
    if analysis.get("missing_evidence"):
        drivers.append("missing_evidence=" + ", ".join(analysis["missing_evidence"]))
    explanation = f"{priority} because {impact_name} impact was evaluated with independent threat, exposure, asset criticality, and mitigation evidence."
    if p0:
        maturity_note = "mature exploit evidence also supports the decision" if mature_exploit else "genuine active exploitation/KEV evidence is sufficient without mature-exploit classification"
        explanation = f"P0 because active exploitation/KEV, internet exposure, and critical consequence triggered the incident guard; {maturity_note}; strong controls are recorded but do not neutralize that stronger evidence; technical impact evidence was evaluated as {impact_name}."
    elif priority == "P4":
        explanation = "P4 because no urgent exploitation/exposure path is established and low context, strong controls, or isolation keep the finding in the hygiene/backlog tier."
    return priority, drivers, guards, explanation


def triage(run_dir: str) -> dict[str, Any]:
    run = ensure_run_dir(run_dir)
    metadata = load_run(run)
    invalidate_downstream(run, metadata, "triage")
    events = EventSink(run / "events.jsonl")
    events.emit("triage.started", run_id=str(metadata.get("run_id") or run.name))
    source = stage_path(run, "analyzed")
    if not source.exists():
        raise FileNotFoundError(f"analyzed stage not found: {source}")
    target = stage_path(run, "triaged")
    counts: Counter[str] = Counter()
    dispositions: Counter[str] = Counter()

    def records():
        for finding in iter_jsonl(source):
            calculated, drivers, guards, explanation = calculate_priority(finding)
            disposition = finding.get("disposition", "confirmed")
            active_queue = disposition == "confirmed"
            effective_priority = calculated if active_queue else None
            finding["calculated_priority"] = calculated
            finding["effective_priority"] = effective_priority
            # `priority` is retained as the compatibility alias for the
            # effective remediation-queue priority.
            priority = effective_priority
            finding["priority"] = priority
            finding["triage"] = {
                "priority": priority, "calculated_priority": calculated,
                "effective_priority": effective_priority,
                "drivers": drivers, "guard_results": guards,
                "explanation": explanation, "triage_version": TRIAGE_VERSION,
                "disposition": disposition, "active_queue": active_queue,
                "evidence_basis": (finding.get("evidence") or {}).get("basis", "report_only"),
            }
            counts[calculated] += 1
            dispositions[disposition] += 1
            yield finding

    count = write_jsonl(target, records())
    record_stage_lineage(metadata, "triage", source, target)
    enforce_run_limits(run, metadata, "triage")
    metadata["triaged_findings"] = count
    metadata["triage_counts"] = dict(counts)
    metadata["triage_disposition_counts"] = dict(dispositions)
    metadata["stages"]["triage"] = {"status": "complete", "findings": count, "counts": dict(counts), "triage_version": TRIAGE_VERSION}
    metadata["updated_at"] = utc_now()
    save_run(run, metadata)
    write_lineage_manifest(run, metadata)
    events.emit("triage.completed", run_id=str(metadata.get("run_id") or run.name), payload={"findings": count, "counts": dict(counts)})
    return metadata
