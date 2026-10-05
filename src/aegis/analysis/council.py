"""Evidence-oriented Council analysis.

This is an Aegis adaptation of Trident's useful independent-review/challenge
pattern. Roles develop structured evidence observations, the Judge records
conflicts and missing context, and the Challenge reviewer identifies systemic
relationships. The final priority is never produced here.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from typing import Any

from aegis.analysis.budget import LLMBudget
from aegis.analysis.llm import ChatMessage, MockModelBackend
from aegis.analysis.schemas import MockModelResponse
from aegis.analysis.structured import chat_structured
from aegis.analysis.convergence import convergence
from aegis.config import settings
from aegis.intelligence.inference import enrich_finding, load_active_model, load_cwe_profiles
from aegis.models import DISPOSITIONS
from aegis.remediation_evidence import remediation_available, remediation_evidence
from aegis.observability.events import EventSink
from aegis.storage import ensure_run_dir, iter_jsonl, load_run, save_run, stage_path, utc_now, write_jsonl, invalidate_downstream, record_stage_lineage, enforce_run_limits, write_lineage_manifest

ROLES = (
    "Exploitability Expert", "Exposure / Attack Path Expert", "Threat Intelligence Expert",
    "Asset / Business Criticality Expert", "Remediation Expert", "Judge", "Red Team / Challenge Reviewer",
)


def _parallel(items: list[Any], worker, *, max_workers: int = 8) -> list[Any]:
    """Ordered ThreadPoolExecutor phase adapted from Trident deliberation."""
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as pool:
        futures = [pool.submit(worker, item) for item in items]
        return [future.result() for future in futures]


def _text(finding: dict[str, Any]) -> str:
    vuln = finding.get("vulnerability") or {}
    return " ".join(str(value or "") for value in (finding.get("title"), finding.get("description"), vuln.get("technical_impact"), vuln.get("cwe"))).lower()


def infer_technical_impact(finding: dict[str, Any]) -> tuple[str, list[str]]:
    vuln = finding.get("vulnerability") or {}
    text = _text(finding)
    explicit = str(vuln.get("technical_impact") or "").lower()
    if any(token in text for token in ("remote code execution", "rce", "command execution", "arbitrary code")) or explicit in {"critical", "rce", "auth_bypass"}:
        return "critical", ["technical impact indicates code execution or authentication bypass"]
    if any(token in text for token in ("authentication bypass", "privilege escalation", "data breach", "injection", "sql injection", "ssrf")) or explicit in {"high", "injection", "data_exposure", "data_tampering"}:
        return "high", ["technical impact indicates material control or data compromise"]
    if any(token in text for token in ("denial of service", "dos", "exposure", "disclosure", "sensitive data")) or explicit == "medium":
        return "medium", ["technical impact indicates service or information impact"]
    # Source severity and CVSS are evidence about potential consequence even
    # when a provider does not include a prose impact description.  They are
    # kept as analysis basis, not collapsed with threat or exposure signals.
    severity = str(vuln.get("severity_normalized") or "").lower()
    score_values = []
    for item in vuln.get("cvss_scores") or []:
        if isinstance(item, dict):
            try:
                score_values.append(float(item.get("score")))
            except (TypeError, ValueError):
                continue
    max_score = max(score_values, default=None)
    if severity == "critical" or (max_score is not None and max_score >= 9.0):
        return "critical", ["source severity/CVSS establishes critical potential technical consequence"]
    if severity == "high" or (max_score is not None and max_score >= 7.0):
        return "high", ["source severity/CVSS establishes high potential technical consequence"]
    if severity == "medium" or (max_score is not None and max_score >= 4.0):
        return "medium", ["source severity/CVSS establishes medium potential technical consequence"]
    return "low", ["no higher technical impact is established by the imported evidence"]


def _status_to_disposition(finding: dict[str, Any]) -> str:
    state = finding.get("state") or {}
    raw = str(state.get("status") or "").lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "fixed": "remediated", "resolved": "remediated", "closed": "remediated",
        "remediated": "remediated", "false_positive": "false_positive", "falsepositive": "false_positive",
        "accepted": "accepted_risk", "accepted_risk": "accepted_risk", "risk_accepted": "accepted_risk",
        "mitigated": "mitigated", "unconfirmed": "unconfirmed", "open": "confirmed", "active": "confirmed",
    }
    return aliases.get(raw, finding.get("disposition") if finding.get("disposition") in DISPOSITIONS else "confirmed")


def _analysis_for(finding: dict[str, Any], backend_name: str = "offline") -> dict[str, Any]:
    vuln = finding.get("vulnerability") or {}
    asset = finding.get("asset") or {}
    state = finding.get("state") or {}
    remediation = remediation_evidence(finding)
    epss = vuln.get("epss")
    kev = vuln.get("kev") or {}
    exploit = vuln.get("exploit_available")
    exploited = vuln.get("exploited_in_wild")
    impact, impact_refs = infer_technical_impact(finding)
    missing: list[str] = []
    if asset.get("internet_exposed") is None:
        missing.append("internet_exposure")
    if not asset.get("business_criticality") and not asset.get("asset_criticality"):
        missing.append("business_criticality")
    kev_listed = kev.get("listed") is True
    if epss is None and exploited is None and not kev_listed:
        missing.append("threat_intelligence")
    if not remediation_available(finding):
        missing.append("remediation_path")
    exposure = "internet" if asset.get("internet_exposed") is True else "network" if asset.get("internet_exposed") is False else "unknown"
    maturity = str(vuln.get("exploit_maturity") or "").strip().lower()
    mature = maturity in {"functional", "weaponized", "mature", "public", "in_the_wild", "reliable"}
    threat = "active_exploitation" if exploited is True or kev_listed else "high_likelihood" if (mature or (exploit is True and not maturity) or (isinstance(epss, (int, float)) and epss >= 0.7)) else "unconfirmed"
    exploitability = "active" if exploited is True or kev_listed else "mature" if mature else "poc" if maturity else "public" if exploit is True else "high" if isinstance(epss, (int, float)) and epss >= 0.7 else "moderate" if isinstance(epss, (int, float)) and epss >= 0.3 else "unknown"
    business = str(asset.get("business_criticality") or "unknown").lower()
    controls = state.get("compensating_controls") or []
    confidence = max(0.25, min(1.0, 1.0 - 0.08 * len(missing)))
    observations = []
    observation_data = [
        ("Exploitability Expert", f"exploitability={exploitability}", exploitability, ["exploit_available", "exploit_maturity", "epss"]),
        ("Exposure / Attack Path Expert", f"exposure={exposure}", exposure, ["internet_exposed", "asset_id", "hostname"]),
        ("Threat Intelligence Expert", f"threat={threat}", threat, ["kev", "exploited_in_wild", "epss"]),
        ("Asset / Business Criticality Expert", f"business_criticality={business}", business, ["business_criticality", "asset_criticality", "data_sensitivity"]),
        ("Remediation Expert", f"remediation={'available' if remediation_available(finding) else 'unknown'}", "available" if remediation_available(finding) else "unknown", ["solution", "fixed_version", "patch_available"]),
    ]
    def independent_review(item):
        role, conclusion, _value, refs = item
        return {"role": role, "conclusion": conclusion, "confidence": confidence,
                "evidence_refs": [ref for ref in refs if ref in vuln or ref in asset or ref in state],
                "conflicts": [], "missing_evidence": [item for item in missing if item in refs]}
    # The phase is parallelized at the finding-batch boundary in analyze();
    # keeping these five role projections local avoids one executor per
    # finding on million-record corpora while preserving phase-A semantics.
    observations.extend(independent_review(item) for item in observation_data)
    observations.append({"role": "Judge", "conclusion": "evidence retained with explicit uncertainty", "confidence": confidence, "evidence_refs": ["original_record", "mapping_confidence"], "conflicts": [], "missing_evidence": missing})
    ml = finding.get("ml") or {}
    if ml.get("model_used"):
        ml_probability = ((ml.get("prediction") or {}).get("elevated_epss_band_probability"))
        observed_epss = ((ml.get("public_signals") or {}).get("observed_epss"))
        observed_band = isinstance(observed_epss, (int, float)) and observed_epss >= 0.1
        model_band = isinstance(ml_probability, (int, float)) and ml_probability >= 0.5
        mismatch = observed_epss is not None and observed_band != model_band
        if mismatch:
            finding["evidence"]["conflicts"].append(
                "ML estimate differs from the observed EPSS band; the source EPSS value remains independent evidence"
            )
        observations.append({
            "role": "ML Vulnerability Intelligence Reviewer",
            "conclusion": f"estimated elevated EPSS-band probability={ml_probability}; this is advisory and not an exploitation fact",
            "confidence": ml.get("confidence", 0.0),
            "evidence_refs": ["vulnerability.cve", "vulnerability.cwe", "vulnerability.cvss_scores", "vulnerability.cvss_vectors"],
            "conflicts": ["model estimate differs from observed EPSS band"] if mismatch else [],
            "missing_evidence": ml.get("missing_features", []),
        })
    else:
        observations.append({
            "role": "ML Vulnerability Intelligence Reviewer",
            "conclusion": f"model evidence unavailable: {ml.get('status', 'not supplied')}",
            "confidence": 0.0, "evidence_refs": [], "conflicts": [],
            "missing_evidence": ml.get("missing_features", []),
        })
    observations.append({"role": "Red Team / Challenge Reviewer", "conclusion": "cross-finding challenge deferred until correlation", "confidence": 0.8, "evidence_refs": ["original_record"], "conflicts": [], "missing_evidence": []})
    if vuln.get("severity_normalized") and vuln.get("vendor_risk_score") is not None:
        score = float(vuln["vendor_risk_score"])
        if (vuln["severity_normalized"] in {"critical", "high"} and score < 4) or (vuln["severity_normalized"] in {"low", "none"} and score >= 8):
            finding["evidence"]["conflicts"].append("provider severity conflicts with vendor risk score")
    return {
        "exploitability": {"level": exploitability, "evidence": ["exploit_available", "exploit_maturity", "epss"]},
        "exposure": {"level": exposure, "internet_exposed": asset.get("internet_exposed"), "evidence": ["internet_exposed"]},
        "threat": {"level": threat, "evidence": ["kev", "exploited_in_wild", "epss"]},
        "technical_impact": impact, "business_impact": business,
        "prevalence": state.get("prevalence") if state.get("prevalence") is not None else state.get("recurrence", 1),
        "remediation": {"available": remediation_available(finding), "solution": remediation["solution"], "fixed_version": remediation["fixed_version"], "patch_available": remediation["patch_available"], "remediation_action_id": remediation["remediation_action_id"], "remediation_id": remediation["remediation_id"]},
        "confidence": confidence, "conflicts": list(finding["evidence"].get("conflicts") or []),
        "missing_evidence": missing, "council": observations,
        "ml_review": {"model_used": bool(ml.get("model_used")), "model_version": ml.get("model_version"),
                      "model_hash": ml.get("model_hash"), "risk_band": ml.get("risk_band"),
                      "prediction": ml.get("prediction"), "priority_authority": False},
        "model_provenance": {"backend": backend_name, "mode": "evidence_analysis_only", "priority_authority": False,
                             "ml_model_used": bool(ml.get("model_used")), "ml_model_hash": ml.get("model_hash")},
        "impact_basis": impact_refs, "controls": controls,
    }


def analyze(run_dir: str, *, backend_name: str = "offline") -> dict[str, Any]:
    run = ensure_run_dir(run_dir)
    metadata = load_run(run)
    invalidate_downstream(run, metadata, "analyze")
    events = EventSink(run / "events.jsonl")
    events.emit("analyze.started", run_id=str(metadata.get("run_id") or run.name), payload={"backend": backend_name})
    input_path = stage_path(run, "findings")
    if not input_path.exists():
        raise FileNotFoundError(f"findings stage not found: {input_path}")
    output_path = stage_path(run, "analyzed")
    disposition_counts: Counter[str] = Counter()
    configured = settings()
    budget = LLMBudget(limit=configured.max_model_calls)
    model_backend = MockModelBackend() if backend_name == "mock" else None
    model_name = configured.model
    intelligence_model, intelligence_status = load_active_model()
    cwe_profiles = load_cwe_profiles() if intelligence_model else {}

    def analyze_one(finding: dict[str, Any]) -> dict[str, Any]:
        finding["disposition"] = _status_to_disposition(finding)
        finding["ml"] = enrich_finding(
            finding, intelligence_model, unavailable_reason=intelligence_status, profiles=cwe_profiles,
        )
        finding["analysis"] = _analysis_for(finding, backend_name)
        if model_backend is not None:
            result = chat_structured(
                model_backend,
                [ChatMessage("user", "Summarize the supplied vulnerability evidence without assigning priority."),
                 ChatMessage("user", str({"finding_id": finding.get("id"), "title": finding.get("title"), "evidence": finding.get("evidence")}))],
                MockModelResponse, model=model_name,
                context={"run_id": metadata.get("run_id"), "finding_id": finding.get("id"), "task_type": "council_observation", "role": "Judge"},
                max_repair_retries=configured.repair_retries,
                call_permit=budget.take,
            )
            finding["analysis"]["model_observation"] = {
                "ok": result.ok, "request_id": result.request_id, "status": result.status,
                "conclusion": result.obj.conclusion if result.obj else None,
                "rationale": result.obj.rationale if result.obj else result.error,
                "priority_authority": False,
            }
        return finding

    def records():
        batch: list[dict[str, Any]] = []
        for finding in iter_jsonl(input_path):
            batch.append(finding)
            if len(batch) >= 2048:
                for analyzed in _parallel(batch, analyze_one, max_workers=configured.max_analysis_workers):
                    disposition_counts[analyzed["disposition"]] += 1
                    yield analyzed
                batch = []
        for analyzed in _parallel(batch, analyze_one, max_workers=configured.max_analysis_workers):
            disposition_counts[analyzed["disposition"]] += 1
            yield analyzed

    count = write_jsonl(output_path, records())
    record_stage_lineage(metadata, "analyze", input_path, output_path)
    enforce_run_limits(run, metadata, "analyze")
    metadata["analyzed_findings"] = count
    metadata["disposition_counts"] = dict(disposition_counts)
    metadata["stages"]["analyze"] = {"status": "complete", "findings": count, "backend": backend_name,
                                       "priority_authority": False, "model_calls": budget.used,
                                       "model_call_limit": budget.limit, "council_pattern": "phase_a_independent_reviews_then_judge_challenge",
                                       "convergence": convergence(iteration=1, max_iterations=1, unresolved=0, budget_exhausted=budget.exhausted).__dict__}
    metadata["updated_at"] = utc_now()
    save_run(run, metadata)
    write_lineage_manifest(run, metadata)
    events.emit("analyze.completed", run_id=str(metadata.get("run_id") or run.name), payload={"findings": count, "model_calls": budget.used})
    return metadata
