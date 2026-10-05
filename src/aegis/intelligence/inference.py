"""Pure-Python scoring and structured ML evidence attached to findings."""

from __future__ import annotations

import math
import sqlite3
from pathlib import Path
from typing import Any

from aegis.intelligence.artifact import read_artifact
from aegis.intelligence.features import extract_features, normalized_cves
from aegis.intelligence.paths import corpus_path, model_path


def load_active_model(path: Path | None = None) -> tuple[dict[str, Any] | None, str]:
    artifact, reason = read_artifact(path or model_path())
    if artifact is None:
        return None, reason
    if not artifact.get("model_eligible_for_inference", False):
        return None, "held-out evaluation did not improve on the temporal prevalence baseline"
    return artifact, "active"


def load_cwe_profiles(path: Path | None = None) -> dict[str, dict[str, Any]]:
    db = path or corpus_path()
    if not db.is_file():
        return {}
    try:
        with sqlite3.connect(db) as conn:
            conn.row_factory = sqlite3.Row
            return {str(row["cwe_id"]): dict(row) for row in conn.execute("SELECT * FROM cwe_profile")}
    except (sqlite3.Error, OSError):
        return {}


def _sigmoid(value: float) -> float:
    if value >= 0:
        inverse = math.exp(-min(value, 700.0))
        return 1.0 / (1.0 + inverse)
    exp_value = math.exp(max(value, -700.0))
    return exp_value / (1.0 + exp_value)


def _context(finding: dict[str, Any]) -> dict[str, Any]:
    asset = finding.get("asset") or {}
    state = finding.get("state") or {}
    return {
        "not_model_features": True,
        "internet_exposed": asset.get("internet_exposed"),
        "network_zone": asset.get("network_zone"),
        "asset_criticality": asset.get("asset_criticality"),
        "business_criticality": asset.get("business_criticality"),
        "data_sensitivity": asset.get("data_sensitivity"),
        "environment": asset.get("environment"),
        "compensating_controls": state.get("compensating_controls") or [],
        "isolation": asset.get("isolation"),
        "remediation_available": state.get("patch_available"),
        "recurrence": state.get("recurrence"),
        "prevalence": state.get("prevalence"),
    }


def _public_signals(finding: dict[str, Any]) -> dict[str, Any]:
    vulnerability = finding.get("vulnerability") or {}
    kev = vulnerability.get("kev") or {}
    return {
        "observed_epss": vulnerability.get("epss"),
        "observed_kev_listed": kev.get("listed"),
        "observed_exploited_in_wild": vulnerability.get("exploited_in_wild"),
        "observed_exploit_available": vulnerability.get("exploit_available"),
        "observed_exploit_maturity": vulnerability.get("exploit_maturity"),
        "provider_risk_score": vulnerability.get("vendor_risk_score"),
        "provider_risk_metadata": vulnerability.get("vendor_risk_metadata") or {},
    }


def _profile(finding: dict[str, Any], profiles: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    vulnerability = finding.get("vulnerability") or {}
    cwes = vulnerability.get("cwe") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    for cwe in sorted(str(value).upper() for value in cwes if value):
        row = profiles.get(cwe)
        if row:
            return {
                "cwe": cwe,
                "cve_count": row.get("cve_count"),
                "mean_cvss": row.get("mean_cvss"),
                "mean_public_epss": row.get("mean_epss"),
                "kev_prevalence": row.get("kev_rate"),
                "elevated_epss_prevalence": row.get("high_epss_rate"),
                "first_published": row.get("first_published"),
                "last_published": row.get("last_published"),
                "interpretation": "descriptive corpus association; not causal and not a priority",
            }
    return None


def enrich_finding(
    finding: dict[str, Any], artifact: dict[str, Any] | None,
    *, unavailable_reason: str = "model unavailable", profiles: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Attach explicit model, public-signal, and enterprise-context evidence."""
    vulnerability = finding.get("vulnerability") or {}
    categories = (artifact or {}).get("cwe_categories") or []
    features, extracted = extract_features(finding, categories)
    cves = normalized_cves(vulnerability)
    public = _public_signals(finding)
    base: dict[str, Any] = {
        "schema_version": "aegis-ml-evidence-v1",
        "model_version": (artifact or {}).get("model_version"),
        "model_hash": (artifact or {}).get("model_hash"),
        "model_used": False,
        "prediction": None,
        "confidence": 0.0,
        "risk_band": "unavailable",
        "major_drivers": [],
        "source_features": extracted["source_features"],
        "feature_provenance": [
            "vulnerability.cve", "vulnerability.cwe", "vulnerability.cvss_scores", "vulnerability.cvss_vectors",
        ],
        "missing_features": list(extracted["missing_features"]),
        "public_signals": public,
        "enterprise_context": _context(finding),
        "cwe_profile": _profile(finding, profiles or {}),
        "priority_authority": False,
    }
    if artifact is None:
        base["status"] = unavailable_reason
        base["missing_features"].append("trained_model")
        return base
    if len(cves) != 1:
        base["status"] = "exactly_one_valid_cve_required_for_public_vulnerability_model"
        base["missing_features"].append("single_valid_cve")
        return base

    names = artifact["feature_names"]
    means = artifact["means"]
    scales = artifact["scales"]
    coefficients = artifact["coefficients"]
    logit = float(artifact["intercept"])
    contributions = []
    coverage_sources = {"cvss_base_score", "cve_year", "cvss_vector"}
    for index, name in enumerate(names):
        value = float(features.get(name, 0.0))
        if name == "cvss_base_score" and name in extracted["missing_features"]:
            value = float(means[index])
        standardized = (value - float(means[index])) / float(scales[index])
        contribution = float(coefficients[index]) * standardized
        logit += contribution
        if abs(contribution) > 1e-9:
            contributions.append({
                "feature": name,
                "direction": "toward_elevated_epss_band" if contribution > 0 else "away_from_elevated_epss_band",
                "standardized_contribution": round(contribution, 6),
                "value": value,
            })

    calibration = artifact.get("calibration") or {}
    calibrated_logit = float(calibration.get("slope", 1.0)) * logit + float(calibration.get("intercept", 0.0))
    probability = min(1.0, max(0.0, _sigmoid(calibrated_logit)))
    predicted = {"elevated_epss_band_probability": round(probability, 8)}
    if public.get("observed_epss") is not None:
        predicted["observed_epss_is_separate_source_evidence"] = True
    if public.get("observed_kev_listed") is True or public.get("observed_exploited_in_wild") is True:
        predicted["known_exploitation_facts_are_not_overridden"] = True

    risk_band = "low" if probability < 0.02 else "moderate" if probability < 0.10 else "elevated"
    used_count = sum(1 for name in coverage_sources if name not in extracted["missing_features"])
    # Confidence is a transparent coverage-and-margin proxy, not a statistical
    # confidence interval. Evaluation/calibration metrics remain in model info.
    required = len(coverage_sources)
    coverage = used_count / required
    confidence = min(1.0, max(0.0, coverage * (0.5 + abs(probability - 0.5))))
    base.update({
        "model_used": True,
        "status": "active",
        "prediction": predicted,
        "confidence": round(confidence, 6),
        "risk_band": risk_band,
        "major_drivers": sorted(contributions, key=lambda item: (-abs(item["standardized_contribution"]), item["feature"]))[:5],
        "model_scope": "estimates whether current public EPSS is at least 0.10; not a direct exploitation probability or enterprise loss estimate",
    })
    return base
