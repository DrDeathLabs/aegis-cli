"""Provider-independent feature extraction for vulnerability-level modeling.

The model deliberately excludes provider name, asset context, controls, KEV,
active-exploitation, and observed EPSS. Those remain independent evidence and
are described beside the prediction; they are not rewritten by this estimator.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

FEATURE_SCHEMA_VERSION = "aegis-vulnerability-features-v1"
EPSS_HIGH_THRESHOLD = 0.1
BASE_FEATURES = (
    "cvss_base_score",
    "cve_year",
    "av_network",
    "av_adjacent",
    "av_local",
    "av_physical",
    "av_unknown",
    "ac_low",
    "ac_high",
    "ac_unknown",
    "pr_none",
    "pr_low",
    "pr_high",
    "pr_unknown",
    "ui_none",
    "ui_required",
    "ui_unknown",
    "impact_c_high",
    "impact_c_low",
    "impact_c_none",
    "impact_c_unknown",
    "impact_i_high",
    "impact_i_low",
    "impact_i_none",
    "impact_i_unknown",
    "impact_a_high",
    "impact_a_low",
    "impact_a_none",
    "impact_a_unknown",
)
_CVE_RE = re.compile(r"^CVE-(\d{4})-\d{4,}$", re.I)
_CWE_RE = re.compile(r"^CWE-\d+$", re.I)
_VECTOR_RE = re.compile(r"(?:^|/)(AV|AC|PR|UI|C|I|A|VC|VI|VA):([A-Z]+)")
_CVSS_VERSION_RE = re.compile(r"^CVSS:(?:3\.[01]|4\.0)/", re.I)


def normalized_cves(vulnerability: dict[str, Any]) -> list[str]:
    values = vulnerability.get("cve") or []
    if isinstance(values, str):
        values = [values]
    return sorted({str(value).strip().upper() for value in values if _CVE_RE.fullmatch(str(value).strip())})


def _valid_cwes(values: Any) -> list[str]:
    if isinstance(values, str):
        values = [values]
    return sorted({str(value).strip().upper() for value in (values or []) if _CWE_RE.fullmatch(str(value).strip())})


def _score(vulnerability: dict[str, Any]) -> float | None:
    candidates: list[float] = []
    for item in vulnerability.get("cvss_scores") or []:
        if not isinstance(item, dict):
            continue
        try:
            value = float(item.get("score"))
        except (TypeError, ValueError):
            continue
        if math.isfinite(value) and 0.0 <= value <= 10.0:
            candidates.append(value)
    return max(candidates) if candidates else None


def _vector(vulnerability: dict[str, Any]) -> dict[str, str]:
    vectors = vulnerability.get("cvss_vectors") or []
    if isinstance(vectors, str):
        vectors = [vectors]
    clean = sorted({str(item).strip().upper() for item in vectors if isinstance(item, str) and item.strip()})
    # Ignore CVSS v2 and unknown vector syntax. Sorting removes source/provider
    # ordering as a source of model differences when canonical evidence agrees.
    for text in clean:
        if _CVSS_VERSION_RE.match(text):
            return {key.lower(): value.lower() for key, value in _VECTOR_RE.findall(text)}
    return {}


def feature_names(cwe_categories: list[str] | tuple[str, ...] = ()) -> list[str]:
    return [*BASE_FEATURES, *(f"cwe_{cwe}" for cwe in sorted(set(cwe_categories))), "cwe_other"]


def extract_features(
    finding: dict[str, Any], cwe_categories: list[str] | tuple[str, ...] = (),
) -> tuple[dict[str, float], dict[str, Any]]:
    vulnerability = finding.get("vulnerability") or {}
    cves = normalized_cves(vulnerability)
    cwes = _valid_cwes(vulnerability.get("cwe"))
    vector = _vector(vulnerability)
    score = _score(vulnerability)
    year = None
    for cve in cves:
        match = _CVE_RE.fullmatch(cve)
        if match:
            year = int(match.group(1))
            break

    features = {name: 0.0 for name in feature_names(cwe_categories)}
    features["cvss_base_score"] = score if score is not None else 0.0
    features["cve_year"] = float(year or 0)

    av = vector.get("av")
    av_aliases = {"n": "network", "a": "adjacent", "l": "local", "p": "physical"}
    av_name = av_aliases.get(av or "")
    features[f"av_{av_name or 'unknown'}"] = 1.0

    categories = {
        "ac": {"l": "low", "h": "high"},
        "pr": {"n": "none", "l": "low", "h": "high"},
        "ui": {"n": "none", "r": "required"},
    }
    for metric, allowed in categories.items():
        mapped = allowed.get(vector.get(metric, ""))
        features[f"{metric}_{mapped or 'unknown'}"] = 1.0

    for metric, v4_metric, prefix in (("c", "vc", "impact_c"), ("i", "vi", "impact_i"), ("a", "va", "impact_a")):
        value = vector.get(metric) or vector.get(v4_metric)
        mapped = value.lower() if value in {"H", "L"} else "none" if value == "N" else "unknown"
        features[f"{prefix}_{mapped}"] = 1.0

    categories_present = sorted(set(cwe_categories))
    selected = set(categories_present)
    matched = [cwe for cwe in cwes if cwe in selected]
    for cwe in matched:
        features[f"cwe_{cwe}"] = 1.0
    if cwes and not matched:
        features["cwe_other"] = 1.0

    vectors = vulnerability.get("cvss_vectors") or []
    if isinstance(vectors, str):
        vectors = [vectors]
    safe_vectors = sorted({str(item).strip() for item in vectors if isinstance(item, str) and item.strip()})
    source_features = {
        "cve": cves,
        "cwe": cwes,
        "cvss_base_score": score,
        "cvss_vector": safe_vectors[0] if safe_vectors else None,
        "cve_year": year,
    }
    missing = []
    if not cves:
        missing.append("cve")
    if score is None:
        missing.append("cvss_base_score")
    if not cwes:
        missing.append("cwe")
    if not vector:
        missing.append("cvss_vector")
    return features, {"source_features": source_features, "missing_features": missing}


def cwe_categories_from_rows(rows: list[dict[str, Any]], limit: int = 32) -> list[str]:
    counts: Counter[str] = Counter()
    for row in rows:
        counts.update(_valid_cwes(row.get("cwes")))
    return [value for value, _ in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))[:limit]]
