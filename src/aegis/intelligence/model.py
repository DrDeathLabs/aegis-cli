"""Train an interpretable temporal-holdout estimator of elevated EPSS band."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis import __version__
from aegis.intelligence.artifact import write_artifact
from aegis.intelligence.features import (
    EPSS_HIGH_THRESHOLD,
    cwe_categories_from_rows,
    extract_features,
    feature_names,
)
from aegis.intelligence.paths import model_path


class ModelTrainingError(RuntimeError):
    """The available corpus cannot support a defensible fitted model."""


def _row_finding(row: dict[str, Any]) -> dict[str, Any]:
    vulnerability = {
        "cve": [row.get("cve_id")],
        "cwe": row.get("cwes") or [],
        "cvss_scores": [{"score": row["cvss_score"]}] if row.get("cvss_score") is not None else [],
        "cvss_vectors": [row["cvss_vector"]] if row.get("cvss_vector") else [],
    }
    return {"vulnerability": vulnerability}


def _metrics(labels: list[int], probabilities: list[float], reference_prevalence: float) -> dict[str, Any]:
    from sklearn.metrics import average_precision_score, confusion_matrix, log_loss, roc_auc_score

    clipped = [min(max(value, 1e-8), 1 - 1e-8) for value in probabilities]
    brier = sum((prob - label) ** 2 for prob, label in zip(clipped, labels)) / len(labels)
    threshold = 0.5
    predicted = [int(prob >= threshold) for prob in clipped]
    matrix = confusion_matrix(labels, predicted, labels=[0, 1]).tolist()
    true_negative, false_positive = matrix[0]
    false_negative, true_positive = matrix[1]
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    result: dict[str, Any] = {
        "n": len(labels),
        "positive_count": sum(labels),
        "observed_prevalence": sum(labels) / len(labels) if labels else 0.0,
        "reference_prevalence": reference_prevalence,
        "brier_score": brier,
        "log_loss": float(log_loss(labels, clipped, labels=[0, 1])),
        "average_precision_pr_auc": float(average_precision_score(labels, clipped)),
        "classification_threshold": threshold,
        "precision_at_threshold": precision,
        "recall_at_threshold": recall,
        "f1_at_threshold": f1,
        "confusion_matrix_at_threshold": matrix,
    }
    result["roc_auc"] = float(roc_auc_score(labels, clipped)) if len(set(labels)) == 2 else None
    return result


def _temporal_split(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    valid = [row for row in rows if row.get("published") and row.get("epss") is not None]
    valid.sort(key=lambda row: (str(row["published"]), str(row["cve_id"])))
    if len(valid) < 100:
        raise ModelTrainingError(f"need at least 100 dated EPSS-labeled CVEs; found {len(valid)}")
    train_end = int(len(valid) * 0.70)
    calibration_end = int(len(valid) * 0.85)
    train, calibration, test = valid[:train_end], valid[train_end:calibration_end], valid[calibration_end:]
    if not train or not calibration or not test:
        raise ModelTrainingError("temporal holdout could not form non-empty train/calibration/test sets")
    labels = lambda values: [int(float(row["epss"]) >= EPSS_HIGH_THRESHOLD) for row in values]
    if len(set(labels(train))) < 2 or len(set(labels(calibration))) < 2 or len(set(labels(test))) < 2:
        raise ModelTrainingError("each temporal split must contain both elevated and non-elevated EPSS examples")
    return train, calibration, test


def _to_matrix(rows: list[dict[str, Any]], categories: list[str], names: list[str]):
    import numpy as np

    matrix = []
    for row in rows:
        values, _ = extract_features(_row_finding(row), categories)
        matrix.append([values[name] for name in names])
    return np.asarray(matrix, dtype=float)


def train_model(
    rows: list[dict[str, Any]], corpus_metadata: dict[str, Any] | None = None,
    *, seed: int = 42, output: Path | None = None,
) -> dict[str, Any]:
    """Fit, calibrate, evaluate, and atomically serialize a pure-JSON model.

    scikit-learn is used only for fitting. The deployed artifact contains the
    standardized logistic coefficients and can be scored without sklearn,
    network access, or pickle/joblib deserialization.
    """
    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:
        raise ModelTrainingError("model fitting requires the optional dependency; install aegis-vulnerability-triage[ml]") from exc

    train, calibration, test = _temporal_split(rows)
    categories = cwe_categories_from_rows(train)
    names = feature_names(categories)
    train_x = _to_matrix(train, categories, names)
    calibration_x = _to_matrix(calibration, categories, names)
    test_x = _to_matrix(test, categories, names)
    train_y = np.asarray([int(float(row["epss"]) >= EPSS_HIGH_THRESHOLD) for row in train], dtype=int)
    calibration_y = np.asarray([int(float(row["epss"]) >= EPSS_HIGH_THRESHOLD) for row in calibration], dtype=int)
    test_y = [int(float(row["epss"]) >= EPSS_HIGH_THRESHOLD) for row in test]

    scaler = StandardScaler()
    train_z = scaler.fit_transform(train_x)
    calibration_z = scaler.transform(calibration_x)
    test_z = scaler.transform(test_x)
    classifier = LogisticRegression(C=0.5, solver="liblinear", random_state=seed, max_iter=2000)
    classifier.fit(train_z, train_y)

    calibration_logits = classifier.decision_function(calibration_z).reshape(-1, 1)
    calibrator = LogisticRegression(C=1.0, solver="lbfgs", random_state=seed, max_iter=2000)
    calibrator.fit(calibration_logits, calibration_y)
    calibration_slope = float(calibrator.coef_[0][0])
    calibration_intercept = float(calibrator.intercept_[0])
    raw_test_logits = classifier.decision_function(test_z)
    calibrated_test = 1.0 / (1.0 + np.exp(-np.clip(calibration_slope * raw_test_logits + calibration_intercept, -35, 35)))

    train_prevalence = float(train_y.mean())
    baseline = [train_prevalence] * len(test_y)
    test_metrics = _metrics(test_y, calibrated_test.tolist(), train_prevalence)
    baseline_metrics = _metrics(test_y, baseline, train_prevalence)
    better = (
        test_metrics["brier_score"] < baseline_metrics["brier_score"]
        and test_metrics["average_precision_pr_auc"] >= baseline_metrics["average_precision_pr_auc"]
    )
    quality = "better_than_temporal_prevalence_baseline" if better else "not_better_than_temporal_prevalence_baseline"

    train_dates = [str(row["published"]) for row in train]
    calibration_dates = [str(row["published"]) for row in calibration]
    test_dates = [str(row["published"]) for row in test]
    weights = classifier.coef_[0].tolist()
    means = scaler.mean_.tolist()
    scales = [float(value) if value > 0 else 1.0 for value in scaler.scale_.tolist()]
    coefficient_importance = sorted(
        ({"feature": name, "standardized_coefficient": float(weight)} for name, weight in zip(names, weights)),
        key=lambda item: (-abs(item["standardized_coefficient"]), item["feature"]),
    )[:20]
    false_positive = []
    false_negative = []
    for row, label, probability in zip(test, test_y, calibrated_test.tolist()):
        if probability >= 0.5 and label == 0 and len(false_positive) < 20:
            false_positive.append({"cve": row["cve_id"], "probability": probability, "epss": row["epss"]})
        if probability < 0.5 and label == 1 and len(false_negative) < 20:
            false_negative.append({"cve": row["cve_id"], "probability": probability, "epss": row["epss"]})

    metadata = corpus_metadata or {}
    evaluation = {
        "evaluation_schema_version": "aegis-ml-evaluation-v1",
        "model_type": "regularized logistic regression with Platt calibration",
        "target": f"current EPSS score >= {EPSS_HIGH_THRESHOLD:.2f}; this is an EPSS-band label, not observed exploitation ground truth",
        "split_method": "chronological by NVD published timestamp: 70% train, 15% calibration, 15% test",
        "temporal_leakage_controls": [
            "CVE IDs and published timestamps determine split ordering; later-published records are held out.",
            "Observed EPSS, KEV status, provider identity, asset context, and controls are excluded from model features.",
            "A single current EPSS snapshot labels every split; this is not a prospective historical snapshot evaluation and may retain temporal/data-vintage bias.",
        ],
        "class_balance": {
            "train": {"n": len(train), "positive": int(train_y.sum()), "negative": int(len(train_y) - train_y.sum())},
            "calibration": {"n": len(calibration), "positive": int(calibration_y.sum()), "negative": int(len(calibration_y) - calibration_y.sum())},
            "test": {"n": len(test_y), "positive": sum(test_y), "negative": len(test_y) - sum(test_y)},
        },
        "date_ranges": {
            "train": [min(train_dates), max(train_dates)],
            "calibration": [min(calibration_dates), max(calibration_dates)],
            "test": [min(test_dates), max(test_dates)],
        },
        "metrics": {"model": test_metrics, "temporal_prevalence_baseline": baseline_metrics},
        "quality_status": quality,
        "model_eligible_for_inference": better,
        "feature_importance": coefficient_importance,
        "error_analysis": {"false_positive_examples_at_0_5": false_positive, "false_negative_examples_at_0_5": false_negative},
        "known_biases": [
            "EPSS is a public model score estimating sensor-observed exploitation activity, not a census of exploitation.",
            "A current EPSS snapshot on older and newer CVEs is not equivalent to historical point-in-time prediction.",
            "NVD CVSS/CWE coverage and record quality vary; missing evidence is imputed to the training mean and lowers confidence.",
            "The model is CVE-level and does not estimate organization-specific loss or assign P0-P4.",
        ],
        "corpus": {"sha256": metadata.get("corpus_sha256"), "nvd_records_seen": metadata.get("nvd_records_seen"),
                   "epss_records_seen": metadata.get("epss_records_seen"), "kev_records_seen": metadata.get("kev_records_seen"),
                   "feed_manifest": metadata.get("feed_manifest", [])},
    }
    payload = {
        "model_version": "aegis-epss-band-logistic-v1",
        "model_type": "binary_logistic_regression",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "software_version": __version__,
        "feature_schema_version": "aegis-vulnerability-features-v1",
        "feature_names": names,
        "cwe_categories": categories,
        "means": means,
        "scales": scales,
        "coefficients": weights,
        "intercept": float(classifier.intercept_[0]),
        "calibration": {"method": "platt_logistic", "slope": calibration_slope, "intercept": calibration_intercept},
        "positive_label": f"EPSS >= {EPSS_HIGH_THRESHOLD:.2f}",
        "training": {
            "seed": seed, "configuration": {"C": 0.5, "solver": "liblinear", "class_weight": None, "max_iter": 2000},
            "n_samples": len(train), "training_date_range": evaluation["date_ranges"]["train"],
            "corpus_sha256": metadata.get("corpus_sha256"), "feed_manifest": metadata.get("feed_manifest", []),
        },
        "evaluation": evaluation,
        "model_eligible_for_inference": better,
    }
    target = output or model_path()
    artifact = write_artifact(target, payload)
    evaluation["model_hash"] = artifact["model_hash"]
    evaluation_path = target.parent / "model-evaluation.json"
    evaluation_path.write_text(json.dumps(evaluation, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {"model_path": str(target), "model_hash": artifact["model_hash"], "quality_status": quality,
            "model_eligible_for_inference": better, "training_rows": len(train), "calibration_rows": len(calibration),
            "test_rows": len(test), "evaluation": evaluation, "evaluation_path": str(evaluation_path)}
