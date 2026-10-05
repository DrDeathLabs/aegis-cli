# Aegis ML vulnerability intelligence

## Purpose and authority

The optional Aegis model is a vulnerability-level statistical estimate. It predicts whether the *current public EPSS score* for a CVE is at least `0.10` from NVD CVE features. It does not predict asset compromise with certainty, causal risk, or enterprise loss. It does not assign P0–P4.

Observed EPSS, CISA KEV membership, exploit availability/maturity, provider-native risk scores, exposure, criticality, controls, and remediation remain independent evidence. They are retained in the ML evidence envelope but are deliberately excluded from this model's feature vector. Adding or changing provider name, asset context, controls, observed EPSS, or KEV does not change the vulnerability-only model prediction. The deterministic triage engine continues to own final priority and consumes structured evidence under the documented policy.

## Model and interpretable evidence

The training extra uses regularized binary logistic regression with a held-out Platt calibration stage. Its fixed feature family includes valid CVE year, CVSS base score and v3/v4 vector dimensions where present, and a bounded set of common CWE indicators. Missing numeric values are imputed to the training mean; categorical unknowns have explicit indicator features. No source path, scanner filename, code reachability, local host path, provider name, or private/blind corpus feature is used.

The local artifact is versioned JSON, not pickle or joblib. It contains the feature schema, standardization values, coefficients, calibration parameters, seed/configuration, train-data date ranges, corpus hash, feed hashes, software version, evaluation report, and an integrity SHA-256. Inference is pure Python and requires no scikit-learn. Major drivers are standardized linear contributions; they are associations in this fitted model, not causal explanations.

Each analyzed finding includes `ml` fields: `model_version`, `model_hash`, `prediction.elevated_epss_band_probability`, `confidence`, `risk_band`, `major_drivers`, `source_features`, `feature_provenance`, `missing_features`, separate `public_signals`, descriptive `cwe_profile`, `enterprise_context`, `model_used`, and `priority_authority: false`. Confidence is a documented feature-coverage-and-margin proxy, not a prediction interval. The model's risk-band boundaries are descriptive output only.

## Lifecycle

```powershell
python -m pip install "aegis-vulnerability-triage[ml]"
aegis model status
aegis model refresh
aegis model info
aegis model path
```

`refresh` explicitly downloads NVD year feeds (default: current year minus five through current year), current EPSS CSV, and the CISA KEV catalog; it then builds local CWE statistics, trains and evaluates the model. It may take time and disk space. The default cache reuse window is twelve hours. Use `--force` for fresh downloads; `--start-year`/`--end-year` select a bounded calendar range (at most eleven years).

`aegis model build` compiles an existing feed cache into a local SQLite corpus without network access. `aegis model train` fits from that corpus without network access and accepts `--seed`. `aegis model info` reports held-out metrics, errors, data ranges, feature contributions, and known biases. `aegis model reset` requires confirmation and removes only recognized Aegis model/corpus/feed files. `status`, `info`, `path`, and all ordinary Aegis processing are offline.

If the model is absent, corrupt, has an unsupported schema, the finding does not contain exactly one valid CVE, or the model fails to beat the temporal prevalence baseline on both the Brier and PR-AUC checks, normal processing continues with `model_used: false` and an explicit status. No network refresh is attempted automatically.

## Evaluation and limits

Training sorts dated CVEs by NVD publication timestamp and uses the oldest 70% for training, the next 15% for calibration, and newest 15% for test. Observed EPSS is excluded from features; it is the target label. KEV, provider, asset context, controls, exploit data, and remediation are excluded from features. The evaluation reports Brier score, log loss, PR-AUC/average precision, ROC-AUC when defined, precision/recall/F1 and confusion matrix at a fixed 0.5 diagnostic threshold, class balance, coefficient importance, false-positive/false-negative examples, and a temporal prevalence baseline. It reports observed test prevalence separately from the training prevalence used by the baseline. The 0.5 threshold is descriptive, not an operational decision threshold; at low target prevalence it may yield no positive classifications even when ranking metrics improve.

The available public feed provides one current EPSS snapshot, so this is a chronology-based CVE cohort split, not a strict historical point-in-time or future-season prospective evaluation. EPSS's target is sensor-observed exploitation reporting, not complete ground truth. A model can be eligible for inference without establishing field effectiveness or production suitability. Read the generated `model-evaluation.json` and [Limitations](LIMITATIONS.md); do not infer efficacy from successful training.
