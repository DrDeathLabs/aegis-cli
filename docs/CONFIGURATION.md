# Configuration

Aegis reads optional `aegis.toml` from the current directory or its parents. Environment variables named `AEGIS_<SETTING>` override file values. Configuration does not accept provider credentials; v0.1.0 file ingestion does not call provider APIs.

| Setting | Default | Meaning |
|---|---:|---|
| `max_input_bytes` | 1 GiB | Maximum input file size. |
| `max_whole_document_bytes` | 64 MiB | JSON/XML whole-document bound; prefer JSONL/CSV above it. |
| `max_json_depth` | 64 | Structural nesting bound. |
| `max_json_nodes` | 2,000,000 | Structural node bound. |
| `max_record_bytes` | 8 MiB | Maximum normalized source record size. |
| `max_analysis_workers` | 8 | Worker limit for offline evidence analysis. |
| `max_model_calls` | 0 | Model invocation budget. Zero means no model calls. The v0.1 CLI exposes offline and mock analysis backends. |
| `backend` | `offline` | Default analysis mode (`offline` or `mock`). |
| `model` | `aegis-offline` | Model label used in analysis metadata; does not install or contact a service. |
| `repair_retries` | 1 | Structured-output repair retry limit where a model backend is enabled by the application. |
| `max_run_disk_bytes` | 128 GiB | Enforced run-directory disk budget at stage boundaries. |
| `max_stage_peak_rss_mb` | 8,192 MiB | Measured/advisory stage RSS threshold; not a portable hard process kill. |
| `max_run_seconds` | 6 hours | Enforced wall-clock budget at stage boundaries. |

Example:

```toml
[aegis]
max_input_bytes = 1073741824
max_whole_document_bytes = 67108864
max_record_bytes = 8388608
max_model_calls = 0
max_run_disk_bytes = 137438953472
max_run_seconds = 21600
```

Each setting is range-checked. Values are reported in non-secret run configuration metadata. See [Ingestion](INGESTION.md) and [Performance](PERFORMANCE.md) for parsing and operational limits.
