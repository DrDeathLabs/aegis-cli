# Requirement-to-evidence matrix

| Requirement | Implementation evidence | Acceptance evidence |
|---|---|---|
| New independent Aegis repository; root-only Git | root `pyproject.toml`, root `.git`, `_reference/` ignored | `git rev-parse --show-toplevel`; no nested reference `.git` |
| Read-only Trident reference | `_reference/trident-cli/`, baseline and final SHA manifests | before/after manifests identical; reference omitted from runtime imports |
| Provider-independent canonical model | `src/aegis/models.py`, `providers/common.py` | all eight fixtures normalize to `aegis-finding-v1` |
| Tenable, Qualys, Rapid7, Defender, CrowdStrike, Nessus, generic JSON/CSV | `src/aegis/providers/` | fixture directory produces 13 findings across all eight adapters |
| Preserve provider context and original records | `source_metadata`, `source_signals`, `provider_metadata` | final fixture report and JSON assertions |
| Generic schema inference and no silent data loss | `ingest/mapping.py`, `ingest/inference.py`, `RecordAccounting` | inferred mapping/coverage/hash in `run.json`; unknown fields retained; malformed row quarantined |
| Separate disposition from priority | `analysis/council.py`, `triage/engine.py`, disposition docs | false-positive/remediated null effective priority; accepted-risk/mitigated retain calculated priority |
| Deterministic P0–P4 with drivers/guards | `triage/engine.py` | golden corpus and fixture P0/P1/P2/P4 outputs; repeatable rules |
| Council evidence development and challenge | `analysis/council.py`, `analysis/structured.py` | role observations, Judge/Challenge records, mock structured-output run; priority authority false |
| Correlate duplicates/cross-provider/recurrence/conflicts | `correlation.py` | fixture: 2 exact duplicate rows, 1 cross-provider group, recurrence retained |
| Remediation action grouping | `remediation.py` | shared payments upgrade action links both provider findings; action IDs and finding IDs emitted |
| Structured output, replay, logging/events | `analysis/structured.py`, `replay.py`, `observability/events.py` | strict parser/retry tests, replay CLI hash validation, complete stage events |
| Actual CLI end-to-end | `src/aegis/cli.py` | installed `aegis run-all`, table/JSON/CSV/HTML exports inspected |
| 1k/100k/1m scale benchmark | `tools/generate_synthetic_corpus.py`, `tools/benchmark_aegis.py` | benchmark artifacts for all three sizes; 1m completed through remediation |
| Live commercial validation | intentionally not claimed | NO for every provider because no live instances/credentials were available |
