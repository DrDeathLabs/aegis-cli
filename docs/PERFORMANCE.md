# Performance and operating budgets

## Published defaults

| Resource | Default/boundary | Enforcement |
|---|---:|---|
| Per-input bytes | 1 GiB | Checked during input handling. |
| Whole-document JSON/XML | 64 MiB | Fails early above the configured document bound; use JSONL/CSV for larger records. |
| JSON nesting / nodes | 64 / 2,000,000 | Parser structural validation. |
| Per-record bytes | 8 MiB | Record validation/quarantine boundary. |
| Run-directory growth | 128 GiB | Enforced at stage boundaries. |
| Run wall clock | 6 hours | Enforced at stage boundaries. |
| Stage peak RSS | 8,192 MiB | Measured/advisory; not a portable hard process limit. |

These are configurable operating limits, not capacity guarantees. A host may run out of disk or memory before a configured threshold; operators should set lower limits based on available resources. JSON/CSV/HTML full exports are proportional to finding count and downstream consumers may load them all. Table and `findings --limit` are the bounded inspection paths.

## Large input guidance

Prefer JSONL/NDJSON or CSV/TSV for large corpora. Whole-document JSON arrays/XML use bounded parsing and may require memory proportional to the document. Do not raise `max_whole_document_bytes` as a substitute for a streaming format without measuring the host.

## Reproducible measurements

Use the included deterministic synthetic corpus generator and benchmark tool:

```powershell
python tools/generate_synthetic_corpus.py --count 1000000 --output .\corpus-1000000.jsonl
python tools/benchmark_aegis.py --input .\corpus-1000000.jsonl --run-dir .\aegis-benchmark-run --output .\benchmark.json
```

Record commit, Python/dependency versions, OS, corpus generator parameters, wall time, measured RSS, disk growth, and stages run. A benchmark is relevant only to the exact tested build and command path. This release-readiness candidate does not claim a new million-record benchmark at its release-prep commit; available earlier results belong to prior runtime commits and are not presented as measurements of this candidate. No generalized speed or memory claim is made.
