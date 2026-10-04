# Testing and benchmarks

The repository test suite covers:

- canonical model, provenance pointers, mapping selectors, record accounting, path containment, configuration, budgets, and typed model parsing;
- all eight adapters, provider fixture normalization, Nessus XML context, malformed JSON/CSV/XML, XXE rejection, unknown-field preservation, and generic schema inference;
- pagination, retry, rate-limit, idempotency/request identity, replay validation, deterministic P0–P4/disposition behavior, correlation, duplicate/cross-provider grouping, and remediation actions;
- the real subprocess CLI from ingest through report/export;
- curated golden cases with documented rationale.

Synthetic generation is deterministic:

```powershell
python tools/generate_synthetic_corpus.py --count 1000 --output artifacts/benchmarks/corpus_1000.jsonl
python tools/generate_synthetic_corpus.py --count 100000 --output artifacts/benchmarks/corpus_100000.jsonl
python tools/generate_synthetic_corpus.py --count 1000000 --output artifacts/benchmarks/corpus_1000000.jsonl
python tools/benchmark_aegis.py --input artifacts/benchmarks/corpus_1000000.jsonl --run-dir artifacts/runs/benchmark_1000000 --output artifacts/benchmarks/benchmark_1000000.json
```

The benchmark records per-stage wall-clock time, sampled peak process RSS, total input records, artifact growth, report JSON/CSV time, and replay export/validation time. Results are host-specific and are acceptance evidence only for the measured environment. The exhaustive-hardening evidence package records the fresh million-record run on the final executable commit; the older numbers below are historical comparison data, not a current acceptance claim.

Measured on this Windows host with the deterministic synthetic JSONL corpus:

| Corpus | Total path time | Result |
|---:|---:|---|
| 1,000 | 1.915 s | 1,000 records through remediation |
| 100,000 | 284.867 s | 100,000 records through remediation |
| 1,000,000 | 2,613.826 s (43m 34s) | 1,000,000 records through remediation; completed after the remediation retention fix |

The historical million-row run produced approximately 727 MB raw JSONL, 5.4 GB canonical findings, 7.3 GB analyzed, 8.2 GB triaged, 8.5 GB correlated, and 0.8 GB remediated artifacts. The largest observed worker working set was approximately 460 MB during correlation; remediation was approximately 270 MB after bounded action-evidence sampling. These measurements describe this host and the required lossless artifact format, not a universal capacity guarantee. The final fresh run supersedes these values for acceptance and includes the report/export/replay stages.

## Residual-hardening scale policy

The default settings expose explicit operating budgets in each run's
`operational_budgets` metadata: 128 GiB run-directory growth, 8,192 MiB peak
RSS per stage (advisory), an 8 MiB record bound, and six hours total wall
clock. Disk and wall-clock limits are enforced at stage boundaries; RSS is
measured and reported but is not a portable hard kill. These are measured host
budgets, not a claim that every deployment has the same capacity.

Whole-document JSON/XML parsing has a separate 64 MiB bound. Larger JSON
arrays must use JSONL or a provider streaming contract; larger XML exports
fail early with an actionable error. Qualys and Nessus XML parsing rejects
entity declarations and does not resolve external resources.

The report JSON keeps the complete normalized finding array but does not
duplicate a million-row active queue. `active_queue` is a deterministic top
100 view with `active_queue_top_n` and `active_queue_truncated` metadata. The
default table and `findings --limit` paths are bounded streaming views.

For large-run evidence, `tools/scale_evidence.py` hashes every artifact and
records byte counts, JSONL record counts, deterministic sampled line hashes,
sampled identity fields, ordered 4 MiB chunk/Merkle-root evidence, and
stage-lineage hash checks. The evidence ZIP
contains this compact verification instead of copying the full multi-gigabyte
run directory.
