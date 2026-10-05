# Limitations and unverified areas

- Aegis v0.1 is file-first. It does not connect to commercial tenants, authenticate to vendor APIs, run scanners, deploy patches, or validate remediations.
- Provider exports change over time. The finite documented shapes may reject a different export version; unsupported schemas require an explicit, reviewed contract update.
- Fixture tests, API transport mocks, installed-wheel E2E, and a public blind-pack acceptance are different evidence levels. None is live-provider validation. No live Tenable, Qualys, Rapid7, Microsoft Defender, CrowdStrike, or Nessus instance was exercised.
- Priority is a deterministic decision aid, not a guaranteed SLA, safety case, or substitute for asset-owner review. Evidence can be missing, stale, inaccurate, or contradictory.
- v0.1.0 has no trained vulnerability classifier or corpus-calibration guard. Any future guard requires Aegis-specific operational evidence of a repeatable calibration error; source-code calibration labels, artifacts, and answer keys are not applicable.
- Correlation is conservative and identity-based; conflicts and missing target data can prevent a merge. A CVE alone does not prove same-asset identity. Longitudinal stale counts are snapshot comparisons, not proof of remediation.
- JSONL is the preferred large-record format. Whole-document JSON/XML is bounded by `max_whole_document_bytes`; raising limits changes resource use. RSS is advisory, while disk and wall-clock thresholds are checked at stage boundaries.
- JSON/CSV/HTML export preserves the full finding set and can require significant storage; only table and bounded finding-list paths are summary/paging views. Downstream report consumers need their own memory/size budgets.
- Reports omit complete raw records by default but may still contain sensitive mapped values, hostnames, IPs, descriptions, and unknown fields. `--include-raw` is an explicit internal export and is not access-controlled.
- Local JSON/JSONL artifacts are not a shared transactional database, durable backup system, multi-user service, or hosted platform. Host ACLs and retention remain operator responsibilities.
- No universal throughput/latency/availability guarantee is made. Benchmarks are host- and corpus-specific; see [Performance](PERFORMANCE.md).
- PDF, SARIF, source-code reachability, scanner subprocesses, online calibration feeds, and source-exploration agents are outside v0.1.
- The BSL 1.1 license is source-available, not open source. No commercial contact address or paid-support promise is published.
