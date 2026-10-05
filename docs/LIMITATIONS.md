# Limitations and unverified areas

- Aegis v0.1 is file-first. It does not connect to commercial tenants, authenticate to vendor APIs, run scanners, deploy patches, or validate remediations.
- Provider exports change over time. The finite documented shapes may reject a different export version; unsupported schemas require an explicit, reviewed contract update.
- Fixture tests, API transport mocks, installed-wheel E2E, and a public blind-pack acceptance are different evidence levels. None is live-provider validation. No live Tenable, Qualys, Rapid7, Microsoft Defender, CrowdStrike, or Nessus instance was exercised.
- Priority is a deterministic decision aid, not a guaranteed SLA, safety case, or substitute for asset-owner review. Evidence can be missing, stale, inaccurate, or contradictory.
- Correlation is conservative and identity-based; conflicts and missing target data can prevent a merge. A CVE alone does not prove same-asset identity. Longitudinal stale counts are snapshot comparisons, not proof of remediation.
- JSONL is the preferred large-record format. Whole-document JSON/XML is bounded by `max_whole_document_bytes`; raising limits changes resource use. RSS is advisory, while disk and wall-clock thresholds are checked at stage boundaries.
- JSON/CSV/HTML export preserves the full finding set and can require significant storage; only table and bounded finding-list paths are summary/paging views. Downstream report consumers need their own memory/size budgets.
- Reports omit complete raw records by default but may still contain sensitive mapped values, hostnames, IPs, descriptions, and unknown fields. `--include-raw` is an explicit internal export and is not access-controlled.
- The optional ML target is the current public EPSS band (`EPSS >= 0.10`), not observed exploit truth or a full exploitation-probability model. The evaluation uses a chronological CVE-publication split but one current EPSS label snapshot; it is not a fully prospective point-in-time evaluation. Model evidence is CVE-level and does not estimate organization-specific loss.
- Model training requires the optional `[ml]` extra and a local NVD/EPSS/KEV corpus. Feed refresh requires network access and may use hundreds of megabytes of local storage for selected NVD year files; feed files are not included in the Python package. If held-out performance does not improve over the temporal prevalence baseline, inference is disabled and Aegis degrades to its existing deterministic analysis.
- Local JSON/JSONL artifacts are not a shared transactional database, durable backup system, multi-user service, or hosted platform. Host ACLs and retention remain operator responsibilities.
- No universal throughput/latency/availability guarantee is made. Benchmarks are host- and corpus-specific; see [Performance](PERFORMANCE.md).
- PDF, SARIF, source-code reachability, scanner subprocesses, OSV bulk data, public exploit metadata, and source-exploration agents are outside v0.1.
- The BSL 1.1 license is source-available, not open source. No commercial contact address or paid-support promise is published.
