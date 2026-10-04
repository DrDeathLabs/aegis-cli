# Aegis CLI v0.1.0

Aegis turns vulnerability-management exports into an explainable remediation queue. It normalizes supported scanner/management exports into a provider-independent finding model, preserves evidence and provenance, applies deterministic P0–P4 triage, correlates related findings, and groups actionable remediation.

Aegis v0.1.0 is a local, file-first CLI. It does not connect to commercial provider tenants, run scanners, or publish data. Provider fixtures, mocks, and offline tests are not live-provider validation. The project is licensed under the Business Source License 1.1 (BSL 1.1), not an OSI-approved open-source license; see [LICENSE](LICENSE) and [COMMERCIAL.md](COMMERCIAL.md).

## What it does

- Imports supported Tenable, Qualys, Rapid7, Microsoft Defender, CrowdStrike, Nessus, Generic JSON, and Generic CSV file shapes.
- Normalizes records to a canonical model while preserving provider-native signals, original records, field provenance, unknown fields, and quarantine accounting.
- Develops evidence observations offline; deterministic rules, not an LLM or Council vote, assign P0–P4.
- Keeps calculated priority separate from disposition and effective queue priority.
- Correlates duplicates, cross-provider findings, recurrence, conflicts, and remediation actions without CVE-only asset merges.
- Exports JSON, CSV, HTML, or table reports. Default shareable exports omit full raw source records; `--include-raw` is an explicitly restricted lossless export option.

## Quick start

Use a Python 3.11 environment and a source checkout containing `fixtures/providers/`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
aegis --version
aegis run-all fixtures/providers --run-dir .\aegis-quickstart-run
aegis report --run-dir .\aegis-quickstart-run --format table
aegis export json --run-dir .\aegis-quickstart-run --output .\aegis-quickstart-run\report.json
```

See [Installation](docs/INSTALLATION.md) and [Quick Start](docs/QUICK_START.md) for source-archive and wheel workflows. These commands were checked against a clean installed CLI; the fixtures are examples, not a live provider connection.

## Workflow

The stages are explicit and produce local run artifacts:

`ingest → normalize → analyze → triage → correlate → remediation → report/export`

`aegis run-all` executes through remediation. Generate a report or export separately after it finishes. Any rejected or invalid upstream stage causes a nonzero result rather than silently reusing a stale downstream artifact.

## Documentation

Start at [the documentation index](docs/README.md). It links to installation, CLI reference, provider contracts, ingestion, architecture, prioritization, dispositions, correlation, remediation, longitudinal analysis, provenance/replay, output formats, configuration, security, validation, performance, development, and limitations.

## Support and security

Use the project’s GitHub issue tracker for ordinary support after the repository location is published. Do not post credentials, customer records, or vulnerability details in public issues. See [SECURITY.md](SECURITY.md) for security-reporting guidance. No separate support or commercial contact address is published in this release candidate.

## Release status

This is release-preparation material, not a published GitHub Release or package-index release. No package has been published by this work. Review [CHANGELOG.md](CHANGELOG.md), [the feature status](docs/FEATURE_STATUS.md), and [known limitations](docs/LIMITATIONS.md) before distribution.
