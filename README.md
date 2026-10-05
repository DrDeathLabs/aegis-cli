# Aegis CLI

AI-assisted enterprise vulnerability prioritization, correlation, and remediation.

Aegis turns vulnerability-management exports into an explainable remediation queue. It normalizes supported findings into a provider-independent model, preserves source evidence and provenance, develops evidence through an AI Council, applies deterministic P0–P4 triage, correlates related findings, and groups remediation actions.

## What it does

- Imports supported Tenable, Qualys, Rapid7, Microsoft Defender, CrowdStrike, Nessus, Generic JSON, and Generic CSV file shapes; this is file support, not live commercial-provider validation.
- Normalizes records to a canonical model while preserving provider-native signals, original records, field provenance, unknown fields, and quarantine accounting.
- Uses an AI Council to interpret and challenge evidence; deterministic rules, not an LLM or Council vote, assign P0–P4.
- Adds optional local ML vulnerability intelligence learned from public CVE/EPSS data. Model output is advisory evidence; it does not replace source EPSS/KEV/provider signals or assign priority.
- Keeps calculated priority separate from disposition and effective queue priority.
- Correlates duplicates, cross-provider findings, recurrence, conflicts, and remediation actions without CVE-only asset merges.
- Supports baseline/current longitudinal comparison, source provenance, and hash-checked replay.
- Offers local corpus/model status, refresh, build, train, info, path, and reset lifecycle commands. Normal analysis is offline and gracefully degrades when no usable model is installed.
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

To train the optional local model, install the `ml` extra (`python -m pip install "aegis-vulnerability-triage[ml]"`) and explicitly run `aegis model refresh`. Refresh downloads supported public feeds; normal import/analysis does not access the network. See [ML model](docs/ML_MODEL.md) and [model data sources](docs/MODEL_DATA.md).

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

## Current v0.1.0 scope

The CLI is local and file-first. It does not connect to commercial provider tenants, run scanners, deploy patches, or provide live-provider validation. Public feed and fixture evidence is not a commercial-provider validation claim. The optional model estimates whether a CVE's public EPSS value falls into an elevated band; it is not a direct exploitation fact, enterprise-loss forecast, or P0–P4 authority. The project is licensed under the Business Source License 1.1 (BSL 1.1), not an OSI-approved open-source license; see [LICENSE](LICENSE) and [COMMERCIAL.md](COMMERCIAL.md).
