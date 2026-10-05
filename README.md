# Aegis CLI

AI-assisted enterprise vulnerability prioritization, correlation, and remediation.

Aegis turns vulnerability-management exports into an explainable remediation queue. It normalizes supported findings into a provider-independent model, preserves source evidence and provenance, develops evidence through an AI Council, applies deterministic P0–P4 triage, correlates related findings, and groups remediation actions.

## What it does

- Imports supported Tenable, Qualys, Rapid7, Microsoft Defender, CrowdStrike, Nessus, Generic JSON, and Generic CSV file shapes; this is file support, not live commercial-provider validation.
- Normalizes records to a canonical model while preserving provider-native signals, original records, field provenance, unknown fields, and quarantine accounting.
- Uses an AI Council to interpret and challenge evidence; deterministic rules, not an LLM or Council vote, assign P0–P4.
- Keeps calculated priority separate from disposition and effective queue priority.
- Correlates duplicates, cross-provider findings, recurrence, conflicts, and remediation actions without CVE-only asset merges.
- Supports baseline/current longitudinal comparison, source provenance, and hash-checked replay.
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

The v0.1.0 distribution channel is GitHub Releases; PyPI publication is not part of this release. The repository remains private unless the owner changes its visibility separately. Review [CHANGELOG.md](CHANGELOG.md), [the feature status](docs/FEATURE_STATUS.md), and [known limitations](docs/LIMITATIONS.md) for the exact scope.

## Current v0.1.0 scope

The CLI is local and file-first. It supports eight provider/import paths but does not connect to commercial provider tenants, run scanners, deploy patches, or provide live-provider validation. The AI Council develops and challenges evidence while deterministic rules retain final P0–P4 authority. Aegis does not perform autonomous remediation. The project is licensed under the Business Source License 1.1 (BSL 1.1), not an OSI-approved open-source license; see [LICENSE](LICENSE) and [COMMERCIAL.md](COMMERCIAL.md).
