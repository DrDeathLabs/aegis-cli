# Aegis documentation

This documentation describes the supported v0.1.0 file-first contract. Start with [Installation](INSTALLATION.md) and [Quick Start](QUICK_START.md), then use the [CLI reference](CLI_REFERENCE.md) and [provider matrix](PROVIDERS.md).

## By task

| Task | Guide |
|---|---|
| Install and run the CLI | [Installation](INSTALLATION.md), [Quick Start](QUICK_START.md), [CLI reference](CLI_REFERENCE.md) |
| Prepare and import scanner exports | [Provider contracts](PROVIDERS.md), [Ingestion](INGESTION.md), [Canonical schema](CANONICAL_SCHEMA.md) |
| Understand system boundaries | [Architecture](ARCHITECTURE.md), [Security model](SECURITY_MODEL.md), [Limitations](LIMITATIONS.md) |
| Interpret decisions | [Prioritization](PRIORITIZATION.md), [Disposition](DISPOSITIONS.md), [Correlation](CORRELATION.md), [Remediation](REMEDIATION.md) |
| Compare runs and preserve evidence | [Longitudinal analysis](LONGITUDINAL_ANALYSIS.md), [Provenance and replay](PROVENANCE_AND_REPLAY.md) |
| Consume generated artifacts | [Output formats](OUTPUT_FORMATS.md), [Configuration](CONFIGURATION.md) |
| Review maturity and evidence | [Feature status](FEATURE_STATUS.md), [Validation](VALIDATION.md), [Performance](PERFORMANCE.md) |
| Build and troubleshoot | [Development](DEVELOPMENT.md), [CI/CD](CI_CD.md), [Troubleshooting](TROUBLESHOOTING.md) |
| Understand license status | [Open-source/source-available readiness](OPEN_SOURCE_READINESS.md), [LICENSE](../LICENSE), [COMMERCIAL.md](../COMMERCIAL.md) |

## Product boundary

Aegis is a local, file-first vulnerability-management and triage CLI. It does not call commercial scanner APIs in v0.1.0. Mocks and fixtures prove only the exercised offline contract. The AI Council develops and challenges evidence but cannot assign final priority; deterministic triage owns P0–P4. The BSL 1.1 license is source-available and is not an open-source license.
