# Changelog

Changes are recorded by release version. The v0.1.0 GitHub Release was initially issued while the repository was private; the repository was made public on 2026-10-05. This release has not been published to PyPI.

## 0.1.0

Aegis CLI is an AI-assisted enterprise vulnerability prioritization, correlation, and remediation tool. Its AI Council interprets and challenges evidence while deterministic rules retain final P0–P4 authority.

### Included

- File-first ingestion for the documented provider and generic formats listed in [the provider matrix](docs/PROVIDERS.md).
- Canonical evidence and provenance, deterministic P0–P4 triage, separate dispositions, correlation, remediation grouping, local replay, and JSON/CSV/HTML/table output.
- AI Council evidence development/challenge and deterministic P0–P4 triage; the Council has no final-priority authority.
- Evidence-preserving correlation, remediation grouping, longitudinal comparisons, provenance, replay, and JSON/CSV/HTML/table output.
- Release validation, documentation, CI, and manually gated release automation.

### Boundaries

- Local/file-first operation and eight supported provider/import paths; no live commercial-provider API validation is claimed.
- No ML classifier, corpus-calibration guard, or autonomous remediation.
- The repository was private when v0.1.0 was initially issued and was made public on 2026-10-05. No PyPI publication is made by this release.
- See [limitations](docs/LIMITATIONS.md) for the exact v0.1.0 boundaries.
