# Contributing

Contributions should improve the documented v0.1 contract without weakening provenance, deterministic triage, disposition separation, quarantine/accounting, or default report redaction. Read [Development](docs/DEVELOPMENT.md), [Architecture](docs/ARCHITECTURE.md), [Limitations](docs/LIMITATIONS.md), and [LICENSE](LICENSE) first.

## Before opening a change

1. Search existing issues and documentation for the behavior.
2. For a defect, provide a sanitized minimal reproduction. Never attach a real tenant export, credentials, hidden acceptance data, or customer-identifying records.
3. For provider changes, cite the exact supported file contract and add a fixture that represents that contract; do not imply a live API integration.
4. For triage or identity changes, describe the invariant and test adjacent behavior, not only one example.

## Local checks

```powershell
python -m pip install -e ".[dev]"
ruff check src tests
python -m compileall -q src tests
pytest
python -m build
twine check dist\*
```

The CI workflow runs these checks plus a clean installed-wheel smoke and fixture E2E. Release-specific validation is documented in [CI/CD](docs/CI_CD.md).

## Licensing and review

The project is distributed under BSL 1.1 with the Aegis-specific grant in [LICENSE](LICENSE). Authors retain copyright in their contributions. By submitting a pull request, you represent that you have the right to contribute the material and agree it may be distributed as part of Aegis under the project license. No separate CLA or DCO process is configured in this release candidate. Maintainers may request tests, documentation, or a narrower scope before merge.

This is a source-available project, not an OSI-approved open-source project. Commercial or hosted-service questions are not handled through public issues; no contact address is published.
