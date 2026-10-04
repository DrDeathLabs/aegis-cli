# Development

## Environment

Use Python 3.11 and an isolated environment. From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Runtime constraints are declared in `pyproject.toml`; the `dev` extra contains test/lint tools only. No database or Trident runtime dependency is used.

## Check before review

```powershell
ruff check src tests
python -m compileall -q src tests
pytest
python -m build
twine check dist\*
```

Provider fixtures are under `fixtures/`; tests are under `tests/`. Do not place real vulnerability exports, provider tokens, blind acceptance inputs, or hidden expected outputs in a pull request.

## Release tooling

`scripts/verify_release_candidate.py` validates exact tag/source/version/confirmation/notes without publishing. Its `--self-test` path tests one success case and the required rejection cases in isolated temporary state. `scripts/create_release_manifest.py` generates checksums and a manifest from already-built artifacts; it does not publish. The GitHub workflow is the only release-creation path and is manually gated.

## Changes to supported behavior

Keep public documentation and fixtures aligned with explicit provider/generic contracts. A fixture is not live validation. Triage changes require invariants and regression/metamorphic tests; do not optimize policy for a prior private score. See [Contributing](../CONTRIBUTING.md).
