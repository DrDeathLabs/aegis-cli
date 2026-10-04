# Validation and evidence levels

## Evidence distinctions

| Level | What it establishes | What it does not establish |
|---|---|---|
| Unit/parser test | A bounded function/parser behavior on its test input. | Complete product behavior or a provider tenant. |
| Provider fixture test | Aegis mapping of a representative contract fixture. | All versions/fields or live API behavior. |
| Mock API test | Provider-independent pagination/retry/error mechanics with an injected mock. | Compatibility with or access to a real vendor service. |
| Installed-package integration | A cleanly installed wheel CLI processed the included fixture path. | A live provider, release-host workflow, or every real customer export. |
| Blind end-to-end acceptance | The specific public blind pack was processed by the tested build under its instructions. | Provider-by-provider correctness, live validation, or a score unless independently reported. |
| Live provider test | An actual provider instance was exercised with authorized credentials. | Broad compatibility outside that exercised instance/version. |

## v0.1 test areas

The repository suite covers parser/normalizer behavior, provider fixtures, malformed input, identity, triage/disposition, correlation, remediation, lineage/replay, redaction, budgets, and real CLI flows. Release evidence includes full pytest, Ruff, compileall, Bandit/Semgrep triage, current-tree and history secret scan, clean installed wheel/sdist checks, report/replay inspection, CLI examples, and Trident reference hash comparison.

The supplied accepted baseline is identified by the release owner. This readiness run does not recalculate a blind score or rerun hidden/private scoring. It reports the public pack-level acceptance as baseline context, not as a separate result for each provider. All live commercial provider/API validation remains **NO**.

## Reproducing checks

```powershell
ruff check src tests
python -m compileall -q src tests
pytest
python -m build
twine check dist\*
```

The returned evidence ZIP contains command logs and artifacts. Security scanner outputs must be interpreted with the manual dispositions in the result document; a scanner's success or failure is not the complete security conclusion.
