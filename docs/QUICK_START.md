# Quick Start

This walkthrough assumes a source checkout with the documented provider fixtures. It uses no provider credentials, model service, or network API.

## Install and run

From the repository root, use PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
aegis --version
aegis run-all fixtures/providers --run-dir .\aegis-demo-run
```

`run-all` performs ingest, normalize, analyze, triage, correlate, and remediation. It exits nonzero if an upstream stage is rejected or invalid.

## Inspect output

```powershell
aegis status --run-dir .\aegis-demo-run
aegis findings --run-dir .\aegis-demo-run --limit 20
aegis report --run-dir .\aegis-demo-run --format table
aegis export json --run-dir .\aegis-demo-run --output .\aegis-demo-run\report.json
aegis export csv --run-dir .\aegis-demo-run --output .\aegis-demo-run\report.csv
aegis export html --run-dir .\aegis-demo-run --output .\aegis-demo-run\report.html
```

The `--limit` option bounds the number of rows shown by `findings`. JSON, CSV, and HTML exports contain the complete normalized finding set and may be large. Default reports omit complete raw source records; do not use `--include-raw` for a shareable export.

## Run each stage explicitly

```powershell
aegis ingest fixtures/providers --run-dir .\aegis-explicit-run
aegis normalize --run-dir .\aegis-explicit-run
aegis analyze --run-dir .\aegis-explicit-run --backend offline
aegis triage --run-dir .\aegis-explicit-run
aegis correlate --run-dir .\aegis-explicit-run
aegis remediation --run-dir .\aegis-explicit-run
aegis report --run-dir .\aegis-explicit-run --format json --output .\aegis-explicit-run\report.json
```

## Explicit Generic JSON selector

Automatic collection discovery follows known semantic collection names beneath a small set of documented envelope names. It does not recursively turn arbitrary metadata arrays into findings. If the supported records are under an opaque ancestor, select the collection explicitly:

Save this sample as `input.json` in the repository root:

```json
{
  "metadata": {
    "data": {
      "items": [
        {
          "id": "selected-1",
          "cve": "CVE-2026-3003",
          "hostname": "selected.example"
        }
      ]
    }
  }
}
```

```powershell
aegis run-all .\input.json --provider generic_json --selector /metadata/data/items --run-dir .\aegis-selected-run
```

Selectors are data pointers, not expressions. Read [Ingestion](INGESTION.md) and [CLI reference](CLI_REFERENCE.md) for supported boundaries and failure behavior.
