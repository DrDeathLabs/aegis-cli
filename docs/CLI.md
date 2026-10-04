# CLI reference

All commands are available through `python -m aegis.cli` or the installed `aegis` entry point.

```text
aegis ingest INPUT... [--run-dir PATH] [--provider NAME]
aegis normalize --run-dir PATH
aegis analyze --run-dir PATH [--backend offline|mock]
aegis triage --run-dir PATH
aegis correlate --run-dir PATH
aegis remediation --run-dir PATH
aegis report --run-dir PATH [--format json|csv|html|table] [--output PATH]
aegis export FORMAT --run-dir PATH [--output PATH]
aegis findings --run-dir PATH [--priority P0..P4] [--limit N]
aegis status --run-dir PATH
aegis run-all INPUT... --run-dir PATH [--provider NAME]
aegis replay-export --findings PATH --output PATH
aegis replay-validate ARTIFACT
```

JSON-producing commands return machine-readable stage metadata. Errors identify the input/file/record boundary and do not silently drop malformed data. Scalar JSON rows and CSV values beyond a declared header are retained as quarantine/opaque evidence. An empty or fully unreadable ingest writes run metadata and exits nonzero; mixed inputs continue with per-file errors and warnings.

JSON reports expose separate calculated and effective priority counts. CSV includes both priority fields plus correlation and remediation identifiers. HTML renders the complete finding set; a non-active finding retains its calculated priority while its effective queue priority is blank.
## Product contract details

The file-first v0.1 interface is:

```text
aegis ingest INPUT... [--provider auto|PROVIDER] [--selector /source/path]
aegis normalize --run-dir RUN
aegis analyze --run-dir RUN
aegis triage --run-dir RUN
aegis correlate --run-dir RUN
aegis remediation --run-dir RUN
aegis report --run-dir RUN --format json|csv|html|table
aegis export FORMAT --run-dir RUN
```

`--selector` is a bounded, repeatable explicit collection pointer for Generic
JSON input. It is intended for supported records below an otherwise opaque
ancestor such as `/metadata/data/items`; automatic discovery never traverses
that ancestry. Selectors are data, not executable expressions. Named-provider
inputs must use their declared structural contracts and do not accept a
selector override.

`run-all` executes the same stages transactionally. Any rejected, failed, or
invalid stage persists a terminal failed run and exits nonzero; dependent
stages are not reused.
