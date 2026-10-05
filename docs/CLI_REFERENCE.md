# CLI reference

The installed entry point is `aegis`. `python -m aegis.cli` is equivalent when the package is installed in the active Python environment. Global options are `--version` and `-h/--help`.

## Commands

| Command | Purpose and principal options |
|---|---|
| `aegis ingest INPUT...` | Create a run with raw source snapshots. Options: `--run-dir PATH`, `--provider auto|NAME`, repeatable `--selector POINTER` (Generic JSON only). |
| `aegis normalize --run-dir RUN` | Map raw records into canonical findings and quarantine invalid records. |
| `aegis analyze --run-dir RUN` | Produce evidence observations; `--backend offline|mock` (default `offline`). Neither backend assigns final priority. |
| `aegis triage --run-dir RUN` | Apply deterministic priority and disposition rules. |
| `aegis correlate --run-dir RUN` | Build duplicate, cross-provider, recurrence, stale, and conflict relationships. Optional `--baseline-run-dir RUN`. |
| `aegis remediation --run-dir RUN` | Group supported shared actions. |
| `aegis report --run-dir RUN` | Generate a user-facing report. `--format json|csv|html|table` (default `table`), optional `--output FILE`, optional `--include-raw`. |
| `aegis export FORMAT --run-dir RUN` | Export `json`, `csv`, `html`, or `table`; optional `--output FILE` and restricted `--include-raw`. |
| `aegis findings --run-dir RUN` | Stream findings in order. Optional `--priority P0..P4`, `--limit N` (default 100). |
| `aegis status --run-dir RUN` | Print run and stage status. |
| `aegis run-all INPUT...` | Run ingest through remediation. Options: `--run-dir PATH`, `--provider auto|NAME`, repeatable Generic JSON `--selector`. |
| `aegis replay-export --findings FILE --output FILE` | Export a canonical findings file with schema and content hash. |
| `aegis replay-validate ARTIFACT` | Validate a replay artifact without recomputing decisions. Invalid artifacts return nonzero. |

There is no parent command named `replay`; use the two replay commands above.

## Run paths and exit behavior

Commands that consume a run require its run directory. `run-all` does not generate a final report automatically; call `report` or `export` after it completes. Re-running an upstream stage invalidates stale dependent stages. `run-all` stops on a rejected/invalid upstream state and returns nonzero. An empty usable canonical dataset is rejected, not reported as success.

Malformed files may be accounted for while valid sibling files continue. Inspect `status`, run metadata, error/quarantine records, and stage lineage rather than interpreting an exit code alone.

## Help is authoritative

Options can change only in a versioned release. For exact installed-version syntax, run `aegis COMMAND --help`. Do not copy flags from a different version or infer a live provider/API option from fixture support.
