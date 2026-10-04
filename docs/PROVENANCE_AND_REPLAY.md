# Provenance and replay

## Source provenance

At ingest, each input is copied to a run-local immutable source snapshot. The SHA-256 is calculated over those exact bytes, and the adapters parse that snapshot. Each record retains a source pointer, provider/source type, mapped field paths, original source values, unknown fields, mapping confidence/warnings, and typed provider identifiers. Run metadata, events, stage hashes, and versions support audit and lineage checks.

The raw source snapshot and lossless internal records may contain sensitive infrastructure details. Protect the run directory with appropriate host ACLs and retention controls. Do not attach it to a public issue or share it by default.

## Shareable output

Default report/export formats omit the complete original source record and redact local path fields. They still include mapped evidence and selected provider-native metadata, which may themselves identify assets or contain sensitive organizational information. Review an export before distribution. `--include-raw` explicitly requests lossless source records; the CLI flag is not an access-control boundary and must be treated as an internal-only export.

## Replay

`aegis replay-export --findings PATH --output PATH` creates a versioned, hash-checked canonical replay artifact. `aegis replay-validate PATH` validates its schema/version and content hash without recomputing priority. Invalid replay data returns a nonzero status. Replay is useful for integrity checking and exchanging canonical records; it is not a database backup, source snapshot, or guarantee that future software will make identical analysis choices.

## Lineage and reruns

Each derived stage records its input lineage. Re-running an upstream stage invalidates dependent artifacts; stale output should not be treated as the current run. Check `run.json`, `lineage_manifest.json`, and `events.jsonl` before consuming artifacts outside the CLI.
