# Ingestion

Ingestion snapshots the exact source bytes into a run-local blob, hashes the snapshot, and parses that same snapshot. Each source file receives a provider decision, record pointers, original values, and terminal accounting. Normalization later maps accepted source records to the canonical schema and routes semantically invalid records to quarantine.

## Supported inputs

See [Provider contracts](PROVIDERS.md) for the exact v0.1 variants. JSONL/NDJSON and CSV/TSV are the preferred forms for large streams. JSON arrays and XML are whole-document formats bounded by `max_whole_document_bytes` (default 64 MiB); input files also have an overall bound (`max_input_bytes`, default 1 GiB). Per-record size, structural depth, and node count are bounded. These are implementation limits, not a promise that each maximum-size document fits a particular machine's memory.

## Record selection

Generic JSON uses root records or a finite set of semantic collection names (`findings`, `vulnerabilities`, `detections`, `results`, `issues`, `records`, `resources`, `items`, `value`, and `rows`) only at root or beneath recognized envelope wrappers such as `response`, `result`, `data`, `payload`, `body`, `collection`, `export`, or `page`. Automatic recursion does not cross opaque ancestors. Use repeatable `--selector /path/to/collection` for an otherwise opaque collection. A selector is a bounded pointer, not executable code.

Every accepted finding requires both a legitimate vulnerability/detection identity and a legitimate target identity. A source finding ID alone does not establish either. Titles, filenames, row position, pointers, placeholder values, and opaque IDs in the wrong namespace do not manufacture identity.

## Recovery and accounting

- A malformed JSONL line is quarantined while later valid lines continue through parsing.
- For multi-file imports, a file-level parse/detection failure is reported and other usable files can proceed.
- Duplicate JSON keys and duplicate CSV headers are surfaced for review; they are not silently resolved as canonical evidence.
- Unknown fields, array values, and values beyond a CSV header remain available as opaque source evidence.
- Each parsed record has a terminal accepted, accepted-with-warning, quarantined, or rejected accounting state. Run metadata records whether accounting balances.
- A run with no usable canonical findings is rejected and returns nonzero in `run-all`.

## Reviewing a run

Inspect `run.json`, `events.jsonl`, `raw_records.jsonl`, normalized findings, `quarantined.jsonl`, and the lineage manifest. Raw source records and source paths belong to the local internal run. Default reports are sanitized; see [Provenance and replay](PROVENANCE_AND_REPLAY.md) and [Output formats](OUTPUT_FORMATS.md).
