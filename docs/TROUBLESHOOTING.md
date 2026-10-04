# Troubleshooting

## `aegis` is not found

Activate the Python environment where Aegis was installed, or call the environment's `Scripts/aegis.exe` (Windows) / `bin/aegis` (POSIX). Verify with `python -m pip show aegis-vulnerability-triage` and `aegis --version`.

## Provider not detected or ambiguous

Detection uses complete supported schema paths, not file names. Pass `--provider NAME` when the content matches a documented adapter, or use `generic_json` for supported generic content. Unsupported/ambiguous provider variants need an explicit reviewed mapping/contract change. Do not rename a file to force a provider.

## No usable findings or quarantined records

Check `run.json`, `normalize_accounting`, and `quarantined.jsonl`. A finding needs both a valid vulnerability/detection identifier and a valid target identifier. Empty/placeholder values, an occurrence ID alone, or title-only records do not create a finding. Fix the source export or provide the required Generic JSON selector/mapping; do not infer identities from file names.

## Large JSON/XML file rejected

Whole-document JSON/XML is capped by `max_whole_document_bytes` (64 MiB by default), even though `max_input_bytes` is larger. Use JSONL/NDJSON or CSV for large exports. Raising limits increases memory and should be tested on the target machine.

## Qualys/Nessus XML errors

The Qualys documented external DOCTYPE is stripped without resolving it; entity declarations are rejected. Do not remove the XML security boundary to make an arbitrary file parse. Check that XML is well-formed and follows a supported `HOST`/`DETECTION` or `ReportHost`/`ReportItem` structure.

## Stage is failed or output looks stale

Run `aegis status --run-dir RUN`, inspect events and lineage, and rerun only from the failed/upstream stage after preserving evidence. An upstream rerun invalidates downstream artifacts. `run-all` stops on rejected/invalid state; a nonzero exit needs investigation.

## Export is large or has no raw source record

JSON/CSV/HTML contain the full finding set but omit full raw records by default. Mapped values may still be sensitive. `--include-raw` is explicit and internal-only. The table and `findings --limit N` views are bounded.

## Replay validation fails

Use the exact replay artifact path and inspect the validator's nonzero error. Schema/version/content hash mismatch means the artifact must not be trusted or replayed as valid. Regenerate from a valid canonical findings stage.
