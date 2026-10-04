# Output formats

The `report` and `export` commands provide `json`, `csv`, `html`, and `table`. Both commands read the latest valid completed stages and fail rather than selecting a stale downstream file solely because it exists.

| Format | Intended use | Size/sensitivity notes |
|---|---|---|
| JSON | Machine-readable full findings and summary/queue information. | Includes the full finding set; large JSON may consume substantial disk and memory in downstream consumers. Default excludes the complete raw source record. |
| CSV | Tabular analysis in spreadsheet or data tools. | One row per finding; source identifiers, priority/disposition, correlation and remediation references are separate fields. Treat asset fields as sensitive. |
| HTML | Human-readable report. | Contains the report’s complete finding set; review in a controlled environment before sharing. |
| Table | Bounded CLI summary/top view for quick review. | Does not replace machine-readable full export; use `findings --limit N` for bounded finding-level paging. |

## Priority and disposition columns

`calculated_priority` is retained risk. `effective_priority` is the active remediation-queue priority and is null for inactive findings. Disposition is a separate value. A missing effective priority does not mean P4.

## Raw records and provenance

Default shareable output omits the complete raw source record and local source paths. It may still contain original mapped values, descriptions, hostnames/IPs, unknown scalar metadata, or other context that identifies the organization. Review an export. `--include-raw` opts into full source data and is not permission-controlled by the CLI.

## Bounded paths

`aegis findings --limit N` streams until N matching rows have been selected (so priority filtering may inspect more than N source rows). The table path is bounded. JSON/CSV/HTML export intentionally is not a small summary; ensure output storage and downstream processing can handle the complete report. Replay validation/export uses bounded record processing.
