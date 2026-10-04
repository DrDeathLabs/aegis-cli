# Architecture

## Data flow

```text
Provider files
    ↓ snapshot + hash + provider detection + record accounting
Raw records and provenance
    ↓ explicit adapters
Canonical findings
    ↓ offline/mock evidence analysis (no priority authority)
Evidence observations
    ↓ deterministic triage
Disposition + calculated priority + effective queue priority
    ↓ identity reconciliation and conflict-aware correlation
Groups, recurrence and conflicts
    ↓ evidence-precedence remediation grouping
Actions and report/export
```

The production CLI stages are `ingest → normalize → analyze → triage → correlate → remediation → report/export`. `run-all` runs ingest through remediation; reporting/export remains an explicit later command.

## Components and persistence

- `src/aegis/providers/` defines file readers and provider contracts.
- `src/aegis/ingest/` snapshots inputs, applies bounded selectors, records source accounting, and normalizes accepted records.
- `src/aegis/models.py` defines the canonical finding/evidence structure.
- `src/aegis/analysis/` develops structured evidence observations and challenges.
- `src/aegis/triage/` owns final deterministic P0–P4 assignment.
- `src/aegis/correlation.py` reconciles identities, duplicates, cross-provider observations, recurrence, and conflicts.
- `src/aegis/remediation.py` groups validated remediation evidence into actions.
- `src/aegis/reporting.py` produces sanitized JSON, CSV, HTML, and bounded table/findings views.
- `src/aegis/storage.py` writes local JSON/JSONL stage artifacts, metadata, events, and lineage.

Runtime dependencies are Click and Pydantic plus their installed transitive dependencies; Aegis does not use a database, queue service, or Trident package at runtime. The `_reference/trident-cli` tree is not read or imported by the application.

## Identity and correlation

Import-instance identity, optional provider occurrence ID, provider-native vulnerability ID, global CVE identity, target identity, mutable observations, and durable semantic vulnerability-on-target identity are separate. Enrichment adds non-conflicting observations without rotating the reconciled semantic handle. Provider-local IDs are namespaced. Correlation does not merge solely on CVE and does not use unrestricted transitive closure across conflicting targets. See [Correlation](CORRELATION.md) and [Canonical schema](CANONICAL_SCHEMA.md).

## Failure and lineage

Derived stages validate their upstream status and artifact lineage. Re-running an upstream stage invalidates dependent stage artifacts. Failed/rejected stages are terminal; `run-all` stops and exits nonzero rather than trusting an old file because it exists. Atomic local stage writes and structured events make interrupted work inspectable, but the run directory is not a multi-user transactional database.

## Scale boundaries

JSONL and CSV are the preferred large-file paths. Whole-document JSON/XML parsing is capped at 64 MiB, record size is bounded, and resource budgets are recorded. Disk and wall-clock limits are checked at stage boundaries; memory is reported as advisory, not an OS-enforced process limit. Large JSON reports retain all findings and may be large, while table and `findings --limit` views are bounded. See [Performance](PERFORMANCE.md).
