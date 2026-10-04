# Longitudinal analysis

Longitudinal analysis compares a current completed ingest/triage run with a baseline completed run. It uses reconciled semantic vulnerability-on-target entities, not record row numbers or whichever alias happens to be preferred in one report.

Run `aegis correlate --run-dir CURRENT --baseline-run-dir BASELINE` before remediation/reporting. The current run must have valid upstream stages and the baseline must be completed. Without a baseline, results are snapshot-only and new/stale/recurring counts are not inferred.

## Identity enrichment

When global vulnerability identity and a compatible target agree, a later non-conflicting observation can add a hostname, FQDN, IP, or provider asset identifier without rotating the durable entity handle. The comparator can then identify recurrence and retain stable group/action identifiers where semantics are unchanged. Contradictory target evidence is not automatically inherited; inspect the emitted conflict or ambiguity result.

## Counts

- **Recurring**: a current entity reconciles with a prior baseline entity.
- **New**: current entity has no unambiguous baseline match.
- **Stale**: baseline entity is absent from the current completed snapshot.

These are snapshot counts. They are not proof that an absent record was fixed; export scope, collection timing, asset identity changes, data loss, and provider coverage can affect results. Review source accounting, quarantine, and import scope before acting on stale findings.
