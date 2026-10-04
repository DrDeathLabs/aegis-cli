# Correlation

Correlation relates records without confusing vulnerability identity with target identity. Each finding has an import-instance ID, optional source occurrence ID, validated vulnerability identity, target observations, an observation-local alias signature, and a reconciled durable semantic entity handle. Native provider identifiers remain typed and namespaced.

## Relationships

- Exact duplicates and cross-provider duplicates require matching vulnerability identity and compatible, sufficiently strong target evidence.
- The same CVE across many assets is represented as separate asset-level entities and may appear in a vulnerability rollup; CVE alone never merges different or unknown assets.
- Hostname, FQDN, IP, and provider asset/device ID are separate observations. Non-conflicting enrichment can add aliases while retaining a durable entity handle when reconciled against a prior run.
- Contradictory target evidence is retained as a conflict/ambiguous relation rather than resolved by unrestricted transitive token closure.
- Recurrence/staleness comparison requires a completed baseline run. Without a baseline, Aegis does not infer historical recurrence.

`aegis correlate --run-dir CURRENT --baseline-run-dir BASELINE` compares a current run with a prior completed run. Stable handles are inherited only for an unambiguous, non-conflicting match. A new IP or hostname does not itself create a new vulnerability-on-asset entity; a conflict blocks automatic inheritance.

## Review

Inspect canonical group members, relation type, identity evidence, conflicts, and baseline/current counts. Group IDs are deterministic for the evidence and reconciliation state used; they are not universal identifiers across unrelated datasets. See [Longitudinal analysis](LONGITUDINAL_ANALYSIS.md) and [Provenance and replay](PROVENANCE_AND_REPLAY.md).
