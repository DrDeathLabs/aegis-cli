# Disposition methodology

Disposition describes workflow/evidence state, not urgency:

- `confirmed`: included in the active remediation queue with its calculated priority.
- `unconfirmed`: unresolved evidence; excluded from the active queue and never mislabeled P4.
- `false_positive`: evidence refutes applicability; excluded from the active queue and never mislabeled P4.
- `mitigated`: control evidence exists; calculated priority remains visible and the mitigation is a separate driver.
- `accepted_risk`: the organization accepts the risk; calculated priority remains visible but it is not an active confirmed queue item.
- `remediated`: the source indicates closure/fix; excluded from the active queue and never mislabeled P4.

Provider status values are normalized only through explicit aliases. Unknown statuses remain in the source record and are surfaced as the normalized status where no safe alias exists.
