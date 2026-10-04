# Dispositions

Disposition describes workflow or applicability, not risk severity. It is not encoded as P4.

| Disposition | Meaning | Active queue behavior |
|---|---|---|
| `confirmed` | Finding is accepted as applicable for remediation workflow. | Active; effective priority equals calculated priority. |
| `unconfirmed` | Evidence is insufficient or unresolved. | Inactive; effective priority is null. |
| `false_positive` | Evidence indicates the finding does not apply. | Inactive; not represented as P4. |
| `mitigated` | Effective mitigation is evidenced. | Inactive under the v0.1 queue contract; calculated priority is preserved. |
| `accepted_risk` | The organization has explicitly accepted the risk. | Inactive; calculated risk remains visible for governance and reassessment. |
| `remediated` | The source indicates remediation/closure. | Inactive; not represented as P4. |

The deterministic risk result is `calculated_priority`. `effective_priority` is queue-oriented and is null whenever `active_queue=false`; the compatibility `priority` field follows the queue value. A non-active finding therefore retains its calculated priority, drivers, and decision history without appearing as an active P0–P4 queue item.

Provider status labels are normalized only through known aliases. Unknown source status is retained rather than guessed. Disposition changes should be supported by source evidence or explicit operator workflow; Aegis does not silently turn missing identity/context into a false positive.
