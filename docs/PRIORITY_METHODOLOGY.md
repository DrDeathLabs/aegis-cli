# Priority methodology

Priority is deterministic and reproducible from the structured finding. The engine first derives technical impact, threat, exposure, critical-asset context, mature exploitability, EPSS, and controls. It then evaluates explicit guards in a fixed order and records every driver. CVSS is an impact signal, not a standalone urgency signal; PoC-only evidence remains distinct from mature/reliable exploit evidence. `exploit_available=true` records exploit existence but does not establish mature, reliable, functional, weaponized, or in-the-wild exploit behavior when explicit maturity is absent or says `poc`/another non-mature value.

| Priority | Deterministic meaning |
|---|---|
| P0 | Critical technical impact plus active exploitation/KEV, internet exposure, and critical business/asset consequence. Mature exploit evidence strengthens the case but is not required when genuine KEV or exploited-in-the-wild evidence is present; strong controls remain visible but do not neutralize this incident combination. |
| P1 | Active exploitation with at least medium impact and exposure/criticality, or functional/weaponized/public exploit with high-or-greater impact and exposure/critical consequence, when P0 is not met. Very high EPSS can contribute only with high impact and context. |
| P2 | High impact with meaningful exposure/criticality/EPSS, active exploitation with context, or medium impact with functional/likelihood and meaningful context. High CVSS alone does not create P2. |
| P3 | Medium impact without the P2 context, or equivalent moderate consequence. |
| P4 | Low/unknown current consequence without a high-likelihood/high-consequence path. It is not a disposition. |

Strong compensating controls and isolated/segmented placement are inputs to tier selection, not generic post-tier decrements. They can move a low-likelihood, non-urgent, internally contained finding to P4, while a finding with critical consequence remains at least P3 for monitored remediation. The de-escalation gate is closed by active/KEV evidence, meaningful external exposure, mature exploit evidence, or high EPSS. Weak observations such as monitoring do not count as strong controls. Missing context is reported as missing context; it is not silently treated as a false positive or as P4 disposition. The engine never collapses CVSS, EPSS, KEV, provider risk, exposure, and criticality into an opaque score.

KEV or genuine exploited-in-the-wild evidence triggers `active_exploitation_guard` and establishes a deterministic minimum calculated priority of P2. Impact, exposure, criticality, mature exploit evidence, likelihood, and controls may still distinguish P0, P1, and P2; active evidence is not an automatic P0 or P1. The guard result and final calculated tier therefore cannot disagree by leaving an active/KEV finding at P3 or P4.

Technical impact is the maximum supported by the Council observation, normalized source severity, and numeric CVSS evidence. This source-evidence floor prevents a low or vague analysis observation from suppressing strong technical-impact evidence. Conversely, the P0 incident guard retains its critical-impact gate so a low-impact finding cannot become P0 solely because it has an exploit signal.

The P0 guard is an explicit conjunction of critical impact, active exploitation or KEV, internet exposure, and critical consequence. Mature exploit evidence is an independent strengthening signal, not a prerequisite when genuine active exploitation or KEV evidence is present. Strong controls are an override only when stronger incident evidence is absent; P1 and P2 are evaluated after the incident guard and record their triggered and non-triggered guard results. Calculated priority remains distinct from disposition and effective queue priority.

The final `calculated_priority` is always retained. The effective queue fields `effective_priority` and compatibility `priority` are null whenever `active_queue=false`, including `accepted_risk`, `mitigated`, `false_positive`, `remediated`, and `unconfirmed`; their calculated priority and drivers remain available for audit, reporting, reassessment, and governance.
